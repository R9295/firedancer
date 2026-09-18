//! Opt-in integration test. Requires root, iproute2, nftables, and NFQUEUE.
use std::fs;
use std::io::{Read, Write};
use std::net::UdpSocket;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn ctl(socket: &Path, command: &str) -> std::io::Result<String> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    writeln!(stream, "{command}")?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

struct Session {
    dir: PathBuf,
    socket: PathBuf,
    child: Option<Child>,
}
impl Drop for Session {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = ctl(&self.socket, "stop");
            // Let the controller reap its owned child group before resorting
            // to SIGKILL; otherwise a failed test could leave its helper alive.
            for _ in 0..25 {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn fixture() -> (Session, Vec<PathBuf>) {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "execute this test binary with sudo"
    );
    let dir = PathBuf::from(format!(
        "/tmp/fd-netctl-smoke-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&dir).unwrap();
    let session = Session {
        socket: dir.join("control.sock"),
        dir,
        child: None,
    };
    fs::set_permissions(&session.dir, fs::Permissions::from_mode(0o700)).unwrap();
    let mut configs = Vec::new();
    for id in 0..3 {
        let base = 20000 + id * 100;
        let path = session.dir.join(format!("node-{id}.toml"));
        fs::write(
            &path,
            format!(
                r#"
name = "node-{id}"
[net]
provider = "socket"
interface = "lo"
bind_address = "127.0.0.1"
[gossip]
host = "127.0.0.1"
port = {gossip}
[tiles.quic]
regular_transaction_listen_port = {tpu}
quic_transaction_listen_port = {quic}
[tiles.shred]
shred_listen_port = {shred}
[tiles.repair]
repair_client_listen_port = {repair}
[tiles.rserve]
repair_serve_listen_port = {rserve}
[tiles.txsend]
txsend_src_port = {txsend}
[development.votor]
quic_client_listen_port = {client}
quic_server_listen_port = {server}
"#,
                gossip = base + 1,
                tpu = base + 2,
                quic = base + 3,
                shred = base + 4,
                repair = base + 5,
                rserve = base + 6,
                txsend = base + 7,
                client = base + 8,
                server = base + 9
            ),
        )
        .unwrap();
        configs.push(path);
    }
    (session, configs)
}

fn wait_ready(child: &mut Child, socket: &Path) {
    let start = Instant::now();
    loop {
        assert!(
            child.try_wait().unwrap().is_none(),
            "controller exited during startup"
        );
        if ctl(socket, "status").is_ok_and(|s| s.starts_with("OK ")) {
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "controller startup timed out"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_exit(child: &mut Child) -> ExitStatus {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "controller did not stop"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
#[ignore = "requires root and kernel NFQUEUE support"]
fn network_namespace_smoke() {
    let (mut session, configs) = fixture();
    let socket = session.dir.join("control.sock");
    session.child = Some(
        Command::new(env!("CARGO_BIN_EXE_fd-netctl"))
            .arg("serve")
            .arg(&socket)
            .args(&configs)
            .spawn()
            .unwrap(),
    );
    let child = session.child.as_mut().unwrap();
    wait_ready(child, &socket);
    let pid = child.id();
    assert!(Command::new(env!("CARGO_BIN_EXE_fd-netctl"))
        .arg("ctl")
        .arg(&socket)
        .arg("status")
        .status()
        .unwrap()
        .success());
    assert_ne!(
        fs::read_link("/proc/self/ns/net").unwrap(),
        fs::read_link(format!("/proc/{pid}/ns/net")).unwrap()
    );
    let status = Command::new("/usr/bin/nsenter")
        .args(["-t", &pid.to_string(), "-n", "--"])
        .arg(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "udp_helper", "--nocapture"])
        .env("FD_NETCTL_SMOKE_SOCKET", &socket)
        .status()
        .unwrap();
    assert!(status.success(), "UDP helper failed");
    assert!(ctl(&socket, "status")
        .unwrap()
        .contains(&format!("pid={pid} ")));
    assert!(ctl(&socket, "stop").unwrap().starts_with("OK "));
    assert!(wait_exit(child).success());
    assert!(
        !socket.exists(),
        "clean shutdown must remove the control socket"
    );
}

#[test]
#[ignore = "requires root and kernel NFQUEUE support"]
fn managed_launch_smoke() {
    let (mut session, configs) = fixture();
    // run must create this private parent directory itself.
    let socket = session.dir.join("run/control.sock");
    session.socket = socket.clone();
    session.child = Some(
        Command::new(env!("CARGO_BIN_EXE_fd-netctl"))
            .arg("run")
            .arg(&socket)
            .args(&configs)
            .arg("--")
            .arg(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "udp_helper", "--nocapture"])
            .env("FD_NETCTL_SMOKE_SOCKET", &socket)
            .spawn()
            .unwrap(),
    );
    assert!(wait_exit(session.child.as_mut().unwrap()).success());
    assert!(!socket.exists());
    assert_eq!(
        fs::metadata(socket.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

    // Reuse the same socket after cleanup, and preserve child failures.
    for (program, args, expected) in [
        ("/bin/sh", vec!["-c", "exit 7"], 7),
        ("/fd-netctl-nonexistent-command", vec![], 1),
    ] {
        session.child = Some(
            Command::new(env!("CARGO_BIN_EXE_fd-netctl"))
                .arg("run")
                .arg(&socket)
                .args(&configs)
                .arg("--")
                .arg(program)
                .args(args)
                .spawn()
                .unwrap(),
        );
        assert_eq!(
            wait_exit(session.child.as_mut().unwrap()).code(),
            Some(expected)
        );
        assert!(!socket.exists());
    }

    for signal in [None, Some(libc::SIGINT), Some(libc::SIGTERM)] {
        let pid_file = session.dir.join("child.pid");
        session.child = Some(
            Command::new(env!("CARGO_BIN_EXE_fd-netctl"))
                .arg("run")
                .arg(&socket)
                .args(&configs)
                .arg("--")
                .arg(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", "hold_helper", "--nocapture"])
                .env("FD_NETCTL_CHILD_PID_FILE", &pid_file)
                .spawn()
                .unwrap(),
        );
        let controller = session.child.as_mut().unwrap();
        wait_ready(controller, &socket);
        let start = Instant::now();
        while !pid_file.exists() {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "child did not start"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let pid: i32 = fs::read_to_string(&pid_file).unwrap().parse().unwrap();
        if let Some(signal) = signal {
            assert_eq!(unsafe { libc::kill(controller.id() as i32, signal) }, 0);
        } else {
            assert!(ctl(&socket, "stop").unwrap().starts_with("OK "));
        }
        assert_eq!(wait_exit(controller).code(), Some(130));
        assert!(!socket.exists());
        assert_eq!(
            unsafe { libc::kill(pid, 0) },
            -1,
            "managed child survived shutdown"
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
        fs::remove_file(pid_file).unwrap();
    }
}

#[test]
#[ignore = "requires root and kernel NFQUEUE support"]
fn delay_buffer_limit_smoke() {
    let (mut session, configs) = fixture();
    session.child = Some(
        Command::new(env!("CARGO_BIN_EXE_fd-netctl"))
            .arg("run")
            .arg(&session.socket)
            .args(&configs)
            .arg("--")
            .arg(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "fill_delay_helper", "--nocapture"])
            .env("FD_NETCTL_FILL_SOCKET", &session.socket)
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let child = session.child.as_mut().unwrap();
    assert_eq!(wait_exit(child).code(), Some(1));
    let mut errors = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut errors)
        .unwrap();
    assert!(
        errors.contains("delay buffer full (512 packets; test invalid)"),
        "{errors}"
    );
    assert!(!session.socket.exists());
}

#[test]
#[ignore = "helper runs only in the smoke test's private namespace"]
fn fill_delay_helper() {
    let Some(socket) = std::env::var_os("FD_NETCTL_FILL_SOCKET") else {
        return;
    };
    let socket = Path::new(&socket);
    let src = UdpSocket::bind("127.0.0.1:20001").unwrap();
    let dst = UdpSocket::bind("127.0.0.1:20201").unwrap();
    assert!(ctl(socket, "delay 0 2 5000").unwrap().starts_with("OK "));
    for n in 1..=512 {
        send(&src, &dst);
        wait_pending(socket, n); // Avoid netlink burst overflow masking our limit.
    }
    send(&src, &dst); // This must abort the run and kill this managed helper.
    std::thread::sleep(Duration::from_secs(30));
    panic!("controller did not enforce its delay-buffer limit");
}

#[test]
#[ignore = "helper runs only in the smoke test's private namespace"]
fn hold_helper() {
    let Some(pid_file) = std::env::var_os("FD_NETCTL_CHILD_PID_FILE") else {
        return;
    };
    fs::write(pid_file, std::process::id().to_string()).unwrap();
    std::thread::sleep(Duration::from_secs(30));
    panic!("controller failed to stop its child");
}

fn send(src: &UdpSocket, dst: &UdpSocket) {
    let bytes = [42u8; 513]; // Odd length also exercises duplicate UDP checksums.
    assert_eq!(
        src.send_to(&bytes, dst.local_addr().unwrap()).unwrap(),
        bytes.len()
    );
}

fn receive(src: &UdpSocket, dst: &UdpSocket, delivered: bool) {
    let bytes = [42u8; 513];
    let mut buf = [0; 1024];
    match dst.recv_from(&mut buf) {
        Ok((n, addr)) => {
            assert!(delivered, "blocked datagram arrived");
            assert_eq!(&buf[..n], &bytes);
            assert_eq!(addr, src.local_addr().unwrap());
        }
        Err(e) => {
            assert!(!delivered, "allowed datagram missing: {e}");
            assert!(matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ));
        }
    }
}

fn exchange(src: &UdpSocket, dst: &UdpSocket, delivered: bool) {
    send(src, dst);
    receive(src, dst, delivered);
}

fn wait_pending(socket: &Path, expected: usize) {
    let start = Instant::now();
    loop {
        let status = ctl(socket, "status").unwrap();
        if status
            .split_whitespace()
            .any(|s| s == format!("pending={expected}"))
        {
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "pending count did not reach {expected}: {status}"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
#[ignore = "helper runs only in the smoke test's private namespace"]
fn udp_helper() {
    let Some(socket) = std::env::var_os("FD_NETCTL_SMOKE_SOCKET") else {
        return;
    };
    let socket = Path::new(&socket);
    let status = ctl(socket, "status").unwrap();
    let pid = status
        .split_whitespace()
        .find_map(|s| s.strip_prefix("pid="))
        .unwrap();
    assert_eq!(
        fs::read_link("/proc/self/ns/net").unwrap(),
        fs::read_link(format!("/proc/{pid}/ns/net")).unwrap()
    );
    // No controller sockets should survive the managed child's exec.
    for entry in fs::read_dir("/proc/self/fd").unwrap() {
        let fd: i32 = entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .parse()
            .unwrap();
        let mut domain: libc::c_int = 0;
        let mut len = std::mem::size_of_val(&domain) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_DOMAIN,
                (&mut domain as *mut libc::c_int).cast(),
                &mut len,
            )
        } == 0
        {
            assert_ne!(domain, libc::AF_NETLINK, "inherited controller netlink fd");
        }
    }
    let nodes: Vec<_> = [20001, 20101, 20201, 30001]
        .iter()
        .map(|&port| {
            let sock = UdpSocket::bind(("127.0.0.1", port)).unwrap();
            sock.set_read_timeout(Some(Duration::from_millis(300)))
                .unwrap();
            sock
        })
        .collect();
    let command = |s| assert!(ctl(socket, s).unwrap().starts_with("OK "));
    exchange(&nodes[0], &nodes[2], true);
    command("block 0 2");
    exchange(&nodes[0], &nodes[2], false);
    exchange(&nodes[2], &nodes[0], true);
    command("block 2 0");
    exchange(&nodes[2], &nodes[0], false);
    exchange(&nodes[0], &nodes[1], true);
    exchange(&nodes[0], &nodes[3], true);
    exchange(&nodes[3], &nodes[0], true);
    assert!(ctl(socket, "block 0 3").unwrap().starts_with("ERR "));
    command("allow 0 2");
    exchange(&nodes[0], &nodes[2], true);
    exchange(&nodes[2], &nodes[0], false);
    command("heal");
    exchange(&nodes[0], &nodes[2], true);
    exchange(&nodes[2], &nodes[0], true);
    let status = ctl(socket, "status").unwrap();
    assert!(
        status.contains("accepted=6 dropped=3 unclassified=0"),
        "{status}"
    );
    assert!(status.contains("generation=4"), "{status}");

    // Delay is directional and does not block the controller or other links.
    command("delay 0 2 200");
    let start = Instant::now();
    send(&nodes[0], &nodes[2]);
    exchange(&nodes[2], &nodes[0], true);
    receive(&nodes[0], &nodes[2], true);
    assert!(start.elapsed() >= Duration::from_millis(200));

    // Combined delay/duplication: exactly two intact deliveries, not a loop.
    command("duplicate 0 2 1");
    let start = Instant::now();
    exchange(&nodes[0], &nodes[2], true);
    assert!(start.elapsed() >= Duration::from_millis(200));
    receive(&nodes[0], &nodes[2], true);
    receive(&nodes[0], &nodes[2], false);

    command("delay 0 2 0");
    exchange(&nodes[0], &nodes[2], true);
    receive(&nodes[0], &nodes[2], true);
    receive(&nodes[0], &nodes[2], false);
    exchange(&nodes[2], &nodes[0], true);
    receive(&nodes[2], &nodes[0], false); // Reverse direction was never duplicated.
    command("duplicate 0 2 0");
    exchange(&nodes[0], &nodes[2], true);
    receive(&nodes[0], &nodes[2], false);

    // block cancels held originals AND their prospective copies.
    command("delay 0 2 5000");
    command("duplicate 0 2 1");
    send(&nodes[0], &nodes[2]);
    wait_pending(socket, 1);
    command("block 0 2");
    wait_pending(socket, 0);
    receive(&nodes[0], &nodes[2], false);

    // heal releases each held original once and clears all future faults.
    command("allow 0 2");
    send(&nodes[0], &nodes[2]);
    wait_pending(socket, 1);
    command("heal");
    receive(&nodes[0], &nodes[2], true);
    receive(&nodes[0], &nodes[2], false);
    wait_pending(socket, 0);
    exchange(&nodes[0], &nodes[2], true);
    receive(&nodes[0], &nodes[2], false);
    let status = ctl(socket, "status").unwrap();
    assert!(
        status.contains("duplicated=2 delayed=4 pending=0"),
        "{status}"
    );
    assert!(status.contains("dropped=4"), "{status}");
    assert!(
        !status.contains("\ndelay ") && !status.contains("\nduplicate "),
        "{status}"
    );

    // Entering automatic mode cancels prior delay/duplication policy and
    // releases held originals once before any model-selected fault is applied.
    command("delay 0 2 5000");
    command("duplicate 0 2 1");
    send(&nodes[0], &nodes[2]);
    wait_pending(socket, 1);
    command("typesafe-start");
    receive(&nodes[0], &nodes[2], true);
    receive(&nodes[0], &nodes[2], false);
    wait_pending(socket, 0);
    typesafe_udp_checks(socket, &nodes);
}

fn typesafe_udp_checks(socket: &Path, gossip: &[UdpSocket]) {
    use fd_netctl::typesafe::{DropFault, Protocol, Snapshot};
    let protocols = [
        Protocol::Shred,
        Protocol::Repair,
        Protocol::Repair,
        Protocol::Votor,
        Protocol::Votor,
    ];
    let ports: Vec<Vec<_>> = (0..3)
        .map(|id| {
            [4, 5, 6, 8, 9]
                .into_iter()
                .map(|offset| {
                    let socket = UdpSocket::bind(("127.0.0.1", 20000 + id * 100 + offset)).unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_millis(80)))
                        .unwrap();
                    socket
                })
                .collect()
        })
        .collect();
    for fault in DropFault::all() {
        let raw = ctl(socket, "typesafe-state").unwrap();
        let state: Snapshot = serde_json::from_str(raw.strip_prefix("OK ").unwrap()).unwrap();
        let command = format!(
            "typesafe-drop {} {} {} {}",
            state.instance,
            state.session.unwrap(),
            state.generation,
            fault.id()
        );
        let response = ctl(socket, &command).unwrap();
        assert!(response.starts_with("OK FAULT applied:"), "{response}");
        for src in 0..3 {
            for dst in 0..3 {
                if src == dst {
                    continue;
                }
                for (port, protocol) in protocols.iter().enumerate() {
                    exchange(
                        &ports[src][0],
                        &ports[dst][port],
                        !fault.matches(src, dst, Some(*protocol)),
                    );
                }
            }
        }
        exchange(
            &gossip[fault.src],
            &gossip[fault.dst],
            !fault.matches(fault.src, fault.dst, Some(Protocol::Gossip)),
        );
        assert!(ctl(socket, "block 0 1").unwrap().starts_with("ERR "));
    }
    assert!(ctl(socket, "heal").unwrap().starts_with("OK "));
    for src in 0..3 {
        for dst in 0..3 {
            if src == dst {
                continue;
            }
            for port in &ports[dst] {
                exchange(&ports[src][0], port, true);
            }
        }
    }
    assert!(!ctl(socket, "status").unwrap().contains("\nactive:"));
}
