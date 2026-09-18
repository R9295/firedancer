use fd_netctl::typesafe;
use fd_netctl::{Policy, QUEUE, QUEUE_LEN};
use nfq::Queue;
mod delivery;
use delivery::{Deliveries, COPY_RANGE};
use std::error::Error;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::io::RawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const NETLINK_RECEIVE_BUFFER: libc::c_int = 32 * 1024 * 1024;
const PACKET_BATCH: usize = 4096;
const HELP: &str = "Usage:
  fd-netctl check NODE.toml [...]
  sudo fd-netctl serve SOCKET NODE.toml [...]
  sudo fd-netctl run SOCKET NODE.toml [...] -- PROGRAM [ARG ...]
  sudo fd-netctl ctl SOCKET status
  sudo fd-netctl ctl SOCKET block FROM TO
  sudo fd-netctl ctl SOCKET allow FROM TO
  sudo fd-netctl ctl SOCKET delay FROM TO MS
  sudo fd-netctl ctl SOCKET duplicate FROM TO 0|1
  sudo --preserve-env=TYPESAFE_API_KEY,TYPESAFE_MODEL fd-netctl ctl SOCKET typesafe [SECONDS]
  sudo fd-netctl ctl SOCKET heal
  sudo fd-netctl ctl SOCKET stop

Node IDs are config-list indices, starting at zero. block/allow are directed.
run creates the network setup, launches PROGRAM inside it, and stops with it.
Ctrl-C or ctl stop ends the managed run. serve instead waits for manual launches.
Only configured loopback UDP port pairs enter the controller.
Delay is 0..5000ms; duplicate=1 sends one extra copy. heal resets all faults.
typesafe selects one of 24 directed drops every SECONDS (default 1).
Requires exactly three nodes and TYPESAFE_API_KEY. Ctrl-C or heal stops injection.
No payload editing, TLS termination, or validator restarts are performed.";

fn tool(name: &str) -> Result<PathBuf> {
    ["/usr/sbin", "/usr/bin", "/sbin", "/bin"]
        .iter()
        .map(|dir| Path::new(dir).join(name))
        .find(|path| path.is_file())
        .ok_or_else(|| format!("missing {name}; install iproute2 and nftables").into())
}

fn nft(path: &Path, rules: &str) -> Result<()> {
    let mut child = Command::new(path)
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let written = child.stdin.take().unwrap().write_all(rules.as_bytes());
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(format!("nft: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    written?;
    Ok(())
}

fn open_fds() -> Result<std::collections::HashSet<RawFd>> {
    Ok(std::fs::read_dir("/proc/self/fd")?
        .filter_map(|entry| entry.ok()?.file_name().to_string_lossy().parse().ok())
        .collect())
}

fn set_receive_buffer(fd: RawFd) -> Result<()> {
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&NETLINK_RECEIVE_BUFFER as *const libc::c_int).cast(),
            std::mem::size_of_val(&NETLINK_RECEIVE_BUFFER) as libc::socklen_t,
        )
    } < 0
    {
        return Err(format!(
            "setting NFQUEUE receive buffer: {}",
            io::Error::last_os_error()
        )
        .into());
    }
    Ok(())
}

fn tune_netlink_socket() -> Result<()> {
    let mut matches = Vec::new();
    for fd in open_fds()? {
        let mut domain: libc::c_int = 0;
        let mut protocol: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let domain_ok = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_DOMAIN,
                (&mut domain as *mut libc::c_int).cast(),
                &mut len,
            )
        } == 0;
        len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let protocol_ok = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PROTOCOL,
                (&mut protocol as *mut libc::c_int).cast(),
                &mut len,
            )
        } == 0;
        if domain_ok
            && protocol_ok
            && domain == libc::AF_NETLINK
            && protocol == libc::NETLINK_NETFILTER
        {
            matches.push(fd);
        }
    }
    let [fd] = matches.as_slice() else {
        return Err(format!("expected one new NFQUEUE socket, found {}", matches.len()).into());
    };
    set_receive_buffer(*fd)
}

fn is_nfq_overrun(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ENOBUFS)
}

struct Cleanup {
    socket: PathBuf,
    nft: PathBuf,
    rules_installed: bool,
}
impl Cleanup {
    fn remove_rules(&mut self) -> Result<()> {
        if self.rules_installed {
            nft(&self.nft, "delete table ip fd_cluster_net\n")?;
            self.rules_installed = false;
        }
        Ok(())
    }
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Err(e) = self.remove_rules() {
            eprintln!("cleanup: {e}");
        }
        if let Err(e) = std::fs::remove_file(&self.socket) {
            eprintln!("socket cleanup: {e}");
        }
    }
}

// Own only the command's process group, never the caller's terminal group.
// Drop also runs on controller errors, before removing its network rules.
struct ManagedChild(Child);
impl ManagedChild {
    fn spawn(command: &[String]) -> Result<Self> {
        // nfq opens its netlink socket without CLOEXEC. Do not leak controller
        // descriptors into validators (or keep the queue bound through them).
        let mut fds = Vec::new();
        for entry in std::fs::read_dir("/proc/self/fd")? {
            if let Ok(fd) = entry?.file_name().to_string_lossy().parse::<i32>() {
                if fd > 2 {
                    fds.push(fd);
                }
            }
        }
        let mut cmd = Command::new(&command[0]);
        cmd.args(&command[1..])
            .env_remove("TYPESAFE_API_KEY")
            .stdin(Stdio::null())
            .process_group(0);
        // Only async-signal-safe syscalls in the post-fork child. EBADF is
        // expected for the /proc directory descriptor, already closed above.
        unsafe {
            cmd.pre_exec(move || {
                for &fd in &fds {
                    if libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
                        let e = io::Error::last_os_error();
                        if e.raw_os_error() != Some(libc::EBADF) {
                            return Err(e);
                        }
                    }
                }
                Ok(())
            });
        }
        Ok(Self(cmd.spawn()?))
    }
}
impl Drop for ManagedChild {
    fn drop(&mut self) {
        // The test runner creates a PID-namespace supervisor. Kill the whole
        // owned group, not just its outer waiter, so validators cannot linger.
        unsafe { libc::kill(-(self.0.id() as i32), libc::SIGKILL) };
        let _ = self.0.wait();
    }
}

fn serve(socket: &str, configs: &[String], command: Option<&[String]>) -> Result<i32> {
    let mut policy = Policy::load(configs)?;
    let ip = tool("ip")?;
    let nft_path = tool("nft")?;
    // Never install rules in the caller's namespace, even when run as root.
    if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
        return Err(format!(
            "creating private network namespace: {} (run with sudo)",
            io::Error::last_os_error()
        )
        .into());
    }
    if !Command::new(ip)
        .args(["link", "set", "lo", "up"])
        .status()?
        .success()
    {
        return Err("could not bring up private loopback interface".into());
    }
    let mut queue = Queue::open()?;
    tune_netlink_socket()?;
    queue.bind(QUEUE)?;
    queue.set_queue_max_len(QUEUE, QUEUE_LEN)?;
    queue.set_copy_range(QUEUE, COPY_RANGE)?;
    queue.set_fail_open(QUEUE, false)?;
    queue.set_recv_enobufs(true)?;
    queue.set_nonblocking(true);

    // run creates a private directory if needed; never change permissions on
    // an existing directory or replace an existing/stale control socket.
    let socket = PathBuf::from(socket);
    let parent = socket
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or("use an absolute socket path")?;
    if !socket.is_absolute() {
        return Err("use an absolute socket path".into());
    }
    if command.is_some() {
        match std::fs::DirBuilder::new().mode(0o700).create(parent) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    let meta = std::fs::symlink_metadata(parent)?;
    use std::os::unix::fs::MetadataExt;
    if !meta.is_dir()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.permissions().mode() & 0o077 != 0
    {
        return Err(
            "socket parent must be a private directory owned by the controller user (mode 0700)"
                .into(),
        );
    }
    let listener = UnixListener::bind(&socket)?;
    let mut cleanup = Cleanup {
        socket,
        nft: nft_path,
        rules_installed: false,
    };
    std::fs::set_permissions(&cleanup.socket, std::fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let stop = Arc::new(AtomicBool::new(false));
    let signal_stop = Arc::clone(&stop);
    ctrlc::set_handler(move || signal_stop.store(true, Ordering::Relaxed))?;
    nft(&cleanup.nft, &policy.rules())?;
    cleanup.rules_installed = true;
    print!("{}", policy.status());
    if command.is_some() {
        println!("Network ready. Starting cluster; Ctrl-C stops the cluster and controller.");
    } else {
        println!(
            "Ready. Start validators with: sudo nsenter -t {} -n -- <cluster command>",
            std::process::id()
        );
    }
    io::stdout().flush()?;
    // Spawn only after both the queue and rules are ready. The child inherits
    // this private network namespace; no nsenter or PID handoff is needed.
    let mut child = command.map(ManagedChild::spawn).transpose()?;
    let mut exit_code = if child.is_some() { 130 } else { 0 };
    let mut deliveries = Deliveries::default();

    while !stop.load(Ordering::Relaxed) {
        if let Some(child) = &mut child {
            if let Some(status) = child.0.try_wait()? {
                exit_code = status.code().unwrap_or(128 + status.signal().unwrap_or(1));
                break;
            }
        }
        deliveries.release_due(&mut queue, &mut policy)?;
        let mut busy = false;
        // Drain large bursts while still checking control commands regularly.
        for _ in 0..PACKET_BATCH {
            let msg = match queue.recv() {
                Ok(msg) => msg,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if is_nfq_overrun(&e) => {
                    policy.overruns += 1;
                    if policy.overruns == 1 || policy.overruns.is_power_of_two() {
                        eprintln!("WARNING: NFQUEUE receive overrun #{}; kernel dropped packets; continuing", policy.overruns);
                    }
                    busy = true;
                    continue;
                }
                Err(e) => return Err(format!("NFQUEUE receive failed (test invalid): {e}").into()),
            };
            deliveries.receive(msg, &mut queue, &mut policy)?;
            busy = true;
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_read_timeout(Some(Duration::from_millis(100)))?;
                stream.set_write_timeout(Some(Duration::from_millis(100)))?;
                let mut line = String::new();
                let read = BufReader::new((&stream).take(257)).read_line(&mut line);
                let response = match read {
                    Ok(_) if line.len() <= 256 && line.ends_with('\n') => {
                        if line.trim() == "stop" {
                            stop.store(true, Ordering::Relaxed);
                            "OK stopping\n".to_owned()
                        } else {
                            match policy.command(&line) {
                                Ok(response) => {
                                    let action = line.split_whitespace().next().unwrap_or("");
                                    if matches!(
                                        action,
                                        "heal"
                                            | "block"
                                            | "typesafe-start"
                                            | "typesafe-end"
                                            | "typesafe-drop"
                                    ) {
                                        deliveries.policy_changed(
                                            matches!(
                                                action,
                                                "heal" | "typesafe-start" | "typesafe-end"
                                            ),
                                            &mut queue,
                                            &mut policy,
                                        )?;
                                    }
                                    if action == "typesafe-drop" {
                                        print!("{}", response.trim_start_matches("OK "));
                                        io::stdout().flush()?;
                                    }
                                    response
                                }
                                Err(e) => format!("ERR {e}\n"),
                            }
                        }
                    }
                    _ => "ERR expected one newline-terminated command, at most 256 bytes\n".into(),
                };
                // A disconnected control client must not stop packet handling.
                let _ = stream.write_all(response.as_bytes());
                busy = true;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
        if !busy {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    // Stop managed children before restoring links. Other namespace members can
    // continue communicating after a clean stop; SIGKILL instead fails closed.
    drop(child);
    cleanup.remove_rules()?;
    drop(cleanup);
    Ok(exit_code)
}

fn control(socket: &str, words: &[String]) -> Result<()> {
    if words.first().is_some_and(|word| word == "typesafe") {
        if words.len() > 2 {
            return Err("expected: typesafe [SECONDS]".into());
        }
        return typesafe::run(
            socket,
            typesafe::interval(words.get(1).map(String::as_str))?,
        );
    }
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    writeln!(stream, "{}", words.join(" "))?;
    let mut response = String::new();
    stream.take(1024 * 1024).read_to_string(&mut response)?;
    print!("{response}");
    if !response.starts_with("OK ") && !response.starts_with("OK\n") {
        return Err("controller rejected the command".into());
    }
    Ok(())
}

fn run() -> Result<i32> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("check") if args.len() >= 2 => {
            let policy = Policy::load(&args[1..])?;
            print!("{}{}", policy.status(), policy.rules());
            Ok(0)
        }
        Some("serve") if args.len() >= 3 => serve(&args[1], &args[2..], None),
        Some("run") => {
            let split = args
                .iter()
                .position(|s| s == "--")
                .filter(|&i| i >= 3 && i + 1 < args.len())
                .ok_or(HELP)?;
            serve(&args[1], &args[2..split], Some(&args[split + 1..]))
        }
        Some("ctl") if args.len() >= 3 => control(&args[1], &args[2..]).map(|()| 0),
        None | Some("--help" | "-h") => {
            println!("{HELP}");
            Ok(0)
        }
        _ => Err(HELP.into()),
    }
}

fn main() {
    let status = run().unwrap_or_else(|e| {
        eprintln!("fd-netctl: {e}");
        1
    });
    std::process::exit(status);
}
