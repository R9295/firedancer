//! Test the public launcher with stub binaries: no sudo, network, or validators.
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let dir = PathBuf::from(format!(
            "/tmp/fd-netctl-runner-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        let fixture = Self(dir);
        fixture.script("mock/make", "printf '%s/build\\n' \"$FD\"");
        fixture.script(
            "mock/cargo",
            "printf 'cargo'; printf ' <%s>' \"$@\"; printf '\\n'",
        );
        fixture.script("mock/sudo", "case \"$1\" in --preserve-env=TYPESAFE_API_KEY,TYPESAFE_MODEL) shift ;; *) unset TYPESAFE_API_KEY TYPESAFE_MODEL ;; esac\n[ \"$1\" = -- ] && shift\nexec \"$@\"");
        fixture.script("build/bin/firedancer-dev", "exit 0");
        let report = "printf 'configs=%s\\nroot=%s\\ntimeout=%s\\n' \"${FD_CLUSTER_CONFIGS:-}\" \"${FD_CLUSTER_ROOT_SLOT:-}\" \"${FD_CLUSTER_TIMEOUT_S:-}\"\nprintf 'arg=%s\\n' \"$@\"\nexit \"${FD_NETCTL_STUB_EXIT:-0}\"";
        fixture.script("build/integration-test/test_firedancer_cluster", report);
        fixture.script("contrib/test/fd-netctl/target/release/fd-netctl", report);
        for id in 0..3 {
            fs::write(fixture.0.join(format!("node-{id}.toml")), "").unwrap();
        }
        fixture
    }

    fn script(&self, path: &str, body: &str) {
        let path = self.0.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn configs(&self) -> String {
        format!(
            "{}/node-0.toml:{}/node-1.toml",
            self.0.display(),
            self.0.display()
        )
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new("/bin/bash");
        cmd.arg(concat!(env!("CARGO_MANIFEST_DIR"), "/../run_fd_cluster.sh"))
            .args(args)
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.0.join("mock").display()),
            )
            .env("FD", &self.0)
            .env("C", self.0.join("nonexistent-cluster-dir"))
            .env("FD_CLUSTER_CONFIGS", self.configs())
            .env("FD_NETCTL_SOCKET", self.0.join("control.sock"))
            .env_remove("FD_CLUSTER_ROOT_SLOT")
            .env_remove("FD_CLUSTER_TIMEOUT_S")
            .env_remove("FD_CLUSTER_BUILD_JOBS")
            .env_remove("FD_NETCTL_STUB_EXIT")
            .env_remove("TYPESAFE_API_KEY")
            .env_remove("TYPESAFE_MODEL")
            .env_remove("SUDO_USER");
        cmd
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn launcher_forwards_configs_and_settings() {
    let f = Fixture::new();
    let output = success(f.command(&["net"]).output().unwrap());
    assert!(output.contains("cargo <build> <--locked> <--release>"));
    assert!(
        output.contains(&format!("configs={}\nroot=256\ntimeout=180\n", f.configs())),
        "{output}"
    );
    assert!(output.contains(&format!("arg=run\narg={0}/control.sock\narg={0}/node-0.toml\narg={0}/node-1.toml\narg=--\narg={0}/build/integration-test/test_firedancer_cluster\n", f.0.display())), "{output}");
    let output = success(
        f.command(&["net", "--root-slot", "91", "--timeout", "37"])
            .output()
            .unwrap(),
    );
    assert!(output.contains("root=91\ntimeout=37"));
    let output = success(
        f.command(&["net"])
            .env("FD_CLUSTER_ROOT_SLOT", "72")
            .output()
            .unwrap(),
    );
    assert!(output.contains("root=72\ntimeout=180"));
    let output = success(f.command(&["run"]).output().unwrap());
    assert!(output.contains("root=8\ntimeout=180"));
    assert!(!output.contains("cargo"));
    assert_eq!(
        f.command(&["net"])
            .env("FD_NETCTL_STUB_EXIT", "7")
            .status()
            .unwrap()
            .code(),
        Some(7)
    );
}

#[test]
fn launcher_discovers_every_default_config_in_version_order() {
    let f = Fixture::new();
    fs::write(f.0.join("node-10.toml"), "").unwrap();
    fs::write(f.0.join("node-9.toml"), "").unwrap();
    let output = success(
        f.command(&["run"])
            .env_remove("FD_CLUSTER_CONFIGS")
            .env("C", &f.0)
            .output()
            .unwrap(),
    );
    let configs = [0, 1, 2, 9, 10]
        .map(|id| f.0.join(format!("node-{id}.toml")))
        .map(|path| path.display().to_string())
        .join(":");
    assert!(output.contains(&format!("configs={configs}\n")), "{output}");
}

#[test]
fn control_shortcut_does_not_need_configs_or_build() {
    let f = Fixture::new();
    let output = success(
        f.command(&["netctl", "block", "0", "2"])
            .env_remove("FD_CLUSTER_CONFIGS")
            .output()
            .unwrap(),
    );
    assert!(!output.contains("cargo"));
    assert!(output.contains(&format!(
        "arg=ctl\narg={}/control.sock\narg=block\narg=0\narg=2\n",
        f.0.display()
    )));
    let output = success(
        f.command(&["netctl"])
            .env_remove("FD_CLUSTER_CONFIGS")
            .output()
            .unwrap(),
    );
    assert!(output.ends_with("arg=status\n"));
    for (action, value) in [("delay", "100"), ("duplicate", "1")] {
        let output = success(
            f.command(&["netctl", action, "0", "2", value])
                .output()
                .unwrap(),
        );
        assert!(output.ends_with(&format!("arg={action}\narg=0\narg=2\narg={value}\n")));
    }
    assert_eq!(
        f.command(&["netctl", "heal"])
            .env("FD_NETCTL_STUB_EXIT", "1")
            .status()
            .unwrap()
            .code(),
        Some(1)
    );
}

#[test]
fn typesafe_shortcut_preserves_credentials_without_putting_them_in_argv() {
    let f = Fixture::new();
    f.script("contrib/test/fd-netctl/target/release/fd-netctl",
        "test \"$TYPESAFE_API_KEY\" = stub-secret || exit 2\ntest \"$TYPESAFE_MODEL\" = jev-latest || exit 3\nprintf 'arg=%s\\n' \"$@\"");
    let output = success(
        f.command(&["netctl", "typesafe", "7"])
            .env_remove("FD_CLUSTER_CONFIGS")
            .env("TYPESAFE_API_KEY", "stub-secret")
            .env("TYPESAFE_MODEL", "jev-latest")
            .output()
            .unwrap(),
    );
    assert!(output.ends_with("arg=typesafe\narg=7\n"));
    assert!(!output.contains("stub-secret"));
    assert!(!output.contains("cargo"));
}
