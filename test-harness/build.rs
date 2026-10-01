//! Build Firedancer's `sol_compat` shared library from this repository.

use std::{
    env, io,
    path::PathBuf,
    process::{Command, Stdio},
};

fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("..");
    for path in ["Makefile", "config", "src"] {
        println!("cargo::rerun-if-changed={}", root.join(path).display());
    }
    // Firedancer's make reads these from the environment.
    for var in ["CC", "MACHINE", "EXTRAS", "BUILDDIR"] {
        println!("cargo::rerun-if-env-changed={var}");
    }

    let status = Command::new("make")
        .current_dir(&root)
        .arg("libfd_exec_sol_compat.so")
        // Share Cargo's jobserver instead of starting an unbounded `make -j`.
        .env("MAKEFLAGS", env::var_os("CARGO_MAKEFLAGS").unwrap_or_default())
        // Build-script stdout is reserved for Cargo directives.
        .stdout(Stdio::from(io::stderr()))
        .status()
        .expect("could not run make");
    assert!(status.success(), "make libfd_exec_sol_compat.so failed: {status}");

    let objdir = Command::new("make")
        .current_dir(&root)
        .args(["--silent", "objdir"])
        .env_remove("MAKEFLAGS")
        .output()
        .expect("could not run make objdir");
    assert!(objdir.status.success(), "make objdir failed: {}", objdir.status);
    let objdir = String::from_utf8(objdir.stdout).expect("objdir is not UTF-8");
    let library = root
        .join(objdir.trim())
        .join("lib/libfd_exec_sol_compat.so")
        .canonicalize()
        .expect("make did not produce libfd_exec_sol_compat.so");
    println!("cargo::rustc-env=FD_SOL_COMPAT_LIB={}", library.display());
}
