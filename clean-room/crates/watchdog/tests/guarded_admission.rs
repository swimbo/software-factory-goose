#![cfg(feature = "fixture")]
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, time::Duration};
use watchdog::guarded_admission::{FixtureLauncher, FixtureSpec};

struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("sf-admission-{}", ulid::Ulid::new()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn spec(&self) -> FixtureSpec {
        FixtureSpec::new(
            "/bin/sh",
            ["-c", "printf 'SFR1\\000\\000\\000\\003yes'; exec sleep 5"],
            &self.0,
        )
        .unwrap()
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.join("recovery-required"));
        let _ = fs::remove_file(self.0.join("ready"));
        let _ = fs::remove_dir(&self.0);
    }
}

#[test]
fn killed_owner_cannot_readmit_from_the_same_root() {
    use std::{
        io::{BufRead, BufReader},
        process::{Command, Stdio},
    };
    let root = Root::new();
    let mut owner = Command::new(env!("CARGO_BIN_EXE_sf-watchdog-fixture"))
        .arg("--fixture-admission-owner")
        .arg(&root.0)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(owner.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    if line != "armed\n" {
        let _ = owner.kill();
        let _ = owner.wait();
    }
    assert_eq!(line, "armed\n");
    // This is the live, directly owned fixture supervisor; never restore a PID.
    owner.kill().unwrap();
    owner.wait().unwrap();
    assert!(FixtureLauncher::new(&root.0, root.spec()).is_err());
    // Its already-running child is benign and finite; allow it to finish naturally.
    std::thread::sleep(Duration::from_millis(2300));
}

#[test]
fn latched_single_use_launcher_refuses_restart() {
    let root = Root::new();
    let mut launcher = FixtureLauncher::new(&root.0, root.spec()).unwrap();
    let mut group = launcher.launch().unwrap();
    assert!(launcher.launch().is_err());
    assert_eq!(group.complete(Duration::from_secs(3)).unwrap(), b"yes");
    drop(launcher);
    assert!(FixtureLauncher::new(&root.0, root.spec()).is_err());
}

#[test]
fn existing_latch_refuses_before_any_launch() {
    let root = Root::new();
    fs::write(root.0.join("recovery-required"), b"prior owner").unwrap();
    assert!(FixtureLauncher::new(&root.0, root.spec()).is_err());
    assert_eq!(
        fs::read(root.0.join("recovery-required")).unwrap(),
        b"prior owner"
    );
}

#[test]
fn spawn_failure_is_tombstoned_and_latch_is_not_cleared() {
    let root = Root::new();
    let binary = root.0.join("fixture-program");
    fs::write(&binary, b"#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    let spec = FixtureSpec::new(&binary, [] as [&str; 0], &root.0).unwrap();
    let mut launcher = FixtureLauncher::new(&root.0, spec).unwrap();
    fs::remove_file(binary).unwrap();
    assert!(launcher.launch().is_err());
    assert!(launcher.launch().is_err());
    assert!(FixtureLauncher::new(&root.0, root.spec()).is_err());
}

#[test]
fn concurrent_launchers_cannot_reserve_the_same_root_twice() {
    let root = Root::new();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(9));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let path = root.0.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let spec = FixtureSpec::new("/bin/sh", ["-c", "exit 0"], &path).unwrap();
                barrier.wait();
                FixtureLauncher::new(&path, spec).is_ok()
            })
        })
        .collect();
    barrier.wait();
    assert_eq!(
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|won| *won)
            .count(),
        1
    );
}
