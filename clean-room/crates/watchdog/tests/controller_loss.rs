#![cfg(feature = "fixture")]
use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

struct OwnedPair {
    controller: Child,
    guardian: Child,
}
impl Drop for OwnedPair {
    fn drop(&mut self) {
        if self.controller.try_wait().ok().flatten().is_none() {
            let _ = self.controller.kill();
        }
        let _ = self.controller.wait();
        let deadline = Instant::now() + Duration::from_secs(7);
        while self.guardian.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let forced_guardian_stop = self.guardian.try_wait().ok().flatten().is_none();
        if forced_guardian_stop {
            let _ = self.guardian.kill();
        }
        let _ = self.guardian.wait();
        if forced_guardian_stop {
            // Guardian's fixed benign worker has a five-second lifetime. Allow that
            // lifetime to elapse after forced owner loss without signaling an orphan.
            std::thread::sleep(Duration::from_secs(6));
        }
    }
}

#[test]
fn guardian_stops_its_owned_group_after_controller_death() {
    let mut controller = Command::new("/bin/sleep")
        .arg("30")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let controller_pipe = controller.stdout.take().unwrap();
    let mut guardian = Command::new(env!("CARGO_BIN_EXE_sf-watchdog-fixture"))
        .arg("--fixture-controller-loss")
        .stdin(Stdio::from(controller_pipe))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let output = guardian.stdout.take().unwrap();
    let mut pair = OwnedPair {
        controller,
        guardian,
    };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(output).lines() {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap(),
        "READY"
    );
    assert!(
        matches!(
            rx.recv_timeout(Duration::from_millis(200)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ),
        "guardian stopped before controller loss"
    );
    // Kill and reap only the still-owned controller; the guardian owns the worker.
    pair.controller.kill().unwrap();
    pair.controller.wait().unwrap();
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap(),
        "STOPPED"
    );
    assert!(pair.guardian.wait().unwrap().success());
}

#[test]
fn leaked_writer_cannot_postpone_guardian_cleanup_indefinitely() {
    use std::os::{fd::OwnedFd, unix::net::UnixStream};
    let (reader, writer) = UnixStream::pair().unwrap();
    let leaked_writer = writer.try_clone().unwrap();
    let controller = Command::new("/bin/sleep")
        .arg("30")
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .spawn()
        .unwrap();
    let mut guardian = Command::new(env!("CARGO_BIN_EXE_sf-watchdog-fixture"))
        .arg("--fixture-controller-loss")
        .stdin(Stdio::from(OwnedFd::from(reader)))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let output = guardian.stdout.take().unwrap();
    let mut pair = OwnedPair {
        controller,
        guardian,
    };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(output).lines() {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap(),
        "READY"
    );
    pair.controller.kill().unwrap();
    pair.controller.wait().unwrap();
    // This test-owned duplicate keeps EOF suppressed even after controller death.
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(6)).unwrap().unwrap(),
        "TIMEOUT_STOPPED"
    );
    assert!(!pair.guardian.wait().unwrap().success());
    drop(leaked_writer);
}

#[test]
fn data_on_controller_pipe_never_claims_controller_death() {
    use std::{
        io::Write,
        os::{fd::OwnedFd, unix::net::UnixStream},
    };
    let (reader, mut writer) = UnixStream::pair().unwrap();
    let controller = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let mut guardian = Command::new(env!("CARGO_BIN_EXE_sf-watchdog-fixture"))
        .arg("--fixture-controller-loss")
        .stdin(Stdio::from(OwnedFd::from(reader)))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let output = guardian.stdout.take().unwrap();
    let mut pair = OwnedPair {
        controller,
        guardian,
    };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(output).lines() {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap(),
        "READY"
    );
    writer.write_all(&[1]).unwrap();
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap(),
        "INVALID_STOPPED"
    );
    assert!(!pair.guardian.wait().unwrap().success());
    assert!(pair.controller.try_wait().unwrap().is_none());
}

#[test]
fn guarded_owner_stops_group_after_controller_loss() {
    use std::{fs, os::unix::fs::PermissionsExt};
    let root = std::env::temp_dir().join(format!("sf-guarded-controller-{}", ulid::Ulid::new()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    struct Root(std::path::PathBuf);
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_file(self.0.join("recovery-required"));
            let _ = fs::remove_dir(&self.0);
        }
    }
    let root = Root(root);
    let mut controller = Command::new("/bin/sleep")
        .arg("30")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let input = controller.stdout.take().unwrap();
    let mut guardian = Command::new(env!("CARGO_BIN_EXE_sf-watchdog-fixture"))
        .arg("--fixture-guarded-controller-loss")
        .arg(&root.0)
        .stdin(Stdio::from(input))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let output = guardian.stdout.take().unwrap();
    let mut pair = OwnedPair {
        controller,
        guardian,
    };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(output).lines() {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap(),
        "READY"
    );
    assert!(matches!(
        rx.recv_timeout(Duration::from_millis(200)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    pair.controller.kill().unwrap();
    pair.controller.wait().unwrap();
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap(),
        "STOPPED"
    );
    assert!(pair.guardian.wait().unwrap().success());
}
