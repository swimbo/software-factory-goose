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
