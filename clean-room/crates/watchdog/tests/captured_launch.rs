#![cfg(feature = "fixture")]
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use watchdog::broker::{ApprovedLaunch, FixtureCaptureResult, LaunchRole, SpawnBroker};
use watchdog::{BrakeSecret, Registry};
#[test]
fn owned_capture_preserves_nonzero_stdout_stderr_and_never_waits_outside_registry() {
    let registry = Arc::new(Registry::new().unwrap());
    let family = registry.create_family().unwrap();
    let broker = SpawnBroker::fixture(registry.clone(), BrakeSecret::new([0x69; 32]).unwrap());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let spec = ApprovedLaunch::new(
        family.clone(),
        LaunchRole::Tool,
        PathBuf::from("/bin/sh"),
        vec![
            "-c".into(),
            "read text; printf 'out:%s' \"$text\"; printf err >&2; exit 7".into(),
        ],
        PathBuf::from("/tmp"),
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        now,
        now + 10000,
    )
    .unwrap()
    .with_fixture_io(BTreeMap::new(), b"fixture\n".to_vec())
    .unwrap();
    let id = broker.admit(spec).unwrap();
    let reply = broker.fixture_launch(&id).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    loop {
        match broker.fixture_result(&id).unwrap() {
            FixtureCaptureResult::Running => {
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(10));
            }
            FixtureCaptureResult::Finished {
                exit_code,
                signal,
                stdout,
                stderr,
            } => {
                assert_eq!(exit_code, Some(7));
                assert_eq!(signal, None);
                assert_eq!(stdout, "out:fixture");
                assert_eq!(stderr, "err");
                break;
            }
            FixtureCaptureResult::Withheld => panic!("complete valid output withheld"),
        }
    }
    assert_eq!(broker.fixture_launch(&id).unwrap(), reply);
    let stopped = registry.stop(&family).unwrap();
    assert_eq!(stopped.groups.len(), 1);
    assert!(stopped.leader_reaped && stopped.group_absent);
}

#[test]
fn invalid_utf8_and_oversized_output_are_withheld_in_full() {
    for command in [
        "printf benign; printf '\\377' >&2",
        "/usr/bin/head -c 1048577 /dev/zero",
    ] {
        let registry = Arc::new(Registry::new().unwrap());
        let family = registry.create_family().unwrap();
        let broker = SpawnBroker::fixture(registry.clone(), BrakeSecret::new([0x69; 32]).unwrap());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let spec = ApprovedLaunch::new(
            family.clone(),
            LaunchRole::Tool,
            PathBuf::from("/bin/sh"),
            vec!["-c".into(), command.into()],
            PathBuf::from("/tmp"),
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            now,
            now + 10000,
        )
        .unwrap()
        .with_fixture_io(BTreeMap::new(), Vec::new())
        .unwrap();
        let id = broker.admit(spec).unwrap();
        broker.fixture_launch(&id).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(4);
        loop {
            match broker.fixture_result(&id).unwrap() {
                FixtureCaptureResult::Running => {
                    assert!(std::time::Instant::now() < deadline);
                    std::thread::sleep(Duration::from_millis(10));
                }
                FixtureCaptureResult::Withheld => break,
                FixtureCaptureResult::Finished { .. } => panic!("unsafe output forwarded"),
            }
        }
        let stopped = registry.stop(&family).unwrap();
        assert!(stopped.leader_reaped && stopped.group_absent);
    }
}
