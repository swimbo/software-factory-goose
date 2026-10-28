#![cfg(feature = "fixture")]
use std::{process::Command, time::Duration};
use watchdog::guarded_release::FixtureGroup;

#[test]
fn complete_releases_only_after_owned_leader_is_stopped_and_reaped() {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "printf 'SFR1\\000\\000\\000\\003yes'; exec sleep 5"]);
    let mut group = FixtureGroup::launch(&mut command).unwrap();
    assert_eq!(group.complete(Duration::from_secs(3)).unwrap(), b"yes");
    assert!(group.is_reaped());
    assert!(group.complete(Duration::from_millis(10)).is_err());
}

#[test]
fn incomplete_and_oversize_frames_never_release_payload() {
    for script in [
        "printf 'SFR1\\000\\000\\000\\003x'; exec sleep 5",
        "printf 'SFR1\\000\\000\\020\\001'; exec sleep 5",
    ] {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", script]);
        let mut group = FixtureGroup::launch(&mut command).unwrap();
        assert!(group.complete(Duration::from_millis(150)).is_err());
        assert!(group.is_reaped());
    }
}

#[test]
fn dead_leader_never_releases_frame() {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "printf 'SFR1\\000\\000\\000\\003yes'; exit 0"]);
    let mut group = FixtureGroup::launch(&mut command).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    assert!(group.complete(Duration::from_secs(1)).is_err());
}
