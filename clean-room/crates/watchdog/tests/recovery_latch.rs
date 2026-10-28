#![cfg(feature = "fixture")]
use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
};

#[test]
fn supervisor_death_leaves_latch_that_blocks_restart() {
    let root = std::env::temp_dir().join(format!("sf-latch-{}", ulid::Ulid::new()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let mut owner = Command::new(env!("CARGO_BIN_EXE_sf-watchdog-fixture"))
        .arg("--fixture-recovery-latch")
        .arg(&root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut output = BufReader::new(owner.stdout.take().unwrap());
    let mut ready = String::new();
    output.read_line(&mut ready).unwrap();
    if ready != "armed\n" {
        let _ = owner.wait();
        let _ = fs::remove_dir(&root);
    }
    assert_eq!(ready, "armed\n");
    // The child handle is still owned and unreaped; never signal a stored PID.
    owner.kill().unwrap();
    owner.wait().unwrap();
    let second = Command::new(env!("CARGO_BIN_EXE_sf-watchdog-fixture"))
        .arg("--fixture-recovery-latch")
        .arg(&root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(
        !second.success(),
        "restart accepted with a prior unresolved latch"
    );
    assert!(root.join("recovery-required").is_file());
    fs::remove_file(root.join("recovery-required")).unwrap();
    fs::remove_dir(root).unwrap();
}

#[test]
fn concurrent_arm_has_one_winner_and_never_replaces_existing_marker() {
    let root = std::env::temp_dir().join(format!("sf-latch-{}", ulid::Ulid::new()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(9));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let root = root.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                watchdog::recovery_latch::arm(&root).is_ok()
            })
        })
        .collect();
    barrier.wait();
    assert_eq!(
        threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .filter(|won| *won)
            .count(),
        1
    );
    let original = fs::read(root.join("recovery-required")).unwrap();
    assert!(watchdog::recovery_latch::arm(&root).is_err());
    assert_eq!(fs::read(root.join("recovery-required")).unwrap(), original);
    fs::remove_file(root.join("recovery-required")).unwrap();
    fs::remove_dir(root).unwrap();
}

#[test]
fn preexisting_symlink_and_nonprivate_root_fail_closed() {
    use std::os::unix::fs::symlink;
    let root = std::env::temp_dir().join(format!("sf-latch-{}", ulid::Ulid::new()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(watchdog::recovery_latch::arm(&root).is_err());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let destination = root.join("preserved");
    fs::write(&destination, b"untouched").unwrap();
    symlink(&destination, root.join("recovery-required")).unwrap();
    assert!(watchdog::recovery_latch::arm(&root).is_err());
    assert_eq!(fs::read(&destination).unwrap(), b"untouched");
    fs::remove_file(root.join("recovery-required")).unwrap();
    fs::remove_file(destination).unwrap();
    fs::remove_dir(root).unwrap();
}

#[test]
fn armed_latch_blocks_fixture_server_before_socket_or_child_creation() {
    use std::io::Write;
    let root = std::env::temp_dir().join(format!("sf-latch-{}", ulid::Ulid::new()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    watchdog::recovery_latch::arm(&root).unwrap();
    let mut server = Command::new(env!("CARGO_BIN_EXE_sf-watchdog-fixture"))
        .arg("--fixture-server")
        .arg(&root)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    server.stdin.take().unwrap().write_all(&[0x5a; 32]).unwrap();
    assert!(!server.wait().unwrap().success());
    assert!(!root.join("brake.sock").exists());
    assert!(!root.join("children.json").exists());
    assert!(!root.join("registry.json").exists());
    fs::remove_file(root.join("recovery-required")).unwrap();
    fs::remove_dir(root).unwrap();
}
