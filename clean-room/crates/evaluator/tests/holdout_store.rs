#![cfg(target_os = "macos")]
use evaluator::holdout_store::{ProtectedHoldoutStore, StoreConfig};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    process::Command,
};

const MANIFEST: &[u8] = br#"{"version":1,"scenarios":[{"script":"printf '{\"passed\":true}'"}]}"#;
struct StoreFixture {
    base: PathBuf,
    root: PathBuf,
    uid: u32,
}
impl StoreFixture {
    fn new() -> Self {
        let base = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("holdout-store-test-{}", shared::new_id()));
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let root = base.join("store");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        // Test fixtures validate the actual current owner; other IDs are synthetic, not deployment proof.
        let uid = unsafe { libc::geteuid() };
        Self { base, root, uid }
    }
    fn config(&self) -> StoreConfig {
        StoreConfig {
            root: self.root.clone(),
            store_uid: self.uid,
            evaluator_uid: self.uid + 1,
            generator_uid: self.uid + 2,
        }
    }
    fn put(&self, bytes: &[u8]) -> (String, PathBuf) {
        let digest = format!("{:x}", Sha256::digest(bytes));
        let path = self.root.join(format!("{digest}.json"));
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        (digest, path)
    }
}
impl Drop for StoreFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

#[test]
fn protected_current_owner_manifest_loads_exact_digest() {
    let fixture = StoreFixture::new();
    let (digest, _) = fixture.put(MANIFEST);
    let store = ProtectedHoldoutStore::open(&fixture.config()).unwrap();
    let parsed = store.load_digest(&digest).unwrap();
    assert_eq!(parsed.digest(), digest);
}

#[test]
fn wrong_or_nonseparate_identity_configuration_fails_closed() {
    let fixture = StoreFixture::new();
    for variant in 0..4 {
        let mut config = fixture.config();
        match variant {
            0 => config.store_uid += 5,
            1 => config.generator_uid = config.store_uid,
            2 => config.evaluator_uid = config.generator_uid,
            _ => config.store_uid = 0,
        }
        assert!(ProtectedHoldoutStore::open(&config).is_err());
    }
}

#[test]
fn symlinked_root_ancestor_and_manifest_are_refused() {
    let fixture = StoreFixture::new();
    let (digest, path) = fixture.put(MANIFEST);
    let store = ProtectedHoldoutStore::open(&fixture.config()).unwrap();
    let real = fixture.root.join("real");
    fs::rename(&path, &real).unwrap();
    symlink(&real, &path).unwrap();
    assert!(store.load_digest(&digest).is_err());
    let alias = fixture.base.join("alias");
    symlink(&fixture.root, &alias).unwrap();
    let mut config = fixture.config();
    config.root = alias;
    assert!(ProtectedHoldoutStore::open(&config).is_err());
    let parent_alias = fixture.base.join("parent-alias");
    symlink(&fixture.base, &parent_alias).unwrap();
    config.root = parent_alias.join("store");
    assert!(ProtectedHoldoutStore::open(&config).is_err());
}

#[test]
fn hardlinked_manifest_is_refused() {
    let fixture = StoreFixture::new();
    let (digest, path) = fixture.put(MANIFEST);
    fs::hard_link(&path, fixture.base.join("outside-link")).unwrap();
    let store = ProtectedHoldoutStore::open(&fixture.config()).unwrap();
    assert!(store.load_digest(&digest).is_err());
}

#[test]
fn insecure_modes_are_refused_initially_and_after_store_open() {
    let fixture = StoreFixture::new();
    let (digest, path) = fixture.put(MANIFEST);
    let store = ProtectedHoldoutStore::open(&fixture.config()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(store.load_digest(&digest).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(store.load_digest(&digest).is_err());
    assert!(ProtectedHoldoutStore::open(&fixture.config()).is_err());
    fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&fixture.base, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(ProtectedHoldoutStore::open(&fixture.config()).is_err());
}

#[test]
fn actual_acl_grants_are_rejected_despite_safe_posix_modes() {
    let fixture = StoreFixture::new();
    let (digest, path) = fixture.put(MANIFEST);
    let store = ProtectedHoldoutStore::open(&fixture.config()).unwrap();
    assert!(
        Command::new("/bin/chmod")
            .args(["+a", "everyone allow read"])
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    assert!(store.load_digest(&digest).is_err());
    assert!(
        Command::new("/bin/chmod")
            .arg("-N")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    assert!(store.load_digest(&digest).is_ok());
    assert!(
        Command::new("/bin/chmod")
            .args(["+a", "everyone allow list,search"])
            .arg(&fixture.root)
            .status()
            .unwrap()
            .success()
    );
    assert!(ProtectedHoldoutStore::open(&fixture.config()).is_err());
}

#[test]
fn replaced_root_cannot_redirect_an_open_handle() {
    let fixture = StoreFixture::new();
    let (digest, _) = fixture.put(MANIFEST);
    let store = ProtectedHoldoutStore::open(&fixture.config()).unwrap();
    fs::rename(&fixture.root, fixture.base.join("old-store")).unwrap();
    fs::create_dir(&fixture.root).unwrap();
    fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o700)).unwrap();
    fixture.put(MANIFEST);
    assert!(store.load_digest(&digest).is_err());
}

#[test]
fn traversal_tampering_oversize_and_invalid_json_have_opaque_errors() {
    let fixture = StoreFixture::new();
    let (digest, path) = fixture.put(MANIFEST);
    let store = ProtectedHoldoutStore::open(&fixture.config()).unwrap();
    for value in [
        "../SECRET_BODY",
        "/var/holdout/private",
        &"G".repeat(64),
        "",
    ] {
        assert_eq!(
            store.load_digest(value).err().unwrap().to_string(),
            "protected holdout manifest unavailable"
        );
    }
    fs::write(path, "PRIVATE_SCENARIO_BODY").unwrap();
    assert!(store.load_digest(&digest).is_err());
    for bytes in [b"SECRET_BODY".to_vec(), vec![b'x'; 131073]] {
        let (name, _) = fixture.put(&bytes);
        assert_eq!(
            store.load_digest(&name).err().unwrap().to_string(),
            "protected holdout manifest unavailable"
        );
    }
}

#[test]
fn named_pipe_and_directory_are_refused_without_blocking_on_open() {
    let fixture = StoreFixture::new();
    let (digest, path) = fixture.put(MANIFEST);
    let store = ProtectedHoldoutStore::open(&fixture.config()).unwrap();
    fs::remove_file(&path).unwrap();
    let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: name is a live terminated path inside this disposable fixture.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let started = std::time::Instant::now();
    assert!(store.load_digest(&digest).is_err());
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(store.load_digest(&digest).is_err());
}

#[tokio::test]
async fn loaded_manifest_runs_but_scenario_cannot_read_protected_store() {
    use evaluator::{
        holdout::PrefilterStatus,
        holdout_runner::{FixtureLimits, run_fixture_holdouts},
    };
    let fixture = StoreFixture::new();
    let hidden = fixture.root.join("hidden-sentinel");
    fs::write(&hidden, "PRIVATE_HOLDOUT_BODY").unwrap();
    fs::set_permissions(&hidden, fs::Permissions::from_mode(0o600)).unwrap();
    let script = format!(
        "if cat '{}' >/dev/null 2>&1; then exit 1; fi; if [ \"$(cat README)\" != expected ]; then exit 1; fi; printf '{{\"passed\":true}}'",
        hidden.display()
    );
    let bytes =
        serde_json::to_vec(&serde_json::json!({"version":1,"scenarios":[{"script":script}]}))
            .unwrap();
    let (digest, _) = fixture.put(&bytes);
    let manifest = ProtectedHoldoutStore::open(&fixture.config())
        .unwrap()
        .load_digest(&digest)
        .unwrap();
    let candidate = fixture.base.join("candidate");
    fs::create_dir(&candidate).unwrap();
    let git = |args: &[&str]| {
        let output = Command::new("/usr/bin/git")
            .arg("-C")
            .arg(&candidate)
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    };
    git(&["init", "-q", "-b", "main"]);
    git(&["config", "user.email", "fixture@example.test"]);
    git(&["config", "user.name", "Fixture"]);
    fs::write(candidate.join("README"), "expected\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "fixture"]);
    let sha = git(&["rev-parse", "HEAD"]);
    let report = run_fixture_holdouts(&candidate, &sha, &manifest, FixtureLimits::default())
        .await
        .unwrap();
    assert_eq!(report.feedback().status, PrefilterStatus::Passed);
    assert_eq!(
        serde_json::to_value(report.feedback()).unwrap(),
        serde_json::json!({"status":"passed","messages":[]})
    );
}
