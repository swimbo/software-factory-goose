use evaluator::{
    promote_verified_commit, promote_verified_commit_to_ref, verify_worktree_evidence,
};
use shared::Receipt;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

struct Repo(PathBuf);
impl Repo {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("factory-evaluator-test-{}", shared::new_id()));
        fs::create_dir(&path).unwrap();
        git(&path, &["init", "-q", "-b", "main"]);
        git(&path, &["config", "user.email", "fixture@example.test"]);
        git(&path, &["config", "user.name", "Fixture"]);
        fs::write(path.join("README"), "initial\n").unwrap();
        git(&path, &["add", "."]);
        git(&path, &["commit", "-qm", "initial"]);
        Self(path)
    }
    fn sha(&self) -> String {
        git(&self.0, &["rev-parse", "HEAD"])
    }
    fn receipt(&self) -> Receipt {
        Receipt::Completed {
            sha: self.sha(),
            diff: String::new(),
            turn_count: 1,
            exit_code: 0,
            wall_time_ms: 1,
            spend_usd: 0.0,
        }
    }
}
impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn git(path: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}
#[test]
fn completed_receipt_does_not_prove_missing_checkout_or_project_passes() {
    let repo = Repo::new();
    assert!(
        verify_worktree_evidence(Path::new("/missing-factory-checkout"), &repo.receipt()).is_err()
    );
    assert!(verify_worktree_evidence(&repo.0, &repo.receipt()).is_err());
}
#[test]
fn exact_revision_and_clean_tree_are_required() {
    let repo = Repo::new();
    let receipt = repo.receipt();
    fs::write(repo.0.join("README"), "changed\n").unwrap();
    assert!(verify_worktree_evidence(&repo.0, &receipt).is_err());
    git(&repo.0, &["add", "."]);
    git(&repo.0, &["commit", "-qm", "next"]);
    assert!(verify_worktree_evidence(&repo.0, &receipt).is_err());
}
#[test]
fn promotion_advances_only_exact_approved_fast_forward() {
    let repo = Repo::new();
    let base = repo.sha();
    let destination = Repo::new();
    fs::remove_dir_all(&destination.0).unwrap();
    let output = Command::new("git")
        .args(["clone", "-q", "--bare"])
        .arg(&repo.0)
        .arg(&destination.0)
        .output()
        .unwrap();
    assert!(output.status.success());
    fs::write(repo.0.join("README"), "approved\n").unwrap();
    git(&repo.0, &["add", "."]);
    git(&repo.0, &["commit", "-qm", "candidate"]);
    let candidate = repo.sha();
    promote_verified_commit(&destination.0, &repo.0, &base, &candidate).unwrap();
    assert_eq!(git(&destination.0, &["rev-parse", "HEAD"]), candidate);
    assert!(promote_verified_commit(&destination.0, &repo.0, &base, &candidate).is_err());
}
#[test]
fn promotion_rejects_dirty_changed_and_non_bare_targets() {
    let repo = Repo::new();
    let sha = repo.sha();
    let destination = Repo::new();
    assert!(promote_verified_commit(&destination.0, &repo.0, &sha, &sha).is_err());
    fs::write(repo.0.join("untracked"), "dirty").unwrap();
    assert!(promote_verified_commit(&destination.0, &repo.0, &sha, &sha).is_err());
}

#[test]
fn explicit_promotion_cannot_follow_a_changed_head_or_symbolic_target() {
    let repo = Repo::new();
    let base = repo.sha();
    let destination = Repo::new();
    fs::remove_dir_all(&destination.0).unwrap();
    assert!(
        Command::new("git")
            .args(["clone", "-q", "--bare"])
            .arg(&repo.0)
            .arg(&destination.0)
            .status()
            .unwrap()
            .success()
    );
    git(&destination.0, &["update-ref", "refs/heads/other", &base]);
    git(
        &destination.0,
        &["symbolic-ref", "HEAD", "refs/heads/other"],
    );
    git(
        &destination.0,
        &["symbolic-ref", "refs/heads/alias", "refs/heads/other"],
    );
    fs::write(repo.0.join("README"), "candidate\n").unwrap();
    git(&repo.0, &["add", "."]);
    git(&repo.0, &["commit", "-qm", "candidate"]);
    let candidate = repo.sha();
    for target in [
        "HEAD",
        "main",
        "refs/tags/tag",
        "refs/heads/../other",
        "refs/heads/alias",
    ] {
        assert!(
            promote_verified_commit_to_ref(&destination.0, &repo.0, target, &base, &candidate)
                .is_err()
        );
        assert_eq!(
            git(&destination.0, &["rev-parse", "refs/heads/other"]),
            base
        );
    }
    promote_verified_commit_to_ref(
        &destination.0,
        &repo.0,
        "refs/heads/main",
        &base,
        &candidate,
    )
    .unwrap();
    assert_eq!(
        git(&destination.0, &["rev-parse", "refs/heads/main"]),
        candidate
    );
    assert_eq!(git(&destination.0, &["rev-parse", "HEAD"]), base);
    assert!(
        promote_verified_commit_to_ref(
            &destination.0,
            &repo.0,
            "refs/heads/main",
            &base,
            &candidate
        )
        .is_err()
    );
}

fn cargo_fixture(repo: &Repo, source: &str) {
    fs::write(
        repo.0.join("Cargo.toml"),
        "[package]\nname = \"wall_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    fs::write(
        repo.0.join("Cargo.lock"),
        "version = 4\n\n[[package]]\nname = \"wall_fixture\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    fs::create_dir_all(repo.0.join("src")).unwrap();
    fs::write(repo.0.join("src/lib.rs"), source).unwrap();
    git(&repo.0, &["add", "."]);
    git(&repo.0, &["commit", "-qm", "cargo fixture"]);
}
#[test]
fn scan_uses_committed_content_not_worker_claimed_diff() {
    let repo = Repo::new();
    cargo_fixture(&repo, "const TOKEN: &str = \"ghp_hiddencredential\";");
    let evidence = verify_worktree_evidence(&repo.0, &repo.receipt()).unwrap();
    assert!(!evidence.verdict.secret_scan_clean);
    assert!(!evidence.verdict.tests_pass);
}
#[test]
#[cfg(target_os = "macos")]
fn actual_isolated_check_and_tests_determine_verdict() {
    let repo = Repo::new();
    cargo_fixture(&repo, "#[test] fn works() { assert_eq!(2 + 2, 4); }");
    let evidence = verify_worktree_evidence(&repo.0, &repo.receipt()).unwrap();
    assert!(evidence.verdict.all_pass(), "{evidence:?}");
    assert_eq!(evidence.sha, repo.sha());
    assert!(
        !repo.0.join("target").exists(),
        "checks must use fresh isolated snapshot"
    );
    cargo_fixture(&repo, "#[test] fn fails() { assert_eq!(2 + 2, 5); }");
    let evidence = verify_worktree_evidence(&repo.0, &repo.receipt()).unwrap();
    assert!(evidence.verdict.typecheck);
    assert!(!evidence.verdict.tests_pass);
    cargo_fixture(&repo, "fn invalid() { unknown_symbol(); }");
    let evidence = verify_worktree_evidence(&repo.0, &repo.receipt()).unwrap();
    assert!(!evidence.verdict.typecheck);
    assert!(!evidence.verdict.tests_pass);
}
#[test]
#[cfg(target_os = "macos")]
fn sandbox_build_script_cannot_read_or_write_outside_or_use_network() {
    let repo = Repo::new();
    let host = Repo::new();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    cargo_fixture(&repo, "#[test] fn works() { assert!(true); }");
    let build = format!(
        r#"fn main() {{
        assert!(std::fs::read({:?}).is_err());
        assert!(std::fs::write({:?}, "escaped").is_err());
        assert!(std::net::TcpStream::connect({:?}).is_err());
        assert!(std::env::var("FACTORY_HOST_CANARY_SECRET").is_err());
    }}"#,
        host.0.join("README"),
        host.0.join("escape"),
        address.to_string()
    );
    fs::write(repo.0.join("build.rs"), build).unwrap();
    git(&repo.0, &["add", "."]);
    git(&repo.0, &["commit", "-qm", "hostile build script fixture"]);
    let evidence = verify_worktree_evidence(&repo.0, &repo.receipt()).unwrap();
    assert!(evidence.verdict.all_pass(), "{evidence:?}");
    assert!(!host.0.join("escape").exists());
}
#[test]
fn malicious_git_filter_configuration_is_rejected_before_status() {
    let repo = Repo::new();
    let receipt = repo.receipt();
    git(
        &repo.0,
        &["config", "filter.evil.clean", "touch SHOULD_NOT_EXIST"],
    );
    fs::write(repo.0.join(".gitattributes"), "* filter=evil\n").unwrap();
    assert!(verify_worktree_evidence(&repo.0, &receipt).is_err());
    assert!(!repo.0.join("SHOULD_NOT_EXIST").exists());
}
