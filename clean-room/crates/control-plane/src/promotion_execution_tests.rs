use super::*;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    process::Command,
};

struct Fixture {
    root: PathBuf,
    target: PathBuf,
    candidate: PathBuf,
    base: String,
    sha: String,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(output.status.success(), "fixture Git failed");
    String::from_utf8(output.stdout).unwrap().trim().into()
}
fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &dest)
        } else {
            fs::copy(entry.path(), dest).unwrap();
        }
    }
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("promotion-exec-{}", shared::new_id()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let candidate = root.join("candidate");
        let target = root.join("target.git");
        fs::create_dir(&candidate).unwrap();
        fs::create_dir(&target).unwrap();
        for path in [&candidate, &target] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        git(&candidate, &["init", "-b", "main"]);
        git(&candidate, &["config", "user.name", "Fixture"]);
        git(
            &candidate,
            &["config", "user.email", "fixture@example.invalid"],
        );
        fs::write(candidate.join("README"), "base\n").unwrap();
        git(&candidate, &["add", "README"]);
        git(&candidate, &["commit", "-m", "base"]);
        let base = git(&candidate, &["rev-parse", "HEAD"]);
        fs::write(candidate.join("README"), "candidate\n").unwrap();
        git(&candidate, &["add", "README"]);
        git(&candidate, &["commit", "-m", "candidate"]);
        let sha = git(&candidate, &["rev-parse", "HEAD"]);
        git(&target, &["init", "--bare"]);
        git(&target, &["config", "core.logallrefupdates", "true"]);
        copy_tree(&candidate.join(".git/objects"), &target.join("objects"));
        git(&target, &["update-ref", "refs/heads/main", &base]);
        Self {
            root,
            target,
            candidate,
            base,
            sha,
        }
    }
    fn binding(&self) -> RepositoryBinding {
        RepositoryBinding {
            repository: "fixture".into(),
            target_ref: "refs/heads/main".into(),
            bare_target: self.target.clone(),
            candidate_snapshot: self.candidate.clone(),
            owner_uid: unsafe { libc::geteuid() },
        }
    }
    fn decision(&self) -> PromotionDecision {
        PromotionDecision {
            task_id: "task".into(),
            generation: 1,
            nonce: shared::new_id(),
            action: crate::approval::ApprovalAction {
                operation: crate::approval::Operation::Promote,
                task_id: "task".into(),
                repository: "fixture".into(),
                target_ref: "refs/heads/main".into(),
                candidate_sha: self.sha.clone(),
                base_sha: self.base.clone(),
                evidence_digest: "c".repeat(64),
                reason: "fixture".into(),
                audience: "fixture".into(),
            },
            decided_at_ms: 1000,
            execution: crate::promotion_decision::DecisionExecution::NotRequested,
        }
    }
}

#[test]
fn real_exact_cas_and_lost_receipt_reconcile_without_second_ref_write() {
    let fixture = Fixture::new();
    let registry = TrustedPromotionRepositories::new(vec![fixture.binding()]).unwrap();
    let intent = registry.prepare(&fixture.decision()).unwrap();
    let receipt = registry.execute_once(&intent).unwrap();
    assert_eq!(receipt.disposition, ExecutionDisposition::Advanced);
    assert!(!receipt.attribution_unknown);
    assert_eq!(
        git(&fixture.target, &["rev-parse", "refs/heads/main"]),
        fixture.sha
    );
    let reflog = git(
        &fixture.target,
        &["reflog", "show", "--format=%H", "refs/heads/main"],
    );
    // Simulate a lost acknowledgement: discard the first receipt, restore only the intent.
    let restored: ExecutionIntent =
        serde_json::from_slice(&serde_json::to_vec(&intent).unwrap()).unwrap();
    let recovery = registry.execute_once(&restored).unwrap();
    assert_eq!(
        recovery.disposition,
        ExecutionDisposition::ReconciledAlreadyAtCandidate
    );
    assert!(recovery.attribution_unknown);
    assert_eq!(registry.reconcile(&restored).unwrap(), recovery);
    assert_eq!(
        git(
            &fixture.target,
            &["reflog", "show", "--format=%H", "refs/heads/main"]
        ),
        reflog
    );
}

#[test]
fn marker_before_cas_crash_never_reexecutes_fresh_action() {
    let fixture = Fixture::new();
    let registry = TrustedPromotionRepositories::new(vec![fixture.binding()]).unwrap();
    let intent = registry.prepare(&fixture.decision()).unwrap();
    let binding = registry.bindings.get("fixture").unwrap();
    claim_attempt(binding, &intent).unwrap();
    assert!(registry.execute_once(&intent).is_err());
    assert!(registry.reconcile(&intent).is_err());
    assert_eq!(
        git(&fixture.target, &["rev-parse", "refs/heads/main"]),
        fixture.base
    );
}

#[test]
fn stale_base_dirty_source_and_unregistered_scope_refuse_ref_change() {
    let fixture = Fixture::new();
    let registry = TrustedPromotionRepositories::new(vec![fixture.binding()]).unwrap();
    let mut decision = fixture.decision();
    decision.action.repository = "unregistered".into();
    assert!(registry.prepare(&decision).is_err());
    decision = fixture.decision();
    decision.action.target_ref = "refs/heads/other".into();
    assert!(registry.prepare(&decision).is_err());
    let intent = registry.prepare(&fixture.decision()).unwrap();
    fs::write(fixture.candidate.join("README"), "dirty").unwrap();
    assert!(registry.execute_once(&intent).is_err());
    assert_eq!(
        git(&fixture.target, &["rev-parse", "refs/heads/main"]),
        fixture.base
    );
    fs::write(fixture.candidate.join("README"), "candidate\n").unwrap();
    let mut stale = fixture.decision();
    stale.action.base_sha = "d".repeat(40);
    let stale = registry.prepare(&stale).unwrap();
    assert!(registry.execute_once(&stale).is_err());
    assert_eq!(
        git(&fixture.target, &["rev-parse", "refs/heads/main"]),
        fixture.base
    );
}

#[test]
fn untrusted_paths_permissions_symlinks_and_changed_identity_fail_closed() {
    let fixture = Fixture::new();
    let mut wrong = fixture.binding();
    wrong.owner_uid += 1;
    assert!(TrustedPromotionRepositories::new(vec![wrong]).is_err());
    let alias = fixture.root.join("alias");
    symlink(&fixture.target, &alias).unwrap();
    let mut wrong = fixture.binding();
    wrong.bare_target = alias;
    assert!(TrustedPromotionRepositories::new(vec![wrong]).is_err());
    fs::set_permissions(&fixture.target, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(TrustedPromotionRepositories::new(vec![fixture.binding()]).is_err());
    fs::set_permissions(&fixture.target, fs::Permissions::from_mode(0o700)).unwrap();
    let registry = TrustedPromotionRepositories::new(vec![fixture.binding()]).unwrap();
    let intent = registry.prepare(&fixture.decision()).unwrap();
    fs::rename(&fixture.target, fixture.root.join("original.git")).unwrap();
    copy_tree(&fixture.root.join("original.git"), &fixture.target);
    fs::set_permissions(&fixture.target, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(registry.execute_once(&intent).is_err());
}

#[test]
fn already_at_candidate_is_only_an_unattributed_observation() {
    let fixture = Fixture::new();
    let registry = TrustedPromotionRepositories::new(vec![fixture.binding()]).unwrap();
    let intent = registry.prepare(&fixture.decision()).unwrap();
    git(
        &fixture.target,
        &["update-ref", "refs/heads/main", &fixture.sha, &fixture.base],
    );
    let reflog = git(
        &fixture.target,
        &["reflog", "show", "--format=%H", "refs/heads/main"],
    );
    let receipt = registry.execute_once(&intent).unwrap();
    assert!(receipt.attribution_unknown);
    assert_eq!(
        receipt.disposition,
        ExecutionDisposition::ReconciledAlreadyAtCandidate
    );
    assert!(!fixture.target.join(".sfactory-promotion-intents").exists());
    assert_eq!(
        git(
            &fixture.target,
            &["reflog", "show", "--format=%H", "refs/heads/main"]
        ),
        reflog
    );
}

#[test]
fn internal_link_alternate_object_store_and_changed_intent_are_refused() {
    let fixture = Fixture::new();
    let registry = TrustedPromotionRepositories::new(vec![fixture.binding()]).unwrap();
    let intent = registry.prepare(&fixture.decision()).unwrap();
    let mut forged = serde_json::to_value(&intent).unwrap();
    forged["mapping_fingerprint"] = serde_json::json!("e".repeat(64));
    let forged = serde_json::from_value(forged).unwrap();
    assert!(registry.execute_once(&forged).is_err());
    fs::hard_link(
        fixture.target.join("config"),
        fixture.root.join("linked-config"),
    )
    .unwrap();
    assert!(registry.execute_once(&intent).is_err());
    fs::remove_file(fixture.root.join("linked-config")).unwrap();
    let alternate = fixture.target.join("objects/info/alternates");
    fs::write(
        &alternate,
        fixture.candidate.join(".git/objects").to_str().unwrap(),
    )
    .unwrap();
    assert!(registry.execute_once(&intent).is_err());
    fs::remove_file(alternate).unwrap();
    assert_eq!(
        git(&fixture.target, &["rev-parse", "refs/heads/main"]),
        fixture.base
    );
}

#[test]
fn decoded_nonpromotion_and_noop_intents_cannot_reach_git() {
    for noop in [false, true] {
        let fixture = Fixture::new();
        let registry = TrustedPromotionRepositories::new(vec![fixture.binding()]).unwrap();
        let mut intent = registry.prepare(&fixture.decision()).unwrap();
        if noop {
            intent.action.candidate_sha = fixture.base.clone();
        } else {
            intent.action.operation = Operation::RaiseBudget {
                new_cap_microusd: 1,
            };
        }
        let decoded: ExecutionIntent =
            serde_json::from_slice(&serde_json::to_vec(&intent).unwrap()).unwrap();
        assert!(
            registry.execute_once(&decoded).is_err(),
            "decoded intent bypassed promotion-only validation"
        );
        assert!(registry.reconcile(&decoded).is_err());
        assert_eq!(
            git(&fixture.target, &["rev-parse", "refs/heads/main"]),
            fixture.base
        );
        assert!(!fixture.target.join(".sfactory-promotion-intents").exists());
    }
}

#[test]
fn repository_ref_fence_blocks_other_tasks_and_new_generations() {
    use std::sync::{Arc, Barrier};
    let fixture = Fixture::new();
    let registry = Arc::new(TrustedPromotionRepositories::new(vec![fixture.binding()]).unwrap());
    let first = registry.prepare(&fixture.decision()).unwrap();
    let mut other = fixture.decision();
    other.task_id = "other-task".into();
    other.action.task_id = other.task_id.clone();
    let other = registry.prepare(&other).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let jobs = [first, other]
        .into_iter()
        .map(|intent| {
            let registry = registry.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                registry.execute_once(&intent)
            })
        })
        .collect::<Vec<_>>();
    let results = jobs
        .into_iter()
        .map(|job| job.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        results
            .iter()
            .filter(|result| result
                .as_ref()
                .is_ok_and(|receipt| receipt.disposition == ExecutionDisposition::Advanced))
            .count(),
        1
    );
    assert_eq!(
        git(&fixture.target, &["rev-parse", "refs/heads/main"]),
        fixture.sha
    );
    // A second object legitimately has a new nonce, generation and candidate. It still
    // cannot silently clear an external fence left by the first object/process.
    fs::write(fixture.candidate.join("README"), "next candidate\n").unwrap();
    git(&fixture.candidate, &["add", "README"]);
    git(&fixture.candidate, &["commit", "-m", "next"]);
    let next_sha = git(&fixture.candidate, &["rev-parse", "HEAD"]);
    let mut next = fixture.decision();
    next.task_id = "other-task".into();
    next.action.task_id = next.task_id.clone();
    next.generation = 2;
    next.action.base_sha = fixture.sha.clone();
    next.action.candidate_sha = next_sha;
    let next = registry.prepare(&next).unwrap();
    assert!(registry.execute_once(&next).is_err());
    assert_eq!(
        git(&fixture.target, &["rev-parse", "refs/heads/main"]),
        fixture.sha
    );
}

#[test]
fn repository_ref_fence_survives_sigkill_and_new_process_identity() {
    const ENV: &str = "SFACTORY_FENCE_CHILD_ROOT";
    if let Some(root) = std::env::var_os(ENV) {
        let root = PathBuf::from(root);
        let decision: PromotionDecision =
            serde_json::from_slice(&fs::read(root.join("decision.json")).unwrap()).unwrap();
        let registry = TrustedPromotionRepositories::new(vec![RepositoryBinding {
            repository: "fixture".into(),
            target_ref: "refs/heads/main".into(),
            bare_target: root.join("target.git"),
            candidate_snapshot: root.join("candidate"),
            owner_uid: unsafe { libc::geteuid() },
        }])
        .unwrap();
        let intent = registry.prepare(&decision).unwrap();
        claim_attempt(registry.bindings.get("fixture").unwrap(), &intent).unwrap();
        fs::write(root.join("ready"), b"fenced").unwrap();
        loop {
            std::thread::park();
        }
    }
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let fixture = Fixture::new();
    let decision = fixture.decision();
    fs::write(
        fixture.root.join("decision.json"),
        serde_json::to_vec(&decision).unwrap(),
    )
    .unwrap();
    let mut child=ChildGuard(Command::new(std::env::current_exe().unwrap()).args(["--exact","promotion_execution::tests::repository_ref_fence_survives_sigkill_and_new_process_identity","--nocapture"]).env_clear().env(ENV,&fixture.root).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !fixture.root.join("ready").exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "fence child exited before readiness"
        );
        assert!(std::time::Instant::now() < deadline, "fence child deadline");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    let restarted = TrustedPromotionRepositories::new(vec![fixture.binding()]).unwrap();
    let prior = restarted.prepare(&decision).unwrap();
    assert!(restarted.execute_once(&prior).is_err());
    let mut other = fixture.decision();
    other.task_id = "replacement-task".into();
    other.action.task_id = other.task_id.clone();
    other.generation = 2;
    let other = restarted.prepare(&other).unwrap();
    assert!(restarted.execute_once(&other).is_err());
    assert_eq!(
        git(&fixture.target, &["rev-parse", "refs/heads/main"]),
        fixture.base
    );
}

#[test]
fn legacy_nonce_fence_is_not_silently_replaced_by_ref_fence() {
    let fixture = Fixture::new();
    let registry = TrustedPromotionRepositories::new(vec![fixture.binding()]).unwrap();
    let intent = registry.prepare(&fixture.decision()).unwrap();
    let dir = fixture.target.join(".sfactory-promotion-intents");
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let legacy = dir.join(format!("{}.json", shared::new_id()));
    fs::write(&legacy, "e".repeat(64)).unwrap();
    fs::set_permissions(&legacy, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(registry.execute_once(&intent).is_err());
    assert_eq!(
        git(&fixture.target, &["rev-parse", "refs/heads/main"]),
        fixture.base
    );
    assert_eq!(fs::read_dir(dir).unwrap().count(), 1);
}
