#![cfg(target_os = "macos")]
use evaluator::{
    holdout::PrefilterStatus,
    holdout_runner::{FixtureLimits, FixtureManifest, run_fixture_holdouts},
};
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{Duration, Instant},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("holdout-runner-test-{}", shared::new_id()));
        fs::create_dir(&root).unwrap();
        let fixture = Self(root);
        fixture.git(&["init", "-q", "-b", "main"]);
        fixture.git(&["config", "user.email", "fixture@example.test"]);
        fixture.git(&["config", "user.name", "Fixture"]);
        fs::write(fixture.0.join("README"), "expected\n").unwrap();
        fixture.git(&["add", "."]);
        fixture.git(&["commit", "-qm", "fixture"]);
        fixture
    }
    fn git(&self, args: &[&str]) -> String {
        let result = Command::new("/usr/bin/git")
            .arg("-C")
            .arg(&self.0)
            .args(args)
            .output()
            .unwrap();
        assert!(result.status.success());
        String::from_utf8(result.stdout).unwrap().trim().into()
    }
    fn sha(&self) -> String {
        self.git(&["rev-parse", "HEAD"])
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn manifest(script: &str) -> FixtureManifest {
    FixtureManifest::parse_trusted(
        &serde_json::to_vec(&serde_json::json!({"version":1,"scenarios":[{"script":script}]}))
            .unwrap(),
    )
    .unwrap()
}
fn limits() -> FixtureLimits {
    FixtureLimits {
        per_run_timeout: Duration::from_millis(250),
        output_limit: 1024,
    }
}

#[tokio::test]
async fn executes_snapshot_checks_three_times_with_fresh_attempt_state() {
    let repo = Fixture::new();
    let script = "if [ \"$(cat README)\" = expected ] && [ ! -e attempt-marker ]; then touch attempt-marker; printf '{\"passed\":true}'; else printf '{\"passed\":false}'; fi";
    let report = run_fixture_holdouts(&repo.0, &repo.sha(), &manifest(script), limits())
        .await
        .unwrap();
    assert_eq!(report.feedback().status, PrefilterStatus::Passed);
    assert!(!repo.0.join("attempt-marker").exists());
}

#[tokio::test]
async fn actual_negative_assertion_is_opaque_rejection() {
    let repo = Fixture::new();
    let report = run_fixture_holdouts(
        &repo.0,
        &repo.sha(),
        &manifest("printf '{\"passed\":false}'"),
        limits(),
    )
    .await
    .unwrap();
    assert_eq!(report.feedback().status, PrefilterStatus::Rejected);
    assert_eq!(report.feedback().messages, ["SCN-000001 failed"]);
}

#[tokio::test]
async fn timeout_is_bounded_incomplete_not_a_failed_vote() {
    let repo = Fixture::new();
    let started = Instant::now();
    let report = run_fixture_holdouts(
        &repo.0,
        &repo.sha(),
        &manifest("/bin/sleep 10; printf '{\"passed\":true}'"),
        limits(),
    )
    .await
    .unwrap();
    assert!(started.elapsed() < Duration::from_secs(8));
    assert_eq!(report.feedback().status, PrefilterStatus::Incomplete);
}

#[tokio::test]
async fn unavailable_first_run_stops_before_later_runs() {
    let repo = Fixture::new();
    let fixture = FixtureManifest::parse_trusted(
        &serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "scenarios": [
                {"script": "/bin/sleep 10; printf '{\"passed\":true}'"},
                {"script": "/bin/sleep 10; printf '{\"passed\":true}'"}
            ]
        }))
        .unwrap(),
    )
    .unwrap();
    let started = Instant::now();
    let report = run_fixture_holdouts(
        &repo.0,
        &repo.sha(),
        &fixture,
        FixtureLimits {
            per_run_timeout: Duration::from_secs(2),
            output_limit: 1024,
        },
    )
    .await
    .unwrap();
    assert_eq!(report.feedback().status, PrefilterStatus::Incomplete);
    // A second timed-out run alone takes another two seconds, before setup overhead.
    assert!(
        started.elapsed() < Duration::from_millis(3600),
        "additional timed run started after unavailable observation"
    );
}

#[tokio::test]
async fn malformed_output_nonzero_exit_and_oversize_never_leak_raw_data() {
    let repo = Fixture::new();
    for script in [
        "printf 'PRIVATE_SCENARIO_BODY'; printf 'SECRET_STDERR' >&2",
        "printf '{\"passed\":true,\"detail\":\"PRIVATE_SCENARIO_BODY\"}'",
        "printf '{\"passed\":true}'; exit 7",
        "printf '%05000d' 0",
        "printf '%05000d' 0 >&2; printf '{\"passed\":true}'",
    ] {
        let report = run_fixture_holdouts(&repo.0, &repo.sha(), &manifest(script), limits())
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_value(report.feedback()).unwrap(),
            serde_json::json!({"status":"incomplete","messages":["evaluation incomplete"]})
        );
    }
}

#[tokio::test]
async fn host_reads_writes_and_inherited_home_are_denied() {
    let repo = Fixture::new();
    let host = Fixture::new();
    let script = format!(
        "if cat '{}' >/dev/null 2>&1; then exit 1; fi; if touch '{}' 2>/dev/null; then exit 1; fi; if [ \"$HOME\" = '{}' ]; then exit 1; fi; printf '{{\"passed\":true}}'",
        host.0.join("README").display(),
        host.0.join("escape").display(),
        std::env::var("HOME").unwrap()
    );
    let report = run_fixture_holdouts(&repo.0, &repo.sha(), &manifest(&script), limits())
        .await
        .unwrap();
    assert_eq!(report.feedback().status, PrefilterStatus::Passed);
    assert!(!host.0.join("escape").exists());
}

#[tokio::test]
async fn changed_revision_and_dirty_candidate_refuse_before_scenario_execution() {
    let repo = Fixture::new();
    let sha = repo.sha();
    let fixture = manifest("printf '{\"passed\":true}'");
    assert!(
        run_fixture_holdouts(&repo.0, &"f".repeat(40), &fixture, limits())
            .await
            .is_err()
    );
    fs::write(repo.0.join("README"), "changed").unwrap();
    let error = run_fixture_holdouts(&repo.0, &sha, &fixture, limits())
        .await
        .err()
        .unwrap();
    assert_eq!(error.to_string(), "local holdout runner unavailable");
}

#[test]
fn invalid_manifests_and_unbounded_limits_are_rejected() {
    for bytes in [
        b"PRIVATE_SCENARIO_BODY".as_slice(),
        br#"{"version":1,"scenarios":[]}"#,
        br#"{"version":2,"scenarios":[{"script":"true"}]}"#,
        br#"{"version":1,"scenarios":[{"script":"true","secret":"hidden"}]}"#,
    ] {
        assert_eq!(
            FixtureManifest::parse_trusted(bytes)
                .err()
                .unwrap()
                .to_string(),
            "invalid fixture manifest"
        );
    }
    assert!(FixtureManifest::parse_trusted(&vec![b'x'; 131073]).is_err());
    let oversized_script = serde_json::to_vec(
        &serde_json::json!({"version":1,"scenarios":[{"script":"x".repeat(8193)}]}),
    )
    .unwrap();
    assert!(FixtureManifest::parse_trusted(&oversized_script).is_err());
}

#[tokio::test]
async fn runner_refuses_zero_or_excessive_resource_limits() {
    let repo = Fixture::new();
    let fixture = manifest("printf '{\"passed\":true}'");
    for limit in [
        FixtureLimits {
            per_run_timeout: Duration::ZERO,
            ..limits()
        },
        FixtureLimits {
            per_run_timeout: Duration::from_secs(6),
            ..limits()
        },
        FixtureLimits {
            output_limit: 0,
            ..limits()
        },
        FixtureLimits {
            output_limit: usize::MAX,
            ..limits()
        },
    ] {
        let error = run_fixture_holdouts(&repo.0, &repo.sha(), &fixture, limit)
            .await
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "invalid fixture runner limits");
    }
}
