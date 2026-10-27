use evaluator::{
    holdout::{PrefilterReport, PrefilterSession, RunOutcome},
    holdout_selection::{EvaluationSelection, SelectionConfig},
};
const SHA: &str = "1111111111111111111111111111111111111111";
const MANIFEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn config() -> SelectionConfig {
    SelectionConfig {
        task_id: "task-1".into(),
        repository: "repo-1".into(),
        target_ref: "refs/heads/main".into(),
        base_sha: "2222222222222222222222222222222222222222".into(),
        candidate_sha: SHA.into(),
        manifest_digest: MANIFEST.into(),
        generation: 1,
    }
}
fn report(sha: &str, digest: &str, outcome: RunOutcome) -> PrefilterReport {
    let mut session = PrefilterSession::begin(sha, digest, 1).unwrap();
    let handle = session.scenarios()[0].clone();
    for slot in 0..3 {
        session.record(sha, digest, &handle, slot, outcome).unwrap();
    }
    session.finish()
}
#[test]
fn selection_checks_fresh_full_binding_before_returning_evidence() {
    let original = EvaluationSelection::from_trusted_config(config()).unwrap();
    for i in 0..7 {
        let mut changed = config();
        match i {
            0 => changed.task_id = "task-2".into(),
            1 => changed.repository = "repo-2".into(),
            2 => changed.target_ref = "refs/heads/other".into(),
            3 => changed.base_sha = "3".repeat(40),
            4 => changed.candidate_sha = "4".repeat(40),
            5 => changed.manifest_digest = "b".repeat(64),
            _ => changed.generation = 2,
        }
        let current = EvaluationSelection::from_trusted_config(changed).unwrap();
        assert!(
            original
                .bind_report(&current, report(SHA, MANIFEST, RunOutcome::Pass))
                .is_err(),
            "accepted changed field {i}"
        );
    }
    let current = EvaluationSelection::from_trusted_config(config()).unwrap();
    assert!(
        original
            .bind_report(
                &current,
                report(&"4".repeat(40), MANIFEST, RunOutcome::Pass)
            )
            .is_err()
    );
    assert!(
        original
            .bind_report(&current, report(SHA, &"b".repeat(64), RunOutcome::Pass))
            .is_err()
    );
    let result = original
        .bind_report(&current, report(SHA, MANIFEST, RunOutcome::Pass))
        .unwrap();
    assert!(result.selection() == &original);
    assert_eq!(result.report().feedback().messages.len(), 0);
}
#[test]
fn generator_feedback_contains_no_selection_or_hidden_content() {
    let selected = EvaluationSelection::from_trusted_config(config()).unwrap();
    let result = selected
        .bind_report(&selected, report(SHA, MANIFEST, RunOutcome::Fail))
        .unwrap();
    let feedback = serde_json::to_string(result.report().feedback()).unwrap();
    assert_eq!(
        feedback,
        r#"{"status":"rejected","messages":["SCN-000001 failed"]}"#
    );
    for secret in [SHA, MANIFEST, "task-1", "repo-1", "refs/heads/main"] {
        assert!(!feedback.contains(secret));
    }
}
#[test]
fn malformed_selection_is_rejected() {
    for i in 0..4 {
        let mut c = config();
        match i {
            0 => c.generation = 0,
            1 => c.task_id = "".into(),
            2 => c.candidate_sha = "secret".into(),
            _ => c.manifest_digest = "A".repeat(64),
        }
        assert!(EvaluationSelection::from_trusted_config(c).is_err());
    }
}
