use evaluator::holdout::{PrefilterSession, PrefilterStatus, RunOutcome};

const SHA: &str = "1111111111111111111111111111111111111111";
const MANIFEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn session(count: usize) -> PrefilterSession {
    PrefilterSession::begin(SHA, MANIFEST, count).unwrap()
}

#[test]
fn exact_manifest_accepts_only_complete_ninety_percent_evidence() {
    let mut s = session(10);
    for (index, handle) in s.scenarios().to_vec().iter().enumerate() {
        for run in 0..3 {
            let outcome = if index < 3 && run == 2 {
                RunOutcome::Fail
            } else {
                RunOutcome::Pass
            };
            s.record(SHA, MANIFEST, handle, run, outcome).unwrap();
        }
    }
    let report = s.finish();
    assert_eq!(report.candidate_sha(), SHA);
    assert_eq!(report.manifest_digest(), MANIFEST);
    assert_eq!(report.feedback().status, PrefilterStatus::Passed);
    assert!(report.feedback().messages.is_empty());
}

#[test]
fn omitted_scenario_is_incomplete_even_when_every_supplied_run_passes() {
    let mut s = session(2);
    let handles = s.scenarios().to_vec();
    for run in 0..3 {
        s.record(SHA, MANIFEST, &handles[0], run, RunOutcome::Pass)
            .unwrap();
    }
    let report = s.finish();
    assert_eq!(report.feedback().status, PrefilterStatus::Incomplete);
    assert_eq!(report.feedback().messages, ["evaluation incomplete"]);
}

#[test]
fn duplicate_run_cannot_replace_a_failure_or_be_ignored() {
    let mut s = session(10);
    let handles = s.scenarios().to_vec();
    s.record(SHA, MANIFEST, &handles[0], 0, RunOutcome::Fail)
        .unwrap();
    assert!(
        s.record(SHA, MANIFEST, &handles[0], 0, RunOutcome::Pass)
            .is_err()
    );
    // One failure in 30 would otherwise pass: protocol violation poisons the whole attempt.
    for (index, handle) in handles.iter().enumerate() {
        for run in 0..3 {
            if index != 0 || run != 0 {
                let _ = s.record(SHA, MANIFEST, handle, run, RunOutcome::Pass);
            }
        }
    }
    assert_eq!(s.finish().feedback().status, PrefilterStatus::Incomplete);
}

#[test]
fn wrong_revision_manifest_session_or_slot_invalidates_evidence() {
    for variant in 0..4 {
        let mut s = session(1);
        let handle = s.scenarios()[0].clone();
        let other = session(1);
        let (sha, manifest, submitted, slot) = match variant {
            0 => ("secret revision body", MANIFEST, &handle, 0),
            1 => (SHA, "private manifest text", &handle, 0),
            2 => (SHA, MANIFEST, &other.scenarios()[0], 0),
            _ => (SHA, MANIFEST, &handle, 3),
        };
        let error = s
            .record(sha, manifest, submitted, slot, RunOutcome::Pass)
            .unwrap_err();
        assert_eq!(error.to_string(), "invalid holdout observation");
        for run in 0..3 {
            let _ = s.record(SHA, MANIFEST, &handle, run, RunOutcome::Pass);
        }
        assert_eq!(s.finish().feedback().status, PrefilterStatus::Incomplete);
    }
}

#[test]
fn unavailable_run_is_not_a_negative_vote_that_other_successes_can_outvote() {
    let mut s = session(10);
    for (index, handle) in s.scenarios().to_vec().iter().enumerate() {
        for run in 0..3 {
            let outcome = if index == 0 && run == 0 {
                RunOutcome::Unavailable
            } else {
                RunOutcome::Pass
            };
            s.record(SHA, MANIFEST, handle, run, outcome).unwrap();
        }
    }
    assert_eq!(s.finish().feedback().status, PrefilterStatus::Incomplete);
}

#[test]
fn feedback_has_only_server_assigned_ids_and_never_internal_bindings() {
    let mut s = session(10);
    for (index, handle) in s.scenarios().to_vec().iter().enumerate() {
        for run in 0..3 {
            s.record(
                SHA,
                MANIFEST,
                handle,
                run,
                if index == 0 {
                    RunOutcome::Fail
                } else {
                    RunOutcome::Pass
                },
            )
            .unwrap();
        }
    }
    let report = s.finish();
    assert_eq!(report.feedback().status, PrefilterStatus::Rejected);
    assert_eq!(report.feedback().messages, ["SCN-000001 failed"]);
    let wire = serde_json::to_value(report.feedback()).unwrap();
    assert_eq!(
        wire,
        serde_json::json!({"status":"rejected","messages":["SCN-000001 failed"]})
    );
    assert!(!wire.to_string().contains(SHA));
    assert!(!wire.to_string().contains(MANIFEST));
}

#[test]
fn aggregate_failure_does_not_invent_a_failed_scenario() {
    let mut s = session(10);
    for (index, handle) in s.scenarios().to_vec().iter().enumerate() {
        for run in 0..3 {
            s.record(
                SHA,
                MANIFEST,
                handle,
                run,
                if index < 4 && run == 2 {
                    RunOutcome::Fail
                } else {
                    RunOutcome::Pass
                },
            )
            .unwrap();
        }
    }
    let report = s.finish();
    assert_eq!(report.feedback().status, PrefilterStatus::Rejected);
    assert_eq!(report.feedback().messages, ["holdout prefilter failed"]);
}

#[test]
fn invalid_or_unbounded_configuration_is_refused() {
    for count in [0, 1001, usize::MAX] {
        assert!(PrefilterSession::begin(SHA, MANIFEST, count).is_err());
    }
    for sha in ["HEAD", "1111111", "holdout secret", &"z".repeat(40)] {
        assert!(PrefilterSession::begin(sha, MANIFEST, 1).is_err());
    }
    for manifest in ["", "private scenario body", &"g".repeat(64)] {
        assert!(PrefilterSession::begin(SHA, manifest, 1).is_err());
    }
}
