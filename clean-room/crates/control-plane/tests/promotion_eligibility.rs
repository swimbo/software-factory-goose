use control_plane::{approval, promotion_eligibility::*, state::Stage};
use evaluator::{
    DeterministicVerdict, VerificationEvidence,
    holdout::{PrefilterReport, PrefilterSession, RunOutcome},
};

fn snapshot() -> PromotionSnapshot {
    PromotionSnapshot {
        task_id: "task-1".into(),
        repository: "operator-repo-1".into(),
        target_ref: "refs/heads/main".into(),
        candidate_sha: "a".repeat(40),
        base_sha: "b".repeat(40),
        manifest_digest: "c".repeat(64),
        generation: 7,
        stage: Stage::AwaitingPromotion,
        stopped: false,
        active_claim: false,
    }
}
fn evidence(s: &PromotionSnapshot) -> VerificationEvidence {
    VerificationEvidence {
        sha: s.candidate_sha.clone(),
        verdict: DeterministicVerdict {
            typecheck: true,
            tests_pass: true,
            secret_scan_clean: true,
        },
        isolation: "seatbelt_offline_ephemeral_snapshot",
    }
}
fn holdout(s: &PromotionSnapshot, outcome: Option<RunOutcome>) -> PrefilterReport {
    let mut collector = PrefilterSession::begin(&s.candidate_sha, &s.manifest_digest, 1).unwrap();
    let handle = collector.scenarios()[0].clone();
    if let Some(outcome) = outcome {
        for slot in 0..3 {
            collector
                .record(&s.candidate_sha, &s.manifest_digest, &handle, slot, outcome)
                .unwrap();
        }
    }
    collector.finish()
}
fn operator() -> approval::TrustedOperator {
    approval::authenticate_operator(501, 501, &[502, 503, 504]).unwrap()
}

#[test]
fn authoritative_snapshot_derives_exact_action_and_stable_evidence_digest() {
    let s = snapshot();
    let e = evidence(&s);
    let h = holdout(&s, Some(RunOutcome::Pass));
    let a = prepare_promotion(&s, &e, &h, "reviewed", "local").unwrap();
    assert_eq!(a.operation, approval::Operation::Promote);
    assert_eq!(a.candidate_sha, s.candidate_sha);
    assert_eq!(a.base_sha, s.base_sha);
    assert_eq!(a.target_ref, s.target_ref);
    assert_eq!(a.evidence_digest.len(), 64);
    assert_eq!(
        a,
        prepare_promotion(&s, &e, &h, "reviewed", "local").unwrap()
    );
    let mut changed = s.clone();
    changed.generation += 1;
    assert_ne!(
        a.evidence_digest,
        prepare_promotion(&changed, &e, &h, "reviewed", "local")
            .unwrap()
            .evidence_digest
    );
}

#[test]
fn every_ineligible_state_and_noop_is_refused() {
    let s = snapshot();
    let e = evidence(&s);
    let h = holdout(&s, Some(RunOutcome::Pass));
    for stage in [
        Stage::Queued,
        Stage::Claimed,
        Stage::Building,
        Stage::Evaluating,
        Stage::Failed,
        Stage::HumanLane,
    ] {
        assert!(
            prepare_promotion(
                &PromotionSnapshot { stage, ..s.clone() },
                &e,
                &h,
                "reviewed",
                "local"
            )
            .is_err()
        );
    }
    for variant in 0..4 {
        let mut changed = s.clone();
        match variant {
            0 => changed.stopped = true,
            1 => changed.active_claim = true,
            2 => changed.generation = 0,
            _ => changed.base_sha = changed.candidate_sha.clone(),
        }
        assert!(prepare_promotion(&changed, &e, &h, "reviewed", "local").is_err());
    }
}

#[test]
fn failed_or_wrong_revision_wall_evidence_cannot_authorize() {
    let s = snapshot();
    let h = holdout(&s, Some(RunOutcome::Pass));
    for variant in 0..5 {
        let mut e = evidence(&s);
        match variant {
            0 => e.verdict.typecheck = false,
            1 => e.verdict.tests_pass = false,
            2 => e.verdict.secret_scan_clean = false,
            3 => e.sha = "d".repeat(40),
            _ => e.isolation = "unverified",
        }
        assert!(prepare_promotion(&s, &e, &h, "reviewed", "local").is_err());
    }
}

#[test]
fn absent_failed_foreign_or_stale_holdout_evidence_is_rejected() {
    let s = snapshot();
    let e = evidence(&s);
    for outcome in [None, Some(RunOutcome::Fail), Some(RunOutcome::Unavailable)] {
        assert!(prepare_promotion(&s, &e, &holdout(&s, outcome), "reviewed", "local").is_err());
    }
    for variant in 0..2 {
        let mut changed = s.clone();
        if variant == 0 {
            changed.candidate_sha = "d".repeat(40);
        } else {
            changed.manifest_digest = "e".repeat(64);
        }
        assert!(
            prepare_promotion(
                &s,
                &e,
                &holdout(&changed, Some(RunOutcome::Pass)),
                "reviewed",
                "local"
            )
            .is_err()
        );
    }
}

#[test]
fn changing_any_authoritative_binding_after_issuance_preserves_unconsumed_record() {
    let s = snapshot();
    let e = evidence(&s);
    let h = holdout(&s, Some(RunOutcome::Pass));
    let action = prepare_promotion(&s, &e, &h, "reviewed", "local").unwrap();
    let original = approval::issue(action, &operator(), 1000, 1000).unwrap();
    for variant in 0..8 {
        let mut current = s.clone();
        match variant {
            0 => current.task_id = "other-task".into(),
            1 => current.repository = "other-repo".into(),
            2 => current.target_ref = "refs/heads/other".into(),
            3 => current.base_sha = "e".repeat(40),
            4 => current.candidate_sha = "f".repeat(40),
            5 => current.generation += 1,
            6 => current.manifest_digest = "e".repeat(64),
            _ => current.stopped = true,
        }
        let mut stored = original.clone();
        assert!(
            consume_eligible_promotion(
                &mut stored,
                &original,
                &current,
                &e,
                &h,
                &operator(),
                "local",
                1500
            )
            .is_err()
        );
        assert_eq!(stored, original);
    }
}

#[test]
fn consumption_revalidates_presentation_time_identity_and_single_use() {
    let s = snapshot();
    let e = evidence(&s);
    let h = holdout(&s, Some(RunOutcome::Pass));
    let original = approval::issue(
        prepare_promotion(&s, &e, &h, "reviewed", "local").unwrap(),
        &operator(),
        1000,
        1000,
    )
    .unwrap();
    let mut stored = original.clone();
    let mut forged = original.clone();
    forged.action.evidence_digest = "0".repeat(64);
    assert!(
        consume_eligible_promotion(&mut stored, &forged, &s, &e, &h, &operator(), "local", 1500)
            .is_err()
    );
    assert!(
        consume_eligible_promotion(
            &mut stored,
            &original,
            &s,
            &e,
            &h,
            &operator(),
            "local",
            2000
        )
        .is_err()
    );
    assert_eq!(stored, original);
    let other = approval::authenticate_operator(505, 505, &[502, 503, 504]).unwrap();
    assert!(
        consume_eligible_promotion(&mut stored, &original, &s, &e, &h, &other, "local", 1500)
            .is_err()
    );
    assert!(
        consume_eligible_promotion(
            &mut stored,
            &original,
            &s,
            &e,
            &h,
            &operator(),
            "other-audience",
            1500
        )
        .is_err()
    );
    assert_eq!(stored, original);
    let decision = consume_eligible_promotion(
        &mut stored,
        &original,
        &s,
        &e,
        &h,
        &operator(),
        "local",
        1500,
    )
    .unwrap();
    assert_eq!(decision.target_ref(), "refs/heads/main");
    assert_eq!(decision.candidate_sha(), s.candidate_sha);
    assert_eq!(decision.base_sha(), s.base_sha);
    assert_eq!(stored.consumed_at_ms, Some(1500));
    assert!(
        consume_eligible_promotion(
            &mut stored,
            &original,
            &s,
            &e,
            &h,
            &operator(),
            "local",
            1501
        )
        .is_err()
    );
}

#[test]
fn malformed_snapshot_fields_fail_before_action_issuance() {
    let s = snapshot();
    let e = evidence(&s);
    let h = holdout(&s, Some(RunOutcome::Pass));
    for variant in 0..4 {
        let mut changed = s.clone();
        match variant {
            0 => changed.task_id.clear(),
            1 => changed.target_ref = "HEAD".into(),
            2 => changed.base_sha = "short".into(),
            _ => changed.repository = " hidden-path ".into(),
        }
        assert!(prepare_promotion(&changed, &e, &h, "reviewed", "local").is_err());
    }
}
