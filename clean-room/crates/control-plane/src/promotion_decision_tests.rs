use super::*;
use crate::state::Stage;
use evaluator::{
    DeterministicVerdict, VerificationEvidence,
    holdout::{PrefilterSession, RunOutcome},
};

fn operator() -> TrustedOperator {
    approval::authenticate_operator(501, 501, &[502, 503, 504]).unwrap()
}
fn publication(generation: u64) -> EligibilityPublication {
    let snapshot = PromotionSnapshot {
        task_id: "task".into(),
        repository: "configured-repo".into(),
        target_ref: "refs/heads/main".into(),
        candidate_sha: "a".repeat(40),
        base_sha: "b".repeat(40),
        manifest_digest: "c".repeat(64),
        generation,
        stage: Stage::AwaitingPromotion,
        stopped: false,
        active_claim: false,
    };
    let wall = VerificationEvidence {
        sha: snapshot.candidate_sha.clone(),
        verdict: DeterministicVerdict {
            typecheck: true,
            tests_pass: true,
            secret_scan_clean: true,
        },
        isolation: "seatbelt_offline_ephemeral_snapshot",
    };
    let mut prefilter =
        PrefilterSession::begin(&snapshot.candidate_sha, &snapshot.manifest_digest, 1).unwrap();
    let handle = prefilter.scenarios()[0].clone();
    for slot in 0..3 {
        prefilter
            .record(
                &snapshot.candidate_sha,
                &snapshot.manifest_digest,
                &handle,
                slot,
                RunOutcome::Pass,
            )
            .unwrap();
    }
    EligibilityPublication::from_authoritative(
        shared::new_id(),
        &snapshot,
        &wall,
        &prefilter.finish(),
        "fixture",
    )
    .unwrap()
}
fn ready() -> DecisionState {
    let mut state = DecisionState::new("task");
    publish(&mut state, publication(1), "fixture").unwrap();
    state
}
fn issue_request() -> DecisionIssueRequest {
    DecisionIssueRequest {
        request_id: shared::new_id(),
        reason: "reviewed exact action".into(),
        ttl_ms: 1000,
    }
}
fn issued(state: &mut DecisionState) -> DecisionApproval {
    issue(
        state,
        issue_request(),
        shared::new_id(),
        &operator(),
        "fixture",
        1000,
    )
    .unwrap()
}
fn presented(record: &ApprovalRecord) -> ConsumeRequest {
    ConsumeRequest {
        action: record.action.clone(),
        nonce: record.nonce.clone(),
        issued_at_ms: record.issued_at_ms,
        expires_at_ms: record.expires_at_ms,
    }
}

#[test]
fn one_state_write_contains_consumption_and_exact_decision_after_roundtrip() {
    let mut state = ready();
    let approved = issued(&mut state);
    state = serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    let decision = consume(
        &mut state,
        presented(&approved.record),
        &operator(),
        "fixture",
        1500,
    )
    .unwrap();
    state = serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    assert_eq!(decision.action, approved.record.action);
    assert_eq!(decision.generation, 1);
    assert_eq!(decision.execution, DecisionExecution::NotRequested);
    let stored = state.approvals.values().next().unwrap();
    assert_eq!(stored.record.consumed_at_ms, Some(1500));
    assert_eq!(stored.decision, Some(decision));
    assert!(
        consume(
            &mut state,
            presented(&approved.record),
            &operator(),
            "fixture",
            1501
        )
        .is_err()
    );
}

#[test]
fn duplicate_publication_and_issue_cannot_reset_consumption_or_extend_lifetime() {
    let mut state = DecisionState::new("task");
    let update = publication(1);
    let receipt = publish(&mut state, update.clone(), "fixture").unwrap();
    let request = issue_request();
    let approved = issue(
        &mut state,
        request.clone(),
        shared::new_id(),
        &operator(),
        "fixture",
        1000,
    )
    .unwrap();
    consume(
        &mut state,
        presented(&approved.record),
        &operator(),
        "fixture",
        1500,
    )
    .unwrap();
    let before = state.clone();
    assert_eq!(publish(&mut state, update, "fixture").unwrap(), receipt);
    assert_eq!(state, before);
    let retry = issue(
        &mut state,
        request.clone(),
        shared::new_id(),
        &operator(),
        "fixture",
        9000,
    )
    .unwrap();
    assert_eq!(retry.record.consumed_at_ms, Some(1500));
    assert_eq!(retry.record.expires_at_ms, 2000);
    assert_eq!(state, before);
    let mut changed = request;
    changed.ttl_ms += 1;
    assert!(
        issue(
            &mut state,
            changed,
            shared::new_id(),
            &operator(),
            "fixture",
            1501
        )
        .is_err()
    );
}

#[test]
fn stale_generation_invalidation_and_changed_action_fail_without_consumption() {
    let mut state = ready();
    let approved = issued(&mut state);
    publish(&mut state, publication(2), "fixture").unwrap();
    let before = state.clone();
    assert!(
        consume(
            &mut state,
            presented(&approved.record),
            &operator(),
            "fixture",
            1500
        )
        .is_err()
    );
    assert_eq!(state, before);
    assert!(publish(&mut state, publication(2), "fixture").is_err());
    assert_eq!(state, before);
    let second = issued(&mut state);
    invalidate(
        &mut state,
        InvalidateRequest {
            request_id: shared::new_id(),
            expected_generation: 2,
        },
    )
    .unwrap();
    let before = state.clone();
    assert!(
        consume(
            &mut state,
            presented(&second.record),
            &operator(),
            "fixture",
            1500
        )
        .is_err()
    );
    assert!(
        issue(
            &mut state,
            issue_request(),
            shared::new_id(),
            &operator(),
            "fixture",
            1500
        )
        .is_err()
    );
    assert_eq!(state, before);
}

#[test]
fn expiry_forgery_and_wrong_operator_are_nonmutating() {
    let mut state = ready();
    let approved = issued(&mut state);
    let before = state.clone();
    assert!(
        consume(
            &mut state,
            presented(&approved.record),
            &operator(),
            "fixture",
            2000
        )
        .is_err()
    );
    assert_eq!(state, before);
    let mut forged = presented(&approved.record);
    forged.action.candidate_sha = "d".repeat(40);
    assert!(consume(&mut state, forged, &operator(), "fixture", 1500).is_err());
    assert_eq!(state, before);
    let wrong = approval::authenticate_operator(505, 505, &[502, 503, 504]).unwrap();
    assert!(
        consume(
            &mut state,
            presented(&approved.record),
            &wrong,
            "fixture",
            1500
        )
        .is_err()
    );
    assert_eq!(state, before);
}

#[test]
fn two_approvals_have_only_one_decision_for_the_generation() {
    let mut state = ready();
    let first = issued(&mut state);
    let second = issued(&mut state);
    consume(
        &mut state,
        presented(&first.record),
        &operator(),
        "fixture",
        1500,
    )
    .unwrap();
    let before = state.clone();
    assert!(
        consume(
            &mut state,
            presented(&second.record),
            &operator(),
            "fixture",
            1500
        )
        .is_err()
    );
    assert_eq!(state, before);
    assert!(
        issue(
            &mut state,
            issue_request(),
            shared::new_id(),
            &operator(),
            "fixture",
            1501
        )
        .is_err()
    );
}

#[test]
fn stale_exact_update_retry_returns_historical_receipt_without_reopening_state() {
    let mut state = DecisionState::new("task");
    let first = publication(1);
    let receipt = publish(&mut state, first.clone(), "fixture").unwrap();
    invalidate(
        &mut state,
        InvalidateRequest {
            request_id: shared::new_id(),
            expected_generation: 1,
        },
    )
    .unwrap();
    let before = state.clone();
    assert_eq!(
        publish(&mut state, first.clone(), "fixture").unwrap(),
        receipt
    );
    assert_eq!(state, before);
    let mut reused = first;
    reused.action.candidate_sha = "d".repeat(40);
    assert!(publish(&mut state, reused, "fixture").is_err());
    assert_eq!(state, before);
}

#[test]
fn publication_binding_and_capacity_fail_closed() {
    let mut state = DecisionState::new("task");
    let mut bad = publication(1);
    bad.action.task_id = "other".into();
    assert!(publish(&mut state, bad, "fixture").is_err());
    assert_eq!(state.generation, 0);
    let mut bad = publication(1);
    bad.action.audience = "other".into();
    assert!(publish(&mut state, bad, "fixture").is_err());
    for generation in 1..MAX_CHANGES as u64 {
        publish(&mut state, publication(generation), "fixture").unwrap();
    }
    let before = state.clone();
    assert!(publish(&mut state, publication(MAX_CHANGES as u64), "fixture").is_err());
    assert_eq!(state, before);
    for _ in 0..MAX_APPROVALS {
        issued(&mut state);
    }
    let before = state.clone();
    assert!(
        issue(
            &mut state,
            issue_request(),
            shared::new_id(),
            &operator(),
            "fixture",
            1000
        )
        .is_err()
    );
    assert_eq!(state, before);
}

#[test]
fn exhausted_publication_capacity_still_allows_final_invalidation() {
    let mut state = DecisionState::new("task");
    for generation in 1..MAX_CHANGES as u64 {
        publish(&mut state, publication(generation), "fixture").unwrap();
    }
    let approved = issued(&mut state);
    assert!(publish(&mut state, publication(MAX_CHANGES as u64), "fixture").is_err());
    let receipt = invalidate(
        &mut state,
        InvalidateRequest {
            request_id: shared::new_id(),
            expected_generation: MAX_CHANGES as u64 - 1,
        },
    )
    .unwrap();
    assert_eq!(receipt.generation, MAX_CHANGES as u64);
    assert!(!state.summary().eligible);
    assert!(
        consume(
            &mut state,
            presented(&approved.record),
            &operator(),
            "fixture",
            1500
        )
        .is_err()
    );
    assert!(publish(&mut state, publication(MAX_CHANGES as u64 + 1), "fixture").is_err());
}

#[test]
fn execution_requires_current_consumed_exact_decision_and_prepared_cannot_survive_invalidation() {
    let mut state = ready();
    let approved = issued(&mut state);
    assert!(execution_decision(&state, &approved.record.nonce, &operator(), "fixture").is_err());
    let decision = consume(
        &mut state,
        presented(&approved.record),
        &operator(),
        "fixture",
        1500,
    )
    .unwrap();
    assert_eq!(
        execution_decision(&state, &decision.nonce, &operator(), "fixture")
            .unwrap()
            .1,
        decision
    );
    let intent=serde_json::from_value(serde_json::json!({"task_id":decision.task_id,"generation":decision.generation,"nonce":decision.nonce,"action":decision.action,"mapping_fingerprint":"f".repeat(64)})).unwrap();
    state
        .approvals
        .values_mut()
        .next()
        .unwrap()
        .decision
        .as_mut()
        .unwrap()
        .execution = DecisionExecution::Prepared { intent };
    let prepared = state.clone();
    invalidate(
        &mut state,
        InvalidateRequest {
            request_id: shared::new_id(),
            expected_generation: 1,
        },
    )
    .unwrap();
    assert!(execution_decision(&state, &decision.nonce, &operator(), "fixture").is_err());
    state = prepared.clone();
    state.generation += 1;
    assert!(execution_decision(&state, &decision.nonce, &operator(), "fixture").is_err());
    state = prepared.clone();
    state.eligible_action.as_mut().unwrap().evidence_digest = "d".repeat(64);
    assert!(execution_decision(&state, &decision.nonce, &operator(), "fixture").is_err());
    state = prepared.clone();
    state
        .approvals
        .values_mut()
        .next()
        .unwrap()
        .record
        .consumed_at_ms = None;
    assert!(execution_decision(&state, &decision.nonce, &operator(), "fixture").is_err());
    state = prepared;
    state
        .approvals
        .values_mut()
        .next()
        .unwrap()
        .record
        .operator_uid += 1;
    assert!(execution_decision(&state, &decision.nonce, &operator(), "fixture").is_err());
}

#[test]
fn dropped_queued_execution_does_not_start_after_blocking_pool_frees() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        started_rx.await.unwrap();
        let ran = Arc::new(AtomicUsize::new(0));
        let seen = ran.clone();
        let queued = BlockingAttempt::spawn(move || {
            seen.fetch_add(1, Ordering::SeqCst);
        });
        drop(queued);
        release_tx.send(()).unwrap();
        blocker.await.unwrap();
        // This later pool job proves the queue has drained, without a timing-only assertion.
        tokio::task::spawn_blocking(|| {}).await.unwrap();
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        assert_eq!(BlockingAttempt::spawn(|| 7).join().await.unwrap(), Some(7));
    });
}

#[test]
fn unresolved_prepared_attempt_quarantines_new_generations_even_after_invalidation() {
    let mut state = DecisionState::new("task");
    let first = publication(1);
    let first_receipt = publish(&mut state, first.clone(), "fixture").unwrap();
    let approved = issued(&mut state);
    let decision = consume(
        &mut state,
        presented(&approved.record),
        &operator(),
        "fixture",
        1500,
    )
    .unwrap();
    let intent=serde_json::from_value(serde_json::json!({"task_id":decision.task_id,"generation":decision.generation,"nonce":decision.nonce,"action":decision.action,"mapping_fingerprint":"f".repeat(64)})).unwrap();
    state
        .approvals
        .values_mut()
        .next()
        .unwrap()
        .decision
        .as_mut()
        .unwrap()
        .execution = DecisionExecution::Prepared { intent };
    let prepared = state.clone();
    assert!(publish(&mut state, publication(2), "fixture").is_err());
    assert_eq!(state, prepared);
    invalidate(
        &mut state,
        InvalidateRequest {
            request_id: shared::new_id(),
            expected_generation: 1,
        },
    )
    .unwrap();
    let invalidated = state.clone();
    assert!(publish(&mut state, publication(3), "fixture").is_err());
    assert_eq!(state, invalidated);
    assert!(
        issue(
            &mut state,
            issue_request(),
            shared::new_id(),
            &operator(),
            "fixture",
            1700
        )
        .is_err()
    );
    assert_eq!(state, invalidated);
    assert_eq!(
        publish(&mut state, first, "fixture").unwrap(),
        first_receipt
    );
    assert_eq!(state, invalidated);
}
