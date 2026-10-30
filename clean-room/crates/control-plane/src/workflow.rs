//! Restate workflow — the durable orchestration layer (consensus R3/R5).
//!
//! Restate 0.12 API (verified against the live SDK):
//! - `#[restate_sdk::workflow]` / `#[object]` go on the **impl block**, not the struct.
//! - Handlers are `#[handler]`, take `&self` + a context with a lifetime, return `HandlerResult<T>`.
//!
//! Consensus constraints encoded here:
//! - The Goose subprocess runs *outside* the journal (in the execution plane); only its outcome
//!   is awaited here via a durable promise (R5). Replay never re-runs the model.
//! - The deterministic state transition is a pure function — no side effect to journal (R5).
//! - The budget is a journaled K/V object the gateway reads, defaulting-deny (R7).

use restate_sdk::prelude::*;

/// A work-package workflow: await the worker's Goose run, then apply the deterministic
/// lifecycle transition.
pub struct WorkPackageWorkflow;

#[restate_sdk::workflow]
impl WorkPackageWorkflow {
    #[handler]
    async fn run(
        &self,
        ctx: WorkflowContext<'_>,
        _work_package_id: String,
    ) -> HandlerResult<String> {
        // Await the worker's outcome via a durable promise (R5). The Goose subprocess ran
        // outside this journal, in the execution plane; that plane resolves `worker.done`
        // with the typed Receipt JSON once Goose exits.
        let receipt_json: String = ctx.promise::<String>("worker.done").await?;
        let receipt = parse_receipt(&receipt_json)?;

        // Deterministic lifecycle transition — pure, replayed naturally, no side effect.
        let mut st = crate::state::WorkPackageState::default();
        let _ = crate::state::claim(&mut st);
        st.stage = crate::state::Stage::Building;
        crate::state::on_build_complete(&mut st, &receipt);

        let stage = format!("{:?}", st.stage);
        ctx.set("stage", stage.clone());
        Ok(stage)
    }

    /// Called by the execution plane when Goose finishes; resolves the run handler's promise.
    #[handler]
    async fn complete(
        &self,
        ctx: SharedWorkflowContext<'_>,
        receipt_json: String,
    ) -> HandlerResult<()> {
        // Reject malformed outcomes before irreversibly resolving the promise.
        parse_receipt(&receipt_json)?;
        ctx.resolve_promise::<String>("worker.done", receipt_json);
        Ok(())
    }
}

/// A budget state object (R7): the cumulative spend counter, journaled atomically with each
/// billable call. The gateway reads this and defaults-deny if it cannot.
pub struct BudgetCounter;

#[restate_sdk::object]
impl BudgetCounter {
    #[handler]
    async fn try_spend(&self, ctx: ObjectContext<'_>, estimate_usd: f64) -> HandlerResult<bool> {
        let _admission = crate::registry_journal_gate::enter_production().map_err(|_| {
            TerminalError::new_with_code(503, "registry transition blocks mutations")
        })?;
        let ledger = load_budget_ledger(&ctx).await?;
        let Some(next) = reserved_legacy_usd(&ledger, estimate_usd) else {
            return Ok(false);
        };
        ctx.set("ledger_mode", "legacy_usd".to_string());
        ctx.set("spent", next);
        Ok(true)
    }

    /// Integer wire and ledger avoid floating-point JSON roundtrip under-reservation.
    /// Existing legacy state cannot migrate through this method, even if its spend is zero.
    /// No automatic reset/migration or budget raise is exposed.
    #[handler]
    async fn try_spend_microusd(
        &self,
        ctx: ObjectContext<'_>,
        estimate_microusd: u64,
    ) -> HandlerResult<bool> {
        let _admission = crate::registry_journal_gate::enter_production().map_err(|_| {
            TerminalError::new_with_code(503, "registry transition blocks mutations")
        })?;
        let ledger = load_budget_ledger(&ctx).await?;
        let Some(next) = reserved_microusd(&ledger, estimate_microusd) else {
            return Ok(false);
        };
        ctx.set("ledger_mode", "microusd".to_string());
        ctx.set("spent_microusd", next);
        Ok(true)
    }
}

#[derive(Default)]
struct BudgetLedger {
    mode: Option<String>,
    spent_usd: Option<f64>,
    cap_usd: Option<f64>,
    spent_microusd: Option<u64>,
    cap_microusd: Option<u64>,
}
async fn load_budget_ledger(ctx: &ObjectContext<'_>) -> HandlerResult<BudgetLedger> {
    Ok(BudgetLedger {
        mode: ctx.get("ledger_mode").await?,
        spent_usd: ctx.get("spent").await?,
        cap_usd: ctx.get("cap").await?,
        spent_microusd: ctx.get("spent_microusd").await?,
        cap_microusd: ctx.get("cap_microusd").await?,
    })
}
fn ledger_mode_allows(ledger: &BudgetLedger, integer: bool) -> bool {
    let legacy_present = ledger.spent_usd.is_some() || ledger.cap_usd.is_some();
    let integer_present = ledger.spent_microusd.is_some() || ledger.cap_microusd.is_some();
    if (integer && legacy_present) || (!integer && integer_present) {
        return false;
    }
    match ledger.mode.as_deref() {
        None => true, // Fresh object, or a pre-mode ledger with only the matching key family.
        Some("microusd") => integer && ledger.spent_microusd.is_some(),
        Some("legacy_usd") => !integer && ledger.spent_usd.is_some(),
        _ => false, // Unknown mode or incomplete binding is never treated as a new counter.
    }
}
fn reserved_legacy_usd(ledger: &BudgetLedger, estimate: f64) -> Option<f64> {
    ledger_mode_allows(ledger, false).then_some(())?;
    reserved_spend(
        ledger.spent_usd.unwrap_or(0.0),
        ledger.cap_usd.unwrap_or(0.75),
        estimate,
    )
}
fn reserved_microusd(ledger: &BudgetLedger, estimate: u64) -> Option<u64> {
    if !ledger_mode_allows(ledger, true) || estimate == 0 {
        return None;
    }
    let next = ledger.spent_microusd.unwrap_or(0).checked_add(estimate)?;
    (next <= ledger.cap_microusd.unwrap_or(750_000)).then_some(next)
}

/// Invalid worker input is terminal, never an endlessly retried serde failure.
fn parse_receipt(json: &str) -> Result<shared::Receipt, TerminalError> {
    let receipt: shared::Receipt = serde_json::from_str(json)
        .map_err(|_| TerminalError::new_with_code(400, "invalid receipt JSON"))?;
    if !receipt.spend_usd().is_finite() || receipt.spend_usd() < 0.0 {
        return Err(TerminalError::new_with_code(400, "invalid receipt spend"));
    }
    Ok(receipt)
}

fn reserved_spend(spent: f64, cap: f64, estimate: f64) -> Option<f64> {
    if [spent, cap, estimate]
        .iter()
        .any(|v| !v.is_finite() || *v < 0.0)
    {
        return None;
    }
    let next = spent + estimate;
    (next.is_finite() && next <= cap).then_some(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservations_cannot_reduce_or_corrupt_the_counter() {
        for invalid in [-0.01, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(reserved_spend(0.2, 0.75, invalid), None);
            assert_eq!(reserved_spend(invalid, 0.75, 0.1), None);
            assert_eq!(reserved_spend(0.2, invalid, 0.1), None);
        }
        assert_eq!(reserved_spend(f64::MAX, f64::MAX, f64::MAX), None);
        assert_eq!(reserved_spend(0.5, 0.75, 0.25), Some(0.75));
        assert_eq!(reserved_spend(0.75, 0.75, 0.01), None);
    }

    #[test]
    fn integer_reservations_are_exact_and_fail_closed_on_overage_or_overflow() {
        let state = BudgetLedger::default();
        assert_eq!(reserved_microusd(&state, 750_000), Some(750_000));
        assert_eq!(reserved_microusd(&state, 750_001), None);
        assert_eq!(reserved_microusd(&state, 0), None);
        let state = BudgetLedger {
            mode: Some("microusd".into()),
            spent_microusd: Some(749_999),
            ..Default::default()
        };
        assert_eq!(reserved_microusd(&state, 1), Some(750_000));
        assert_eq!(reserved_microusd(&state, 2), None);
        let state = BudgetLedger {
            mode: Some("microusd".into()),
            spent_microusd: Some(u64::MAX),
            cap_microusd: Some(u64::MAX),
            ..Default::default()
        };
        assert_eq!(reserved_microusd(&state, 1), None);
    }
    #[test]
    fn old_and_integer_handlers_cannot_open_two_ledgers_for_one_budget_key() {
        for legacy_spent in [0.0, 0.25] {
            let old = BudgetLedger {
                spent_usd: Some(legacy_spent),
                ..Default::default()
            };
            assert_eq!(reserved_microusd(&old, 1), None);
            assert!(reserved_legacy_usd(&old, 0.01).is_some());
        }
        let integer = BudgetLedger {
            mode: Some("microusd".into()),
            spent_microusd: Some(1),
            ..Default::default()
        };
        assert_eq!(reserved_legacy_usd(&integer, 0.01), None);
        let old_mode = BudgetLedger {
            mode: Some("legacy_usd".into()),
            spent_usd: Some(0.0),
            ..Default::default()
        };
        assert_eq!(reserved_microusd(&old_mode, 1), None);
        let cap_only = BudgetLedger {
            cap_usd: Some(0.75),
            ..Default::default()
        };
        assert_eq!(reserved_microusd(&cap_only, 1), None);
        let mixed = BudgetLedger {
            spent_usd: Some(0.1),
            spent_microusd: Some(1),
            ..Default::default()
        };
        assert_eq!(reserved_microusd(&mixed, 1), None);
        assert_eq!(reserved_legacy_usd(&mixed, 0.01), None);
        let unknown = BudgetLedger {
            mode: Some("future".into()),
            ..Default::default()
        };
        assert_eq!(reserved_microusd(&unknown, 1), None);
        assert_eq!(reserved_legacy_usd(&unknown, 0.01), None);
    }

    #[test]
    fn malformed_completion_is_terminal_before_promise_resolution() {
        assert_eq!(parse_receipt("not JSON").unwrap_err().code(), 400);
        let invalid = r#"{"status":"completed","sha":"abc","diff":"","turn_count":1,"exit_code":0,"wall_time_ms":1,"spend_usd":-1}"#;
        assert_eq!(parse_receipt(invalid).unwrap_err().code(), 400);
        assert!(parse_receipt(r#"{"status":"failed","exit_code":1,"stderr_tail":"bad"}"#).is_ok());
    }
}

#[cfg(test)]
mod lease_tests {
    use super::*;
    fn state() -> ClaimLeaseState {
        new_lease_state(
            "task",
            LeaseSpec {
                repository: "repo".into(),
                base_revision: "a".repeat(40),
            },
        )
        .unwrap()
    }
    fn receipt() -> shared::Receipt {
        shared::Receipt::Completed {
            sha: "b".repeat(40),
            diff: "fixture".into(),
            turn_count: 1,
            exit_code: 0,
            wall_time_ms: 10,
            spend_usd: 0.1,
        }
    }
    fn proof(lease: &ActiveLease) -> LeaseProof {
        LeaseProof {
            attempt: lease.attempt,
            token: lease.token.clone(),
        }
    }
    #[tokio::test]
    async fn protected_two_claim_scopes_bind_worker_by_task() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://fixture@127.0.0.1/fixture")
            .unwrap();
        let scope = crate::launch_reservation::LaunchScope {
            task_id: "new-task".into(),
            intent_id: "new-intent".into(),
            queue_id: "new-queue".into(),
            generation: "generation".into(),
            spec: LeaseSpec {
                repository: "repo".into(),
                base_revision: "a".repeat(40),
            },
            worker_id: "new-worker".into(),
            catalog_sha256: "b".repeat(64),
        };
        let j = ClaimLeaseJournal::new_with_preserved_launch_scope(
            "new-worker".into(),
            pool,
            scope,
            "old-task".into(),
            "old-worker".into(),
        )
        .unwrap();
        assert_eq!(j.worker_for("old-task").unwrap(), "old-worker");
        assert_eq!(j.worker_for("new-task").unwrap(), "new-worker");
        assert!(j.worker_for("unknown").is_err());
    }
    #[tokio::test]
    async fn three_claim_scopes_preserve_each_root_grant_and_reject_rebinding() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://fixture@127.0.0.1/fixture")
            .unwrap();
        let scope = |task: &str, worker: &str| crate::launch_reservation::LaunchScope {
            task_id: task.into(),
            intent_id: format!("{task}-intent"),
            queue_id: format!("{task}-queue"),
            generation: format!("{task}-gen"),
            spec: LeaseSpec {
                repository: "repo".into(),
                base_revision: "a".repeat(40),
            },
            worker_id: worker.into(),
            catalog_sha256: "b".repeat(64),
        };
        let workers = vec![
            ("old".into(), "w1".into()),
            ("canary".into(), "w2".into()),
            ("real".into(), "w3".into()),
        ];
        let j = ClaimLeaseJournal::new_with_catalog_scopes(
            pool.clone(),
            workers.clone(),
            vec![scope("canary", "w2"), scope("real", "w3")],
        )
        .unwrap();
        assert_eq!(j.worker_for("old").unwrap(), "w1");
        assert_eq!(j.launch_for("canary").unwrap().worker_id, "w2");
        assert_eq!(j.launch_for("real").unwrap().worker_id, "w3");
        assert!(j.launch_for("old").is_err());
        assert!(
            ClaimLeaseJournal::new_with_catalog_scopes(pool, workers, vec![scope("canary", "w3")])
                .is_err()
        );
    }
    #[test]
    fn outbox_versions_only_real_transitions_including_rejected_expiry() {
        let mut s = state();
        let event = next_claim_event(None, &mut s, "initialize")
            .unwrap()
            .unwrap();
        assert_eq!((event.version, event.step_seq), (1, 0));
        assert_eq!(event.snapshot, claim_projection_snapshot(&s).unwrap());
        let before = s.clone();
        assert!(
            next_claim_event(Some(&before), &mut s, "no-change")
                .unwrap()
                .is_none()
        );
        claim_next(&mut s, "worker", shared::new_id(), 1000, 0).unwrap();
        assert_eq!(
            next_claim_event(Some(&before), &mut s, "claim")
                .unwrap()
                .unwrap()
                .version,
            2
        );
        let before = s.clone();
        assert!(claim_next(&mut s, "worker", shared::new_id(), 1000, 1000).is_err());
        let expired = next_claim_event(Some(&before), &mut s, "expiry")
            .unwrap()
            .unwrap();
        assert_eq!(expired.version, 3);
        assert_eq!(s.stage, LeaseStage::CoolingDown);
        s.version = i64::MAX as u64;
        assert!(next_claim_event(None, &mut s, "overflow").is_err());
    }
    #[test]
    fn sql_claim_events_withhold_lease_capabilities_and_unscanned_receipt_text() {
        let mut state = state();
        let token = shared::new_id();
        claim_next(&mut state, "sensitive-worker-label", token.clone(), 1000, 0).unwrap();
        let active = next_claim_event(None, &mut state, "active-event")
            .unwrap()
            .unwrap();
        let wire = serde_json::to_string(&active).unwrap();
        assert!(!wire.contains(&token) && !wire.contains("sensitive-worker-label"));
        for receipt in [
            shared::Receipt::Failed {
                exit_code: 1,
                stderr_tail: "SQL_UNSCANNED_STDERR_CANARY".into(),
            },
            shared::Receipt::Completed {
                sha: "b".repeat(40),
                diff: "SQL_UNSCANNED_DIFF_CANARY".into(),
                turn_count: 1,
                exit_code: 0,
                wall_time_ms: 1,
                spend_usd: 0.01,
            },
        ] {
            let mut state = state.clone();
            let lease = state.active.clone().unwrap();
            state.last_completion = Some(LeaseCompletion { lease, receipt });
            let event = next_claim_event(None, &mut state, "completion-event")
                .unwrap()
                .unwrap();
            let wire = serde_json::to_string(&event).unwrap();
            assert!(
                !wire.contains(&token)
                    && !wire.contains("SQL_UNSCANNED_")
                    && !wire.contains("sensitive-worker-label")
            );
            assert!(
                serde_json::to_string(&state)
                    .unwrap()
                    .contains("SQL_UNSCANNED_")
            );
        }
    }
    #[test]
    fn retained_history_preserves_original_keys_and_rejects_gaps_or_legacy_state() {
        let mut state = state();
        let mut history = ClaimEventHistory::default();
        let event = next_claim_event(None, &mut state, "original-invocation")
            .unwrap()
            .unwrap();
        history.append(event.clone()).unwrap();
        history.validate(Some(&state)).unwrap();
        assert_eq!(history.events[0], event);
        let legacy = ClaimEventHistory::default();
        assert!(legacy.validate(Some(&state)).is_err());
        let mut changed = history.clone();
        changed.events[0].version = 2;
        assert!(changed.validate(Some(&state)).is_err());
        let mut changed = history.clone();
        changed.events[0].snapshot["base_revision"] = "c".repeat(40).into();
        assert!(changed.validate(Some(&state)).is_err());
        assert!(history.validate(None).is_err());
    }
    #[test]
    fn retained_history_never_evicts_at_count_or_byte_limit() {
        let mut state = state();
        let mut history = ClaimEventHistory::default();
        for index in 0..MAX_CLAIM_HISTORY_EVENTS {
            let event = next_claim_event(None, &mut state, &format!("invocation-{index}"))
                .unwrap()
                .unwrap();
            history.append(event).unwrap();
        }
        history.validate(Some(&state)).unwrap();
        let retained = history.clone();
        let event = next_claim_event(None, &mut state, "one-too-many")
            .unwrap()
            .unwrap();
        assert!(history.append(event).is_err());
        assert_eq!(history, retained);
        let mut huge = retained.events[0].clone();
        huge.snapshot["oversized"] = "x".repeat(MAX_CLAIM_HISTORY_BYTES).into();
        let mut empty = ClaimEventHistory::default();
        assert!(empty.append(huge).is_err());
        assert!(empty.events.is_empty());
    }
    #[test]
    fn duplicate_event_key_or_wrong_next_version_cannot_enter_history() {
        let mut state = state();
        let mut history = ClaimEventHistory::default();
        history
            .append(
                next_claim_event(None, &mut state, "same-key")
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        let duplicate = next_claim_event(None, &mut state, "same-key")
            .unwrap()
            .unwrap();
        assert!(history.append(duplicate).is_err());
        let mut wrong = history.events[0].clone();
        wrong.invocation_id = "other".into();
        wrong.version = 3;
        wrong.snapshot["version"] = 3.into();
        assert!(history.append(wrong).is_err());
        assert_eq!(history.events.len(), 1);
    }
    #[test]
    fn conditional_first_claim_cannot_reassign_after_expiry() {
        let mut s = state();
        conditional_claim(
            &mut s,
            "worker",
            shared::new_id(),
            &ClaimRequest {
                ttl_ms: 1000,
                expected_previous_attempt: Some(0),
            },
            0,
        )
        .unwrap();
        let snapshot = s.clone();
        assert!(
            conditional_claim(
                &mut s,
                "worker",
                shared::new_id(),
                &ClaimRequest {
                    ttl_ms: 1000,
                    expected_previous_attempt: Some(0)
                },
                999_999
            )
            .is_err()
        );
        assert_eq!(
            s, snapshot,
            "stale condition must fail before expiry mutation"
        );
        let old: ClaimRequest = serde_json::from_str(r#"{"ttl_ms":1000}"#).unwrap();
        assert_eq!(old.expected_previous_attempt, None);
    }
    #[test]
    fn exclusive_claim_and_wrong_worker_fencing() {
        let mut s = state();
        let lease = claim_next(&mut s, "worker", shared::new_id(), 1000, 0).unwrap();
        assert_eq!(lease.attempt, 1);
        assert!(claim_next(&mut s, "worker", shared::new_id(), 1000, 1).is_err());
        let snapshot = s.clone();
        assert!(complete_lease(&mut s, "other", proof(&lease), receipt(), 10).is_err());
        assert_eq!(s, snapshot);
    }
    #[test]
    fn expiry_cooldown_reassignment_rejects_stale_receipt() {
        let mut s = state();
        let old = claim_next(&mut s, "worker", shared::new_id(), 1000, 0).unwrap();
        assert!(claim_next(&mut s, "worker", shared::new_id(), 1000, 1000).is_err());
        assert_eq!(s.stage, LeaseStage::CoolingDown);
        assert_eq!(s.cooldown_until_ms, 3000);
        let new = claim_next(&mut s, "worker", shared::new_id(), 1000, 3000).unwrap();
        assert_eq!(new.attempt, 2);
        let snapshot = s.clone();
        assert!(complete_lease(&mut s, "worker", proof(&old), receipt(), 3001).is_err());
        assert_eq!(s, snapshot);
        complete_lease(&mut s, "worker", proof(&new), receipt(), 3010).unwrap();
        assert_eq!(s.stage, LeaseStage::Evaluating);
    }
    #[test]
    fn renewal_is_fenced_expiry_checked_and_hard_bounded() {
        let mut s = state();
        let lease = claim_next(&mut s, "worker", shared::new_id(), 1000, 0).unwrap();
        assert!(renew_lease(&mut s, "other", proof(&lease), 1000, 10).is_err());
        let renewed = renew_lease(&mut s, "worker", proof(&lease), MAX_LEASE_MS, 500).unwrap();
        assert_eq!(renewed.expires_at_ms, MAX_LEASE_MS);
        assert!(renew_lease(&mut s, "worker", proof(&lease), 1000, MAX_LEASE_MS).is_err());
    }
    #[test]
    fn attempt_limit_survives_serialization_and_never_resets() {
        let mut s = state();
        for attempt in 1..=crate::state::MAX_ATTEMPTS {
            let now = s.cooldown_until_ms;
            let lease = claim_next(&mut s, "worker", shared::new_id(), 1000, now).unwrap();
            assert_eq!(lease.attempt, attempt);
            complete_lease(
                &mut s,
                "worker",
                proof(&lease),
                shared::Receipt::Failed {
                    exit_code: 1,
                    stderr_tail: "fixture".into(),
                },
                now + 1,
            )
            .unwrap();
            s = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        }
        assert_eq!(s.stage, LeaseStage::Failed);
        assert!(claim_next(&mut s, "worker", shared::new_id(), 1000, 1_000_000).is_err());
    }
    #[test]
    fn duplicate_receipt_is_idempotent_but_changed_receipt_is_rejected() {
        let mut s = state();
        let lease = claim_next(&mut s, "worker", shared::new_id(), 1000, 0).unwrap();
        complete_lease(&mut s, "worker", proof(&lease), receipt(), 10).unwrap();
        let snapshot = s.clone();
        complete_lease(&mut s, "worker", proof(&lease), receipt(), 11).unwrap();
        assert_eq!(s, snapshot);
        assert!(
            complete_lease(
                &mut s,
                "worker",
                proof(&lease),
                shared::Receipt::Crashed {
                    signal: 9,
                    core_dumped: false
                },
                12
            )
            .is_err()
        );
        assert_eq!(s, snapshot);
    }
    #[test]
    fn inconsistent_active_attempt_or_stage_cannot_renew_or_complete() {
        for variant in 0..3 {
            let mut s = state();
            let lease = claim_next(&mut s, "worker", shared::new_id(), 1000, 0).unwrap();
            match variant {
                0 => s.stage = LeaseStage::Queued,
                1 => s.stage = LeaseStage::Failed,
                _ => s.attempts += 1,
            }
            let snapshot = s.clone();
            assert!(renew_lease(&mut s, "worker", proof(&lease), 100, 10).is_err());
            assert_eq!(s, snapshot);
            assert!(complete_lease(&mut s, "worker", proof(&lease), receipt(), 10).is_err());
            assert_eq!(s, snapshot);
        }
    }
    #[test]
    fn inconsistent_lease_state_cannot_be_reassigned_even_after_expiry() {
        for variant in 0..3 {
            let mut s = state();
            let lease = claim_next(&mut s, "worker", shared::new_id(), 1000, 0).unwrap();
            match variant {
                0 => s.stage = LeaseStage::Failed,
                1 => s.attempts += 1,
                _ => s.active = None,
            }
            let snapshot = s.clone();
            assert!(
                claim_next(
                    &mut s,
                    "worker",
                    shared::new_id(),
                    1000,
                    lease.expires_at_ms + 5000
                )
                .is_err()
            );
            assert_eq!(s, snapshot);
        }
    }
    #[test]
    fn duplicate_completion_requires_its_matching_terminal_stage() {
        for failed in [false, true] {
            let mut s = state();
            let lease = claim_next(&mut s, "worker", shared::new_id(), 1000, 0).unwrap();
            let result = if failed {
                shared::Receipt::Failed {
                    exit_code: 1,
                    stderr_tail: "failed".into(),
                }
            } else {
                receipt()
            };
            complete_lease(&mut s, "worker", proof(&lease), result.clone(), 10).unwrap();
            let legitimate = s.clone();
            complete_lease(&mut s, "worker", proof(&lease), result.clone(), 11).unwrap();
            assert_eq!(s, legitimate);
            for stage in [
                LeaseStage::Queued,
                LeaseStage::Leased,
                if failed {
                    LeaseStage::Evaluating
                } else {
                    LeaseStage::CoolingDown
                },
            ] {
                s.stage = stage;
                let snapshot = s.clone();
                assert!(
                    complete_lease(&mut s, "worker", proof(&lease), result.clone(), 11).is_err()
                );
                assert_eq!(s, snapshot);
            }
        }
    }
    #[test]
    fn completion_stage_checks_preserve_the_fail_closed_overflow_case() {
        let failure = shared::Receipt::Failed {
            exit_code: 1,
            stderr_tail: "failure".into(),
        };
        assert!(completion_stage_matches(
            &failure,
            1,
            &LeaseStage::CoolingDown
        ));
        assert!(completion_stage_matches(&failure, 1, &LeaseStage::Failed));
        assert!(!completion_stage_matches(
            &failure,
            1,
            &LeaseStage::Evaluating
        ));
        assert!(completion_stage_matches(
            &failure,
            crate::state::MAX_ATTEMPTS,
            &LeaseStage::Failed
        ));
        assert!(!completion_stage_matches(
            &failure,
            crate::state::MAX_ATTEMPTS,
            &LeaseStage::CoolingDown
        ));
        assert!(completion_stage_matches(
            &receipt(),
            1,
            &LeaseStage::Evaluating
        ));
        assert!(!completion_stage_matches(
            &receipt(),
            1,
            &LeaseStage::Failed
        ));
    }
    #[test]
    fn invalid_ttl_token_revision_and_spend_fail_closed() {
        assert!(
            new_lease_state(
                "task",
                LeaseSpec {
                    repository: "repo".into(),
                    base_revision: "short".into()
                }
            )
            .is_err()
        );
        let mut s = state();
        for ttl in [0, MAX_LEASE_MS + 1, u64::MAX] {
            assert!(claim_next(&mut s, "worker", shared::new_id(), ttl, 0).is_err());
        }
        assert!(claim_next(&mut s, "worker", "bad-token".into(), 1000, 0).is_err());
        assert!(claim_next(&mut s, "worker", shared::new_id(), 1000, u64::MAX).is_err());
        let lease = claim_next(&mut s, "worker", shared::new_id(), 1000, 0).unwrap();
        let snapshot = s.clone();
        let mut bad = receipt();
        if let shared::Receipt::Completed { spend_usd, .. } = &mut bad {
            *spend_usd = f64::NAN;
        }
        assert!(complete_lease(&mut s, "worker", proof(&lease), bad, 10).is_err());
        assert_eq!(s, snapshot);
    }

    #[test]
    fn active_state_roundtrip_preserves_fence_and_expired_receipt_is_denied() {
        let mut s = state();
        let lease = claim_next(&mut s, "worker", shared::new_id(), 1000, 100).unwrap();
        s = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        let snapshot = s.clone();
        let forged = LeaseProof {
            attempt: lease.attempt,
            token: shared::new_id(),
        };
        assert!(complete_lease(&mut s, "worker", forged, receipt(), 101).is_err());
        assert_eq!(s, snapshot);
        assert_eq!(
            complete_lease(&mut s, "worker", proof(&lease), receipt(), 1100)
                .unwrap_err()
                .code(),
            410
        );
        assert_eq!(s.stage, LeaseStage::CoolingDown);
        assert!(s.last_completion.is_none());
    }
}

/// Maximum individual lease and hard lifetime of a single attempt. Renewal never extends
/// an attempt beyond this boundary; it is NOT proof that the external process was killed.
pub const MAX_LEASE_MS: u64 = 300_000;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseSpec {
    pub repository: String,
    pub base_revision: String,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LeaseStage {
    Queued,
    Leased,
    CoolingDown,
    Evaluating,
    Failed,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseProof {
    pub attempt: u32,
    pub token: String,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveLease {
    pub worker_id: String,
    pub attempt: u32,
    pub token: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub hard_deadline_ms: u64,
}
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LeaseCompletion {
    pub lease: ActiveLease,
    pub receipt: shared::Receipt,
}
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ClaimLeaseState {
    pub version: u64,
    pub work_package_id: String,
    pub spec: LeaseSpec,
    pub stage: LeaseStage,
    pub attempts: u32,
    pub cooldown_until_ms: u64,
    pub active: Option<ActiveLease>,
    pub last_completion: Option<LeaseCompletion>,
}

/// The historical worker claim is retained alongside the additive root outcome.
/// Neither this read model nor SQL projection establishes human approval.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootFinalizationStatus {
    pub task_id: String,
    pub generation: String,
    pub finalization: Option<crate::root_finalization::Envelope>,
    pub legacy_claim: Option<HistoricalClaimSummary>,
    pub legacy_claim_is_historical: bool,
    pub approval_not_established_by_finalization: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalClaimSummary {
    pub version: u64,
    pub stage: LeaseStage,
    pub attempts: u32,
}
impl From<ClaimLeaseState> for HistoricalClaimSummary {
    fn from(claim: ClaimLeaseState) -> Self {
        Self {
            version: claim.version,
            stage: claim.stage,
            attempts: claim.attempts,
        }
    }
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimRequest {
    pub ttl_ms: u64,
    /// Compare under this object's exclusive mutation lock, before expiry or claim changes.
    /// Queue consumers use Some(0): expiry alone must never authorize reassignment.
    #[serde(default)]
    pub expected_previous_attempt: Option<u32>,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenewRequest {
    pub proof: LeaseProof,
    pub ttl_ms: u64,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteLeaseRequest {
    pub proof: LeaseProof,
    pub receipt: shared::Receipt,
}

/// Retention is bounded and never evicted. Exhaustion stops further mutations; archival or
/// legacy-state migration requires an explicit future protocol, never an invented history.
pub const MAX_CLAIM_HISTORY_EVENTS: usize = 128;
pub const MAX_CLAIM_HISTORY_BYTES: usize = 512 * 1024;
const CLAIM_HISTORY_KEY: &str = "claim_event_history_v1";
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimEventHistory {
    events: Vec<crate::projection::ClaimTransitionEvent>,
}
impl ClaimEventHistory {
    fn append(
        &mut self,
        event: crate::projection::ClaimTransitionEvent,
    ) -> Result<(), TerminalError> {
        if self.events.len() >= MAX_CLAIM_HISTORY_EVENTS
            || event.version != self.events.len() as u64 + 1
            || self.events.iter().any(|old| {
                (old.invocation_id.as_str(), old.step_seq)
                    == (event.invocation_id.as_str(), event.step_seq)
            })
        {
            return Err(lease_error(
                409,
                "claim event history exhausted or inconsistent; no eviction permitted",
            ));
        }
        event
            .validate()
            .map_err(|_| lease_error(409, "invalid retained claim event"))?;
        let mut candidate = self.clone();
        candidate.events.push(event);
        candidate.check_bounds()?;
        *self = candidate;
        Ok(())
    }
    fn check_bounds(&self) -> Result<(), TerminalError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|_| lease_error(500, "history serialization failed"))?;
        if self.events.len() > MAX_CLAIM_HISTORY_EVENTS || bytes.len() > MAX_CLAIM_HISTORY_BYTES {
            return Err(lease_error(
                409,
                "claim history retention limit reached; no eviction permitted",
            ));
        }
        Ok(())
    }
    fn validate(&self, state: Option<&ClaimLeaseState>) -> Result<(), TerminalError> {
        self.check_bounds()?;
        let Some(state) = state else {
            return if self.events.is_empty() {
                Ok(())
            } else {
                Err(lease_error(409, "orphaned claim history"))
            };
        };
        if self.events.is_empty() || state.version != self.events.len() as u64 {
            return Err(lease_error(
                409,
                "claim history unavailable or incomplete; legacy backfill is not supported",
            ));
        }
        let mut identities = std::collections::BTreeSet::new();
        for (index, event) in self.events.iter().enumerate() {
            event
                .validate()
                .map_err(|_| lease_error(409, "invalid retained claim event"))?;
            let snapshot: crate::projection::ClaimProjectionSnapshot =
                serde_json::from_value(event.snapshot.clone())
                    .map_err(|_| lease_error(409, "invalid retained claim snapshot"))?;
            if event.version != index as u64 + 1
                || event.work_package_id != state.work_package_id
                || snapshot.base_revision != state.spec.base_revision
                || !identities.insert((&event.invocation_id, event.step_seq))
                || serde_json::to_value(&snapshot)
                    .map_err(|_| lease_error(500, "snapshot serialization failed"))?
                    != event.snapshot
            {
                return Err(lease_error(409, "claim history chain or identity mismatch"));
            }
        }
        if self.events.last().map(|event| &event.snapshot)
            != Some(&claim_projection_snapshot(state)?)
        {
            return Err(lease_error(
                409,
                "claim history does not match authoritative state",
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimReexportReport {
    pub work_package_id: String,
    pub events: u64,
    pub latest_version: u64,
    pub quarantined: bool,
}

/// NOT REGISTERED: durable claim state for a single configured worker adapter. Configuration
/// is not per-request authority. A future private adapter must authenticate every worker
/// connection before forwarding calls, and a separate trusted scheduler must initialize the
/// package spec. No request payload can override worker identity. This object does not launch
/// processes, prove prior-process termination, or dispatch a DAG. Each mutation journals a
/// synchronously retried outbox delivery; Postgres is never read to authorize a claim.
pub struct ClaimLeaseJournal {
    worker_id: String,
    projection_pool: sqlx::PgPool,
    launch_scopes: Vec<crate::launch_reservation::LaunchScope>,
    worker_scopes: Option<Vec<(String, String)>>,
}
impl ClaimLeaseJournal {
    pub fn new_for_private_ingress(
        worker_id: String,
        projection_pool: sqlx::PgPool,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            canonical_lease_text(&worker_id),
            "invalid configured worker ID"
        );
        Ok(Self {
            worker_id,
            projection_pool,
            launch_scopes: Vec::new(),
            worker_scopes: None,
        })
    }

    /// The scope must come from protected deployment configuration, never the request.
    pub fn new_with_root_launch_scope(
        worker_id: String,
        projection_pool: sqlx::PgPool,
        scope: crate::launch_reservation::LaunchScope,
    ) -> anyhow::Result<Self> {
        scope.validate()?;
        anyhow::ensure!(scope.worker_id == worker_id, "launch worker scope mismatch");
        let mut journal = Self::new_for_private_ingress(worker_id, projection_pool)?;
        journal.launch_scopes.push(scope);
        Ok(journal)
    }
    pub fn new_with_preserved_launch_scope(
        worker_id: String,
        pool: sqlx::PgPool,
        scope: crate::launch_reservation::LaunchScope,
        old_task: String,
        old_worker: String,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            canonical_lease_text(&old_task)
                && canonical_lease_text(&old_worker)
                && old_task != scope.task_id,
            "claim scopes collide or are invalid"
        );
        let new_task = scope.task_id.clone();
        let mut journal = Self::new_with_root_launch_scope(worker_id.clone(), pool, scope)?;
        journal.worker_scopes = Some(vec![(old_task, old_worker), (new_task, worker_id)]);
        Ok(journal)
    }
    pub fn new_with_catalog_scopes(
        pool: sqlx::PgPool,
        workers: Vec<(String, String)>,
        scopes: Vec<crate::launch_reservation::LaunchScope>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !workers.is_empty() && workers.len() <= 16 && scopes.len() <= workers.len(),
            "invalid claim scopes"
        );
        let mut keys = std::collections::BTreeSet::new();
        for (task, worker) in &workers {
            anyhow::ensure!(
                canonical_lease_text(task) && canonical_lease_text(worker) && keys.insert(task),
                "claim scopes collide or invalid"
            );
        }
        let mut launches = std::collections::BTreeSet::new();
        let mut generations = std::collections::BTreeSet::new();
        for scope in &scopes {
            scope.validate()?;
            anyhow::ensure!(
                launches.insert(&scope.task_id)
                    && generations.insert(&scope.generation)
                    && workers
                        .iter()
                        .any(|(task, worker)| task == &scope.task_id && worker == &scope.worker_id),
                "launch scope mismatch"
            );
        }
        Ok(Self {
            worker_id: workers[0].1.clone(),
            projection_pool: pool,
            launch_scopes: scopes,
            worker_scopes: Some(workers),
        })
    }
    fn worker_for(&self, key: &str) -> Result<&str, TerminalError> {
        match &self.worker_scopes {
            None => Ok(&self.worker_id),
            Some(scopes) => scopes
                .iter()
                .find(|(task, _)| task == key)
                .map(|(_, worker)| worker.as_str())
                .ok_or_else(|| lease_error(403, "claim outside root catalog")),
        }
    }
    fn launch_for(
        &self,
        key: &str,
    ) -> Result<&crate::launch_reservation::LaunchScope, TerminalError> {
        self.launch_scopes
            .iter()
            .find(|scope| scope.task_id == key)
            .ok_or_else(|| lease_error(403, "launch scope unavailable"))
    }
}

#[restate_sdk::object]
impl ClaimLeaseJournal {
    #[handler]
    async fn initialize(
        &self,
        ctx: ObjectContext<'_>,
        spec: restate_sdk::serde::Json<LeaseSpec>,
    ) -> HandlerResult<restate_sdk::serde::Json<ClaimLeaseState>> {
        let _admission = crate::registry_journal_gate::enter_production().map_err(|_| {
            TerminalError::new_with_code(503, "registry transition blocks mutations")
        })?;
        use restate_sdk::serde::Json;
        let _ = self.worker_for(ctx.key())?;
        ensure_launch_unreserved(&ctx).await?;
        ensure_projection_healthy(&ctx).await?;
        let mut requested = new_lease_state(ctx.key(), spec.0)?;
        if let Some(existing) = ctx.get::<Json<ClaimLeaseState>>("claim").await? {
            if existing.0.spec != requested.spec || existing.0.work_package_id != ctx.key() {
                return Err(lease_error(
                    409,
                    "work package already has a different immutable spec",
                )
                .into());
            }
            load_claim_history(&ctx, Some(&existing.0)).await?;
            return Ok(existing);
        }
        persist_claim_transition(&ctx, &self.projection_pool, None, &mut requested).await?;
        Ok(Json(requested))
    }

    #[handler]
    async fn claim(
        &self,
        ctx: ObjectContext<'_>,
        request: restate_sdk::serde::Json<ClaimRequest>,
    ) -> HandlerResult<restate_sdk::serde::Json<ActiveLease>> {
        let _admission = crate::registry_journal_gate::enter_production().map_err(|_| {
            TerminalError::new_with_code(503, "registry transition blocks mutations")
        })?;
        use restate_sdk::serde::Json;
        let worker = self.worker_for(ctx.key())?;
        ensure_launch_unreserved(&ctx).await?;
        let mut state = load_claim(&ctx).await?;
        let before = state.clone();
        let now = ctx.run(lease_clock_millis).await?;
        let token = ctx.run(|| async { Ok(shared::new_id()) }).await?;
        let result = conditional_claim(&mut state, worker, token, &request.0, now);
        // Persist expiry/cooldown transitions even if this request is refused.
        persist_claim_transition(&ctx, &self.projection_pool, Some(&before), &mut state).await?;
        result.map(Json).map_err(Into::into)
    }

    #[handler]
    async fn renew(
        &self,
        ctx: ObjectContext<'_>,
        request: restate_sdk::serde::Json<RenewRequest>,
    ) -> HandlerResult<restate_sdk::serde::Json<ActiveLease>> {
        let _admission = crate::registry_journal_gate::enter_production().map_err(|_| {
            TerminalError::new_with_code(503, "registry transition blocks mutations")
        })?;
        use restate_sdk::serde::Json;
        let worker = self.worker_for(ctx.key())?;
        ensure_launch_unreserved(&ctx).await?;
        let mut state = load_claim(&ctx).await?;
        let before = state.clone();
        let now = ctx.run(lease_clock_millis).await?;
        let result = renew_lease(&mut state, worker, request.0.proof, request.0.ttl_ms, now);
        persist_claim_transition(&ctx, &self.projection_pool, Some(&before), &mut state).await?;
        result.map(Json).map_err(Into::into)
    }

    #[handler]
    async fn complete(
        &self,
        ctx: ObjectContext<'_>,
        request: restate_sdk::serde::Json<CompleteLeaseRequest>,
    ) -> HandlerResult<restate_sdk::serde::Json<ClaimLeaseState>> {
        let _admission = crate::registry_journal_gate::enter_production().map_err(|_| {
            TerminalError::new_with_code(503, "registry transition blocks mutations")
        })?;
        use restate_sdk::serde::Json;
        let worker = self.worker_for(ctx.key())?;
        ensure_launch_unreserved(&ctx).await?;
        let mut state = load_claim(&ctx).await?;
        let before = state.clone();
        let now = ctx.run(lease_clock_millis).await?;
        let result = complete_lease(&mut state, worker, request.0.proof, request.0.receipt, now);
        persist_claim_transition(&ctx, &self.projection_pool, Some(&before), &mut state).await?;
        result?;
        Ok(Json(state))
    }

    /// Single-use reservation in the same exclusive claim journal. No clearing handler
    /// exists until authenticated root closure and engine reconciliation are implemented.
    #[handler]
    async fn reserve_launch(
        &self,
        ctx: ObjectContext<'_>,
        proof: restate_sdk::serde::Json<LeaseProof>,
    ) -> HandlerResult<restate_sdk::serde::Json<crate::launch_reservation::LaunchReservation>> {
        let _admission = crate::registry_journal_gate::enter_production().map_err(|_| {
            TerminalError::new_with_code(503, "registry transition blocks mutations")
        })?;
        use restate_sdk::serde::Json;
        let _ = self.worker_for(ctx.key())?;
        let scope = self.launch_for(ctx.key())?;
        let state = load_claim(&ctx).await?;
        let now = ctx.run(lease_clock_millis).await?;
        let grant = crate::launch_reservation::reserve(scope, &state, &proof.0, now)
            .map_err(|_| lease_error(409, "launch reservation denied"))?;
        if let Some(old) = ctx
            .get::<Json<crate::launch_reservation::LaunchReservation>>("launch_reservation_v1")
            .await?
        {
            if old.0 != grant {
                return Err(lease_error(409, "launch reservation conflict").into());
            }
            return Ok(old);
        }
        ctx.set("launch_reservation_v1", Json(grant.clone()));
        Ok(Json(grant))
    }

    /// The root-only adapter supplies no lease fields. The exclusive claim object
    /// derives the proof from its own current state, then journals the same permanent
    /// reservation used by reserve_launch. This is not a root-consumption receipt.
    #[handler]
    async fn reserve_current_launch(
        &self,
        ctx: ObjectContext<'_>,
    ) -> HandlerResult<restate_sdk::serde::Json<crate::launch_reservation::LaunchReservation>> {
        let _admission = crate::registry_journal_gate::enter_production().map_err(|_| {
            TerminalError::new_with_code(503, "registry transition blocks mutations")
        })?;
        use restate_sdk::serde::Json;
        let _ = self.worker_for(ctx.key())?;
        let scope = self.launch_for(ctx.key())?;
        let state = load_claim(&ctx).await?;
        let active = state
            .active
            .as_ref()
            .ok_or_else(|| lease_error(409, "active claim unavailable"))?;
        let proof = LeaseProof {
            attempt: active.attempt,
            token: active.token.clone(),
        };
        let now = ctx.run(lease_clock_millis).await?;
        let grant = crate::launch_reservation::reserve(scope, &state, &proof, now)
            .map_err(|_| lease_error(409, "launch reservation denied"))?;
        if let Some(old) = ctx
            .get::<Json<crate::launch_reservation::LaunchReservation>>("launch_reservation_v1")
            .await?
        {
            if old.0 != grant {
                return Err(lease_error(409, "launch reservation conflict").into());
            }
            return Ok(old);
        }
        ctx.set("launch_reservation_v1", Json(grant.clone()));
        Ok(Json(grant))
    }

    /// Root ingress supplies immutable, independently verified evidence. Private namespace
    /// isolation and accepted peer authentication must be established before registration.
    /// This handler only journals a decision; it performs no external effects.
    #[handler]
    async fn finalize_root(
        &self,
        ctx: ObjectContext<'_>,
        request: restate_sdk::serde::Json<crate::root_finalization::RootFinalizationRequest>,
    ) -> HandlerResult<restate_sdk::serde::Json<crate::root_finalization::Envelope>> {
        let _admission = crate::registry_journal_gate::enter_production().map_err(|_| {
            TerminalError::new_with_code(503, "registry transition blocks mutations")
        })?;
        use crate::root_finalization::{Envelope, decide, validate};
        use restate_sdk::serde::Json;
        let scope = self.launch_for(ctx.key())?;
        let authorization = crate::root_finalization_authorization::Authorization {
            schema: 1,
            task_id: scope.task_id.clone(),
            generation: scope.generation.clone(),
            request_sha256: crate::root_finalization::record_digest(&request.0)
                .map_err(|_| lease_error(400, "invalid finalization encoding"))?,
        };
        let authorized = ctx
            .run(move || async move {
                Ok(
                    crate::root_finalization_authorization::read_authorization(&authorization)
                        .is_ok(),
                )
            })
            .await?;
        if !authorized {
            return Err(lease_error(403, "root authorization missing or invalid").into());
        }
        let stored = ctx
            .get::<Json<crate::launch_reservation::LaunchReservation>>("launch_reservation_v1")
            .await?
            .ok_or_else(|| lease_error(409, "root finalization requires reservation"))?;
        let claim = load_claim(&ctx).await?;
        let validated = validate(request.0, &stored.0, &claim, scope)
            .map_err(|_| lease_error(409, "root finalization binding denied"))?;
        let existing = ctx.get::<Json<Envelope>>("root_finalization_v1").await?;
        let envelope = decide(existing.as_ref().map(|v| &v.0), validated)
            .map_err(|_| lease_error(409, "root finalization conflict"))?;
        if existing.is_none() {
            ctx.set("root_finalization_v1", Json(envelope.clone()));
        }
        Ok(Json(envelope))
    }

    #[handler]
    async fn root_finalization_status(
        &self,
        ctx: SharedObjectContext<'_>,
    ) -> HandlerResult<restate_sdk::serde::Json<RootFinalizationStatus>> {
        use restate_sdk::serde::Json;
        let scope = self.launch_for(ctx.key())?;
        let reserved = ctx
            .get::<Json<crate::launch_reservation::LaunchReservation>>("launch_reservation_v1")
            .await?
            .is_some();
        Ok(Json(RootFinalizationStatus {
            task_id: scope.task_id.clone(),
            generation: scope.generation.clone(),
            finalization: ctx
                .get::<Json<crate::root_finalization::Envelope>>("root_finalization_v1")
                .await?
                .map(|v| v.0),
            legacy_claim: ctx
                .get::<Json<ClaimLeaseState>>("claim")
                .await?
                .map(|v| v.0.into()),
            legacy_claim_is_historical: reserved,
            approval_not_established_by_finalization: true,
        }))
    }

    /// Serialize an eligibility read with projection quarantine updates. Shared status
    /// is informational; this result still is not human approval or a Git mutation.
    #[handler]
    async fn root_finalization_eligibility(
        &self,
        ctx: ObjectContext<'_>,
    ) -> HandlerResult<restate_sdk::serde::Json<crate::root_finalization::Envelope>> {
        let _admission = crate::registry_journal_gate::enter_production().map_err(|_| {
            TerminalError::new_with_code(503, "registry transition blocks mutations")
        })?;
        use crate::root_finalization::{Envelope, Evidence, ExportState, decide, validate};
        use restate_sdk::serde::Json;
        let scope = self.launch_for(ctx.key())?;
        let envelope = ctx
            .get::<Json<Envelope>>("root_finalization_v1")
            .await?
            .ok_or_else(|| lease_error(409, "root finalization not eligible"))?
            .0;
        if envelope.export == ExportState::Quarantined
            || !matches!(&envelope.record.evidence, Evidence::EvaluatedPass { .. })
        {
            return Err(lease_error(409, "root finalization not eligible").into());
        }
        let reservation = ctx
            .get::<Json<crate::launch_reservation::LaunchReservation>>("launch_reservation_v1")
            .await?
            .ok_or_else(|| lease_error(409, "root reservation missing"))?;
        let claim = load_claim(&ctx).await?;
        let verified = validate(envelope.record.clone(), &reservation.0, &claim, scope)
            .and_then(|v| decide(Some(&envelope), v))
            .map_err(|_| lease_error(409, "root finalization integrity denied"))?;
        Ok(Json(verified))
    }

    /// Explicit idempotent SQL recovery. Each invocation rechecks the destination even
    /// after previous delivery; quarantined integrity conflicts cannot be cleared here.
    #[handler]
    async fn reexport_root_finalization(
        &self,
        ctx: ObjectContext<'_>,
    ) -> HandlerResult<restate_sdk::serde::Json<crate::root_finalization::Envelope>> {
        let _admission = crate::registry_journal_gate::enter_production().map_err(|_| {
            TerminalError::new_with_code(503, "registry transition blocks mutations")
        })?;
        use crate::root_finalization::{Envelope, ExportState};
        use crate::root_finalization_projection::Delivery;
        use restate_sdk::serde::Json;
        let _ = self.launch_for(ctx.key())?;
        let mut envelope = ctx
            .get::<Json<Envelope>>("root_finalization_v1")
            .await?
            .ok_or_else(|| lease_error(404, "root finalization unavailable"))?
            .0;
        if envelope.export == ExportState::Quarantined {
            return Ok(Json(envelope));
        }
        let pool = self.projection_pool.clone();
        let event = envelope.clone();
        let delivery = ctx
            .run(move || async move {
                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    crate::root_finalization_projection::export(&pool, &event),
                )
                .await
                .unwrap_or(Delivery::Pending);
                Ok(Json(result))
            })
            .await?;
        envelope.export = match delivery.0 {
            Delivery::Current => ExportState::Current,
            Delivery::Pending => ExportState::Pending,
            Delivery::IntegrityConflict => ExportState::Quarantined,
        };
        ctx.set("root_finalization_v1", Json(envelope.clone()));
        Ok(Json(envelope))
    }

    /// Explicit fresh recovery invocation: completed delivery runs do NOT rerun after SQL
    /// loss. Private ingress only, fixed configured target pool, no caller-selected database.
    /// Recovery does not clear an integrity quarantine or resume paused worker execution.
    #[handler]
    async fn reexport_claim_history(
        &self,
        ctx: ObjectContext<'_>,
    ) -> HandlerResult<restate_sdk::serde::Json<ClaimReexportReport>> {
        let _admission = crate::registry_journal_gate::enter_production().map_err(|_| {
            TerminalError::new_with_code(503, "registry transition blocks mutations")
        })?;
        use restate_sdk::serde::Json;
        let _ = self.worker_for(ctx.key())?;
        let state = ctx
            .get::<Json<ClaimLeaseState>>("claim")
            .await?
            .ok_or_else(|| lease_error(404, "work package not initialized"))?
            .0;
        let history = load_claim_history(&ctx, Some(&state)).await?;
        let quarantined = ctx
            .get::<Json<crate::projection::ClaimTransitionEvent>>("projection_quarantine")
            .await?
            .is_some();
        let events = history.events.clone();
        let pool = self.projection_pool.clone();
        let result = ctx
            .run(|| async move {
                crate::projection::reexport_claim_events(&pool, &events)
                    .await
                    .map_err(projection_handler_error)
            })
            .await;
        if let Err(error) = result {
            // Deterministic corruption fences mutations even if this recovery invocation
            // was the first observer. Repair/re-export never clears this quarantine.
            if let Some(event) = history.events.last() {
                ctx.set("projection_quarantine", Json(event.clone()));
            }
            return Err(error.into());
        }
        Ok(Json(ClaimReexportReport {
            work_package_id: state.work_package_id,
            events: history.events.len() as u64,
            latest_version: state.version,
            quarantined,
        }))
    }

    #[handler]
    async fn status(
        &self,
        ctx: SharedObjectContext<'_>,
    ) -> HandlerResult<restate_sdk::serde::Json<Option<ClaimLeaseState>>> {
        use restate_sdk::serde::Json;
        let _ = self.worker_for(ctx.key())?;
        Ok(Json(
            ctx.get::<Json<ClaimLeaseState>>("claim")
                .await?
                .map(|s| s.0),
        ))
    }
}

async fn ensure_launch_unreserved(ctx: &ObjectContext<'_>) -> HandlerResult<()> {
    use restate_sdk::serde::Json;
    let reserved = ctx
        .get::<Json<crate::launch_reservation::LaunchReservation>>("launch_reservation_v1")
        .await?;
    crate::launch_reservation::allow_mutation(reserved.as_ref().map(|r| &r.0))
        .map_err(|_| lease_error(409, "launch reserved; closure and reconciliation required"))?;
    Ok(())
}

/// Status is a stored snapshot, not a current wall-clock lease-validity assertion. Mutating
/// handlers enforce expiry. A terminal projection fault preserves its event and fences all
/// subsequent mutations pending an explicit repair procedure (not yet exposed).
async fn ensure_projection_healthy(ctx: &ObjectContext<'_>) -> HandlerResult<()> {
    if ctx
        .get::<restate_sdk::serde::Json<crate::projection::ClaimTransitionEvent>>(
            "projection_quarantine",
        )
        .await?
        .is_some()
    {
        return Err(lease_error(
            503,
            "claim projection quarantined; operator repair required",
        )
        .into());
    }
    Ok(())
}

fn claim_projection_snapshot(state: &ClaimLeaseState) -> Result<serde_json::Value, TerminalError> {
    use crate::projection::{
        ClaimProjectionSnapshot, ClaimProjectionStage, CompletionProjectionSummary,
        LeaseProjectionSummary, ReceiptProjectionSummary,
    };
    let lease = |active: &ActiveLease| LeaseProjectionSummary {
        attempt: active.attempt,
        issued_at_ms: active.issued_at_ms,
        expires_at_ms: active.expires_at_ms,
        hard_deadline_ms: active.hard_deadline_ms,
    };
    let snapshot = ClaimProjectionSnapshot {
        schema_version: 2,
        version: state.version,
        work_package_id: state.work_package_id.clone(),
        base_revision: state.spec.base_revision.clone(),
        stage: match state.stage {
            LeaseStage::Queued => ClaimProjectionStage::Queued,
            LeaseStage::Leased => ClaimProjectionStage::Leased,
            LeaseStage::CoolingDown => ClaimProjectionStage::CoolingDown,
            LeaseStage::Evaluating => ClaimProjectionStage::Evaluating,
            LeaseStage::Failed => ClaimProjectionStage::Failed,
        },
        attempts: state.attempts,
        cooldown_until_ms: state.cooldown_until_ms,
        active: state.active.as_ref().map(lease),
        last_completion: state.last_completion.as_ref().map(|completion| {
            CompletionProjectionSummary {
                lease: lease(&completion.lease),
                receipt: ReceiptProjectionSummary::from(&completion.receipt),
            }
        }),
    };
    serde_json::to_value(snapshot)
        .map_err(|_| lease_error(500, "safe claim snapshot serialization failed"))
}

fn next_claim_event(
    before: Option<&ClaimLeaseState>,
    state: &mut ClaimLeaseState,
    invocation_id: &str,
) -> Result<Option<crate::projection::ClaimTransitionEvent>, TerminalError> {
    if before == Some(state) {
        return Ok(None);
    }
    let version = state
        .version
        .checked_add(1)
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or_else(|| lease_error(500, "claim version exhausted"))?;
    state.version = version;
    Ok(Some(crate::projection::ClaimTransitionEvent {
        invocation_id: invocation_id.into(),
        // Exactly one outbox step per mutating invocation. This value is stable across retries.
        step_seq: 0,
        work_package_id: state.work_package_id.clone(),
        version,
        snapshot: claim_projection_snapshot(state)?,
    }))
}

async fn persist_claim_transition(
    ctx: &ObjectContext<'_>,
    pool: &sqlx::PgPool,
    before: Option<&ClaimLeaseState>,
    state: &mut ClaimLeaseState,
) -> HandlerResult<()> {
    use crate::projection::deliver_claim_event;
    use restate_sdk::serde::Json;
    let mut history = load_claim_history(ctx, before).await?;
    let mut candidate = state.clone();
    let Some(event) = next_claim_event(before, &mut candidate, ctx.invocation_id())? else {
        return Ok(());
    };
    history.append(event.clone())?;
    history.validate(Some(&candidate))?;
    // Both writes belong to this exclusive handler's durable execution. A partial crash
    // resumes the invocation before another exclusive mutation/re-export may run.
    ctx.set(CLAIM_HISTORY_KEY, Json(history));
    *state = candidate;
    ctx.set("claim", Json(state.clone()));
    let delivery = event.clone();
    let pool = pool.clone();
    // Immediately await the journaled side effect. A lost SQL acknowledgement causes safe
    // redelivery. Do not move this SQL call outside ctx.run or swallow database failures.
    let result = ctx
        .run(|| async move {
            deliver_claim_event(&pool, &delivery)
                .await
                .map_err(projection_handler_error)
        })
        .await;
    if let Err(error) = result {
        // ctx.run retries nonterminal errors; only terminal integrity errors reach here.
        ctx.set("projection_quarantine", Json(event));
        return Err(error.into());
    }
    Ok(())
}

fn projection_handler_error(error: crate::projection::ClaimProjectionError) -> HandlerError {
    match error {
        crate::projection::ClaimProjectionError::Conflict(_) => {
            lease_error(500, "claim projection integrity conflict").into()
        }
        crate::projection::ClaimProjectionError::Database(error) => HandlerError::from(error),
    }
}
async fn load_claim_history(
    ctx: &ObjectContext<'_>,
    state: Option<&ClaimLeaseState>,
) -> HandlerResult<ClaimEventHistory> {
    let history = ctx
        .get::<restate_sdk::serde::Json<ClaimEventHistory>>(CLAIM_HISTORY_KEY)
        .await?
        .map(|h| h.0)
        .unwrap_or_default();
    history.validate(state)?;
    Ok(history)
}
async fn load_claim(ctx: &ObjectContext<'_>) -> HandlerResult<ClaimLeaseState> {
    ensure_projection_healthy(ctx).await?;
    let state = ctx
        .get::<restate_sdk::serde::Json<ClaimLeaseState>>("claim")
        .await?
        .ok_or_else(|| lease_error(404, "work package not initialized"))?
        .0;
    load_claim_history(ctx, Some(&state)).await?;
    Ok(state)
}
async fn lease_clock_millis() -> HandlerResult<u64> {
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| lease_error(500, "system clock before epoch"))?;
    u64::try_from(time.as_millis()).map_err(|_| lease_error(500, "system clock overflow").into())
}
fn lease_error(code: u16, message: &str) -> TerminalError {
    TerminalError::new_with_code(code, message)
}
fn canonical_lease_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
fn full_revision(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn new_lease_state(key: &str, spec: LeaseSpec) -> Result<ClaimLeaseState, TerminalError> {
    if !canonical_lease_text(key)
        || !canonical_lease_text(&spec.repository)
        || !full_revision(&spec.base_revision)
    {
        return Err(lease_error(
            400,
            "invalid package key, repository or base revision",
        ));
    }
    Ok(ClaimLeaseState {
        version: 0,
        work_package_id: key.into(),
        spec,
        stage: LeaseStage::Queued,
        attempts: 0,
        cooldown_until_ms: 0,
        active: None,
        last_completion: None,
    })
}
fn ttl_expiry(now: u64, ttl: u64) -> Result<u64, TerminalError> {
    if ttl == 0 || ttl > MAX_LEASE_MS {
        return Err(lease_error(400, "invalid lease TTL"));
    }
    now.checked_add(ttl)
        .ok_or_else(|| lease_error(400, "lease deadline overflow"))
}
fn retry_or_fail(state: &mut ClaimLeaseState, at: u64) {
    state.active = None;
    if state.attempts >= crate::state::MAX_ATTEMPTS {
        state.stage = LeaseStage::Failed;
        return;
    }
    let backoff_ms = crate::state::backoff(state.attempts).as_millis() as u64;
    match at.checked_add(backoff_ms) {
        Some(deadline) => {
            state.cooldown_until_ms = deadline;
            state.stage = LeaseStage::CoolingDown;
        }
        None => {
            state.stage = LeaseStage::Failed;
        }
    }
}
fn expire_lease(state: &mut ClaimLeaseState, now: u64) {
    if let Some(expiry) = state.active.as_ref().map(|l| l.expires_at_ms)
        && now >= expiry
    {
        retry_or_fail(state, expiry);
    }
}
fn conditional_claim(
    state: &mut ClaimLeaseState,
    worker: &str,
    token: String,
    request: &ClaimRequest,
    now: u64,
) -> Result<ActiveLease, TerminalError> {
    if request
        .expected_previous_attempt
        .is_some_and(|expected| expected != state.attempts)
    {
        return Err(lease_error(409, "claim attempt precondition failed"));
    }
    claim_next(state, worker, token, request.ttl_ms, now)
}

fn claim_next(
    state: &mut ClaimLeaseState,
    worker: &str,
    token: String,
    ttl: u64,
    now: u64,
) -> Result<ActiveLease, TerminalError> {
    if match (&state.stage, &state.active) {
        (LeaseStage::Leased, Some(active)) => active.attempt != state.attempts,
        (LeaseStage::Leased, None) | (_, Some(_)) => true,
        _ => false,
    } {
        return Err(lease_error(409, "inconsistent lease state"));
    }
    if !canonical_lease_text(worker)
        || ulid::Ulid::from_string(&token).is_err()
        || ulid::Ulid::from_string(&token).is_ok_and(|n| n.to_string() != token)
    {
        return Err(lease_error(400, "invalid worker or lease token"));
    }
    let expiry = ttl_expiry(now, ttl)?;
    let hard_deadline = ttl_expiry(now, MAX_LEASE_MS)?;
    expire_lease(state, now);
    if state.active.is_some()
        || matches!(state.stage, LeaseStage::Evaluating | LeaseStage::Failed)
        || state.attempts >= crate::state::MAX_ATTEMPTS
        || now < state.cooldown_until_ms
    {
        return Err(lease_error(409, "work package unavailable or cooling down"));
    }
    state.attempts += 1;
    let lease = ActiveLease {
        worker_id: worker.into(),
        attempt: state.attempts,
        token,
        issued_at_ms: now,
        expires_at_ms: expiry,
        hard_deadline_ms: hard_deadline,
    };
    state.active = Some(lease.clone());
    state.stage = LeaseStage::Leased;
    Ok(lease)
}
fn matching_lease(
    state: &ClaimLeaseState,
    worker: &str,
    proof: &LeaseProof,
) -> Result<ActiveLease, TerminalError> {
    if state.stage != LeaseStage::Leased || state.attempts != proof.attempt {
        return Err(lease_error(409, "inconsistent lease stage or attempt"));
    }
    state
        .active
        .as_ref()
        .filter(|l| l.worker_id == worker && l.attempt == proof.attempt && l.token == proof.token)
        .cloned()
        .ok_or_else(|| lease_error(409, "stale or foreign lease"))
}
fn renew_lease(
    state: &mut ClaimLeaseState,
    worker: &str,
    proof: LeaseProof,
    ttl: u64,
    now: u64,
) -> Result<ActiveLease, TerminalError> {
    let requested = ttl_expiry(now, ttl)?;
    let mut lease = matching_lease(state, worker, &proof)?;
    if now < lease.issued_at_ms || now >= lease.expires_at_ms {
        expire_lease(state, now);
        return Err(lease_error(410, "lease expired or clock moved backwards"));
    }
    lease.expires_at_ms = lease
        .expires_at_ms
        .max(requested.min(lease.hard_deadline_ms));
    state.active = Some(lease.clone());
    Ok(lease)
}
fn complete_lease(
    state: &mut ClaimLeaseState,
    worker: &str,
    proof: LeaseProof,
    receipt: shared::Receipt,
    now: u64,
) -> Result<(), TerminalError> {
    if !receipt.spend_usd().is_finite()
        || receipt.spend_usd() < 0.0
        || matches!(&receipt, shared::Receipt::Completed { sha, .. } if !full_revision(sha))
    {
        return Err(lease_error(400, "invalid receipt revision or spend"));
    }
    if state.active.is_none()
        && completion_stage_matches(&receipt, state.attempts, &state.stage)
        && let Some(last) = &state.last_completion
        && last.lease.attempt == state.attempts
        && last.lease.attempt == proof.attempt
        && last.lease.worker_id == worker
        && last.lease.token == proof.token
        && last.receipt == receipt
    {
        return Ok(());
    }
    let lease = matching_lease(state, worker, &proof)?;
    if now < lease.issued_at_ms || now >= lease.expires_at_ms {
        expire_lease(state, now);
        return Err(lease_error(410, "lease expired or clock moved backwards"));
    }
    let success = matches!(receipt, shared::Receipt::Completed { exit_code: 0, .. });
    state.last_completion = Some(LeaseCompletion { lease, receipt });
    if success {
        state.active = None;
        state.stage = LeaseStage::Evaluating;
    } else {
        retry_or_fail(state, now);
    }
    Ok(())
}

/// Stage expected immediately after this journal's completion; not an authorization decision.
pub(crate) fn expected_completion_stage(receipt: &shared::Receipt, attempts: u32) -> LeaseStage {
    if receipt.is_completed() {
        LeaseStage::Evaluating
    } else if attempts >= crate::state::MAX_ATTEMPTS {
        LeaseStage::Failed
    } else {
        LeaseStage::CoolingDown
    }
}

pub(crate) fn completion_stage_matches(
    receipt: &shared::Receipt,
    attempts: u32,
    stage: &LeaseStage,
) -> bool {
    // Failed is also possible before the attempt limit if cooldown arithmetic overflowed.
    *stage == expected_completion_stage(receipt, attempts)
        || (!receipt.is_completed() && *stage == LeaseStage::Failed)
}
