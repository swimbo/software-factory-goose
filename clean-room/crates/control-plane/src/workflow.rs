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
        let spent: f64 = ctx.get::<f64>("spent").await?.unwrap_or(0.0);
        let cap: f64 = ctx.get::<f64>("cap").await?.unwrap_or(0.75);
        let Some(next) = reserved_spend(spent, cap, estimate_usd) else {
            return Ok(false);
        };
        ctx.set("spent", next);
        Ok(true)
    }
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
    #[test]
    fn outbox_versions_only_real_transitions_including_rejected_expiry() {
        let mut s = state();
        let event = next_claim_event(None, &mut s, "initialize")
            .unwrap()
            .unwrap();
        assert_eq!((event.version, event.step_seq), (1, 0));
        assert_eq!(event.snapshot, serde_json::to_value(&s).unwrap());
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimRequest {
    pub ttl_ms: u64,
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

/// NOT REGISTERED: durable claim state for a single configured worker adapter. Configuration
/// is not per-request authority. A future private adapter must authenticate every worker
/// connection before forwarding calls, and a separate trusted scheduler must initialize the
/// package spec. No request payload can override worker identity. This object does not launch
/// processes, prove prior-process termination, or dispatch a DAG. Each mutation journals a
/// synchronously retried outbox delivery; Postgres is never read to authorize a claim.
pub struct ClaimLeaseJournal {
    worker_id: String,
    projection_pool: sqlx::PgPool,
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
        })
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
        use restate_sdk::serde::Json;
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
        use restate_sdk::serde::Json;
        let mut state = load_claim(&ctx).await?;
        let before = state.clone();
        let now = ctx.run(lease_clock_millis).await?;
        let token = ctx.run(|| async { Ok(shared::new_id()) }).await?;
        let result = claim_next(&mut state, &self.worker_id, token, request.0.ttl_ms, now);
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
        use restate_sdk::serde::Json;
        let mut state = load_claim(&ctx).await?;
        let before = state.clone();
        let now = ctx.run(lease_clock_millis).await?;
        let result = renew_lease(
            &mut state,
            &self.worker_id,
            request.0.proof,
            request.0.ttl_ms,
            now,
        );
        persist_claim_transition(&ctx, &self.projection_pool, Some(&before), &mut state).await?;
        result.map(Json).map_err(Into::into)
    }

    #[handler]
    async fn complete(
        &self,
        ctx: ObjectContext<'_>,
        request: restate_sdk::serde::Json<CompleteLeaseRequest>,
    ) -> HandlerResult<restate_sdk::serde::Json<ClaimLeaseState>> {
        use restate_sdk::serde::Json;
        let mut state = load_claim(&ctx).await?;
        let before = state.clone();
        let now = ctx.run(lease_clock_millis).await?;
        let result = complete_lease(
            &mut state,
            &self.worker_id,
            request.0.proof,
            request.0.receipt,
            now,
        );
        persist_claim_transition(&ctx, &self.projection_pool, Some(&before), &mut state).await?;
        result?;
        Ok(Json(state))
    }

    #[handler]
    async fn status(
        &self,
        ctx: SharedObjectContext<'_>,
    ) -> HandlerResult<restate_sdk::serde::Json<Option<ClaimLeaseState>>> {
        use restate_sdk::serde::Json;
        Ok(Json(
            ctx.get::<Json<ClaimLeaseState>>("claim")
                .await?
                .map(|s| s.0),
        ))
    }
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
        snapshot: serde_json::to_value(state)
            .map_err(|_| lease_error(500, "claim snapshot serialization failed"))?,
    }))
}

async fn persist_claim_transition(
    ctx: &ObjectContext<'_>,
    pool: &sqlx::PgPool,
    before: Option<&ClaimLeaseState>,
    state: &mut ClaimLeaseState,
) -> HandlerResult<()> {
    use crate::projection::{ClaimProjectionError, deliver_claim_event};
    use restate_sdk::serde::Json;
    let Some(event) = next_claim_event(before, state, ctx.invocation_id())? else {
        return Ok(());
    };
    ctx.set("claim", Json(state.clone()));
    let delivery = event.clone();
    let pool = pool.clone();
    // Immediately await the journaled side effect. A lost SQL acknowledgement causes safe
    // redelivery. Do not move this SQL call outside ctx.run or swallow database failures.
    let result = ctx
        .run(|| async move {
            deliver_claim_event(&pool, &delivery)
                .await
                .map_err(|error| match error {
                    ClaimProjectionError::Conflict(_) => {
                        lease_error(500, "claim projection integrity conflict").into()
                    }
                    ClaimProjectionError::Database(error) => HandlerError::from(error),
                })
        })
        .await;
    if let Err(error) = result {
        // ctx.run retries nonterminal errors; only terminal integrity errors reach here.
        ctx.set("projection_quarantine", Json(event));
        return Err(error.into());
    }
    Ok(())
}

async fn load_claim(ctx: &ObjectContext<'_>) -> HandlerResult<ClaimLeaseState> {
    ensure_projection_healthy(ctx).await?;
    Ok(ctx
        .get::<restate_sdk::serde::Json<ClaimLeaseState>>("claim")
        .await?
        .ok_or_else(|| lease_error(404, "work package not initialized"))?
        .0)
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
fn claim_next(
    state: &mut ClaimLeaseState,
    worker: &str,
    token: String,
    ttl: u64,
    now: u64,
) -> Result<ActiveLease, TerminalError> {
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
