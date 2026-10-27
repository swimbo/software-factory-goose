//! Unregistered same-object promotion decision ledger with opt-in trusted Git execution.
//!
//! The object owns its eligibility publication/invalidation epoch and approval decisions.
//! Exclusive handlers validate and consume against that same state, writing one state value.
//! This does NOT make a cached external ClaimLeaseJournal snapshot authoritative or atomic.
//! Integration must route every eligibility writer here and authenticate publication as a
//! separately privileged trusted source. Operator ingress may issue/consume/inspect, never
//! publish fabricated eligibility. Constructor identity configuration is not per-request
//! authentication. Keep unregistered until these source/ingress boundaries are established.

use crate::promotion_execution::{ExecutionIntent, ExecutionReceipt, TrustedPromotionRepositories};
use crate::{
    approval::{self, ApprovalAction, ApprovalRecord, TrustedOperator},
    approval_workflow::ConsumeRequest,
    promotion_eligibility::{PromotionSnapshot, prepare_promotion},
};
use evaluator::{VerificationEvidence, holdout::PrefilterReport};
use restate_sdk::{prelude::*, serde::Json};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};

const MAX_CHANGES: usize = 64;
const MAX_APPROVALS: usize = 64;
const SOURCE_REASON: &str = "authoritative eligibility publication";

/// A trusted source derives this from actual authoritative state/evaluator reports. JSON
/// decoding is only transport, not evidence authentication; never accept this from operators
/// or generators. Its digest is a normalized evidence summary, not a signature/transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EligibilityPublication {
    request_id: String,
    expected_generation: u64,
    action: ApprovalAction,
}
impl EligibilityPublication {
    pub fn from_authoritative(
        request_id: String,
        snapshot: &PromotionSnapshot,
        wall: &VerificationEvidence,
        holdout: &PrefilterReport,
        audience: &str,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(canonical_id(&request_id), "invalid publication identity");
        let expected_generation = snapshot
            .generation
            .checked_sub(1)
            .ok_or_else(|| anyhow::anyhow!("generation must start at one"))?;
        let action = prepare_promotion(snapshot, wall, holdout, SOURCE_REASON, audience)?;
        Ok(Self {
            request_id,
            expected_generation,
            action,
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvalidateRequest {
    pub request_id: String,
    pub expected_generation: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationReceipt {
    pub request_id: String,
    pub generation: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionIssueRequest {
    pub request_id: String,
    pub reason: String,
    pub ttl_ms: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionExecution {
    NotRequested,
    Prepared {
        intent: ExecutionIntent,
    },
    Completed {
        intent: ExecutionIntent,
        receipt: ExecutionReceipt,
    },
}
/// Durable decision/inspection data, never a bearer permission to execute Git.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionDecision {
    pub task_id: String,
    pub generation: u64,
    pub nonce: String,
    pub action: ApprovalAction,
    pub decided_at_ms: u64,
    pub execution: DecisionExecution,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionApproval {
    pub generation: u64,
    pub record: ApprovalRecord,
    pub decision: Option<PromotionDecision>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionSummary {
    pub task_id: String,
    pub generation: u64,
    pub eligible: bool,
    pub current_decision: Option<PromotionDecision>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Change {
    request_id: String,
    expected_generation: u64,
    action: Option<ApprovalAction>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ChangeRecord {
    request: Change,
    receipt: GenerationReceipt,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DecisionState {
    task_id: String,
    generation: u64,
    eligible_action: Option<ApprovalAction>,
    current_decision_nonce: Option<String>,
    changes: BTreeMap<String, ChangeRecord>,
    approvals: BTreeMap<String, DecisionApproval>,
}
impl DecisionState {
    fn new(task: &str) -> Self {
        Self {
            task_id: task.into(),
            generation: 0,
            eligible_action: None,
            current_decision_nonce: None,
            changes: BTreeMap::new(),
            approvals: BTreeMap::new(),
        }
    }
    fn summary(&self) -> DecisionSummary {
        DecisionSummary {
            task_id: self.task_id.clone(),
            generation: self.generation,
            eligible: self.eligible_action.is_some() && self.current_decision_nonce.is_none(),
            current_decision: self
                .current_decision_nonce
                .as_ref()
                .and_then(|nonce| {
                    self.approvals
                        .values()
                        .find(|entry| entry.record.nonce == *nonce)
                })
                .and_then(|entry| entry.decision.clone()),
        }
    }
}
#[derive(Debug, thiserror::Error)]
enum DecisionError {
    #[error("invalid promotion decision input")]
    Invalid,
    #[error("promotion generation, action or request identity conflicts")]
    Conflict,
    #[error("promotion eligibility is absent or already decided")]
    Ineligible,
    #[error(
        "unresolved promotion attempt; fresh actions remain quarantined until verified recovery"
    )]
    Quarantined,
    #[error("promotion journal capacity reached; records cannot be evicted")]
    Capacity,
    #[error(transparent)]
    Approval(#[from] approval::ApprovalError),
}
fn canonical_id(value: &str) -> bool {
    ulid::Ulid::from_string(value).is_ok_and(|id| id.to_string() == value)
}
fn canonical_text(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
fn apply_change(
    state: &mut DecisionState,
    request: Change,
) -> Result<GenerationReceipt, DecisionError> {
    if !canonical_id(&request.request_id) {
        return Err(DecisionError::Invalid);
    }
    if let Some(previous) = state.changes.get(&request.request_id) {
        return if previous.request == request {
            Ok(previous.receipt.clone())
        } else {
            Err(DecisionError::Conflict)
        };
    }
    // Unknown external outcomes cannot be cleared by republishing a new generation and
    // issuing a new nonce. Invalidation remains available, but even historical Prepared
    // records quarantine fresh actions until a separately verified recovery exists.
    if request.action.is_some()
        && state.approvals.values().any(|approved| {
            approved.decision.as_ref().is_some_and(|decision| {
                matches!(decision.execution, DecisionExecution::Prepared { .. })
            })
        })
    {
        return Err(DecisionError::Quarantined);
    }
    if state.generation != request.expected_generation {
        return Err(DecisionError::Conflict);
    }
    // Reserve the final retained change slot for invalidation. Full publication history
    // must never strand live eligibility that can no longer be withdrawn.
    let limit = if request.action.is_some() {
        MAX_CHANGES - 1
    } else {
        MAX_CHANGES
    };
    if state.changes.len() >= limit {
        return Err(DecisionError::Capacity);
    }
    let generation = state
        .generation
        .checked_add(1)
        .ok_or(DecisionError::Capacity)?;
    let receipt = GenerationReceipt {
        request_id: request.request_id.clone(),
        generation,
    };
    state.generation = generation;
    state.eligible_action = request.action.clone();
    state.current_decision_nonce = None;
    state.changes.insert(
        request.request_id.clone(),
        ChangeRecord {
            request,
            receipt: receipt.clone(),
        },
    );
    Ok(receipt)
}
fn publish(
    state: &mut DecisionState,
    request: EligibilityPublication,
    audience: &str,
) -> Result<GenerationReceipt, DecisionError> {
    request.action.validate()?;
    if request.action.task_id != state.task_id
        || request.action.audience != audience
        || request.action.operation != approval::Operation::Promote
        || request.action.reason != SOURCE_REASON
        || request.action.base_sha == request.action.candidate_sha
    {
        return Err(DecisionError::Invalid);
    }
    apply_change(
        state,
        Change {
            request_id: request.request_id,
            expected_generation: request.expected_generation,
            action: Some(request.action),
        },
    )
}
fn invalidate(
    state: &mut DecisionState,
    request: InvalidateRequest,
) -> Result<GenerationReceipt, DecisionError> {
    apply_change(
        state,
        Change {
            request_id: request.request_id,
            expected_generation: request.expected_generation,
            action: None,
        },
    )
}
fn issue(
    state: &mut DecisionState,
    request: DecisionIssueRequest,
    nonce: String,
    operator: &TrustedOperator,
    audience: &str,
    now_ms: u64,
) -> Result<DecisionApproval, DecisionError> {
    if !canonical_id(&request.request_id) || !canonical_text(&request.reason, 4096) {
        return Err(DecisionError::Invalid);
    }
    if let Some(existing) = state.approvals.get(&request.request_id) {
        if existing.record.action.reason != request.reason
            || existing
                .record
                .expires_at_ms
                .checked_sub(existing.record.issued_at_ms)
                != Some(request.ttl_ms)
            || existing.record.operator_uid != operator.uid()
            || existing.record.action.audience != audience
        {
            return Err(DecisionError::Conflict);
        }
        return Ok(existing.clone());
    }
    if state.approvals.len() >= MAX_APPROVALS {
        return Err(DecisionError::Capacity);
    }
    if state.current_decision_nonce.is_some() {
        return Err(DecisionError::Ineligible);
    }
    let mut action = state
        .eligible_action
        .clone()
        .ok_or(DecisionError::Ineligible)?;
    if action.audience != audience
        || state
            .approvals
            .values()
            .any(|entry| entry.record.nonce == nonce)
    {
        return Err(DecisionError::Conflict);
    }
    action.reason = request.reason;
    let record = approval::issue_with_nonce(action, nonce, operator, now_ms, request.ttl_ms)?;
    let approved = DecisionApproval {
        generation: state.generation,
        record,
        decision: None,
    };
    state.approvals.insert(request.request_id, approved.clone());
    Ok(approved)
}
fn consume(
    state: &mut DecisionState,
    request: ConsumeRequest,
    operator: &TrustedOperator,
    audience: &str,
    now_ms: u64,
) -> Result<PromotionDecision, DecisionError> {
    let (request_id, mut approved) = state
        .approvals
        .iter()
        .find(|(_, entry)| entry.record.nonce == request.nonce)
        .map(|(id, entry)| (id.clone(), entry.clone()))
        .ok_or(DecisionError::Conflict)?;
    if approved.generation != state.generation || state.current_decision_nonce.is_some() {
        return Err(DecisionError::Conflict);
    }
    let mut expected = state
        .eligible_action
        .clone()
        .ok_or(DecisionError::Ineligible)?;
    expected.reason = approved.record.action.reason.clone();
    if expected != approved.record.action {
        return Err(DecisionError::Conflict);
    }
    let presented = ApprovalRecord {
        action: request.action,
        nonce: request.nonce,
        issued_at_ms: request.issued_at_ms,
        expires_at_ms: request.expires_at_ms,
        operator_uid: approved.record.operator_uid,
        consumed_at_ms: None,
    };
    approval::consume(&mut approved.record, &presented, operator, audience, now_ms)?;
    let decision = PromotionDecision {
        task_id: state.task_id.clone(),
        generation: state.generation,
        nonce: approved.record.nonce.clone(),
        action: approved.record.action.clone(),
        decided_at_ms: now_ms,
        execution: DecisionExecution::NotRequested,
    };
    approved.decision = Some(decision.clone());
    state.current_decision_nonce = Some(decision.nonce.clone());
    state.approvals.insert(request_id, approved);
    Ok(decision)
}

/// Revalidate the durable source immediately before selecting execution/reconciliation.
/// A saved Prepared intent is never sufficient after invalidation or generation replacement.
fn execution_decision(
    state: &DecisionState,
    nonce: &str,
    operator: &TrustedOperator,
    audience: &str,
) -> Result<(String, PromotionDecision), DecisionError> {
    if !canonical_id(nonce) || state.current_decision_nonce.as_deref() != Some(nonce) {
        return Err(DecisionError::Conflict);
    }
    let (id, approved) = state
        .approvals
        .iter()
        .find(|(_, entry)| entry.record.nonce == nonce)
        .ok_or(DecisionError::Conflict)?;
    let decision = approved
        .decision
        .as_ref()
        .ok_or(DecisionError::Ineligible)?;
    let mut expected = state
        .eligible_action
        .clone()
        .ok_or(DecisionError::Ineligible)?;
    expected.reason = approved.record.action.reason.clone();
    if approved.generation != state.generation
        || decision.generation != state.generation
        || decision.task_id != state.task_id
        || decision.nonce != nonce
        || decision.action != expected
        || approved.record.action != expected
        || approved.record.operator_uid != operator.uid()
        || expected.audience != audience
        || approved.record.consumed_at_ms != Some(decision.decided_at_ms)
        || decision.decided_at_ms < approved.record.issued_at_ms
        || decision.decided_at_ms >= approved.record.expires_at_ms
    {
        return Err(DecisionError::Conflict);
    }
    Ok((id.clone(), decision.clone()))
}

/// Dropping the handler future aborts queued work and flags any not-yet-started closure.
/// A blocking closure already in progress still needs an independent external stop fence;
/// Tokio cannot abort running blocking work, so this is deliberately only a queued-start guard.
struct BlockingAttempt<T> {
    handle: tokio::task::JoinHandle<Option<T>>,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
}
impl<T: Send + 'static> BlockingAttempt<T> {
    fn spawn(work: impl FnOnce() -> T + Send + 'static) -> Self {
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let before_start = cancelled.clone();
        let handle = tokio::task::spawn_blocking(move || {
            if before_start.load(std::sync::atomic::Ordering::SeqCst) {
                None
            } else {
                Some(work())
            }
        });
        Self { handle, cancelled }
    }
    async fn join(mut self) -> Result<Option<T>, tokio::task::JoinError> {
        (&mut self.handle).await
    }
}
impl<T> Drop for BlockingAttempt<T> {
    fn drop(&mut self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.handle.abort();
    }
}

/// Configuration is not request authentication. Only the disposable fixture registers this
/// object; production source/stop/operator roles must be enforced outside the SDK handlers.
pub struct PromotionDecisionJournal {
    operator: TrustedOperator,
    audience: String,
    repositories: Option<Arc<TrustedPromotionRepositories>>,
}
impl PromotionDecisionJournal {
    pub fn new_for_private_ingress(
        operator: TrustedOperator,
        audience: String,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            canonical_text(&audience, 256),
            "invalid promotion decision audience"
        );
        Ok(Self {
            operator,
            audience,
            repositories: None,
        })
    }
    /// Trusted process configuration only. This does not register an ingress or authorize
    /// callers. Source ownership, operator peer authentication and the stop gate are external.
    pub fn with_private_execution_registry(
        mut self,
        repositories: Arc<TrustedPromotionRepositories>,
    ) -> Self {
        self.repositories = Some(repositories);
        self
    }
}
#[restate_sdk::object]
impl PromotionDecisionJournal {
    #[handler]
    async fn publish(
        &self,
        ctx: ObjectContext<'_>,
        request: Json<EligibilityPublication>,
    ) -> HandlerResult<Json<GenerationReceipt>> {
        let mut state = load_state(&ctx).await?;
        let receipt = publish(&mut state, request.0, &self.audience).map_err(terminal)?;
        ctx.set("promotion", Json(state));
        Ok(Json(receipt))
    }
    #[handler]
    async fn invalidate(
        &self,
        ctx: ObjectContext<'_>,
        request: Json<InvalidateRequest>,
    ) -> HandlerResult<Json<GenerationReceipt>> {
        let mut state = load_state(&ctx).await?;
        let receipt = invalidate(&mut state, request.0).map_err(terminal)?;
        ctx.set("promotion", Json(state));
        Ok(Json(receipt))
    }
    #[handler]
    async fn issue(
        &self,
        ctx: ObjectContext<'_>,
        request: Json<DecisionIssueRequest>,
    ) -> HandlerResult<Json<DecisionApproval>> {
        let mut state = load_state(&ctx).await?;
        // Correlation ID resolves lost issuance replies without regenerating nonce or TTL.
        let (nonce, now) = if state.approvals.contains_key(&request.0.request_id) {
            (String::new(), 0)
        } else {
            (ctx.run(new_nonce).await?, ctx.run(clock_millis).await?)
        };
        let approved = issue(
            &mut state,
            request.0,
            nonce,
            &self.operator,
            &self.audience,
            now,
        )
        .map_err(terminal)?;
        ctx.set("promotion", Json(state));
        Ok(Json(approved))
    }
    #[handler]
    async fn consume(
        &self,
        ctx: ObjectContext<'_>,
        request: Json<ConsumeRequest>,
    ) -> HandlerResult<Json<PromotionDecision>> {
        let mut state = load_state(&ctx).await?;
        let now = ctx.run(clock_millis).await?;
        let decision = consume(&mut state, request.0, &self.operator, &self.audience, now)
            .map_err(terminal)?;
        // One complete state write contains BOTH consumed approval and decision. No calls
        // to another object or external executor occur between eligibility and this write.
        ctx.set("promotion", Json(state));
        Ok(Json(decision))
    }
    /// Nonce is only a correlation key. The action and paths are resolved server-side.
    #[handler]
    async fn execute(
        &self,
        ctx: ObjectContext<'_>,
        nonce: Json<String>,
    ) -> HandlerResult<Json<ExecutionReceipt>> {
        let repositories = self.repositories.clone().ok_or_else(|| {
            TerminalError::new_with_code(503, "promotion executor is not configured")
        })?;
        let mut state = load_state(&ctx).await?;
        let (id, mut decision) =
            execution_decision(&state, &nonce.0, &self.operator, &self.audience)
                .map_err(terminal)?;
        let (intent, fresh) = match &decision.execution {
            DecisionExecution::NotRequested => {
                let intent = repositories
                    .prepare(&decision)
                    .map_err(|_| execution_refused())?;
                decision.execution = DecisionExecution::Prepared {
                    intent: intent.clone(),
                };
                state
                    .approvals
                    .get_mut(&id)
                    .ok_or_else(execution_refused)?
                    .decision = Some(decision.clone());
                // This write precedes the journaled side effect. A new invocation which
                // observes Prepared can only reconcile; it may never start another CAS.
                ctx.set("promotion", Json(state.clone()));
                (intent, true)
            }
            DecisionExecution::Prepared { intent } => {
                repositories
                    .matches_decision(intent, &decision)
                    .map_err(|_| execution_refused())?;
                (intent.clone(), false)
            }
            DecisionExecution::Completed { intent, receipt } => {
                repositories
                    .matches_decision(intent, &decision)
                    .map_err(|_| execution_refused())?;
                return Ok(Json(receipt.clone()));
            }
        };
        let run_intent = intent.clone();
        let receipt = ctx
            .run(move || async move {
                // Restate replay may repeat this closure after an ambiguous OS result. The
                // create-once marker makes even that replay read-only after the first attempt.
                let result = BlockingAttempt::spawn(move || {
                    if fresh {
                        repositories.execute_once(&run_intent)
                    } else {
                        repositories.reconcile(&run_intent)
                    }
                })
                .join()
                .await
                .map_err(|_| execution_refused())?
                .ok_or_else(execution_refused)?;
                Ok::<Json<ExecutionReceipt>, HandlerError>(Json(
                    result.map_err(|_| execution_refused())?,
                ))
            })
            .await?
            .0;
        decision.execution = DecisionExecution::Completed {
            intent,
            receipt: receipt.clone(),
        };
        state
            .approvals
            .get_mut(&id)
            .ok_or_else(execution_refused)?
            .decision = Some(decision);
        ctx.set("promotion", Json(state));
        Ok(Json(receipt))
    }
    #[handler]
    async fn lookup(
        &self,
        ctx: SharedObjectContext<'_>,
        request_id: Json<String>,
    ) -> HandlerResult<Json<Option<DecisionApproval>>> {
        if !canonical_id(&request_id.0) {
            return Err(terminal(DecisionError::Invalid).into());
        }
        let state = ctx.get::<Json<DecisionState>>("promotion").await?;
        if let Some(state) = state {
            if state.0.task_id != ctx.key() {
                return Err(terminal(DecisionError::Conflict).into());
            }
            Ok(Json(state.0.approvals.get(&request_id.0).cloned()))
        } else {
            Ok(Json(None))
        }
    }
    #[handler]
    async fn inspect(&self, ctx: SharedObjectContext<'_>) -> HandlerResult<Json<DecisionSummary>> {
        let state = ctx
            .get::<Json<DecisionState>>("promotion")
            .await?
            .map(|value| value.0)
            .unwrap_or_else(|| DecisionState::new(ctx.key()));
        if state.task_id != ctx.key() {
            return Err(terminal(DecisionError::Conflict).into());
        }
        Ok(Json(state.summary()))
    }
}
fn execution_refused() -> TerminalError {
    TerminalError::new_with_code(
        409,
        "promotion refused or outcome unknown; inspect the exact target and durable decision",
    )
}
async fn load_state(ctx: &ObjectContext<'_>) -> HandlerResult<DecisionState> {
    if !canonical_text(ctx.key(), 256) {
        return Err(terminal(DecisionError::Invalid).into());
    }
    let state = ctx
        .get::<Json<DecisionState>>("promotion")
        .await?
        .map(|value| value.0)
        .unwrap_or_else(|| DecisionState::new(ctx.key()));
    if state.task_id != ctx.key() {
        return Err(terminal(DecisionError::Conflict).into());
    }
    Ok(state)
}
async fn new_nonce() -> HandlerResult<String> {
    Ok(shared::new_id())
}
async fn clock_millis() -> HandlerResult<u64> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| TerminalError::new("clock before epoch"))?;
    u64::try_from(elapsed.as_millis()).map_err(|_| TerminalError::new("clock overflow").into())
}
fn terminal(error: DecisionError) -> TerminalError {
    let code = match &error {
        DecisionError::Invalid => 400,
        DecisionError::Conflict | DecisionError::Ineligible | DecisionError::Quarantined => 409,
        DecisionError::Capacity => 429,
        DecisionError::Approval(approval::ApprovalError::OutsideValidityWindow) => 410,
        DecisionError::Approval(
            approval::ApprovalError::UnauthorizedOperator | approval::ApprovalError::WrongAudience,
        ) => 403,
        DecisionError::Approval(_) => 409,
    };
    TerminalError::new_with_code(code, error.to_string())
}

#[cfg(test)]
#[path = "promotion_decision_tests.rs"]
mod tests;
