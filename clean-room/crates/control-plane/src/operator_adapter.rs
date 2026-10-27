//! Unregistered, approval-only operator routes. No Git/external execution method exists.
//!
//! Production callers obtain OperatorPolicy from the protected socket binder and serve with
//! OperatorPeer connect info. Every route authenticates kernel UID, never a body assertion.
//! State/evidence comes only from a trusted authority guard. That guard's exclusion contract
//! is an integration obligation, not durable atomicity established by this adapter. In
//! particular, cancellation can leave a remote journal call running after a guard drops.
//! Therefore consumption records are never returned as permission to execute externally.

use crate::{
    approval::{self, ApprovalRecord, Operation, TrustedOperator},
    approval_workflow::{ConsumeRequest, IssueRequest},
    operator_transport::{AuthenticatedOperator, OperatorPolicy, require_operator},
    promotion_eligibility::{PromotionSnapshot, consume_eligible_promotion, prepare_promotion},
    worker_adapter::UnixRestateBackend,
};
use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::post,
};
use evaluator::{VerificationEvidence, holdout::PrefilterReport};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Trusted source must hold exclusion for state AND evidence until this guard is dropped.
/// Every eligibility/evidence update must advance snapshot generation. No production
/// implementation is supplied here; an in-process mutex fixture is not a durable lock.
pub trait PromotionGuard: Send {
    fn snapshot(&self) -> &PromotionSnapshot;
    fn verification(&self) -> &VerificationEvidence;
    fn holdout(&self) -> &PrefilterReport;
}
pub trait PromotionAuthority: Send + Sync + 'static {
    type Guard: PromotionGuard;
    fn acquire(
        &self,
        task: &str,
    ) -> impl Future<Output = Result<Self::Guard, OperatorError>> + Send;
}

/// Trusted private-journal adapter, never selected from a request. No mutation executor.
pub trait ApprovalBackend: Send + Sync + 'static {
    fn issue(
        &self,
        nonce: String,
        request: IssueRequest,
    ) -> impl Future<Output = Result<ApprovalRecord, OperatorError>> + Send;
    fn status(
        &self,
        nonce: String,
    ) -> impl Future<Output = Result<Option<ApprovalRecord>, OperatorError>> + Send;
    fn consume(
        &self,
        request: ConsumeRequest,
    ) -> impl Future<Output = Result<ApprovalRecord, OperatorError>> + Send;
}

/// Reuses protected Unix ingress checks and bounded HTTP from the worker backend, with only
/// these three fixed ApprovalJournal handlers exposed. Upstream private routing is required;
/// owning a socket does not by itself isolate a loopback TCP Restate/admin service.
pub struct UnixApprovalBackend(UnixRestateBackend);
impl UnixApprovalBackend {
    pub async fn new(path: PathBuf, service_uid: u32) -> anyhow::Result<Self> {
        Ok(Self(UnixRestateBackend::new(path, service_uid).await?))
    }
}
impl ApprovalBackend for UnixApprovalBackend {
    async fn issue(
        &self,
        nonce: String,
        request: IssueRequest,
    ) -> Result<ApprovalRecord, OperatorError> {
        self.0
            .call("ApprovalJournal", &nonce, "issue", Some(&request))
            .await
            .map_err(|_| OperatorError::unavailable())
    }
    async fn status(&self, nonce: String) -> Result<Option<ApprovalRecord>, OperatorError> {
        self.0
            .call::<(), _>("ApprovalJournal", &nonce, "status", None)
            .await
            .map_err(|_| OperatorError::unavailable())
    }
    async fn consume(&self, request: ConsumeRequest) -> Result<ApprovalRecord, OperatorError> {
        self.0
            .call("ApprovalJournal", &request.nonce, "consume", Some(&request))
            .await
            .map_err(|_| OperatorError::unavailable())
    }
}

#[derive(Clone)]
pub struct OperatorAdapterConfig {
    pub operator_uid: u32,
    pub service_uid: u32,
    pub generator_uid: u32,
    pub evaluator_uid: u32,
    pub audience: String,
    pub ttl_ms: u64,
    pub request_timeout: Duration,
}
impl OperatorAdapterConfig {
    fn operator(&self, peer: AuthenticatedOperator) -> Result<TrustedOperator, OperatorError> {
        approval::authenticate_operator(
            peer.uid(),
            self.operator_uid,
            &[self.service_uid, self.generator_uid, self.evaluator_uid],
        )
        .map_err(|_| OperatorError::new(403, "operator_identity_refused"))
    }
}

#[derive(Debug)]
pub struct OperatorError {
    status: u16,
    code: &'static str,
    nonce: Option<String>,
}
impl OperatorError {
    pub fn unavailable() -> Self {
        Self::new(503, "approval_state_unavailable")
    }
    fn new(status: u16, code: &'static str) -> Self {
        Self {
            status,
            code,
            nonce: None,
        }
    }
    fn unknown(nonce: String) -> Self {
        Self {
            status: 503,
            code: "approval_outcome_unknown",
            nonce: Some(nonce),
        }
    }
}
impl IntoResponse for OperatorError {
    fn into_response(self) -> Response {
        (
            StatusCode::from_u16(self.status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE),
            Json(
                serde_json::json!({"code":self.code,"nonce":self.nonce,"execution":"not_executed"}),
            ),
        )
            .into_response()
    }
}
struct AdapterState<A, B> {
    config: OperatorAdapterConfig,
    authority: Arc<A>,
    backend: Arc<B>,
}

/// Requires a policy from bind_operator_socket and actual service principal. No same-UID
/// production bypass. This function creates a Router only; it registers/listens nowhere.
pub fn operator_router<A: PromotionAuthority, B: ApprovalBackend>(
    policy: OperatorPolicy,
    config: OperatorAdapterConfig,
    authority: Arc<A>,
    backend: Arc<B>,
) -> anyhow::Result<Router> {
    anyhow::ensure!(
        tokio::runtime::Handle::try_current().is_ok(),
        "operator adapter requires Tokio runtime"
    );
    approval::authenticate_operator(
        config.operator_uid,
        config.operator_uid,
        &[
            config.service_uid,
            config.generator_uid,
            config.evaluator_uid,
        ],
    )?;
    anyhow::ensure!(
        canonical(&config.audience, 256)
            && config.ttl_ms > 0
            && config.ttl_ms <= approval::MAX_APPROVAL_TTL_MS
            && (Duration::from_millis(10)..=Duration::from_secs(30))
                .contains(&config.request_timeout),
        "invalid operator adapter bounds"
    );
    let (a, b) = tokio::net::UnixStream::pair()?;
    anyhow::ensure!(
        a.peer_cred()?.uid() == config.service_uid,
        "operator adapter service UID mismatch"
    );
    drop((a, b));
    Ok(scoped_router(policy, config, authority, backend))
}
fn scoped_router<A: PromotionAuthority, B: ApprovalBackend>(
    policy: OperatorPolicy,
    config: OperatorAdapterConfig,
    authority: Arc<A>,
    backend: Arc<B>,
) -> Router {
    Router::new()
        .route("/prepare", post(prepare::<A, B>))
        .route("/consume", post(consume::<A, B>))
        .route("/status", post(status::<A, B>))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn_with_state(policy, require_operator))
        .with_state(Arc::new(AdapterState {
            config,
            authority,
            backend,
        }))
}
fn canonical(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
fn nonce_valid(value: &str) -> bool {
    ulid::Ulid::from_string(value).is_ok_and(|id| id.to_string() == value)
}
fn now_ms() -> Result<u64, OperatorError> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| OperatorError::unavailable())?
            .as_millis(),
    )
    .map_err(|_| OperatorError::unavailable())
}
fn verify_record(
    record: &ApprovalRecord,
    nonce: &str,
    operator: &TrustedOperator,
    audience: &str,
) -> Result<(), OperatorError> {
    if record.nonce != nonce
        || !nonce_valid(nonce)
        || record.operator_uid != operator.uid()
        || record.action.audience != audience
        || record.action.operation != Operation::Promote
        || record.action.validate().is_err()
        || !record
            .expires_at_ms
            .checked_sub(record.issued_at_ms)
            .is_some_and(|ttl| ttl > 0 && ttl <= approval::MAX_APPROVAL_TTL_MS)
        || record
            .consumed_at_ms
            .is_some_and(|at| at < record.issued_at_ms || at >= record.expires_at_ms)
    {
        return Err(OperatorError::unavailable());
    }
    Ok(())
}
fn presentation_digest(record: &ApprovalRecord) -> Result<String, OperatorError> {
    let mut original = record.clone();
    original.consumed_at_ms = None;
    let bytes = serde_json::to_vec(&original).map_err(|_| OperatorError::unavailable())?;
    let mut hash = Sha256::new();
    hash.update(b"sfactory-operator-presentation-v1\0");
    hash.update(bytes);
    Ok(format!("{:x}", hash.finalize()))
}
#[derive(Serialize)]
struct Presentation {
    record: ApprovalRecord,
    presentation_digest: String,
    execution: &'static str,
}
impl Presentation {
    fn new(record: ApprovalRecord) -> Result<Self, OperatorError> {
        Ok(Self {
            presentation_digest: presentation_digest(&record)?,
            record,
            execution: "not_executed",
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareInput {
    task_id: String,
    reason: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumeInput {
    nonce: String,
    presentation_digest: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusInput {
    nonce: String,
}

async fn prepare<A: PromotionAuthority, B: ApprovalBackend>(
    State(state): State<Arc<AdapterState<A, B>>>,
    Extension(peer): Extension<AuthenticatedOperator>,
    Json(request): Json<PrepareInput>,
) -> Result<Json<Presentation>, OperatorError> {
    let operator = state.config.operator(peer)?;
    if !canonical(&request.task_id, 256) || !canonical(&request.reason, 4096) {
        return Err(OperatorError::new(400, "invalid_presentation_request"));
    }
    let nonce = shared::new_id();
    tokio::time::timeout(state.config.request_timeout, async {
        let guard = state.authority.acquire(&request.task_id).await?;
        if guard.snapshot().task_id != request.task_id {
            return Err(OperatorError::unavailable());
        }
        let action = prepare_promotion(
            guard.snapshot(),
            guard.verification(),
            guard.holdout(),
            &request.reason,
            &state.config.audience,
        )
        .map_err(|_| OperatorError::new(409, "promotion_ineligible"))?;
        let record = state
            .backend
            .issue(
                nonce.clone(),
                IssueRequest {
                    action: action.clone(),
                    ttl_ms: state.config.ttl_ms,
                },
            )
            .await
            .map_err(|_| OperatorError::unknown(nonce.clone()))?;
        verify_record(&record, &nonce, &operator, &state.config.audience)?;
        let now = now_ms()?;
        if record.action != action
            || record.consumed_at_ms.is_some()
            || record.issued_at_ms > now
            || record.expires_at_ms <= now
            || record.expires_at_ms - record.issued_at_ms != state.config.ttl_ms
        {
            return Err(OperatorError::unknown(nonce.clone()));
        }
        // Keep source exclusion through response validation; not a durable execution claim.
        drop(guard);
        Ok(Json(Presentation::new(record)?))
    })
    .await
    .map_err(|_| OperatorError::unknown(nonce))?
}
async fn consume<A: PromotionAuthority, B: ApprovalBackend>(
    State(state): State<Arc<AdapterState<A, B>>>,
    Extension(peer): Extension<AuthenticatedOperator>,
    Json(request): Json<ConsumeInput>,
) -> Result<Json<serde_json::Value>, OperatorError> {
    let operator = state.config.operator(peer)?;
    if !nonce_valid(&request.nonce)
        || request.presentation_digest.len() != 64
        || !request
            .presentation_digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(OperatorError::new(400, "invalid_presentation_request"));
    }
    tokio::time::timeout(state.config.request_timeout,async {
        let stored=state.backend.status(request.nonce.clone()).await?.ok_or_else(||OperatorError::new(404,"approval_not_found"))?;
        verify_record(&stored,&request.nonce,&operator,&state.config.audience)?;
        if presentation_digest(&stored)?!=request.presentation_digest||stored.consumed_at_ms.is_some(){return Err(OperatorError::new(409,"approval_changed_or_consumed"));}
        let guard=state.authority.acquire(&stored.action.task_id).await?;
        let mut checked=stored.clone();
        consume_eligible_promotion(&mut checked,&stored,guard.snapshot(),guard.verification(),guard.holdout(),&operator,&state.config.audience,now_ms()?).map_err(|_|OperatorError::new(409,"approval_or_authoritative_state_changed"))?;
        let result=state.backend.consume(ConsumeRequest{action:stored.action.clone(),nonce:stored.nonce.clone(),issued_at_ms:stored.issued_at_ms,expires_at_ms:stored.expires_at_ms}).await.map_err(|_|OperatorError::unknown(request.nonce.clone()))?;
        verify_record(&result,&request.nonce,&operator,&state.config.audience).map_err(|_|OperatorError::unknown(request.nonce.clone()))?;
        let mut original=result.clone();original.consumed_at_ms=None;
        if original!=stored||result.consumed_at_ms.is_none(){return Err(OperatorError::unknown(request.nonce.clone()));}
        drop(guard);
        Ok(Json(serde_json::json!({"nonce":request.nonce,"state":"consumed","execution":"not_executed"})))
    }).await.map_err(|_|OperatorError::unknown(request.nonce.clone()))?
}
async fn status<A: PromotionAuthority, B: ApprovalBackend>(
    State(state): State<Arc<AdapterState<A, B>>>,
    Extension(peer): Extension<AuthenticatedOperator>,
    Json(request): Json<StatusInput>,
) -> Result<Json<Presentation>, OperatorError> {
    let operator = state.config.operator(peer)?;
    if !nonce_valid(&request.nonce) {
        return Err(OperatorError::new(400, "invalid_nonce"));
    }
    tokio::time::timeout(state.config.request_timeout, async {
        let record = state
            .backend
            .status(request.nonce.clone())
            .await?
            .ok_or_else(|| OperatorError::new(404, "approval_not_found"))?;
        verify_record(&record, &request.nonce, &operator, &state.config.audience)?;
        Ok(Json(Presentation::new(record)?))
    })
    .await
    .map_err(|_| OperatorError::unavailable())?
}

#[cfg(test)]
#[path = "operator_adapter_tests.rs"]
mod tests;
