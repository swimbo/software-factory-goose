//! Unregistered Unix worker adapter. Only kernel connection credentials select the worker
//! and queue. This module neither provisions accounts nor registers any Restate service.
//! Private ingress, process launch/reap, and runtime replay remain separate activation gates.
use crate::{
    worker_queue::{PullOutcome, PullRequest, QueueCompletion},
    workflow::{ClaimLeaseState, LeaseStage, completion_stage_matches},
};
use axum::{
    Extension, Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Request, State, connect_info::Connected},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
    serve::IncomingStream,
};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    collections::BTreeSet,
    future::Future,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::net::{UnixListener, UnixStream};

const BODY_LIMIT: usize = 256 * 1024;
#[derive(Debug, Clone)]
pub struct WorkerBinding {
    pub uid: u32,
    pub worker_id: String,
    pub queue_id: String,
}
#[derive(Debug, Clone)]
pub struct WorkerPolicy {
    service_uid: u32,
    bindings: Vec<WorkerBinding>,
}
impl WorkerPolicy {
    /// These are provisioned OS scopes, never identity assertions supplied by a request.
    pub fn new(
        service_uid: u32,
        operator_uid: u32,
        evaluator_uid: u32,
        bindings: Vec<WorkerBinding>,
    ) -> anyhow::Result<Self> {
        let mut uids = BTreeSet::new();
        for uid in [service_uid, operator_uid, evaluator_uid] {
            anyhow::ensure!(
                uid > 0 && uids.insert(uid),
                "service/operator/evaluator must be distinct non-root UIDs"
            );
        }
        anyhow::ensure!(
            !bindings.is_empty() && bindings.len() <= 64,
            "worker binding count outside bounds"
        );
        let mut workers = BTreeSet::new();
        let mut queues = BTreeSet::new();
        for b in &bindings {
            anyhow::ensure!(
                b.uid > 0
                    && uids.insert(b.uid)
                    && valid_scope(&b.worker_id)
                    && valid_scope(&b.queue_id)
                    && workers.insert(b.worker_id.clone())
                    && queues.insert(b.queue_id.clone()),
                "worker identity and queue bindings must be distinct and canonical"
            );
        }
        Ok(Self {
            service_uid,
            bindings,
        })
    }
}
fn valid_scope(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && value != "."
        && value != ".."
        && !value
            .chars()
            .any(|c| c.is_control() || matches!(c, '/' | '\\' | '%' | '?' | '#'))
}

/// Constructed solely from the accepted stream. No Deserialize or public UID constructor.
#[derive(Clone, Debug)]
pub struct WorkerPeer {
    uid: Option<u32>,
}
impl Connected<IncomingStream<'_, UnixListener>> for WorkerPeer {
    fn connect_info(stream: IncomingStream<'_, UnixListener>) -> Self {
        Self {
            uid: stream.io().peer_cred().ok().map(|c| c.uid()),
        }
    }
}
#[derive(Clone)]
struct AuthenticatedWorker(WorkerBinding);
async fn authenticate(
    State(policy): State<WorkerPolicy>,
    mut request: Request,
    next: Next,
) -> Response {
    let binding = request
        .extensions()
        .get::<ConnectInfo<WorkerPeer>>()
        .and_then(|p| p.0.uid)
        .and_then(|uid| policy.bindings.iter().find(|b| b.uid == uid));
    let Some(binding) = binding else {
        return AdapterError::new(403, "worker peer identity missing or mismatched")
            .into_response();
    };
    request
        .extensions_mut()
        .insert(AuthenticatedWorker(binding.clone()));
    next.run(request).await
}
#[derive(Debug)]
pub struct AdapterError {
    code: u16,
    message: &'static str,
}
impl AdapterError {
    pub fn new(code: u16, message: &'static str) -> Self {
        Self { code, message }
    }
}
impl IntoResponse for AdapterError {
    fn into_response(self) -> Response {
        (
            StatusCode::from_u16(self.code).unwrap_or(StatusCode::BAD_GATEWAY),
            self.message,
        )
            .into_response()
    }
}

/// Implementations are trusted adapters, never supplied or selected by an HTTP caller.
/// A timeout is an unknown execution outcome, not proof that a durable call did not execute.
pub trait WorkerBackend: Send + Sync + 'static {
    fn pull(
        &self,
        queue: String,
        request: PullRequest,
    ) -> impl Future<Output = Result<PullOutcome, AdapterError>> + Send;
    fn lookup_pull(
        &self,
        queue: String,
        request_id: String,
    ) -> impl Future<Output = Result<Option<PullOutcome>, AdapterError>> + Send;
    fn status(
        &self,
        task: String,
    ) -> impl Future<Output = Result<Option<ClaimLeaseState>, AdapterError>> + Send;
    fn complete(
        &self,
        queue: String,
        request: QueueCompletion,
    ) -> impl Future<Output = Result<ClaimLeaseState, AdapterError>> + Send;
}

/// Serve only on the intended private Unix listener using
/// into_make_service_with_connect_info::<WorkerPeer>(). Missing connection metadata denies.
/// No schedule, renewal, arbitrary object key, or generic Restate forwarding route exists.
/// Socket/group provisioning and service-private Restate ingress are not established here.
pub fn worker_router<B: WorkerBackend>(
    policy: WorkerPolicy,
    backend: Arc<B>,
) -> anyhow::Result<Router> {
    anyhow::ensure!(
        tokio::runtime::Handle::try_current().is_ok(),
        "worker router requires Tokio runtime"
    );
    let (a, b) = UnixStream::pair()?;
    anyhow::ensure!(
        a.peer_cred()?.uid() == policy.service_uid,
        "configured service UID does not match kernel process identity"
    );
    drop((a, b));
    Ok(scoped_router(policy, backend))
}
// Private factoring permits inert same-process transport fixtures. The public constructor
// above has no same-UID mode or environment bypass.
fn scoped_router<B: WorkerBackend>(policy: WorkerPolicy, backend: Arc<B>) -> Router {
    Router::new()
        .route("/pull", post(pull::<B>))
        .route("/complete", post(complete::<B>))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(middleware::from_fn_with_state(policy, authenticate))
        .with_state(backend)
}
async fn pull<B: WorkerBackend>(
    State(backend): State<Arc<B>>,
    Extension(worker): Extension<AuthenticatedWorker>,
    Json(request): Json<PullRequest>,
) -> Result<Json<PullOutcome>, AdapterError> {
    let outcome = backend.pull(worker.0.queue_id.clone(), request).await?;
    if let PullOutcome::Assigned {
        work_package_id, ..
    } = &outcome
    {
        let current = backend.status(work_package_id.clone()).await?;
        validate_delivery(&worker.0, &outcome, current.as_ref(), clock_ms()?)?;
    }
    Ok(Json(outcome))
}
async fn complete<B: WorkerBackend>(
    State(backend): State<Arc<B>>,
    Extension(worker): Extension<AuthenticatedWorker>,
    Json(request): Json<QueueCompletion>,
) -> Result<Json<ClaimLeaseState>, AdapterError> {
    // Crucially read-only: an unknown completion ID must never claim new work.
    let delivery = backend
        .lookup_pull(worker.0.queue_id.clone(), request.request_id.clone())
        .await?
        .ok_or_else(|| AdapterError::new(409, "unknown pull receipt"))?;
    let PullOutcome::Assigned {
        work_package_id,
        lease,
        ..
    } = &delivery
    else {
        return Err(AdapterError::new(409, "pull has no assigned lease"));
    };
    if lease.worker_id != worker.0.worker_id
        || lease.attempt != request.proof.attempt
        || lease.token != request.proof.token
    {
        return Err(AdapterError::new(
            409,
            "completion proof mismatches delivery",
        ));
    }
    let current = backend.status(work_package_id.clone()).await?;
    let state = current
        .as_ref()
        .ok_or_else(|| AdapterError::new(409, "claim state missing"))?;
    validate_completion(&worker.0, &delivery, state, &request, clock_ms()?)?;
    // This status check can race. ClaimLeaseJournal.complete must still atomically enforce
    // expiry/proof/receipt; no adapter response authorizes bypassing that authoritative check.
    let result = backend
        .complete(worker.0.queue_id.clone(), request.clone())
        .await?;
    if result.work_package_id != *work_package_id
        || result.spec != state.spec
        || result.active.is_some()
        || result.attempts != lease.attempt
        || !completion_stage_matches(&request.receipt, result.attempts, &result.stage)
        || !result
            .last_completion
            .as_ref()
            .is_some_and(|last| last.lease == *lease && last.receipt == request.receipt)
    {
        return Err(AdapterError::new(
            502,
            "durable completion response binding mismatch; outcome unknown",
        ));
    }
    Ok(Json(result))
}
fn clock_ms() -> Result<u64, AdapterError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|t| u64::try_from(t.as_millis()).ok())
        .ok_or_else(|| AdapterError::new(503, "worker adapter clock unavailable"))
}
fn validate_delivery(
    binding: &WorkerBinding,
    delivery: &PullOutcome,
    current: Option<&ClaimLeaseState>,
    now: u64,
) -> Result<(), AdapterError> {
    let PullOutcome::Assigned {
        work_package_id,
        spec,
        lease,
    } = delivery
    else {
        return Ok(());
    };
    let state = current.ok_or_else(|| AdapterError::new(409, "claim state missing"))?;
    if state.work_package_id != *work_package_id
        || state.spec != *spec
        || state.stage != LeaseStage::Leased
        || state.attempts != lease.attempt
        || state.active.as_ref() != Some(lease)
        || lease.worker_id != binding.worker_id
    {
        return Err(AdapterError::new(
            409,
            "delivery is no longer the authoritative lease",
        ));
    }
    if lease.issued_at_ms > now
        || now >= lease.expires_at_ms
        || lease.expires_at_ms > lease.hard_deadline_ms
    {
        return Err(AdapterError::new(
            410,
            "delivery lease expired or clock inconsistent",
        ));
    }
    Ok(())
}
fn validate_completion(
    binding: &WorkerBinding,
    delivery: &PullOutcome,
    state: &ClaimLeaseState,
    request: &QueueCompletion,
    now: u64,
) -> Result<(), AdapterError> {
    let PullOutcome::Assigned {
        work_package_id,
        spec,
        lease,
    } = delivery
    else {
        return Err(AdapterError::new(409, "no lease for completion"));
    };
    // Preserve exact completed-result retries even after the original deadline. The child
    // makes this same idempotency decision; changed results and superseded attempts deny.
    if state.work_package_id == *work_package_id
        && state.spec == *spec
        && state.active.is_none()
        && state.attempts == lease.attempt
        && completion_stage_matches(&request.receipt, state.attempts, &state.stage)
        && lease.worker_id == binding.worker_id
        && state
            .last_completion
            .as_ref()
            .is_some_and(|last| last.lease == *lease && last.receipt == request.receipt)
    {
        return Ok(());
    }
    validate_delivery(binding, delivery, Some(state), now)
}

// Reject path ambiguity before socket checks or network I/O. The URL library silently
// drops dot segments, and proxies may differ in how they decode path delimiters.
fn restate_call_url(service: &str, key: &str, handler: &str) -> Result<reqwest::Url, AdapterError> {
    if ![service, key, handler].into_iter().all(valid_scope) {
        return Err(AdapterError::new(400, "invalid durable call scope"));
    }
    let mut url = reqwest::Url::parse("http://localhost/").expect("constant URL");
    url.path_segments_mut()
        .expect("constant base")
        .extend(["restate", "call", service, key, handler]);
    Ok(url)
}

/// Real bounded HTTP backend over a service-private Unix ingress/proxy socket, with no TCP
/// fallback or environment proxies. This does NOT provision a Restate proxy or prove that
/// its upstream Restate service is inaccessible to workers; that remains an activation gate.
pub struct UnixRestateBackend {
    client: reqwest::Client,
    path: PathBuf,
    uid: u32,
    identity: (u64, u64),
}
impl UnixRestateBackend {
    pub async fn new(path: PathBuf, service_uid: u32) -> anyhow::Result<Self> {
        anyhow::ensure!(service_uid > 0, "root service scope unsupported");
        let metadata = check_private_socket(&path, service_uid)?;
        check_private_acls(&path).await?;
        let peer =
            tokio::time::timeout(Duration::from_secs(10), UnixStream::connect(&path)).await??;
        anyhow::ensure!(
            peer.peer_cred()?.uid() == service_uid,
            "private ingress peer UID mismatch"
        );
        let client = reqwest::Client::builder()
            .unix_socket(path.clone())
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            client,
            path,
            uid: service_uid,
            identity: metadata,
        })
    }
    pub(crate) async fn call<T: Serialize + Sync, R: DeserializeOwned>(
        &self,
        service: &str,
        key: &str,
        handler: &str,
        payload: Option<&T>,
    ) -> Result<R, AdapterError> {
        let url = restate_call_url(service, key, handler)?;
        let check = || check_private_socket(&self.path, self.uid).ok() == Some(self.identity);
        if !check() {
            return Err(AdapterError::new(
                503,
                "private ingress socket identity changed",
            ));
        }
        check_private_acls(&self.path)
            .await
            .map_err(|_| AdapterError::new(503, "private ingress ACL policy not verified"))?;
        // The containing directories prohibit replacement by other UIDs. This additional
        // kernel peer check is preflight; reqwest's subsequent connection is protected by
        // that filesystem boundary, not a claim that reqwest exposes its peer credentials.
        let peer = tokio::time::timeout(Duration::from_secs(10), UnixStream::connect(&self.path))
            .await
            .map_err(|_| AdapterError::new(503, "private ingress connection timed out"))?
            .map_err(|_| AdapterError::new(503, "private ingress unavailable"))?;
        if peer.peer_cred().ok().map(|p| p.uid()) != Some(self.uid) {
            return Err(AdapterError::new(503, "private ingress peer mismatch"));
        }
        let request = self.client.post(url);
        // SDK no-argument handlers reject JSON null: omit both body and Content-Type.
        let request = if let Some(payload) = payload {
            request.json(payload)
        } else {
            request
        };
        let mut response = request.send().await.map_err(|_| {
            AdapterError::new(
                503,
                "durable call outcome unknown; retry same request identity",
            )
        })?;
        let status = response.status();
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| AdapterError::new(503, "durable response incomplete; outcome unknown"))?
        {
            if bytes.len().saturating_add(chunk.len()) > BODY_LIMIT {
                return Err(AdapterError::new(502, "durable reply exceeds limit"));
            }
            bytes.extend_from_slice(&chunk);
        }
        if !check() || check_private_acls(&self.path).await.is_err() {
            return Err(AdapterError::new(
                503,
                "private ingress identity changed during call",
            ));
        }
        if !status.is_success() {
            return Err(AdapterError::new(
                if matches!(status.as_u16(), 400 | 403 | 404 | 409 | 410 | 429) {
                    status.as_u16()
                } else {
                    502
                },
                "durable call rejected; no execution inference",
            ));
        }
        serde_json::from_slice(&bytes)
            .map_err(|_| AdapterError::new(502, "invalid durable response"))
    }
}
async fn check_private_acls(path: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        cfg!(target_os = "macos"),
        "private ingress ACL inspection is currently macOS-only"
    );
    for entry in path.ancestors() {
        let text = entry
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("unsupported socket pathname"))?;
        anyhow::ensure!(
            !text.chars().any(char::is_control),
            "unsupported socket pathname"
        );
        let mut command = tokio::process::Command::new("/bin/ls");
        command.args(["-lde", text]).env_clear().kill_on_drop(true);
        let output = tokio::time::timeout(Duration::from_secs(3), command.output()).await??;
        anyhow::ensure!(
            output.status.success() && output.stdout.len() <= 16_384,
            "ACL inspection failed or exceeded limit"
        );
        let listing = std::str::from_utf8(&output.stdout)?;
        // macOS commonly adds this exact non-granting home-directory ACE. All other
        // extended ACLs are unsupported, rather than guessing at principal/action parsing.
        anyhow::ensure!(
            listing
                .lines()
                .skip(1)
                .all(|line| line.trim() == "0: group:everyone deny delete"),
            "extended ACL needs explicit review"
        );
    }
    Ok(())
}

fn check_private_socket(path: &Path, uid: u32) -> anyhow::Result<(u64, u64)> {
    anyhow::ensure!(path.is_absolute(), "private ingress path must be absolute");
    let socket = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        socket.file_type().is_socket() && socket.uid() == uid && socket.mode() & 0o777 == 0o600,
        "private ingress socket must be service-owned 0600"
    );
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("missing socket parent"))?;
    let pm = std::fs::symlink_metadata(parent)?;
    anyhow::ensure!(
        pm.is_dir()
            && !pm.file_type().is_symlink()
            && pm.uid() == uid
            && pm.mode() & 0o777 == 0o700,
        "private ingress parent must be service-owned 0700"
    );
    for ancestor in parent.ancestors() {
        let m = std::fs::symlink_metadata(ancestor)?;
        anyhow::ensure!(
            m.is_dir()
                && !m.file_type().is_symlink()
                && (m.uid() == uid || m.uid() == 0)
                && m.mode() & 0o022 == 0,
            "private ingress ancestors must be trusted and not group/world writable"
        );
    }
    Ok((socket.dev(), socket.ino()))
}
impl WorkerBackend for UnixRestateBackend {
    async fn pull(&self, queue: String, request: PullRequest) -> Result<PullOutcome, AdapterError> {
        self.call("WorkerQueueJournal", &queue, "pull", Some(&request))
            .await
    }
    async fn lookup_pull(
        &self,
        queue: String,
        request_id: String,
    ) -> Result<Option<PullOutcome>, AdapterError> {
        self.call(
            "WorkerQueueJournal",
            &queue,
            "lookup_pull",
            Some(&request_id),
        )
        .await
    }
    async fn status(&self, task: String) -> Result<Option<ClaimLeaseState>, AdapterError> {
        self.call::<(), _>("ClaimLeaseJournal", &task, "status", None)
            .await
    }
    async fn complete(
        &self,
        queue: String,
        request: QueueCompletion,
    ) -> Result<ClaimLeaseState, AdapterError> {
        self.call("WorkerQueueJournal", &queue, "complete", Some(&request))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::{ActiveLease, LeaseSpec};
    fn binding(uid: u32) -> WorkerBinding {
        WorkerBinding {
            uid,
            worker_id: "worker".into(),
            queue_id: "queue".into(),
        }
    }
    fn lease() -> ActiveLease {
        ActiveLease {
            worker_id: "worker".into(),
            attempt: 1,
            token: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            issued_at_ms: 100,
            expires_at_ms: 1000,
            hard_deadline_ms: 300100,
        }
    }
    fn spec() -> LeaseSpec {
        LeaseSpec {
            repository: "repo".into(),
            base_revision: "a".repeat(40),
        }
    }
    fn assignment() -> PullOutcome {
        PullOutcome::Assigned {
            work_package_id: "task".into(),
            spec: spec(),
            lease: lease(),
        }
    }
    fn claim() -> ClaimLeaseState {
        ClaimLeaseState {
            version: 2,
            work_package_id: "task".into(),
            spec: spec(),
            stage: LeaseStage::Leased,
            attempts: 1,
            cooldown_until_ms: 0,
            active: Some(lease()),
            last_completion: None,
        }
    }
    #[test]
    fn policy_rejects_ambiguous_transport_keys() {
        for bad in [
            ".",
            "..",
            "a/b",
            "a\\b",
            "%2e%2e",
            "%252e%252e",
            "a?b",
            "a#b",
            "",
            "space ",
        ] {
            let mut candidate = binding(503);
            candidate.queue_id = bad.into();
            assert!(
                WorkerPolicy::new(500, 501, 502, vec![candidate]).is_err(),
                "accepted {bad}"
            );
        }
        assert!(WorkerPolicy::new(500, 501, 502, vec![binding(503)]).is_ok());
        for bad in [
            ".",
            "..",
            "%2e",
            "%2e%2e",
            "%252e%252e",
            "a/b",
            "a\\b",
            "a?b",
            "a#b",
        ] {
            assert!(restate_call_url("WorkerQueueJournal", bad, "pull").is_err());
            assert!(restate_call_url(bad, "worker-1", "pull").is_err());
            assert!(restate_call_url("WorkerQueueJournal", "worker-1", bad).is_err());
        }
        let url = restate_call_url("WorkerQueueJournal", "task:one-1", "pull").unwrap();
        assert_eq!(
            url.path(),
            "/restate/call/WorkerQueueJournal/task:one-1/pull"
        );
    }

    #[test]
    fn pull_requires_authoritative_binding_and_live_deadline() {
        assert!(validate_delivery(&binding(501), &assignment(), Some(&claim()), 101).is_ok());
        for now in [99, 1000, u64::MAX] {
            assert!(validate_delivery(&binding(501), &assignment(), Some(&claim()), now).is_err());
        }
        let mut stale = claim();
        stale.active.as_mut().unwrap().token = "forged".into();
        assert!(validate_delivery(&binding(501), &assignment(), Some(&stale), 101).is_err());
        assert!(validate_delivery(&binding(501), &assignment(), None, 101).is_err());
    }
    #[test]
    fn policy_never_accepts_shared_or_root_identity() {
        assert!(WorkerPolicy::new(500, 501, 502, vec![binding(503)]).is_ok());
        assert!(WorkerPolicy::new(500, 501, 502, vec![binding(500)]).is_err());
        assert!(WorkerPolicy::new(500, 501, 502, vec![binding(0)]).is_err());
        assert!(WorkerPolicy::new(500, 501, 502, vec![binding(503), binding(503)]).is_err());
    }
    use crate::workflow::{LeaseCompletion, LeaseProof};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    struct MockBackend {
        outcome: PullOutcome,
        claim: Mutex<ClaimLeaseState>,
        pulls: AtomicUsize,
        completions: AtomicUsize,
        contradictory_stage: bool,
    }
    impl MockBackend {
        fn live() -> Arc<Self> {
            Self::live_with_bad_stage(false)
        }
        fn live_with_bad_stage(contradictory_stage: bool) -> Arc<Self> {
            let now = clock_ms().unwrap();
            let active = ActiveLease {
                issued_at_ms: now - 1,
                expires_at_ms: now + 60_000,
                hard_deadline_ms: now + 299_999,
                ..lease()
            };
            let mut current = claim();
            current.active = Some(active.clone());
            Arc::new(Self {
                outcome: PullOutcome::Assigned {
                    work_package_id: "task".into(),
                    spec: spec(),
                    lease: active,
                },
                claim: Mutex::new(current),
                pulls: AtomicUsize::new(0),
                completions: AtomicUsize::new(0),
                contradictory_stage,
            })
        }
    }
    impl WorkerBackend for MockBackend {
        async fn pull(
            &self,
            queue: String,
            _request: PullRequest,
        ) -> Result<PullOutcome, AdapterError> {
            assert_eq!(queue, "queue");
            self.pulls.fetch_add(1, Ordering::SeqCst);
            Ok(self.outcome.clone())
        }
        async fn lookup_pull(
            &self,
            queue: String,
            request_id: String,
        ) -> Result<Option<PullOutcome>, AdapterError> {
            assert_eq!(queue, "queue");
            Ok((request_id == "01ARZ3NDEKTSV4RRFFQ69G5FAV").then(|| self.outcome.clone()))
        }
        async fn status(&self, task: String) -> Result<Option<ClaimLeaseState>, AdapterError> {
            assert_eq!(task, "task");
            Ok(Some(self.claim.lock().unwrap().clone()))
        }
        async fn complete(
            &self,
            queue: String,
            request: QueueCompletion,
        ) -> Result<ClaimLeaseState, AdapterError> {
            assert_eq!(queue, "queue");
            self.completions.fetch_add(1, Ordering::SeqCst);
            let mut state = self.claim.lock().unwrap();
            if let Some(active) = state.active.take() {
                let stage = if self.contradictory_stage {
                    LeaseStage::Evaluating
                } else {
                    crate::workflow::expected_completion_stage(&request.receipt, state.attempts)
                };
                state.last_completion = Some(LeaseCompletion {
                    lease: active,
                    receipt: request.receipt,
                });
                state.stage = stage;
            }
            Ok(state.clone())
        }
    }
    struct Fixture {
        root: PathBuf,
        path: PathBuf,
        server: tokio::task::JoinHandle<()>,
        client: reqwest::Client,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.server.abort();
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_dir(&self.root);
        }
    }
    impl Fixture {
        async fn start(router: Router) -> Self {
            let root = PathBuf::from(format!("/tmp/sfwa-{}", &shared::new_id()[10..]));
            Self::start_at(root, router).await
        }
        async fn start_at(root: PathBuf, router: Router) -> Self {
            std::fs::create_dir(&root).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            let path = root.join("s");
            let listener = UnixListener::bind(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let server = tokio::spawn(async move {
                axum::serve(
                    listener,
                    router.into_make_service_with_connect_info::<WorkerPeer>(),
                )
                .await
                .unwrap();
            });
            let client = reqwest::Client::builder()
                .unix_socket(path.clone())
                .no_proxy()
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap();
            Self {
                root,
                path,
                server,
                client,
            }
        }
        async fn post(&self, path: &str, body: serde_json::Value) -> reqwest::Response {
            self.client
                .post(format!("http://localhost{path}"))
                .json(&body)
                .send()
                .await
                .unwrap()
        }
    }
    fn actual_uid() -> u32 {
        UnixStream::pair().unwrap().0.peer_cred().unwrap().uid()
    }
    fn fixture_policy(uid: u32) -> WorkerPolicy {
        WorkerPolicy::new(uid + 1, uid + 2, uid + 3, vec![binding(uid)]).unwrap()
    }
    fn pull_body() -> serde_json::Value {
        serde_json::json!({"request_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","ttl_ms":60001})
    }
    fn completion_body() -> serde_json::Value {
        serde_json::to_value(QueueCompletion {
            request_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            proof: LeaseProof {
                attempt: 1,
                token: lease().token,
            },
            receipt: shared::Receipt::Failed {
                exit_code: 1,
                stderr_tail: "synthetic".into(),
            },
        })
        .unwrap()
    }
    #[tokio::test]
    async fn actual_peer_wins_over_headers_and_body_and_wrong_uid_denies() {
        let uid = actual_uid();
        let backend = MockBackend::live();
        assert!(
            worker_router(fixture_policy(uid), backend.clone()).is_err(),
            "public constructor cannot pretend same-process fixture is distinct service"
        );
        let fixture = Fixture::start(scoped_router(fixture_policy(uid), backend.clone())).await;
        let accepted = fixture.post("/pull", pull_body()).await;
        assert_eq!(accepted.status(), 200);
        let first: PullOutcome = accepted.json().await.unwrap();
        let repeated: PullOutcome = fixture
            .post("/pull", pull_body())
            .await
            .json()
            .await
            .unwrap();
        assert_eq!(first, repeated);
        let mut forged = pull_body();
        forged["worker_id"] = serde_json::json!("admin");
        assert_eq!(fixture.post("/pull", forged).await.status(), 422);
        let wrong = WorkerPolicy::new(uid + 1, uid + 2, uid + 3, vec![binding(uid + 4)]).unwrap();
        let denied = Fixture::start(scoped_router(wrong, backend.clone())).await;
        let before = backend.pulls.load(Ordering::SeqCst);
        let response = denied
            .client
            .post("http://localhost/pull")
            .header("x-worker-uid", uid + 4)
            .json(&pull_body())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
        assert_eq!(backend.pulls.load(Ordering::SeqCst), before);
    }
    #[tokio::test]
    async fn deadline_and_stale_state_deny_replayed_delivery() {
        let backend = MockBackend::live();
        let fixture =
            Fixture::start(scoped_router(fixture_policy(actual_uid()), backend.clone())).await;
        backend.claim.lock().unwrap().active.as_mut().unwrap().token = "changed".into();
        assert_eq!(fixture.post("/pull", pull_body()).await.status(), 409);
        let expired = Arc::new(MockBackend {
            outcome: assignment(),
            claim: Mutex::new(claim()),
            pulls: AtomicUsize::new(0),
            completions: AtomicUsize::new(0),
            contradictory_stage: false,
        });
        let fixture = Fixture::start(scoped_router(fixture_policy(actual_uid()), expired)).await;
        assert_eq!(fixture.post("/pull", pull_body()).await.status(), 410);
    }
    #[tokio::test]
    async fn completion_read_only_lookup_exact_retry_and_changed_result() {
        let backend = MockBackend::live();
        let fixture =
            Fixture::start(scoped_router(fixture_policy(actual_uid()), backend.clone())).await;
        let mut missing = completion_body();
        missing["request_id"] = serde_json::json!("01ARZ3NDEKTSV4RRFFQ69G5FAW");
        assert_eq!(fixture.post("/complete", missing).await.status(), 409);
        assert_eq!(backend.pulls.load(Ordering::SeqCst), 0);
        assert_eq!(backend.completions.load(Ordering::SeqCst), 0);
        let mut forged = completion_body();
        forged["proof"]["attempt"] = serde_json::json!(2);
        assert_eq!(fixture.post("/complete", forged).await.status(), 409);
        assert_eq!(
            fixture.post("/complete", completion_body()).await.status(),
            200
        );
        assert_eq!(
            fixture.post("/complete", completion_body()).await.status(),
            200
        );
        let mut changed = completion_body();
        changed["receipt"]["stderr_tail"] = serde_json::json!("different");
        assert_eq!(fixture.post("/complete", changed).await.status(), 409);
        assert_eq!(backend.completions.load(Ordering::SeqCst), 2);
        assert_eq!(backend.pulls.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn contradictory_completion_stage_is_unknown_and_retry_is_rejected() {
        let backend = MockBackend::live_with_bad_stage(true);
        let fixture =
            Fixture::start(scoped_router(fixture_policy(actual_uid()), backend.clone())).await;
        // The mock deliberately reports Evaluating for a failed receipt.
        assert_eq!(
            fixture.post("/complete", completion_body()).await.status(),
            502
        );
        assert_eq!(backend.completions.load(Ordering::SeqCst), 1);
        assert_eq!(
            fixture.post("/complete", completion_body()).await.status(),
            409
        );
        assert_eq!(backend.completions.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn missing_connection_metadata_and_oversized_payload_fail_before_backend() {
        use tower::ServiceExt;
        let backend = MockBackend::live();
        let router = scoped_router(fixture_policy(actual_uid()), backend.clone());
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/pull")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(pull_body().to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
        let fixture = Fixture::start(router).await;
        let mut body = pull_body();
        body["request_id"] = serde_json::json!("a".repeat(BODY_LIMIT));
        assert_eq!(fixture.post("/pull", body).await.status(), 413);
        assert_eq!(backend.pulls.load(Ordering::SeqCst), 0);
        assert_eq!(
            fixture
                .post("/schedule", serde_json::json!({}))
                .await
                .status(),
            404
        );
    }
    #[tokio::test]
    async fn unix_backend_uses_exact_routes_json_and_rejects_changed_socket_permissions() {
        use axum::extract::OriginalUri;
        type Calls = Arc<Mutex<Vec<(String, serde_json::Value)>>>;
        async fn ingress(
            State(calls): State<Calls>,
            OriginalUri(uri): OriginalUri,
            request: Request,
        ) -> Response {
            let handler = uri.path().rsplit('/').next().unwrap();
            let content_type = request.headers().contains_key("content-type");
            let bytes = axum::body::to_bytes(request.into_body(), BODY_LIMIT)
                .await
                .unwrap();
            if handler == "status" && (!bytes.is_empty() || content_type) {
                return (
                    StatusCode::BAD_REQUEST,
                    "no-argument handler requires empty body and no content type",
                )
                    .into_response();
            }
            let body = if bytes.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            };
            let response = match handler {
                "pull" | "lookup_pull" => serde_json::to_value(assignment()).unwrap(),
                "status" | "complete" => serde_json::to_value(claim()).unwrap(),
                _ => serde_json::Value::Null,
            };
            calls.lock().unwrap().push((uri.to_string(), body));
            Json(response).into_response()
        }
        let calls: Calls = Arc::new(Mutex::new(Vec::new()));
        let router = Router::new()
            .route("/restate/call/{service}/{key}/{handler}", post(ingress))
            .with_state(calls.clone());
        // Private fixture under this user's home: /tmp's writable ancestor deliberately
        // does not satisfy the production backend path policy. No existing files modified.
        let root = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(format!(".sfwa-{}", &shared::new_id()[10..]));
        let fixture = Fixture::start_at(root, router).await;
        let uid = actual_uid();
        let backend = UnixRestateBackend::new(fixture.path.clone(), uid)
            .await
            .unwrap();
        let request: PullRequest = serde_json::from_value(pull_body()).unwrap();
        backend.pull("queue".into(), request).await.unwrap();
        backend
            .lookup_pull("queue".into(), "01ARZ3NDEKTSV4RRFFQ69G5FAV".into())
            .await
            .unwrap();
        backend.status("task".into()).await.unwrap();
        backend
            .complete(
                "queue".into(),
                serde_json::from_value(completion_body()).unwrap(),
            )
            .await
            .unwrap();
        let observed = calls.lock().unwrap().clone();
        assert_eq!(
            observed[0],
            (
                "/restate/call/WorkerQueueJournal/queue/pull".into(),
                pull_body()
            )
        );
        assert_eq!(
            observed[1],
            (
                "/restate/call/WorkerQueueJournal/queue/lookup_pull".into(),
                serde_json::json!("01ARZ3NDEKTSV4RRFFQ69G5FAV")
            )
        );
        assert_eq!(
            observed[2],
            (
                "/restate/call/ClaimLeaseJournal/task/status".into(),
                serde_json::Value::Null
            )
        );
        assert_eq!(
            observed[3],
            (
                "/restate/call/WorkerQueueJournal/queue/complete".into(),
                completion_body()
            )
        );
        for key in [".", "..", "%2e%2e", "a/b", "a?b", "a#b"] {
            assert!(backend.status(key.into()).await.is_err());
        }
        assert_eq!(
            calls.lock().unwrap().len(),
            4,
            "invalid keys reached ingress"
        );
        assert!(
            UnixRestateBackend::new(fixture.path.clone(), uid + 1)
                .await
                .is_err()
        );
        std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(backend.status("task".into()).await.is_err());
        assert_eq!(calls.lock().unwrap().len(), 4);
        std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    struct AmbiguousBackend {
        inner: Arc<MockBackend>,
        first: std::sync::atomic::AtomicBool,
        ids: Mutex<Vec<String>>,
    }
    impl WorkerBackend for AmbiguousBackend {
        async fn pull(
            &self,
            queue: String,
            request: PullRequest,
        ) -> Result<PullOutcome, AdapterError> {
            self.ids.lock().unwrap().push(request.request_id.clone());
            let result = self.inner.pull(queue, request).await?;
            if self.first.swap(false, Ordering::SeqCst) {
                return Err(AdapterError::new(
                    503,
                    "synthetic acknowledgement loss; outcome unknown",
                ));
            }
            Ok(result)
        }
        async fn lookup_pull(
            &self,
            queue: String,
            id: String,
        ) -> Result<Option<PullOutcome>, AdapterError> {
            self.inner.lookup_pull(queue, id).await
        }
        async fn status(&self, task: String) -> Result<Option<ClaimLeaseState>, AdapterError> {
            self.inner.status(task).await
        }
        async fn complete(
            &self,
            queue: String,
            request: QueueCompletion,
        ) -> Result<ClaimLeaseState, AdapterError> {
            self.inner.complete(queue, request).await
        }
    }
    #[tokio::test]
    async fn unknown_outcome_preserves_request_identity_for_caller_retry() {
        let backend = Arc::new(AmbiguousBackend {
            inner: MockBackend::live(),
            first: std::sync::atomic::AtomicBool::new(true),
            ids: Mutex::new(Vec::new()),
        });
        let fixture =
            Fixture::start(scoped_router(fixture_policy(actual_uid()), backend.clone())).await;
        assert_eq!(fixture.post("/pull", pull_body()).await.status(), 503);
        let replay = fixture.post("/pull", pull_body()).await;
        assert_eq!(replay.status(), 200);
        let receipt: PullOutcome = replay.json().await.unwrap();
        assert_eq!(receipt, backend.inner.outcome);
        assert_eq!(
            *backend.ids.lock().unwrap(),
            vec!["01ARZ3NDEKTSV4RRFFQ69G5FAV", "01ARZ3NDEKTSV4RRFFQ69G5FAV"]
        );
    }
}
