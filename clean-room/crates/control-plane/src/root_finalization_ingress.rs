//! Unregistered candidate. Serving requires a verified root-owned listener, independently
//! attested server process and private Restate ingress; this module provisions none of them.
use crate::{
    launch_reservation::LaunchScope,
    root_finalization::{
        self, Envelope, Evidence, RootFinalizationRequest, RootLaunchCatalog, RootLaunchRecipe,
        UnknownPhase, UnknownReason,
    },
    root_finalization_evidence as evidence,
};
use axum::{
    Router,
    body::to_bytes,
    extract::{ConnectInfo, State, connect_info::Connected},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    serve::IncomingStream,
};
use serde::Deserialize;
use sha2::Digest;
use std::{future::Future, path::PathBuf, pin::Pin, sync::Arc, time::Duration};
use tokio::{net::UnixListener, sync::Semaphore};

#[derive(Clone, Copy)]
pub struct Peer {
    uid: Option<u32>,
}
impl Connected<IncomingStream<'_, UnixListener>> for Peer {
    fn connect_info(stream: IncomingStream<'_, UnixListener>) -> Self {
        Self {
            uid: stream.io().peer_cred().ok().map(|v| v.uid()),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selector {
    generation: String,
}

/// This must independently verify actual root-produced closure/reconciliation and evaluator
/// evidence, not merely compare hashes contained in the request. No production implementation
/// exists yet; no affirmative default or caller-provided verifier is installed by this module.
pub trait EvidenceVerifier: Send + Sync + 'static {
    fn verify(&self, request: &RootFinalizationRequest) -> anyhow::Result<()>;
}

/// Four independently selected root-owned files, with digests from a protected bootstrap.
/// This narrow implementation can attest only a recorded, unresolved cleanup observation;
/// evaluated outcomes require a separately implemented evaluator provenance authority.
pub struct UnknownCleanupVerifier {
    pub grant: (PathBuf, String),
    pub catalog: (PathBuf, String),
    pub recipe: (PathBuf, String),
    pub observation: (PathBuf, String),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifiedGrantFile {
    schema: u32,
    generation: String,
    binding_sha256: String,
    reservation: crate::launch_reservation::LaunchReservation,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StopObservation {
    target_id: String,
    boot_id: String,
    cgroup_dev: u64,
    cgroup_ino: u64,
    observed: bool,
    observed_at_unix: Option<u64>,
    closed: bool,
    frozen: bool,
    empty: bool,
    engine_reconciled: bool,
}
fn read_bound(pair: &(PathBuf, String)) -> anyhow::Result<Vec<u8>> {
    evidence::read_fixed(&pair.0, &pair.1)
}
impl EvidenceVerifier for UnknownCleanupVerifier {
    fn verify(&self, request: &RootFinalizationRequest) -> anyhow::Result<()> {
        let Evidence::Unknown {
            phase: UnknownPhase::Cleanup,
            reason: UnknownReason::OutcomeUnknown,
            observation_sha256,
        } = &request.evidence
        else {
            anyhow::bail!("only unresolved cleanup is supported");
        };
        anyhow::ensure!(
            observation_sha256 == &self.observation.1,
            "observation binding mismatch"
        );
        let grant: VerifiedGrantFile = serde_json::from_slice(&read_bound(&self.grant)?)?;
        let catalog: RootLaunchCatalog = serde_json::from_slice(&read_bound(&self.catalog)?)?;
        let recipe: RootLaunchRecipe = serde_json::from_slice(&read_bound(&self.recipe)?)?;
        let observation: StopObservation = serde_json::from_slice(&read_bound(&self.observation)?)?;
        anyhow::ensure!(
            grant.schema == 1
                && grant.generation == request.reservation.generation
                && grant.reservation == request.reservation
                && grant.binding_sha256 == request.binding_sha256
                && catalog == request.catalog
                && recipe == request.recipe,
            "root grant evidence mismatch"
        );
        anyhow::ensure!(
            root_finalization::binding_digest(&grant.reservation, &catalog)?
                == grant.binding_sha256
                && format!(
                    "{:x}",
                    sha2::Sha256::digest(root_finalization::canonical_bytes(&recipe)?)
                ) == catalog.recipe_sha256,
            "root binding mismatch"
        );
        anyhow::ensure!(
            observation.target_id == grant.generation
                && observation.boot_id == catalog.boot_id
                && observation.cgroup_dev == catalog.cgroup_dev
                && observation.cgroup_ino == catalog.cgroup_ino
                && observation.observed
                && observation.observed_at_unix.is_some()
                && !observation.engine_reconciled,
            "cleanup observation mismatch"
        );
        // Merely recording an observation never establishes closure or empty state.
        let _ = (observation.closed, observation.frozen, observation.empty);
        Ok(())
    }
}
pub trait FinalizationBackend: Send + Sync + 'static {
    fn finalize(
        &self,
        request: RootFinalizationRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Envelope>> + Send + '_>>;
    fn status(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = anyhow::Result<crate::workflow::RootFinalizationStatus>>
                + Send
                + '_,
        >,
    >;
    fn reexport(&self) -> Pin<Box<dyn Future<Output = anyhow::Result<Envelope>> + Send + '_>>;
}

/// Exact scope and expected evidence digest must come from independently authenticated root
/// bootstrap. The fixed file is reopened and digest-checked for every invocation.
pub struct FixedEvidence<V> {
    scope: LaunchScope,
    path: PathBuf,
    digest: String,
    verifier: V,
}
impl<V: EvidenceVerifier> FixedEvidence<V> {
    pub fn new(
        scope: LaunchScope,
        path: PathBuf,
        digest: String,
        verifier: V,
    ) -> anyhow::Result<Self> {
        scope.validate()?;
        anyhow::ensure!(
            path.is_absolute()
                && digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid evidence configuration"
        );
        Ok(Self {
            scope,
            path,
            digest,
            verifier,
        })
    }
    pub fn load(&self) -> anyhow::Result<RootFinalizationRequest> {
        let bytes = evidence::read_fixed(&self.path, &self.digest)?;
        let request = root_finalization::parse_request(&bytes)?;
        anyhow::ensure!(
            request.reservation.scope == self.scope
                && request.reservation.generation == self.scope.generation
                && request.catalog.scope == self.scope,
            "evidence scope mismatch"
        );
        self.verifier.verify(&request)?;
        Ok(request)
    }
}

/// Loopback only: a timeout may follow a committed journal record and is never a retry signal.
pub struct FixedJournalBackend {
    client: reqwest::Client,
    url: String,
    status_url: String,
    reexport_url: String,
}
impl FixedJournalBackend {
    pub fn new(port: u16, scope: &LaunchScope) -> anyhow::Result<Self> {
        scope.validate()?;
        anyhow::ensure!(port >= 1024, "invalid journal port");
        Ok(Self {
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(8))
                .build()?,
            url: format!(
                "http://127.0.0.1:{port}/restate/call/ClaimLeaseJournal/{}/finalize_root",
                scope.task_id
            ),
            status_url: format!(
                "http://127.0.0.1:{port}/restate/call/ClaimLeaseJournal/{}/root_finalization_status",
                scope.task_id
            ),
            reexport_url: format!(
                "http://127.0.0.1:{port}/restate/call/ClaimLeaseJournal/{}/reexport_root_finalization",
                scope.task_id
            ),
        })
    }
}
impl FinalizationBackend for FixedJournalBackend {
    fn finalize(
        &self,
        request: RootFinalizationRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Envelope>> + Send + '_>> {
        Box::pin(async move {
            let mut response = self.client.post(&self.url).json(&request).send().await?;
            anyhow::ensure!(response.status().is_success(), "journal unavailable");
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                anyhow::ensure!(
                    bytes.len().saturating_add(chunk.len()) <= 131072,
                    "journal response too large"
                );
                bytes.extend_from_slice(&chunk);
            }
            let envelope: Envelope = serde_json::from_slice(&bytes)?;
            anyhow::ensure!(envelope.record == request, "journal response conflict");
            Ok(envelope)
        })
    }
    fn status(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = anyhow::Result<crate::workflow::RootFinalizationStatus>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            let mut response = self.client.post(&self.status_url).send().await?;
            anyhow::ensure!(response.status().is_success(), "journal status unavailable");
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                anyhow::ensure!(
                    bytes.len().saturating_add(chunk.len()) <= 131072,
                    "journal status too large"
                );
                bytes.extend_from_slice(&chunk);
            }
            Ok(serde_json::from_slice(&bytes)?)
        })
    }
    fn reexport(&self) -> Pin<Box<dyn Future<Output = anyhow::Result<Envelope>> + Send + '_>> {
        Box::pin(async move {
            let mut response = self.client.post(&self.reexport_url).send().await?;
            anyhow::ensure!(
                response.status().is_success(),
                "journal reexport unavailable"
            );
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                anyhow::ensure!(
                    bytes.len().saturating_add(chunk.len()) <= 131072,
                    "journal response too large"
                );
                bytes.extend_from_slice(&chunk);
            }
            Ok(serde_json::from_slice(&bytes)?)
        })
    }
}
struct Context<V, B> {
    evidence: FixedEvidence<V>,
    backend: Arc<B>,
    permits: Semaphore,
}
pub fn router<B: FinalizationBackend>(
    evidence: FixedEvidence<UnknownCleanupVerifier>,
    backend: Arc<B>,
) -> anyhow::Result<Router> {
    anyhow::ensure!(
        unsafe { libc::geteuid() } == 0,
        "root service identity required"
    );
    Ok(scoped_router(evidence, backend))
}

/// Admission happens before HTTP parsing. A bounded header deadline and connection
/// count do not impose a deadline on an already admitted journal mutation.
pub async fn serve(listener: UnixListener, app: Router) -> std::io::Result<()> {
    serve_allowed(listener, app, [0, 1000]).await
}
async fn serve_allowed(
    listener: UnixListener,
    app: Router,
    allowed: [u32; 2],
) -> std::io::Result<()> {
    use hyper::{server::conn::http1, service::service_fn};
    use hyper_util::rt::{TokioIo, TokioTimer};
    use tower::ServiceExt;
    let connections = Arc::new(Semaphore::new(16));
    loop {
        let (stream, _) = listener.accept().await?;
        let uid = match stream.peer_cred() {
            Ok(peer) if allowed.contains(&peer.uid()) => peer.uid(),
            _ => continue,
        };
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            continue;
        };
        let app = app.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                let app = app.clone();
                async move {
                    let mut request = request.map(axum::body::Body::new);
                    request
                        .extensions_mut()
                        .insert(ConnectInfo(Peer { uid: Some(uid) }));
                    app.oneshot(request).await
                }
            });
            let mut builder = http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(2))
                .max_buf_size(8192)
                .keep_alive(false);
            let _ = builder
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}
fn scoped_router<V: EvidenceVerifier, B: FinalizationBackend>(
    evidence: FixedEvidence<V>,
    backend: Arc<B>,
) -> Router {
    Router::new()
        .route("/finalize", post(finalize::<V, B>))
        .route("/reexport", post(reexport::<V, B>))
        .route("/status", get(status::<V, B>))
        .with_state(Arc::new(Context {
            evidence,
            backend,
            permits: Semaphore::new(1),
        }))
}
async fn reexport<V: EvidenceVerifier, B: FinalizationBackend>(
    State(ctx): State<Arc<Context<V, B>>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    request: Request<axum::body::Body>,
) -> Response {
    if peer.uid != Some(0) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(_permit) = ctx.permits.try_acquire() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(Ok(body)) =
        tokio::time::timeout(Duration::from_secs(3), to_bytes(request.into_body(), 1024)).await
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(selector) = serde_json::from_slice::<Selector>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if selector.generation != ctx.evidence.scope.generation {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(Ok(value)) = tokio::time::timeout(Duration::from_secs(10), ctx.backend.reexport()).await
    else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if value.record.reservation.scope != ctx.evidence.scope
        || value.event.version != 1
        || root_finalization::record_digest(&value.record)
            .ok()
            .as_deref()
            != Some(value.event.payload_sha256.as_str())
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    (StatusCode::OK, axum::Json(value)).into_response()
}
async fn status<V: EvidenceVerifier, B: FinalizationBackend>(
    State(ctx): State<Arc<Context<V, B>>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
) -> Response {
    if peer.uid != Some(1000) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(_permit) = ctx.permits.try_acquire() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(Ok(value)) = tokio::time::timeout(Duration::from_secs(10), ctx.backend.status()).await
    else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if value.task_id != ctx.evidence.scope.task_id
        || value.generation != ctx.evidence.scope.generation
        || !value.approval_not_established_by_finalization
        || value
            .finalization
            .as_ref()
            .is_some_and(|e| e.record.reservation.scope != ctx.evidence.scope)
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    (StatusCode::OK, axum::Json(value)).into_response()
}
async fn finalize<V: EvidenceVerifier, B: FinalizationBackend>(
    State(ctx): State<Arc<Context<V, B>>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    request: Request<axum::body::Body>,
) -> Response {
    if peer.uid != Some(0) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(_permit) = ctx.permits.try_acquire() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(Ok(body)) =
        tokio::time::timeout(Duration::from_secs(3), to_bytes(request.into_body(), 1024)).await
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(selector) = serde_json::from_slice::<Selector>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if selector.generation != ctx.evidence.scope.generation {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(record) = ctx.evidence.load() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(Ok(envelope)) = tokio::time::timeout(
        Duration::from_secs(10),
        ctx.backend.finalize(record.clone()),
    )
    .await
    else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if envelope.record != record {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    (StatusCode::OK, axum::Json(envelope)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::LeaseSpec;
    use axum::body::{Body, Bytes, HttpBody};
    use std::{
        convert::Infallible,
        pin::Pin,
        task::{Context as TaskContext, Poll},
    };
    use tower::ServiceExt;

    struct NeverRead;
    impl HttpBody for NeverRead {
        type Data = Bytes;
        type Error = Infallible;
        fn poll_frame(
            self: Pin<&mut Self>,
            _: &mut TaskContext<'_>,
        ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, Infallible>>> {
            panic!("body was read before peer admission")
        }
    }
    struct Deny;
    impl EvidenceVerifier for Deny {
        fn verify(&self, _: &RootFinalizationRequest) -> anyhow::Result<()> {
            anyhow::bail!("no producer attestation")
        }
    }
    struct Unreachable;
    impl FinalizationBackend for Unreachable {
        fn reexport(&self) -> Pin<Box<dyn Future<Output = anyhow::Result<Envelope>> + Send + '_>> {
            Box::pin(async { panic!("backend invoked") })
        }
        fn finalize(
            &self,
            _: RootFinalizationRequest,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<Envelope>> + Send + '_>> {
            Box::pin(async { panic!("backend invoked") })
        }
        fn status(
            &self,
        ) -> Pin<
            Box<
                dyn Future<Output = anyhow::Result<crate::workflow::RootFinalizationStatus>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async { panic!("backend invoked") })
        }
    }
    struct StatusOnly;
    impl FinalizationBackend for StatusOnly {
        fn reexport(&self) -> Pin<Box<dyn Future<Output = anyhow::Result<Envelope>> + Send + '_>> {
            Box::pin(async { panic!("backend invoked") })
        }
        fn finalize(
            &self,
            _: RootFinalizationRequest,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<Envelope>> + Send + '_>> {
            Box::pin(async { panic!("finalize invoked") })
        }
        fn status(
            &self,
        ) -> Pin<
            Box<
                dyn Future<Output = anyhow::Result<crate::workflow::RootFinalizationStatus>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async {
                Ok(crate::workflow::RootFinalizationStatus {
                    task_id: "task".into(),
                    generation: "generation".into(),
                    finalization: None,
                    legacy_claim: Some(crate::workflow::HistoricalClaimSummary {
                        version: 1,
                        stage: crate::workflow::LeaseStage::Leased,
                        attempts: 1,
                    }),
                    legacy_claim_is_historical: true,
                    approval_not_established_by_finalization: true,
                })
            })
        }
    }
    fn app() -> Router {
        let scope = LaunchScope {
            task_id: "task".into(),
            intent_id: "intent".into(),
            queue_id: "queue".into(),
            generation: "generation".into(),
            spec: LeaseSpec {
                repository: "repo".into(),
                base_revision: "a".repeat(40),
            },
            worker_id: "worker".into(),
            catalog_sha256: "b".repeat(64),
        };
        scoped_router(
            FixedEvidence::new(scope, "/nonexistent/evidence".into(), "c".repeat(64), Deny)
                .unwrap(),
            Arc::new(Unreachable),
        )
    }
    #[tokio::test]
    async fn wrong_peer_is_rejected_without_reading_body() {
        let req = Request::builder()
            .method("POST")
            .uri("/finalize")
            .extension(ConnectInfo(Peer { uid: Some(1001) }))
            .body(Body::new(NeverRead))
            .unwrap();
        assert_eq!(
            app().oneshot(req).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let req = Request::builder()
            .method("POST")
            .uri("/reexport")
            .extension(ConnectInfo(Peer { uid: Some(1000) }))
            .body(Body::new(NeverRead))
            .unwrap();
        assert_eq!(
            app().oneshot(req).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
    #[tokio::test]
    async fn selectors_cannot_supply_authority_or_paths() {
        for body in [
            r#"{"generation":"generation","path":"/tmp/evil"}"#,
            r#"{"generation":"generation","result":"pass"}"#,
            r#"{"generation":"other"}"#,
        ] {
            let req = Request::builder()
                .method("POST")
                .uri("/finalize")
                .extension(ConnectInfo(Peer { uid: Some(0) }))
                .body(Body::from(body))
                .unwrap();
            let status = app().oneshot(req).await.unwrap().status();
            assert!(status == StatusCode::BAD_REQUEST || status == StatusCode::FORBIDDEN);
        }
    }
    #[tokio::test]
    async fn missing_fixed_evidence_denies_before_backend() {
        let req = Request::builder()
            .method("POST")
            .uri("/finalize")
            .extension(ConnectInfo(Peer { uid: Some(0) }))
            .body(Body::from(r#"{"generation":"generation"}"#))
            .unwrap();
        assert_eq!(
            app().oneshot(req).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    #[tokio::test]
    async fn operator_status_is_fixed_and_never_contains_raw_claim_secrets() {
        let scope = LaunchScope {
            task_id: "task".into(),
            intent_id: "intent".into(),
            queue_id: "queue".into(),
            generation: "generation".into(),
            spec: LeaseSpec {
                repository: "repo".into(),
                base_revision: "a".repeat(40),
            },
            worker_id: "worker".into(),
            catalog_sha256: "b".repeat(64),
        };
        let router = scoped_router(
            FixedEvidence::new(scope, "/nonexistent/evidence".into(), "c".repeat(64), Deny)
                .unwrap(),
            Arc::new(StatusOnly),
        );
        let request = Request::builder()
            .uri("/status")
            .extension(ConnectInfo(Peer { uid: Some(1000) }))
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 131072).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(!text.contains("token") && !text.contains("receipt") && !text.contains("diff"));
        assert!(text.contains("approval_not_established_by_finalization"));
    }

    #[tokio::test]
    async fn worker_cannot_read_operator_status() {
        let request = Request::builder()
            .uri("/status")
            .extension(ConnectInfo(Peer { uid: Some(2001) }))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app().oneshot(request).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
    #[tokio::test]
    async fn authenticated_incomplete_headers_timeout() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let path = std::env::temp_dir().join(format!(
            "sfactory-root-finalization-header-{}.sock",
            std::process::id()
        ));
        let listener = UnixListener::bind(&path).unwrap();
        let uid = unsafe { libc::geteuid() };
        let server = tokio::spawn(serve_allowed(listener, app(), [uid, uid]));
        let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
        stream
            .write_all(b"POST /finalize HTTP/1.1\r\nHost: example\r\n")
            .await
            .unwrap();
        let mut byte = [0u8; 1];
        let result = tokio::time::timeout(Duration::from_secs(4), stream.read(&mut byte)).await;
        assert!(
            result.is_ok(),
            "incomplete header did not close within bound"
        );
        server.abort();
        std::fs::remove_file(path).unwrap();
    }
}
