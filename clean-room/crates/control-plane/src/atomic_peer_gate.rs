//! Unregistered peer-authenticated experimental gate. No task provisioning or production listener.
use crate::{
    atomic_inference_fixture::{Call, Stage},
    worker_adapter::{AdapterError, UnixRestateBackend},
};
use axum::{
    Json, Router,
    extract::{
        ConnectInfo, DefaultBodyLimit, FromRequest, Request as HttpRequest, State,
        connect_info::Connected,
    },
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
    serve::IncomingStream,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{future::Future, sync::Arc};
use tokio::net::UnixListener;

#[derive(Clone)]
pub struct Entry {
    pub task: String,
    pub call: Call,
    pub payload: Vec<u8>,
}
#[derive(Clone)]
pub struct Policy {
    service_uid: u32,
    worker_uid: u32,
    entries: Vec<Entry>,
}
impl Policy {
    /// Deployment input is trusted configuration, never selected from an HTTP request. This
    /// does not prove the catalog derives from an actual lease or a separate OS account.
    pub fn new(
        service_uid: u32,
        worker_uid: u32,
        worker_id: &str,
        entries: Vec<Entry>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            service_uid > 0 && worker_uid > 0 && service_uid != worker_uid,
            "distinct non-root identities required"
        );
        Self::checked(service_uid, worker_uid, worker_id, entries)
    }
    fn checked(
        service_uid: u32,
        worker_uid: u32,
        worker_id: &str,
        entries: Vec<Entry>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !worker_id.is_empty() && !entries.is_empty() && entries.len() <= 64,
            "invalid catalog scope"
        );
        let first = &entries[0];
        anyhow::ensure!(
            first.call.attempt > 0
                && ulid::Ulid::from_string(&first.call.token)
                    .is_ok_and(|id| id.to_string() == first.call.token),
            "invalid lease scope"
        );
        let mut ids = std::collections::HashSet::new();
        for e in &entries {
            anyhow::ensure!(
                !e.task.is_empty()
                    && e.task.len() <= 256
                    && e.task
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                    && e.call.worker_id == worker_id
                    && e.task == first.task
                    && e.call.token == first.call.token
                    && e.call.attempt == first.call.attempt
                    && e.payload.len() <= 65_536
                    && format!("{:x}", Sha256::digest(&e.payload)) == e.call.request_digest
                    && ulid::Ulid::from_string(&e.call.call_id)
                        .is_ok_and(|id| id.to_string() == e.call.call_id)
                    && ids.insert(e.call.call_id.clone()),
                "invalid catalog entry"
            );
        }
        Ok(Self {
            service_uid,
            worker_uid,
            entries,
        })
    }
}
#[derive(Clone, Debug)]
pub struct Peer {
    uid: Option<u32>,
}
impl Connected<IncomingStream<'_, UnixListener>> for Peer {
    fn connect_info(stream: IncomingStream<'_, UnixListener>) -> Self {
        Self {
            uid: stream.io().peer_cred().ok().map(|p| p.uid()),
        }
    }
}
/// Trusted service implementations only. Errors represent unknown or denied outcomes.
pub trait Authority: Send + Sync + 'static {
    fn admit(
        &self,
        task: &str,
        call: &Call,
    ) -> impl Future<Output = Result<(), AdapterError>> + Send;
}
pub trait Provider: Send + Sync + 'static {
    /// Pure check of immutable trusted provider bindings; grants no dispatch authority.
    fn check_binding(&self, call: &Call, payload: &[u8]) -> Result<(), AdapterError>;
    fn send(
        &self,
        call: &Call,
        payload: &[u8],
    ) -> impl Future<Output = Result<(), AdapterError>> + Send;
}
/// Fixed loopback fixture only. It is not a production provider or credential broker.
/// A single catalogued model and exact payload are bound at trusted bootstrap.
pub struct LoopbackFixtureProvider {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    credential: reqwest::header::HeaderValue,
    model: String,
    payload: Vec<u8>,
}
impl LoopbackFixtureProvider {
    pub fn new(
        endpoint: &str,
        credential: &str,
        model: &str,
        payload: Vec<u8>,
    ) -> anyhow::Result<Self> {
        let url = reqwest::Url::parse(endpoint)?;
        anyhow::ensure!(
            url.scheme() == "http"
                && url.host_str() == Some("127.0.0.1")
                && url.port().is_some()
                && url.path() == "/fixture"
                && url.query().is_none()
                && url.fragment().is_none()
                && url.username().is_empty()
                && url.password().is_none(),
            "invalid fixture provider endpoint"
        );
        anyhow::ensure!(
            !model.is_empty() && model.len() <= 256 && payload.len() <= 65_536,
            "invalid fixture provider binding"
        );
        let mut key = reqwest::header::HeaderValue::from_str(credential)
            .map_err(|_| anyhow::anyhow!("invalid fixture credential"))?;
        anyhow::ensure!(!key.is_empty(), "invalid fixture credential");
        key.set_sensitive(true);
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(5))
            .build()?;
        Ok(Self {
            client,
            endpoint: url,
            credential: key,
            model: model.into(),
            payload,
        })
    }
}
impl Provider for LoopbackFixtureProvider {
    fn check_binding(&self, call: &Call, payload: &[u8]) -> Result<(), AdapterError> {
        if call.model != self.model || payload != self.payload {
            return Err(AdapterError::new(403, "fixture provider binding mismatch"));
        }
        Ok(())
    }
    async fn send(&self, call: &Call, payload: &[u8]) -> Result<(), AdapterError> {
        self.check_binding(call, payload)?;
        let response = self
            .client
            .post(self.endpoint.clone())
            .header("x-fixture-key", self.credential.clone())
            .body(self.payload.clone())
            .send()
            .await
            .map_err(|_| AdapterError::new(502, "fixture provider unavailable"))?;
        if response.status() != StatusCode::NO_CONTENT
            || response.content_length().is_some_and(|n| n != 0)
        {
            return Err(AdapterError::new(502, "fixture provider response rejected"));
        }
        Ok(())
    }
}
/// The sole backend methods here call the atomic fixture's exact prepare/begin handlers.
/// No arbitrary service/route forwarding is exposed to the worker.
pub struct AtomicUnixAuthority {
    backend: UnixRestateBackend,
}
impl AtomicUnixAuthority {
    pub fn new(backend: UnixRestateBackend) -> Self {
        Self { backend }
    }
}
impl Authority for AtomicUnixAuthority {
    async fn admit(&self, task: &str, call: &Call) -> Result<(), AdapterError> {
        let stage: Stage = self
            .backend
            .call("AtomicInferenceFixture", task, "prepare", Some(call))
            .await?;
        if stage != Stage::Reserved {
            return Err(AdapterError::new(409, "inference unavailable or ambiguous"));
        }
        let begun: bool = self
            .backend
            .call("AtomicInferenceFixture", task, "begin", Some(call))
            .await?;
        if !begun {
            return Err(AdapterError::new(409, "inference not admitted"));
        }
        Ok(())
    }
}
struct GateState<A, P> {
    policy: Policy,
    authority: Arc<A>,
    provider: Arc<P>,
}
impl<A, P> Clone for GateState<A, P> {
    fn clone(&self) -> Self {
        Self {
            policy: self.policy.clone(),
            authority: self.authority.clone(),
            provider: self.provider.clone(),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    task: String,
    call_id: String,
}
/// Caller must bind a private Unix listener and serve with `Peer` connect metadata; this
/// constructor checks the actual service UID, but does not provision the socket or accounts.
pub fn router<A: Authority, P: Provider>(
    policy: Policy,
    authority: Arc<A>,
    provider: Arc<P>,
) -> anyhow::Result<Router> {
    // The effective identity of this process must match trusted configuration.
    let uid = unsafe { libc::geteuid() };
    anyhow::ensure!(uid == policy.service_uid, "service identity mismatch");
    Ok(scoped_router(policy, authority, provider))
}
/// Experimental HTTP/1 listener, for an already privately provisioned Unix socket only.
/// Socket ownership, access permissions, safe cleanup and shutdown are caller obligations.
/// Accepted requests are not cancelled by a server-wide request deadline.
pub async fn serve_fixture_listener(
    listener: UnixListener,
    app: Router,
    worker_uid: u32,
) -> std::io::Result<()> {
    serve_with_connection_limit(
        listener,
        app,
        worker_uid,
        Arc::new(tokio::sync::Semaphore::new(16)),
    )
    .await
}
async fn serve_with_connection_limit(
    listener: UnixListener,
    app: Router,
    worker_uid: u32,
    connections: Arc<tokio::sync::Semaphore>,
) -> std::io::Result<()> {
    use hyper::{server::conn::http1, service::service_fn};
    use hyper_util::rt::{TokioIo, TokioTimer};
    use tower::ServiceExt;
    loop {
        let (stream, _) = listener.accept().await?;
        let peer_uid = match stream.peer_cred() {
            Ok(peer) if peer.uid() == worker_uid => peer.uid(),
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
                    request.extensions_mut().insert(ConnectInfo(Peer {
                        uid: Some(peer_uid),
                    }));
                    app.oneshot(request).await
                }
            });
            let mut builder = http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(std::time::Duration::from_secs(2))
                .max_buf_size(8192)
                .keep_alive(false);
            let _ = builder
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}
fn scoped_router<A: Authority, P: Provider>(
    policy: Policy,
    authority: Arc<A>,
    provider: Arc<P>,
) -> Router {
    scoped_router_with_limit(
        policy,
        authority,
        provider,
        Arc::new(tokio::sync::Semaphore::new(8)),
    )
}
fn scoped_router_with_limit<A: Authority, P: Provider>(
    policy: Policy,
    authority: Arc<A>,
    provider: Arc<P>,
    limit: Arc<tokio::sync::Semaphore>,
) -> Router {
    let worker_uid = policy.worker_uid;
    Router::new()
        .route("/infer", post(infer::<A, P>))
        .layer(DefaultBodyLimit::max(4096))
        .layer(middleware::from_fn_with_state(limit, limit_inflight))
        .layer(middleware::from_fn_with_state(
            worker_uid,
            authenticate_peer,
        ))
        .with_state(GateState {
            policy,
            authority,
            provider,
        })
}
async fn limit_inflight(
    State(limit): State<Arc<tokio::sync::Semaphore>>,
    request: HttpRequest,
    next: Next,
) -> Response {
    let Ok(_permit) = limit.try_acquire_owned() else {
        return AdapterError::new(429, "gate busy").into_response();
    };
    next.run(request).await
}
async fn authenticate_peer(State(uid): State<u32>, request: HttpRequest, next: Next) -> Response {
    if request
        .extensions()
        .get::<ConnectInfo<Peer>>()
        .and_then(|peer| peer.0.uid)
        != Some(uid)
    {
        return AdapterError::new(403, "worker peer denied").into_response();
    }
    next.run(request).await
}
async fn infer<A: Authority, P: Provider>(
    State(state): State<GateState<A, P>>,
    request: HttpRequest,
) -> Result<StatusCode, AdapterError> {
    // Only body extraction has a deadline. Once admission begins, do not cancel an
    // ambiguous journal or provider operation under a router timeout.
    let Json(request) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        Json::<Request>::from_request(request, &()),
    )
    .await
    .map_err(|_| AdapterError::new(408, "request body timed out"))?
    .map_err(|e| AdapterError::new(e.status().as_u16(), "invalid request body"))?;
    let entry = state
        .policy
        .entries
        .iter()
        .find(|e| e.task == request.task && e.call.call_id == request.call_id)
        .ok_or_else(|| AdapterError::new(403, "call absent from catalog"))?;
    state.provider.check_binding(&entry.call, &entry.payload)?;
    state.authority.admit(&entry.task, &entry.call).await?;
    state.provider.send(&entry.call, &entry.payload).await?;
    // Never return a begin capability or raw provider content to the worker.
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{Request, StatusCode},
    };
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    fn entry(task: &str, id: &str) -> Entry {
        let payload = b"synthetic".to_vec();
        Entry {
            task: task.into(),
            call: Call {
                call_id: id.into(),
                request_digest: format!("{:x}", Sha256::digest(&payload)),
                review_digest: "a".repeat(64),
                model: "fixture-model".into(),
                amount_microusd: 1000,
                worker_id: "fixture-worker".into(),
                token: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
                attempt: 1,
            },
            payload,
        }
    }
    struct Noop(AtomicUsize);
    impl Authority for Noop {
        async fn admit(&self, _: &str, _: &Call) -> Result<(), AdapterError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    impl Provider for Noop {
        fn check_binding(&self, _: &Call, _: &[u8]) -> Result<(), AdapterError> {
            Ok(())
        }
        async fn send(&self, _: &Call, _: &[u8]) -> Result<(), AdapterError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    fn request(body: serde_json::Value, uid: Option<u32>) -> Request<Body> {
        let mut req = Request::builder()
            .method("POST")
            .uri("/infer")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        if let Some(uid) = uid {
            req.extensions_mut()
                .insert(ConnectInfo(Peer { uid: Some(uid) }));
        }
        req
    }

    #[test]
    fn policy_cannot_mix_tasks_or_lease_generations() {
        let first = entry("task", "01ARZ3NDEKTSV4RRFFQ69G5FAW");
        let next = entry("task", "01ARZ3NDEKTSV4RRFFQ69G5FAX");
        assert!(Policy::new(7, 8, "fixture-worker", vec![first.clone(), next.clone()]).is_ok());
        let mut other_task = next.clone();
        other_task.task = "other-task".into();
        let mut other_token = next.clone();
        other_token.call.token = "01ARZ3NDEKTSV4RRFFQ69G5FAY".into();
        let mut other_attempt = next;
        other_attempt.call.attempt = 2;
        for invalid in [other_task, other_token, other_attempt] {
            assert!(Policy::new(7, 8, "fixture-worker", vec![first.clone(), invalid]).is_err());
        }
    }
    #[tokio::test]
    async fn unix_listener_uses_kernel_peer_credentials() {
        use std::os::unix::fs::PermissionsExt;
        use tokio::io::AsyncReadExt;
        let uid = unsafe { libc::geteuid() };
        assert!(uid > 0);
        let dir = std::env::temp_dir().join(format!("sfactory-peer-{}", ulid::Ulid::new()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let good_path = dir.join("good.sock");
        let bad_path = dir.join("bad.sock");
        let good_listener = UnixListener::bind(&good_path).unwrap();
        let bad_listener = UnixListener::bind(&bad_path).unwrap();
        std::fs::set_permissions(&good_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&bad_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let call = entry("task", "01ARZ3NDEKTSV4RRFFQ69G5FAW");
        let authority = Arc::new(Noop(AtomicUsize::new(0)));
        let provider = Arc::new(Noop(AtomicUsize::new(0)));
        let good_app = scoped_router(
            Policy::checked(uid, uid, "fixture-worker", vec![call.clone()]).unwrap(),
            authority.clone(),
            provider.clone(),
        );
        let bad_app = scoped_router(
            Policy::checked(uid, uid + 1, "fixture-worker", vec![call.clone()]).unwrap(),
            authority.clone(),
            provider.clone(),
        );
        let good = tokio::spawn(async move {
            serve_fixture_listener(good_listener, good_app, uid)
                .await
                .unwrap()
        });
        let bad = tokio::spawn(async move {
            serve_fixture_listener(bad_listener, bad_app, uid + 1)
                .await
                .unwrap()
        });
        let mut wrong = tokio::net::UnixStream::connect(&bad_path).await.unwrap();
        let mut byte = [0; 1];
        let denied = tokio::time::timeout(std::time::Duration::from_secs(2), wrong.read(&mut byte))
            .await
            .unwrap();
        assert!(matches!(denied, Ok(0) | Err(_)));
        assert_eq!(authority.0.load(Ordering::SeqCst), 0);
        assert_eq!(provider.0.load(Ordering::SeqCst), 0);
        let client = reqwest::Client::builder()
            .unix_socket(good_path.clone())
            .no_proxy()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap();
        let response = client
            .post("http://localhost/infer")
            .json(&json!({"task":call.task,"call_id":call.call.call_id}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(authority.0.load(Ordering::SeqCst), 1);
        assert_eq!(provider.0.load(Ordering::SeqCst), 1);
        good.abort();
        bad.abort();
        std::fs::remove_file(good_path).unwrap();
        std::fs::remove_file(bad_path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
    #[tokio::test]
    async fn provider_mismatch_never_admits_call() {
        let call = entry("task", "01ARZ3NDEKTSV4RRFFQ69G5FAW");
        let policy = Policy::checked(7, 8, "fixture-worker", vec![call.clone()]).unwrap();
        let authority = Arc::new(Noop(AtomicUsize::new(0)));
        let provider = Arc::new(
            LoopbackFixtureProvider::new(
                "http://127.0.0.1:9/fixture",
                "fixture-key",
                "other-model",
                call.payload.clone(),
            )
            .unwrap(),
        );
        let app = scoped_router(policy, authority.clone(), provider);
        let response = app
            .oneshot(request(
                json!({"task":call.task,"call_id":call.call.call_id}),
                Some(8),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(authority.0.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn fixture_provider_refuses_mismatch_and_redirect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/fixture", listener.local_addr().unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let server = tokio::spawn(async move {
            let app = Router::new().route(
                "/fixture",
                post(move || {
                    let seen = seen.clone();
                    async move {
                        seen.fetch_add(1, Ordering::SeqCst);
                        (StatusCode::TEMPORARY_REDIRECT, [("location", "/fixture")])
                    }
                }),
            );
            axum::serve(listener, app).await.unwrap();
        });
        assert!(
            LoopbackFixtureProvider::new(
                "http://example.com/fixture",
                "key",
                "fixture-model",
                vec![]
            )
            .is_err()
        );
        assert!(
            LoopbackFixtureProvider::new(
                &format!("{endpoint}?key=secret"),
                "key",
                "fixture-model",
                vec![]
            )
            .is_err()
        );
        let provider = LoopbackFixtureProvider::new(
            &endpoint,
            "fixture-only-key",
            "fixture-model",
            b"synthetic".to_vec(),
        )
        .unwrap();
        let mut call = entry("task", "01ARZ3NDEKTSV4RRFFQ69G5FAW").call;
        call.model = "other".into();
        assert!(provider.send(&call, b"synthetic").await.is_err());
        call.model = "fixture-model".into();
        assert!(provider.send(&call, b"changed").await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(provider.send(&call, b"synthetic").await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        server.abort();
    }
    #[tokio::test]
    async fn catalog_and_peer_refuse_spoofing_before_authority_or_provider() {
        let call = entry("task", "01ARZ3NDEKTSV4RRFFQ69G5FAW");
        assert!(Policy::new(7, 7, "fixture-worker", vec![call.clone()]).is_err());
        let mut bad = call.clone();
        bad.payload = b"changed".to_vec();
        assert!(Policy::new(7, 8, "fixture-worker", vec![bad]).is_err());
        let policy = Policy::checked(7, 8, "fixture-worker", vec![call.clone()]).unwrap();
        let authority = Arc::new(Noop(AtomicUsize::new(0)));
        let provider = Arc::new(Noop(AtomicUsize::new(0)));
        let router = scoped_router(policy, authority.clone(), provider.clone());
        for (body, uid) in [
            (json!({"task":"task","call_id":call.call.call_id}), None),
            (json!({"task":"task","call_id":call.call.call_id}), Some(9)),
            (json!({"task":"other","call_id":call.call.call_id}), Some(8)),
            (
                json!({"task":"task","call_id":call.call.call_id,"uid":8}),
                Some(8),
            ),
        ] {
            assert_ne!(
                router
                    .clone()
                    .oneshot(request(body, uid))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::NO_CONTENT
            );
        }
        assert_eq!(authority.0.load(Ordering::SeqCst), 0);
        assert_eq!(provider.0.load(Ordering::SeqCst), 0);
        assert_eq!(
            router
                .oneshot(request(
                    json!({"task":"task","call_id":call.call.call_id}),
                    Some(8)
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(authority.0.load(Ordering::SeqCst), 1);
        assert_eq!(provider.0.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unavailable_authority_never_calls_provider() {
        struct Unavailable;
        impl Authority for Unavailable {
            async fn admit(&self, _: &str, _: &Call) -> Result<(), AdapterError> {
                Err(AdapterError::new(503, "admission outcome unknown"))
            }
        }
        let call = entry("task", "01ARZ3NDEKTSV4RRFFQ69G5FAW");
        let policy = Policy::checked(7, 8, "fixture-worker", vec![call.clone()]).unwrap();
        let provider = Arc::new(Noop(AtomicUsize::new(0)));
        let router = scoped_router(policy, Arc::new(Unavailable), provider.clone());
        assert_eq!(
            router
                .oneshot(request(
                    json!({"task":"task","call_id":call.call.call_id}),
                    Some(8)
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(provider.0.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn wrong_peer_is_denied_before_json_parsing() {
        let call = entry("task", "01ARZ3NDEKTSV4RRFFQ69G5FAW");
        let policy = Policy::checked(7, 8, "fixture-worker", vec![call]).unwrap();
        let authority = Arc::new(Noop(AtomicUsize::new(0)));
        let provider = Arc::new(Noop(AtomicUsize::new(0)));
        let router = scoped_router(policy, authority.clone(), provider.clone());
        let mut req = Request::builder()
            .method("POST")
            .uri("/infer")
            .header("content-type", "application/json")
            .body(Body::from("{"))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(Peer { uid: Some(9) }));
        assert_eq!(
            router.oneshot(req).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(authority.0.load(Ordering::SeqCst), 0);
        assert_eq!(provider.0.load(Ordering::SeqCst), 0);
    }

    /// Explicitly invoked only by the owned disposable Restate fixture. Normal tests never
    /// assume loopback is trusted or require an existing service.
    #[tokio::test]
    #[ignore = "requires owned disposable Restate fixture and private Unix relay"]
    async fn real_unix_peer_and_atomic_journal_fixture() {
        use crate::atomic_inference_fixture::Lease;
        use std::{
            os::unix::fs::PermissionsExt,
            path::PathBuf,
            time::{Duration, SystemTime, UNIX_EPOCH},
        };
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::{TcpListener, UnixListener, UnixStream},
        };
        let relay = PathBuf::from(std::env::var("SFACTORY_TEST_ATOMIC_RELAY").unwrap());
        let socket = PathBuf::from(std::env::var("SFACTORY_TEST_ATOMIC_SOCKET").unwrap());
        let restate = std::env::var("SFACTORY_TEST_ATOMIC_RESTATE").unwrap();
        let parsed = reqwest::Url::parse(&restate).unwrap();
        assert_eq!(parsed.host_str(), Some("127.0.0.1"));
        let uid = unsafe { libc::geteuid() };
        assert!(uid > 0);
        let backend = UnixRestateBackend::new(relay.clone(), uid).await.unwrap();
        let authority = Arc::new(AtomicUnixAuthority::new(backend));
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        let lease = Lease {
            worker_id: "fixture-worker".into(),
            token: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            attempt: 1,
            issued_ms: now - 1000,
            expires_ms: now + 299000,
        };
        let task = "rust-atomic-gate-task";
        let first = entry(task, "01ARZ3NDEKTSV4RRFFQ69G5FAW");
        let second = entry(task, "01ARZ3NDEKTSV4RRFFQ69G5FAX");
        let restate_client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        assert!(
            restate_client
                .post(format!(
                    "{restate}/restate/call/AtomicInferenceFixture/{task}/initialize"
                ))
                .json(&lease)
                .send()
                .await
                .unwrap()
                .status()
                .is_success()
        );
        // Fixed, synthetic endpoint and credential are owned by the gate, never the worker.
        // This exercises an actual HTTP hop, but is not a production provider client.
        let calls = Arc::new(AtomicUsize::new(0));
        let upstream_calls = calls.clone();
        let accepted = Arc::new(tokio::sync::Notify::new());
        let upstream_accepted = accepted.clone();
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let upstream_release = release.clone();
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/fixture", upstream.local_addr().unwrap());
        let upstream_server = tokio::spawn(async move {
            let route = Router::new().route(
                "/fixture",
                post(
                    move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
                        let calls = upstream_calls.clone();
                        let accepted = upstream_accepted.clone();
                        let release = upstream_release.clone();
                        async move {
                            if headers.get("x-fixture-key").and_then(|v| v.to_str().ok())
                                != Some("fixture-only-key")
                                || body.as_ref() != b"synthetic"
                            {
                                return StatusCode::FORBIDDEN;
                            }
                            calls.fetch_add(1, Ordering::SeqCst);
                            accepted.notify_one();
                            release.acquire().await.unwrap().forget();
                            StatusCode::NO_CONTENT
                        }
                    },
                ),
            );
            axum::serve(upstream, route).await.unwrap();
        });
        let provider = Arc::new(
            LoopbackFixtureProvider::new(
                &endpoint,
                "fixture-only-key",
                "fixture-model",
                b"synthetic".to_vec(),
            )
            .unwrap(),
        );
        // This private test-only constructor uses same UID deliberately; public constructor forbids it.
        let policy = Policy::checked(
            uid,
            uid,
            "fixture-worker",
            vec![first.clone(), second.clone()],
        )
        .unwrap();
        // A misconfigured provider must not create a reservation or dispatch record.
        let mismatch = Arc::new(
            LoopbackFixtureProvider::new(
                &endpoint,
                "fixture-only-key",
                "wrong-model",
                b"synthetic".to_vec(),
            )
            .unwrap(),
        );
        let mismatch_app = scoped_router(policy.clone(), authority.clone(), mismatch);
        let mismatched = mismatch_app
            .oneshot(request(
                json!({"task": task,"call_id":first.call.call_id}),
                Some(uid),
            ))
            .await
            .unwrap();
        assert_eq!(mismatched.status(), StatusCode::FORBIDDEN);
        let inspect = restate_client
            .post(format!(
                "{restate}/restate/call/AtomicInferenceFixture/{task}/inspect"
            ))
            .json(&first.call)
            .send()
            .await
            .unwrap();
        assert_eq!(inspect.status(), StatusCode::NOT_FOUND);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let wrong_policy =
            Policy::checked(uid, uid + 1, "fixture-worker", vec![first.clone()]).unwrap();
        let wrong_socket = socket.with_file_name("wrong-atomic-gate.sock");
        let wrong_listener = UnixListener::bind(&wrong_socket).unwrap();
        std::fs::set_permissions(&wrong_socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let wrong_authority = authority.clone();
        let wrong_provider = provider.clone();
        let denied_socket = socket.with_file_name("denied-atomic-gate.sock");
        let denied_listener = UnixListener::bind(&denied_socket).unwrap();
        let denied_policy = wrong_policy.clone();
        let denied_authority = authority.clone();
        let denied_provider = provider.clone();
        let denied_server = tokio::spawn(async move {
            serve_fixture_listener(
                denied_listener,
                scoped_router(denied_policy, denied_authority, denied_provider),
                uid + 1,
            )
            .await
            .unwrap();
        });
        let wrong_server = tokio::spawn(async move {
            axum::serve(
                wrong_listener,
                scoped_router(wrong_policy, wrong_authority, wrong_provider)
                    .into_make_service_with_connect_info::<Peer>(),
            )
            .await
            .unwrap();
        });
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let provider_for_server = provider.clone();
        let limit = Arc::new(tokio::sync::Semaphore::new(8));
        let server_limit = limit.clone();
        let connections = Arc::new(tokio::sync::Semaphore::new(16));
        let server_connections = connections.clone();
        let server = tokio::spawn(async move {
            serve_with_connection_limit(
                listener,
                scoped_router_with_limit(policy, authority, provider_for_server, server_limit),
                uid,
                server_connections,
            )
            .await
            .unwrap();
        });
        let client = reqwest::Client::builder()
            .unix_socket(socket.clone())
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let body = json!({"task":task,"call_id":first.call.call_id});
        let mut denied = UnixStream::connect(&denied_socket).await.unwrap();
        let mut denied_buf = [0; 1];
        let denied_read =
            tokio::time::timeout(Duration::from_secs(1), denied.read(&mut denied_buf))
                .await
                .unwrap();
        assert!(matches!(denied_read, Ok(0) | Err(_)));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        // A mix of silent and partial-header peers cannot pin more than 16 connections.
        let mut headers = Vec::new();
        for i in 0..16 {
            let mut stream = UnixStream::connect(&socket).await.unwrap();
            if i % 2 == 0 {
                stream
                    .write_all(b"POST /infer HTTP/1.1\r\nHost:")
                    .await
                    .unwrap();
            }
            headers.push(stream);
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while connections.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("all connection permits must be held");
        let mut overflow = UnixStream::connect(&socket).await.unwrap();
        let mut buf = [0; 512];
        let rejected = tokio::time::timeout(Duration::from_secs(1), overflow.read(&mut buf))
            .await
            .unwrap();
        assert!(matches!(rejected, Ok(0) | Err(_)));
        for mut stream in headers {
            let n = tokio::time::timeout(Duration::from_secs(4), stream.read(&mut buf))
                .await
                .unwrap();
            match n {
                Ok(0) | Err(_) => (),
                Ok(n) => assert!(buf[..n].starts_with(b"HTTP/1.1 408")),
            }
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while connections.available_permits() != 16 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("timed-out connections must release permits");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let disconnect = UnixStream::connect(&socket).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while connections.available_permits() == 16 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        drop(disconnect);
        tokio::time::timeout(Duration::from_secs(1), async {
            while connections.available_permits() != 16 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("disconnect must release its connection permit");
        // Authenticated clients cannot hold unbounded body reads or gate slots.
        let mut stalled = Vec::new();
        for _ in 0..8 {
            let mut stream = UnixStream::connect(&socket).await.unwrap();
            stream.write_all(b"POST /infer HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 4000\r\n\r\n{").await.unwrap();
            stalled.push(stream);
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while limit.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("all stalled requests must reach the gate");
        assert_eq!(
            client
                .post("http://localhost/infer")
                .json(&body)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        for mut stream in stalled {
            let mut buf = [0; 512];
            let n = tokio::time::timeout(Duration::from_secs(4), stream.read(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert!(buf[..n].starts_with(b"HTTP/1.1 408"));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let mut raw = UnixStream::connect(&wrong_socket).await.unwrap();
        raw.write_all(b"POST /infer HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 4000\r\n\r\n{").await.unwrap();
        let mut response = [0; 512];
        let bytes = tokio::time::timeout(Duration::from_secs(2), raw.read(&mut response))
            .await
            .expect("wrong peer must be rejected without waiting for its body")
            .unwrap();
        assert!(response[..bytes].starts_with(b"HTTP/1.1 403"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let wrong_client = reqwest::Client::builder()
            .unix_socket(wrong_socket.clone())
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        assert_eq!(
            wrong_client
                .post("http://localhost/infer")
                .header("x-worker-uid", (uid + 1).to_string())
                .json(&body)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let response = client
            .post("http://localhost/infer")
            .json(&json!({"task":"other","call_id":first.call.call_id}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        for extra in [
            "payload",
            "credential",
            "endpoint",
            "token",
            "amount_microusd",
        ] {
            let mut forged = body.clone();
            forged
                .as_object_mut()
                .unwrap()
                .insert(extra.into(), json!("forged"));
            assert_eq!(
                client
                    .post("http://localhost/infer")
                    .json(&forged)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                StatusCode::UNPROCESSABLE_ENTITY
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let mut jobs = tokio::task::JoinSet::new();
        // Each Unix backend call holds a preflight connection while opening the request;
        // keep concurrency below the fixture relay's eight-connection bound.
        for _ in 0..3 {
            let c = client.clone();
            let b = body.clone();
            jobs.spawn(async move {
                c.post("http://localhost/infer")
                    .header("x-worker-uid", "spoofed")
                    .json(&b)
                    .send()
                    .await
                    .unwrap()
                    .status()
            });
        }
        tokio::time::timeout(Duration::from_secs(10), accepted.notified())
            .await
            .expect("provider must receive admitted request");
        assert!(
            connections.available_permits() < 16,
            "connection must stay counted while provider is in flight"
        );
        release.add_permits(1);
        let mut sent = 0;
        while let Some(result) = jobs.join_next().await {
            let status = result.unwrap();
            if status == StatusCode::NO_CONTENT {
                sent += 1;
            } else {
                assert_eq!(status, StatusCode::CONFLICT);
            }
        }
        assert_eq!(sent, 1);
        tokio::time::timeout(Duration::from_secs(1), async {
            while connections.available_permits() != 16 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("completed responses must release connection permits");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            client
                .post("http://localhost/infer")
                .json(&body)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(
            restate_client
                .post(format!(
                    "{restate}/restate/call/AtomicInferenceFixture/{task}/revoke"
                ))
                .json(&lease)
                .send()
                .await
                .unwrap()
                .status()
                .is_success()
        );
        assert_eq!(
            client
                .post("http://localhost/infer")
                .json(&json!({"task":task,"call_id":second.call.call_id}))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        #[cfg(target_os = "linux")]
        if std::env::var_os("SFACTORY_TEST_CROSS_UID").as_deref() == Some(std::ffi::OsStr::new("1"))
        {
            // Disposable numeric UID in a network-disabled container, with exactly one
            // bind-mounted socket. The 0700 host parent is a fixture prerequisite.
            let cross_task = "rust-cross-uid-task";
            let cross_call = entry(cross_task, "01ARZ3NDEKTSV4RRFFQ69G5FAW");
            assert!(
                restate_client
                    .post(format!(
                        "{restate}/restate/call/AtomicInferenceFixture/{cross_task}/initialize"
                    ))
                    .json(&lease)
                    .send()
                    .await
                    .unwrap()
                    .status()
                    .is_success()
            );
            let cross_socket = socket.with_file_name("cross-uid-gate.sock");
            let cross_listener = UnixListener::bind(&cross_socket).unwrap();
            std::fs::set_permissions(&cross_socket, std::fs::Permissions::from_mode(0o666))
                .unwrap();
            let cross_policy = Policy::new(uid, 1001, "fixture-worker", vec![cross_call]).unwrap();
            let cross_backend = UnixRestateBackend::new(relay, uid).await.unwrap();
            let cross_app = router(
                cross_policy,
                Arc::new(AtomicUnixAuthority::new(cross_backend)),
                provider.clone(),
            )
            .unwrap();
            let cross_server = tokio::spawn(async move {
                serve_fixture_listener(cross_listener, cross_app, 1001)
                    .await
                    .unwrap()
            });
            let mut denied = UnixStream::connect(&cross_socket).await.unwrap();
            let mut byte = [0; 1];
            let result = tokio::time::timeout(Duration::from_secs(2), denied.read(&mut byte))
                .await
                .unwrap();
            assert!(matches!(result, Ok(0) | Err(_)));
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            let script = r#"import socket,http.client,json,sys
class C(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX);self.sock.settimeout(5);self.sock.connect('/gate.sock')
def req(body):
 c=C('localhost',timeout=5);c.request('POST','/infer',json.dumps(body),{'Content-Type':'application/json'});r=c.getresponse();status=r.status;r.read();c.close();return status
b={'task':'rust-cross-uid-task','call_id':'01ARZ3NDEKTSV4RRFFQ69G5FAW'}
if sys.argv[1]=='deny':
 try:
  c=socket.socket(socket.AF_UNIX);c.settimeout(5);c.connect('/gate.sock');c.sendall(b'x');assert c.recv(1)==b''
 except (BrokenPipeError,ConnectionResetError): pass
else:
 assert req({**b,'payload':'forged'})==422
 assert req({**b,'task':'forged'})==403
 assert req(b)==204
 assert req(b)==409
"#;
            async fn run_worker(path: &std::path::Path, uid: &str, mode: &str, script: &str) {
                let name = format!(
                    "sfactory-cross-{}",
                    ulid::Ulid::new().to_string().to_lowercase()
                );
                let mount = format!("type=bind,src={},dst=/gate.sock,readonly", path.display());
                let mut child = tokio::process::Command::new("/usr/bin/docker");
                child.args([
                    "run",
                    "--name",
                    &name,
                    "--rm",
                    "--pull=never",
                    "--network=none",
                    "--read-only",
                    "--user",
                    uid,
                    "--cap-drop=ALL",
                    "--security-opt=no-new-privileges",
                    "--pids-limit=16",
                    "--memory=64m",
                    "--cpus=0.5",
                    "--log-driver=none",
                    "--mount",
                    &mount,
                    "sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937",
                    "python3",
                    "-c",
                    script,
                    mode,
                ]);
                child.kill_on_drop(true);
                let output = tokio::time::timeout(Duration::from_secs(30), child.output()).await;
                if output.is_err() {
                    let _ = tokio::process::Command::new("/usr/bin/docker")
                        .args(["rm", "-f", &name])
                        .output()
                        .await;
                }
                let output = output.expect("fixture worker timeout").unwrap();
                assert!(
                    output.status.success(),
                    "fixture worker failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            run_worker(&cross_socket, "1002:1002", "deny", script).await;
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            release.add_permits(1);
            run_worker(&cross_socket, "1001:1001", "allow", script).await;
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            println!(
                "PASS: kernel UID 1000 and container UID 1002 denied; UID 1001 admitted once and replay denied"
            );
            cross_server.abort();
            std::fs::remove_file(cross_socket).unwrap();
        }
        server.abort();
        wrong_server.abort();
        denied_server.abort();
        upstream_server.abort();
        std::fs::remove_file(socket).unwrap();
        std::fs::remove_file(wrong_socket).unwrap();
        std::fs::remove_file(denied_socket).unwrap();
    }
}
