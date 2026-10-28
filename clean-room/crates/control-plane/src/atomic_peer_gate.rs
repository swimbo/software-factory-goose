//! Unregistered peer-authenticated experimental gate. No task provisioning or production listener.
use crate::{
    atomic_inference_fixture::{Call, Stage},
    worker_adapter::{AdapterError, UnixRestateBackend},
};
use axum::{
    Json, Router,
    extract::{
        ConnectInfo, DefaultBodyLimit, Request as HttpRequest, State, connect_info::Connected,
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
    async fn send(&self, call: &Call, payload: &[u8]) -> Result<(), AdapterError> {
        if call.model != self.model || payload != self.payload {
            return Err(AdapterError::new(403, "fixture provider binding mismatch"));
        }
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
fn scoped_router<A: Authority, P: Provider>(
    policy: Policy,
    authority: Arc<A>,
    provider: Arc<P>,
) -> Router {
    let worker_uid = policy.worker_uid;
    Router::new()
        .route("/infer", post(infer::<A, P>))
        .layer(DefaultBodyLimit::max(4096))
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
    Json(request): Json<Request>,
) -> Result<StatusCode, AdapterError> {
    let entry = state
        .policy
        .entries
        .iter()
        .find(|e| e.task == request.task && e.call.call_id == request.call_id)
        .ok_or_else(|| AdapterError::new(403, "call absent from catalog"))?;
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
        let backend = UnixRestateBackend::new(relay, uid).await.unwrap();
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
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/fixture", upstream.local_addr().unwrap());
        let upstream_server = tokio::spawn(async move {
            let route = Router::new().route(
                "/fixture",
                post(
                    move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
                        let calls = upstream_calls.clone();
                        async move {
                            if headers.get("x-fixture-key").and_then(|v| v.to_str().ok())
                                != Some("fixture-only-key")
                                || body.as_ref() != b"synthetic"
                            {
                                return StatusCode::FORBIDDEN;
                            }
                            calls.fetch_add(1, Ordering::SeqCst);
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
        let wrong_policy =
            Policy::checked(uid, uid + 1, "fixture-worker", vec![first.clone()]).unwrap();
        let wrong_socket = socket.with_file_name("wrong-atomic-gate.sock");
        let wrong_listener = UnixListener::bind(&wrong_socket).unwrap();
        std::fs::set_permissions(&wrong_socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let wrong_authority = authority.clone();
        let wrong_provider = provider.clone();
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
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                scoped_router(policy, authority, provider_for_server)
                    .into_make_service_with_connect_info::<Peer>(),
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
        server.abort();
        wrong_server.abort();
        upstream_server.abort();
        std::fs::remove_file(socket).unwrap();
        std::fs::remove_file(wrong_socket).unwrap();
    }
}
