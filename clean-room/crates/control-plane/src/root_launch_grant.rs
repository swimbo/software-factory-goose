//! Root-only fixed launch-grant adapter; not registered or deployed.
//! The backend must obtain a reservation from the exclusive claim journal. This
//! adapter cannot establish root-side consumption, timer, or process safety.
use crate::{
    launch_reservation::{LaunchReservation, LaunchScope},
    workflow::{ClaimLeaseState, LeaseProof},
};
use axum::{
    Router,
    body::to_bytes,
    extract::{ConnectInfo, State, connect_info::Connected},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    serve::IncomingStream,
};
use serde::Deserialize;
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::net::UnixListener;
use tokio::sync::Semaphore;

#[derive(Clone, Copy, Debug)]
pub struct Peer {
    uid: Option<u32>,
}
impl Connected<IncomingStream<'_, UnixListener>> for Peer {
    fn connect_info(stream: IncomingStream<'_, UnixListener>) -> Self {
        Self {
            uid: stream.io().peer_cred().ok().map(|c| c.uid()),
        }
    }
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestBody {
    generation: String,
}

pub trait GrantBackend: Send + Sync + 'static {
    /// Fixed, server-owned task and lease scope; no caller-selected proof or task.
    fn reserve(
        &self,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<LaunchReservation>> + Send + '_>>;
}
/// Used only inside the exclusive claim handler: proof comes from authoritative
/// state rather than the root request. It does not itself persist the reservation.
pub fn reserve_current(
    scope: &LaunchScope,
    state: &ClaimLeaseState,
    now: u64,
) -> anyhow::Result<LaunchReservation> {
    let active = state
        .active
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("active claim unavailable"))?;
    let proof = LeaseProof {
        attempt: active.attempt,
        token: active.token.clone(),
    };
    crate::launch_reservation::reserve(scope, state, &proof, now)
}

/// Fixed private loopback backend; protected bootstrap supplies the only task scope.
/// A failure may follow journal commit; callers must retain the outcome as unknown.
pub struct FixedJournalBackend {
    client: reqwest::Client,
    url: String,
}
impl FixedJournalBackend {
    pub fn new(port: u16, scope: &LaunchScope) -> anyhow::Result<Self> {
        scope.validate()?;
        anyhow::ensure!(port >= 1024, "private journal port invalid");
        Ok(Self {
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(8))
                .build()?,
            url: format!(
                "http://127.0.0.1:{port}/restate/call/ClaimLeaseJournal/{}/reserve_current_launch",
                scope.task_id
            ),
        })
    }
}
impl GrantBackend for FixedJournalBackend {
    fn reserve(
        &self,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<LaunchReservation>> + Send + '_>> {
        Box::pin(async move {
            let mut response = self.client.post(&self.url).send().await?;
            anyhow::ensure!(response.status().is_success(), "journal grant unavailable");
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                anyhow::ensure!(
                    body.len().saturating_add(chunk.len()) <= 16384,
                    "journal grant exceeds limit"
                );
                body.extend_from_slice(&chunk);
            }
            Ok(serde_json::from_slice(&body)?)
        })
    }
}

struct Context<B> {
    scope: LaunchScope,
    backend: Arc<B>,
    permits: Semaphore,
}

pub fn router<B: GrantBackend>(scope: LaunchScope, backend: Arc<B>) -> anyhow::Result<Router> {
    scope.validate()?;
    let context = Arc::new(Context {
        scope,
        backend,
        permits: Semaphore::new(4),
    });
    Ok(Router::new()
        .route("/reserve", post(reserve::<B>))
        .with_state(context))
}
async fn reserve<B: GrantBackend>(
    State(ctx): State<Arc<Context<B>>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    request: Request<axum::body::Body>,
) -> Response {
    if peer.uid != Some(0) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(permit) = ctx.permits.try_acquire() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let body =
        match tokio::time::timeout(Duration::from_secs(3), to_bytes(request.into_body(), 1024))
            .await
        {
            Ok(Ok(body)) => body,
            _ => return StatusCode::BAD_REQUEST.into_response(),
        };
    let Ok(body) = serde_json::from_slice::<RequestBody>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if body.generation != ctx.scope.generation {
        return StatusCode::FORBIDDEN.into_response();
    }
    let result = tokio::time::timeout(Duration::from_secs(10), ctx.backend.reserve()).await;
    drop(permit);
    // Timeout may follow a durable reservation; callers must preserve unknown.
    let Ok(Ok(grant)) = result else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if grant.scope != ctx.scope
        || grant.generation != ctx.scope.generation
        || grant.attempt == 0
        || grant.token_sha256.len() != 64
        || !grant
            .token_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || grant.expires_at_ms == 0
        || grant.expires_at_ms > grant.hard_deadline_ms
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    (StatusCode::OK, axum::Json(grant)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::LeaseSpec;
    use axum::body::Body;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;
    struct Fake {
        calls: AtomicUsize,
        grant: LaunchReservation,
    }
    impl GrantBackend for Fake {
        fn reserve(
            &self,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<LaunchReservation>> + Send + '_>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(self.grant.clone())
            })
        }
    }
    fn scope() -> LaunchScope {
        LaunchScope {
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
        }
    }
    fn fake() -> Arc<Fake> {
        let scope = scope();
        Arc::new(Fake {
            calls: AtomicUsize::new(0),
            grant: LaunchReservation {
                scope: scope.clone(),
                generation: scope.generation,
                attempt: 1,
                token_sha256: "c".repeat(64),
                expires_at_ms: 200,
                hard_deadline_ms: 300,
            },
        })
    }
    fn req(uid: Option<u32>, body: &str) -> Request<Body> {
        let mut r = Request::builder()
            .method("POST")
            .uri("/reserve")
            .header("content-type", "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap();
        r.extensions_mut().insert(ConnectInfo(Peer { uid }));
        r
    }
    #[tokio::test]
    async fn denies_wrong_peer_and_wrong_generation_before_backend() {
        let backend = fake();
        let app = router(scope(), backend.clone()).unwrap();
        for (uid, body, expected) in [
            (
                Some(2001),
                r#"{"generation":"generation"}"#,
                StatusCode::FORBIDDEN,
            ),
            (
                None,
                r#"{"generation":"generation"}"#,
                StatusCode::FORBIDDEN,
            ),
            (Some(0), r#"{"generation":"other"}"#, StatusCode::FORBIDDEN),
            (
                Some(0),
                r#"{"generation":"generation","task":"forged"}"#,
                StatusCode::BAD_REQUEST,
            ),
        ] {
            assert_eq!(
                app.clone().oneshot(req(uid, body)).await.unwrap().status(),
                expected
            );
        }
        let huge = "x".repeat(1025);
        assert_eq!(
            app.clone()
                .oneshot(req(Some(0), &huge))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            app.oneshot(req(Some(0), r#"{"generation":"generation"}"#))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn current_proof_is_derived_from_exact_active_claim() {
        use crate::workflow::{ActiveLease, LeaseStage};
        let scope = scope();
        let lease = ActiveLease {
            worker_id: scope.worker_id.clone(),
            attempt: 1,
            token: "01ARZ3NDEKTSV4RRFFQ69G5FAX".into(),
            issued_at_ms: 100,
            expires_at_ms: 200,
            hard_deadline_ms: 300,
        };
        let state = ClaimLeaseState {
            version: 1,
            work_package_id: scope.task_id.clone(),
            spec: scope.spec.clone(),
            stage: LeaseStage::Leased,
            attempts: 1,
            cooldown_until_ms: 0,
            active: Some(lease),
            last_completion: None,
        };
        assert!(reserve_current(&scope, &state, 150).is_ok());
        let mut missing = state.clone();
        missing.active = None;
        assert!(reserve_current(&scope, &missing, 150).is_err());
        let mut changed = state;
        changed.active.as_mut().unwrap().worker_id = "other".into();
        assert!(reserve_current(&scope, &changed, 150).is_err());
    }
    #[tokio::test]
    async fn fixed_backend_calls_only_scoped_claim_handler() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let expected = fake().grant.clone();
        let body = serde_json::to_vec(&expected).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut input = [0u8; 4096];
            let count = stream.read(&mut input).await.unwrap();
            let request = std::str::from_utf8(&input[..count]).unwrap();
            assert!(request.starts_with(
                "POST /restate/call/ClaimLeaseJournal/task/reserve_current_launch HTTP/1.1\r\n"
            ));
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(headers.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
        });
        let backend = FixedJournalBackend::new(port, &scope()).unwrap();
        assert_eq!(backend.reserve().await.unwrap(), expected);
        server.await.unwrap();
    }
    #[tokio::test]
    async fn wrong_backend_scope_is_never_released() {
        let mut other = scope();
        other.spec.base_revision = "d".repeat(40);
        let backend = Arc::new(Fake {
            calls: AtomicUsize::new(0),
            grant: LaunchReservation {
                scope: other,
                generation: "generation".into(),
                attempt: 1,
                token_sha256: "c".repeat(64),
                expires_at_ms: 200,
                hard_deadline_ms: 300,
            },
        });
        let app = router(scope(), backend).unwrap();
        assert_eq!(
            app.oneshot(req(Some(0), r#"{"generation":"generation"}"#))
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
