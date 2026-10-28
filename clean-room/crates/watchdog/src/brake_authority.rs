//! Authenticated stop transport for a trusted independent authority.
//! No listener, identity, backend or worker is provisioned here.
use crate::{BrakePolicy, StopRequest, authenticate, bounded_request};
use anyhow::{Result, ensure};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::Serialize;
use std::{sync::Arc, time::Duration};

/// Trusted implementations resolve opaque targets against their own protected catalogue.
/// Caller-provided OS IDs must never become signalling authority.
pub trait StopAuthority: Send + Sync + 'static {
    fn stop(&self, target: &str) -> Result<StopDisposition>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopDisposition {
    /// Stop requested, completion not established.
    Pending,
    /// The trusted backend observed its required teardown proof.
    Verified,
}
#[derive(Clone)]
struct Server {
    authority: Arc<dyn StopAuthority>,
    permit: Arc<tokio::sync::Semaphore>,
}
/// The policy requires distinct non-root identities and the current service UID.
/// This does not establish the correctness or provisioning of the supplied backend.
pub fn router(policy: BrakePolicy, authority: Arc<dyn StopAuthority>) -> Result<Router> {
    // SAFETY: reading the effective UID has no side effects.
    ensure!(
        unsafe { libc::geteuid() } == policy.service_uid,
        "watchdog service UID mismatch"
    );
    Ok(build(policy, authority))
}
fn build(policy: BrakePolicy, authority: Arc<dyn StopAuthority>) -> Router {
    Router::new()
        .route("/stop", post(stop))
        .layer(DefaultBodyLimit::max(1024))
        .layer(middleware::from_fn_with_state(policy, authenticate))
        .layer(middleware::from_fn(bounded_request))
        .with_state(Server {
            authority,
            permit: Arc::new(tokio::sync::Semaphore::new(16)),
        })
}
async fn stop(State(state): State<Server>, Json(request): Json<StopRequest>) -> Response {
    if !ulid::Ulid::from_string(&request.target).is_ok_and(|id| id.to_string() == request.target) {
        return (
            StatusCode::BAD_REQUEST,
            "invalid registered target identity",
        )
            .into_response();
    }
    let Ok(permit) = state.permit.try_acquire_owned() else {
        return (StatusCode::TOO_MANY_REQUESTS, "brake capacity exhausted").into_response();
    };
    let work = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        state.authority.stop(&request.target)
    });
    match tokio::time::timeout(Duration::from_secs(3), work).await {
        Ok(Ok(Ok(disposition))) => (
            match disposition {
                StopDisposition::Pending => StatusCode::ACCEPTED,
                StopDisposition::Verified => StatusCode::OK,
            },
            Json(disposition),
        )
            .into_response(),
        Ok(Ok(Err(_))) => (StatusCode::CONFLICT, "stop unowned or unverified").into_response(),
        _ => (StatusCode::SERVICE_UNAVAILABLE, "stop outcome unknown").into_response(),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BrakePeer, BrakeSecret};
    use axum::{body::Body, extract::ConnectInfo, http::Request};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;
    struct Authority {
        target: String,
        calls: AtomicUsize,
    }
    impl StopAuthority for Authority {
        fn stop(&self, target: &str) -> Result<StopDisposition> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            ensure!(target == self.target, "unknown target");
            Ok(StopDisposition::Pending)
        }
    }
    #[tokio::test]
    async fn auth_precedes_authority_and_pending_is_not_success() {
        let uid = unsafe { libc::geteuid() };
        let authority = Arc::new(Authority {
            target: ulid::Ulid::new().to_string(),
            calls: AtomicUsize::new(0),
        });
        let policy = BrakePolicy {
            service_uid: uid,
            brake_uid: uid,
            secret: Arc::new(BrakeSecret::new([7; 32]).unwrap()),
        };
        let router = build(policy, authority.clone());
        let request = |peer: Option<u32>, key: &str, target: &str| {
            let mut b = Request::builder()
                .method("POST")
                .uri("/stop")
                .header("content-type", "application/json")
                .header("x-brake-key", key);
            if let Some(uid) = peer {
                b = b.extension(ConnectInfo(BrakePeer { uid: Some(uid) }));
            }
            b.body(Body::from(format!("{{\"target\":\"{target}\"}}")))
                .unwrap()
        };
        let key = "07".repeat(32);
        for (peer, credential) in [
            (None, key.as_str()),
            (Some(uid.wrapping_add(1)), key.as_str()),
            (Some(uid), "wrong"),
        ] {
            assert_eq!(
                router
                    .clone()
                    .oneshot(request(peer, credential, &authority.target))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::FORBIDDEN
            );
        }
        assert_eq!(authority.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            router
                .clone()
                .oneshot(request(Some(uid), &key, &ulid::Ulid::new().to_string()))
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            router
                .oneshot(request(Some(uid), &key, &authority.target))
                .await
                .unwrap()
                .status(),
            StatusCode::ACCEPTED
        );
        assert_eq!(authority.calls.load(Ordering::SeqCst), 2);
    }
}
