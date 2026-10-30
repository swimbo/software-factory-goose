//! Authenticated stop transport for a trusted independent authority.
//! No listener, identity, backend or worker is provisioned here.
use crate::root_cgroup::StopObservation;
use crate::{
    BrakePolicy, OperatorBrakePolicy, StopRequest, authenticate, authenticate_operator,
    bounded_request,
};
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
pub trait StopStatusAuthority: Send + Sync + 'static {
    fn status(&self, target: &str) -> Result<StopObservation>;
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
    status: Option<Arc<dyn StopStatusAuthority>>,
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
    build_with_status(policy, authority, None)
}
/// Status uses the identical peer/key middleware and does not change the stop API.
pub fn router_with_status(
    policy: BrakePolicy,
    authority: Arc<dyn StopAuthority>,
    status: Arc<dyn StopStatusAuthority>,
) -> Result<Router> {
    // SAFETY: reading the effective UID has no side effects.
    ensure!(
        unsafe { libc::geteuid() } == policy.service_uid,
        "watchdog service UID mismatch"
    );
    Ok(build_with_status(policy, authority, Some(status)))
}
fn build_with_status(
    policy: BrakePolicy,
    authority: Arc<dyn StopAuthority>,
    status: Option<Arc<dyn StopStatusAuthority>>,
) -> Router {
    Router::new()
        .route("/stop", post(stop))
        .route("/status", post(status_route))
        .layer(DefaultBodyLimit::max(1024))
        .layer(middleware::from_fn_with_state(policy, authenticate))
        .layer(middleware::from_fn(bounded_request))
        .with_state(Server {
            authority,
            status,
            permit: Arc::new(tokio::sync::Semaphore::new(16)),
        })
}
/// Explicit operator-caller production router; the older strict BrakePolicy is unchanged.
/// Provisioning, key separation and backend availability remain external gates.
pub fn operator_router_with_status(
    policy: OperatorBrakePolicy,
    authority: Arc<dyn StopAuthority>,
    status: Arc<dyn StopStatusAuthority>,
) -> Result<Router> {
    ensure!(
        unsafe { libc::geteuid() } == policy.service_uid,
        "watchdog service UID mismatch"
    );
    Ok(build_operator_with_status(policy, authority, Some(status)))
}
fn build_operator_with_status(
    policy: OperatorBrakePolicy,
    authority: Arc<dyn StopAuthority>,
    status: Option<Arc<dyn StopStatusAuthority>>,
) -> Router {
    Router::new()
        .route("/stop", post(stop))
        .route("/status", post(status_route))
        .layer(DefaultBodyLimit::max(1024))
        .layer(middleware::from_fn_with_state(
            policy,
            authenticate_operator,
        ))
        .layer(middleware::from_fn(bounded_request))
        .with_state(Server {
            authority,
            status,
            permit: Arc::new(tokio::sync::Semaphore::new(16)),
        })
}
async fn status_route(State(state): State<Server>, Json(request): Json<StopRequest>) -> Response {
    if !ulid::Ulid::from_string(&request.target).is_ok_and(|id| id.to_string() == request.target) {
        return (
            StatusCode::BAD_REQUEST,
            "invalid registered target identity",
        )
            .into_response();
    }
    let Some(status) = state.status else {
        return (StatusCode::CONFLICT, "status unavailable").into_response();
    };
    let Ok(permit) = state.permit.try_acquire_owned() else {
        return (StatusCode::TOO_MANY_REQUESTS, "brake capacity exhausted").into_response();
    };
    let work = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        status.status(&request.target)
    });
    match tokio::time::timeout(Duration::from_secs(3), work).await {
        Ok(Ok(Ok(value))) => (StatusCode::OK, Json(value)).into_response(),
        Ok(Ok(Err(_))) => (StatusCode::CONFLICT, "status unavailable").into_response(),
        _ => (StatusCode::SERVICE_UNAVAILABLE, "status unavailable").into_response(),
    }
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
    impl StopStatusAuthority for Authority {
        fn status(&self, target: &str) -> Result<StopObservation> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            ensure!(target == self.target, "unknown target");
            Ok(StopObservation {
                target_id: target.into(),
                boot_id: "test".into(),
                cgroup_dev: 1,
                cgroup_ino: 2,
                observed: true,
                observed_at_unix: Some(1),
                closed: true,
                frozen: true,
                empty: true,
                engine_reconciled: false,
            })
        }
    }
    #[tokio::test]
    async fn operator_policy_denies_wrong_peer_ordinary_token_and_duplicate_keys() {
        let authority = Arc::new(Authority {
            target: ulid::Ulid::new().to_string(),
            calls: AtomicUsize::new(0),
        });
        let policy = crate::OperatorBrakePolicy::new(
            2003,
            1000,
            2000,
            2001,
            2002,
            2004,
            BrakeSecret::new([7; 32]).unwrap(),
        )
        .unwrap();
        let router = build_operator_with_status(policy, authority.clone(), Some(authority.clone()));
        let request = |peer: u32, key: &str, duplicate: bool, target: &str| {
            let mut req = Request::builder()
                .method("POST")
                .uri("/stop")
                .header("content-type", "application/json")
                .header("x-brake-key", key);
            if duplicate {
                req = req.header("x-brake-key", key);
            }
            req.extension(ConnectInfo(BrakePeer { uid: Some(peer) }))
                .body(Body::from(format!("{{\"target\":\"{target}\"}}")))
                .unwrap()
        };
        let key = "07".repeat(32);
        for (peer, secret, duplicate) in [
            (2001, key.as_str(), false),
            (1000, "approval-bearer", false),
            (1000, key.as_str(), true),
        ] {
            assert_eq!(
                router
                    .clone()
                    .oneshot(request(peer, secret, duplicate, &authority.target))
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
                .oneshot(request(1000, &key, false, &ulid::Ulid::new().to_string()))
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            router
                .oneshot(request(1000, &key, false, &authority.target))
                .await
                .unwrap()
                .status(),
            StatusCode::ACCEPTED
        );
    }

    #[tokio::test]
    async fn status_requires_same_peer_and_key_and_hides_unknown_targets() {
        let uid = unsafe { libc::geteuid() };
        let a = Arc::new(Authority {
            target: ulid::Ulid::new().to_string(),
            calls: AtomicUsize::new(0),
        });
        let policy = BrakePolicy {
            service_uid: uid,
            brake_uid: uid,
            secret: Arc::new(BrakeSecret::new([7; 32]).unwrap()),
        };
        let router = build_with_status(policy, a.clone(), Some(a.clone()));
        let request = |peer: u32, key: &str, target: &str| {
            Request::builder()
                .method("POST")
                .uri("/status")
                .header("content-type", "application/json")
                .header("x-brake-key", key)
                .extension(ConnectInfo(BrakePeer { uid: Some(peer) }))
                .body(Body::from(format!("{{\"target\":\"{target}\"}}")))
                .unwrap()
        };
        let key = "07".repeat(32);
        for (peer, secret) in [(uid.wrapping_add(1), key.as_str()), (uid, "wrong")] {
            assert_eq!(
                router
                    .clone()
                    .oneshot(request(peer, secret, &a.target))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::FORBIDDEN
            );
        }
        assert_eq!(a.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            router
                .clone()
                .oneshot(request(uid, &key, &ulid::Ulid::new().to_string()))
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        let response = router.oneshot(request(uid, &key, &a.target)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 2048)
            .await
            .unwrap();
        let value: StopObservation = serde_json::from_slice(&body).unwrap();
        assert!(value.observed && value.closed && value.frozen && value.empty);
        assert!(!value.engine_reconciled);
        assert_eq!(value.target_id, a.target);
        assert_eq!(a.calls.load(Ordering::SeqCst), 2);
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
