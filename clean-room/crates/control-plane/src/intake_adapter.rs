//! Unregistered, single-principal private intake. The deployment must separately bind
//! this adapter's trusted backend to the same immutable IntakeJournal principal.
use crate::{
    intake::{IntakeRequest, StoredIntake, submit_once, valid_principal},
    worker_adapter::{AdapterError, UnixRestateBackend},
};
use axum::{
    Extension, Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Request, State, connect_info::Connected},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
    serve::IncomingStream,
};
use serde::Deserialize;
use std::{future::Future, sync::Arc};
use tokio::net::{UnixListener, UnixStream};

const BODY_LIMIT: usize = 64 * 1024;
#[derive(Clone)]
pub struct IntakePolicy {
    service_uid: u32,
    submitter_uid: u32,
    principal: String,
}
impl IntakePolicy {
    pub fn new(service_uid: u32, submitter_uid: u32, principal: String) -> anyhow::Result<Self> {
        anyhow::ensure!(
            service_uid > 0
                && submitter_uid > 0
                && service_uid != submitter_uid
                && valid_principal(&principal),
            "invalid intake identity scope"
        );
        Ok(Self {
            service_uid,
            submitter_uid,
            principal,
        })
    }
}
#[derive(Clone, Debug)]
pub struct IntakePeer {
    uid: Option<u32>,
}
impl Connected<IncomingStream<'_, UnixListener>> for IntakePeer {
    fn connect_info(stream: IncomingStream<'_, UnixListener>) -> Self {
        Self {
            uid: stream.io().peer_cred().ok().map(|c| c.uid()),
        }
    }
}
#[derive(Clone)]
struct AuthenticatedIntake(String);
async fn authenticate(
    State(policy): State<IntakePolicy>,
    mut request: Request,
    next: Next,
) -> Response {
    if request
        .extensions()
        .get::<ConnectInfo<IntakePeer>>()
        .and_then(|p| p.0.uid)
        != Some(policy.submitter_uid)
    {
        return AdapterError::new(403, "intake peer identity missing or mismatched")
            .into_response();
    }
    request
        .extensions_mut()
        .insert(AuthenticatedIntake(policy.principal));
    next.run(request).await
}
/// Trusted backend configuration must bind the declared principal to the actual journal.
/// Network timeouts remain unknown outcomes; callers retry the same key and request.
pub trait IntakeBackend: Send + Sync + 'static {
    fn principal(&self) -> &str;
    fn submit(
        &self,
        key: String,
        request: IntakeRequest,
    ) -> impl Future<Output = Result<StoredIntake, AdapterError>> + Send;
    fn inspect(
        &self,
        key: String,
    ) -> impl Future<Output = Result<Option<StoredIntake>, AdapterError>> + Send;
}
pub struct UnixIntakeBackend {
    backend: UnixRestateBackend,
    principal: String,
}
impl UnixIntakeBackend {
    pub fn new(backend: UnixRestateBackend, principal: String) -> anyhow::Result<Self> {
        anyhow::ensure!(
            valid_principal(&principal),
            "invalid configured journal principal"
        );
        Ok(Self { backend, principal })
    }
}
impl IntakeBackend for UnixIntakeBackend {
    fn principal(&self) -> &str {
        &self.principal
    }
    async fn submit(
        &self,
        key: String,
        request: IntakeRequest,
    ) -> Result<StoredIntake, AdapterError> {
        self.backend
            .call("IntakeJournal", &key, "submit", Some(&request))
            .await
    }
    async fn inspect(&self, key: String) -> Result<Option<StoredIntake>, AdapterError> {
        self.backend
            .call::<(), _>("IntakeJournal", &key, "inspect", None)
            .await
    }
}
/// Requires a protected Unix listener served with `IntakePeer` connect information.
/// Neither this constructor nor backend verifies remote Restate registration or reachability.
pub fn intake_router<B: IntakeBackend>(
    policy: IntakePolicy,
    backend: Arc<B>,
) -> anyhow::Result<Router> {
    anyhow::ensure!(
        policy.principal == backend.principal(),
        "journal principal mismatch"
    );
    anyhow::ensure!(
        tokio::runtime::Handle::try_current().is_ok(),
        "Tokio runtime required"
    );
    let (a, _b) = UnixStream::pair()?;
    anyhow::ensure!(
        a.peer_cred()?.uid() == policy.service_uid,
        "configured service UID mismatch"
    );
    Ok(scoped_router(policy, backend))
}
fn scoped_router<B: IntakeBackend>(policy: IntakePolicy, backend: Arc<B>) -> Router {
    Router::new()
        .route("/submit", post(submit::<B>))
        .route("/inspect", post(inspect::<B>))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(middleware::from_fn_with_state(policy, authenticate))
        .with_state(backend)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Submit {
    key: String,
    request: IntakeRequest,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inspect {
    key: String,
}
fn valid_key(key: &str) -> bool {
    ulid::Ulid::from_string(key).is_ok_and(|u| u.to_string() == key)
}
async fn submit<B: IntakeBackend>(
    State(backend): State<Arc<B>>,
    Extension(identity): Extension<AuthenticatedIntake>,
    Json(body): Json<Submit>,
) -> Result<Json<StoredIntake>, AdapterError> {
    submit_once(None, &body.key, &identity.0, body.request.clone(), 0)
        .map_err(|_| AdapterError::new(400, "invalid intake request"))?;
    let stored = backend
        .submit(body.key.clone(), body.request.clone())
        .await?;
    submit_once(Some(&stored), &body.key, &identity.0, body.request, 0)
        .map_err(|_| AdapterError::new(502, "journal reply does not match intake binding"))?;
    Ok(Json(stored))
}
async fn inspect<B: IntakeBackend>(
    State(backend): State<Arc<B>>,
    Extension(identity): Extension<AuthenticatedIntake>,
    Json(body): Json<Inspect>,
) -> Result<Json<Option<StoredIntake>>, AdapterError> {
    if !valid_key(&body.key) {
        return Err(AdapterError::new(400, "invalid intake key"));
    }
    let stored = backend.inspect(body.key.clone()).await?;
    if let Some(value) = &stored {
        submit_once(
            Some(value),
            &body.key,
            &identity.0,
            value.request.clone(),
            0,
        )
        .map_err(|_| AdapterError::new(502, "journal reply does not match intake binding"))?;
    }
    Ok(Json(stored))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashMap,
        os::unix::fs::PermissionsExt,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };
    const KEY: &str = "01J00000000000000000000000";
    struct Backend {
        principal: String,
        records: Mutex<HashMap<String, StoredIntake>>,
        calls: AtomicUsize,
    }
    impl IntakeBackend for Backend {
        fn principal(&self) -> &str {
            &self.principal
        }
        async fn submit(
            &self,
            key: String,
            request: IntakeRequest,
        ) -> Result<StoredIntake, AdapterError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut records = self.records.lock().unwrap();
            let value = submit_once(records.get(&key), &key, &self.principal, request, 100)
                .map_err(|_| AdapterError::new(409, "conflict"))?;
            records.insert(key, value.clone());
            Ok(value)
        }
        async fn inspect(&self, key: String) -> Result<Option<StoredIntake>, AdapterError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.records.lock().unwrap().get(&key).cloned())
        }
    }
    fn uid() -> u32 {
        UnixStream::pair().unwrap().0.peer_cred().unwrap().uid()
    }
    fn backend() -> Arc<Backend> {
        Arc::new(Backend {
            principal: "operator-1".into(),
            records: Mutex::new(HashMap::new()),
            calls: AtomicUsize::new(0),
        })
    }
    fn policy(submitter: u32) -> IntakePolicy {
        IntakePolicy::new(uid() + 1, submitter, "operator-1".into()).unwrap()
    }
    fn body() -> serde_json::Value {
        serde_json::json!({"key": KEY, "request": {"schema_version": 1,"repository":"org/repo","target_ref":"refs/heads/main","base_revision":"a".repeat(40),"intent":"Add parser","acceptance_criteria":["Reject invalid input"]}})
    }
    struct Fixture {
        path: std::path::PathBuf,
        root: std::path::PathBuf,
        task: tokio::task::JoinHandle<()>,
        client: reqwest::Client,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.task.abort();
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_dir(&self.root);
        }
    }
    impl Fixture {
        async fn new(policy: IntakePolicy, backend: Arc<Backend>) -> Self {
            let root = std::path::PathBuf::from(format!("/tmp/sfia-{}", &shared::new_id()[10..]));
            std::fs::create_dir(&root).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            let path = root.join("s");
            let listener = UnixListener::bind(&path).unwrap();
            let router = scoped_router(policy, backend);
            let task = tokio::spawn(async move {
                axum::serve(
                    listener,
                    router.into_make_service_with_connect_info::<IntakePeer>(),
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
                path,
                root,
                task,
                client,
            }
        }
        async fn post(&self, path: &str, data: serde_json::Value) -> reqwest::Response {
            self.client
                .post(format!("http://localhost{path}"))
                .json(&data)
                .send()
                .await
                .unwrap()
        }
    }
    #[tokio::test]
    async fn real_peer_retry_conflict_and_inspection() {
        let b = backend();
        let f = Fixture::new(policy(uid()), b).await;
        let first: StoredIntake = f.post("/submit", body()).await.json().await.unwrap();
        assert_eq!(first.submitted_by, "operator-1");
        let again: StoredIntake = f.post("/submit", body()).await.json().await.unwrap();
        assert_eq!(first, again);
        let mut changed = body();
        changed["request"]["intent"] = "changed".into();
        assert_eq!(f.post("/submit", changed).await.status(), 409);
        let inspected: Option<StoredIntake> = f
            .post("/inspect", serde_json::json!({"key": KEY}))
            .await
            .json()
            .await
            .unwrap();
        assert_eq!(inspected, Some(first));
    }
    #[tokio::test]
    async fn forged_identity_unknown_routes_and_oversized_reject_before_backend() {
        let b = backend();
        let f = Fixture::new(policy(uid() + 2), b.clone()).await;
        let response = f
            .client
            .post("http://localhost/submit")
            .header("x-submitter-uid", uid() + 2)
            .json(&body())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
        assert_eq!(b.calls.load(Ordering::SeqCst), 0);
        let f = Fixture::new(policy(uid()), b.clone()).await;
        let mut spoof = body();
        spoof["request"]["submitted_by"] = "other".into();
        assert_eq!(f.post("/submit", spoof).await.status(), 422);
        let mut large = body();
        large["request"]["intent"] = "x".repeat(BODY_LIMIT).into();
        assert_eq!(f.post("/submit", large).await.status(), 413);
        assert_eq!(f.post("/schedule", body()).await.status(), 404);
        assert_eq!(
            f.post("/inspect", serde_json::json!({"key":"../../bad"}))
                .await
                .status(),
            400
        );
        assert_eq!(b.calls.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn missing_peer_and_principal_or_service_mismatch_fail_closed() {
        use tower::ServiceExt;
        let b = backend();
        assert!(intake_router(policy(uid()), b.clone()).is_err());
        let p = IntakePolicy::new(uid(), uid() + 1, "other".into()).unwrap();
        assert!(intake_router(p, b.clone()).is_err());
        let response = scoped_router(policy(uid()), b.clone())
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/submit")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body().to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
        assert_eq!(b.calls.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn foreign_journal_record_is_not_disclosed() {
        let b = backend();
        let req: IntakeRequest = serde_json::from_value(body()["request"].clone()).unwrap();
        b.records.lock().unwrap().insert(
            KEY.into(),
            submit_once(None, KEY, "other", req, 100).unwrap(),
        );
        let f = Fixture::new(policy(uid()), b).await;
        assert_eq!(
            f.post("/inspect", serde_json::json!({"key":KEY}))
                .await
                .status(),
            502
        );
    }
}
