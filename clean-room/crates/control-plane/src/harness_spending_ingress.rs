//! Private spending ingress. A fixed owner and kernel UID roles create no worker
//! authority. Provisioning must isolate the underlying SDK socket from every caller
//! except this service and fence predecessor dispatch before root bootstrap.

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, Request, State, connect_info::Connected},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    serve::IncomingStream,
};
use serde_json::Value;
use std::{
    future::Future,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::Semaphore,
};

const BODY_LIMIT: usize = 1_048_576;

#[derive(Debug)]
pub struct Refused(u16, &'static str);
impl Refused {
    pub(crate) fn new(code: u16, message: &'static str) -> Self {
        Self(code, message)
    }
}
impl IntoResponse for Refused {
    fn into_response(self) -> Response {
        (
            StatusCode::from_u16(self.0).unwrap_or(StatusCode::BAD_GATEWAY),
            self.1,
        )
            .into_response()
    }
}

#[derive(Clone, Debug)]
pub struct Policy {
    service_uid: u32,
    root_uid: u32,
    broker_uid: u32,
    collector_uid: u32,
    worker_uid: u32,
    owner: String,
}
impl Policy {
    /// All identities and the sole owner come from protected bootstrap, never JSON
    /// or headers. Root administration is specifically UID 0, not a user alias.
    pub fn new(
        service_uid: u32,
        broker_uid: u32,
        collector_uid: u32,
        worker_uid: u32,
        owner: String,
    ) -> anyhow::Result<Self> {
        let roles = [0, service_uid, broker_uid, collector_uid, worker_uid];
        anyhow::ensure!(
            roles
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == roles.len(),
            "distinct spending identities required"
        );
        anyhow::ensure!(scope(&owner), "invalid spending owner");
        Ok(Self {
            service_uid,
            root_uid: 0,
            broker_uid,
            collector_uid,
            worker_uid,
            owner,
        })
    }
    fn allows(&self, uid: u32, method: &str) -> bool {
        if uid == self.worker_uid {
            return false;
        }
        match method {
            "initialize" | "admit_attempt" | "admit_day" | "revoke" => uid == self.root_uid,
            "reserve" | "begin" | "verify_inflight" => uid == self.broker_uid,
            "claim_receipts" | "complete" => uid == self.collector_uid,
            _ => false,
        }
    }
}
fn scope(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
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

/// A trusted fixed-owner journal transport. No worker-selected service, owner,
/// endpoint or path is forwarded. Failed mutations may already be committed.
pub trait Journal: Send + Sync + 'static {
    fn owner(&self) -> &str;
    fn call(
        &self,
        method: &'static str,
        body: Value,
    ) -> impl Future<Output = Result<Value, Refused>> + Send;
}
struct Context<J> {
    policy: Policy,
    journal: Arc<J>,
    inflight: Arc<Semaphore>,
}
impl<J> Clone for Context<J> {
    fn clone(&self) -> Self {
        Self {
            policy: self.policy.clone(),
            journal: self.journal.clone(),
            inflight: self.inflight.clone(),
        }
    }
}
fn decode<T: serde::de::DeserializeOwned + serde::Serialize>(raw: &[u8]) -> Result<Value, Refused> {
    let value: T =
        serde_json::from_slice(raw).map_err(|_| Refused::new(400, "invalid spending body"))?;
    serde_json::to_value(value).map_err(|_| Refused::new(400, "invalid spending body"))
}

pub fn router<J: Journal>(policy: Policy, journal: Arc<J>) -> anyhow::Result<Router> {
    anyhow::ensure!(
        unsafe { libc::geteuid() } == policy.service_uid,
        "spending service identity mismatch"
    );
    anyhow::ensure!(
        journal.owner() == policy.owner,
        "spending backend owner mismatch"
    );
    Ok(scoped_router(policy, journal))
}
fn scoped_router<J: Journal>(policy: Policy, journal: Arc<J>) -> Router {
    Router::new()
        .route("/spending/{method}", post(dispatch::<J>))
        .with_state(Context {
            policy,
            journal,
            inflight: Arc::new(Semaphore::new(8)),
        })
}
async fn dispatch<J: Journal>(
    State(ctx): State<Context<J>>,
    request: Request,
) -> Result<Json<Value>, Refused> {
    let method = match request.uri().path() {
        "/spending/initialize" => "initialize",
        "/spending/admit_attempt" => "admit_attempt",
        "/spending/admit_day" => "admit_day",
        "/spending/revoke" => "revoke",
        "/spending/reserve" => "reserve",
        "/spending/begin" => "begin",
        "/spending/verify_inflight" => "verify_inflight",
        "/spending/claim_receipts" => "claim_receipts",
        "/spending/complete" => "complete",
        _ => return Err(Refused::new(404, "spending method unavailable")),
    };
    let uid = request
        .extensions()
        .get::<ConnectInfo<Peer>>()
        .and_then(|v| v.0.uid)
        .ok_or_else(|| Refused::new(403, "spending peer unavailable"))?;
    if !ctx.policy.allows(uid, method) || request.uri().query().is_some() {
        return Err(Refused::new(403, "spending role denied"));
    }
    let permit = ctx
        .inflight
        .clone()
        .try_acquire_owned()
        .map_err(|_| Refused::new(429, "spending ingress busy"))?;
    let raw = tokio::time::timeout(
        Duration::from_secs(2),
        to_bytes(request.into_body(), BODY_LIMIT),
    )
    .await
    .map_err(|_| Refused::new(408, "spending body timed out"))?
    .map_err(|_| Refused::new(413, "spending body exceeds limit"))?;
    use crate::harness_spending::{
        AttemptScope, Bootstrap, Call, CollectorReceipt, DayInventory, GenerationClaim,
    };
    let value = match method {
        "initialize" => decode::<Bootstrap>(&raw)?,
        "admit_attempt" => decode::<AttemptScope>(&raw)?,
        "admit_day" => decode::<DayInventory>(&raw)?,
        "revoke" => decode::<String>(&raw)?,
        "reserve" | "begin" | "verify_inflight" => decode::<Call>(&raw)?,
        "claim_receipts" => decode::<GenerationClaim>(&raw)?,
        "complete" => decode::<CollectorReceipt>(&raw)?,
        _ => return Err(Refused::new(404, "spending method unavailable")),
    };
    if method == "initialize"
        && value.get("owner").and_then(Value::as_str) != Some(ctx.policy.owner.as_str())
    {
        return Err(Refused::new(403, "spending owner mismatch"));
    }
    // Once durable mutation starts, no request-wide cancellation/deadline is
    // installed. Client disconnect cannot manufacture a safe retry or rollback.
    let journal = ctx.journal.clone();
    let job = tokio::spawn(async move {
        let _permit = permit;
        journal.call(method, value).await
    });
    Ok(Json(job.await.map_err(|_| {
        Refused::new(503, "spending outcome unknown")
    })??))
}

/// Kernel-authenticated HTTP/1 Unix serving, bounded even for silent peers. The
/// caller owns a privately provisioned socket; no pathname removal is performed.
pub async fn serve(listener: UnixListener, app: Router) -> std::io::Result<()> {
    use hyper::{server::conn::http1, service::service_fn};
    use hyper_util::rt::{TokioIo, TokioTimer};
    use tower::ServiceExt;
    let connections = Arc::new(Semaphore::new(16));
    loop {
        let (stream, _) = listener.accept().await?;
        let uid = stream.peer_cred().ok().map(|p| p.uid());
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            continue;
        };
        let app = app.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                let app = app.clone();
                async move {
                    let mut request = request.map(Body::new);
                    request.extensions_mut().insert(ConnectInfo(Peer { uid }));
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

pub struct PrivateUnixJournal {
    client: reqwest::Client,
    path: PathBuf,
    uid: u32,
    identity: (u64, u64),
    owner: String,
}
impl PrivateUnixJournal {
    pub async fn new(path: PathBuf, uid: u32, owner: String) -> anyhow::Result<Self> {
        anyhow::ensure!(uid > 0 && scope(&owner), "invalid private spending backend");
        let identity = check_socket(&path, uid)?;
        bounded_acls(&path).await?;
        let peer =
            tokio::time::timeout(Duration::from_secs(5), UnixStream::connect(&path)).await??;
        anyhow::ensure!(
            peer.peer_cred()?.uid() == uid,
            "private spending backend peer mismatch"
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
            uid,
            identity,
            owner,
        })
    }
}
impl Journal for PrivateUnixJournal {
    fn owner(&self) -> &str {
        &self.owner
    }
    async fn call(&self, method: &'static str, body: Value) -> Result<Value, Refused> {
        if !matches!(
            method,
            "initialize"
                | "admit_attempt"
                | "admit_day"
                | "revoke"
                | "reserve"
                | "begin"
                | "verify_inflight"
                | "claim_receipts"
                | "complete"
        ) {
            return Err(Refused::new(403, "private spending method denied"));
        }
        let check = || check_socket(&self.path, self.uid).ok() == Some(self.identity);
        if !check() {
            return Err(Refused::new(503, "private spending backend changed"));
        }
        bounded_acls(&self.path)
            .await
            .map_err(|_| Refused::new(503, "private spending ACL unavailable"))?;
        let peer = tokio::time::timeout(Duration::from_secs(5), UnixStream::connect(&self.path))
            .await
            .map_err(|_| Refused::new(503, "private spending backend unavailable"))?
            .map_err(|_| Refused::new(503, "private spending backend unavailable"))?;
        if peer.peer_cred().ok().map(|p| p.uid()) != Some(self.uid) {
            return Err(Refused::new(503, "private spending backend peer mismatch"));
        }
        let url = format!(
            "http://localhost/restate/call/HarnessSpending/{}/{method}",
            self.owner
        );
        let mut response = self
            .client
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|_| Refused::new(503, "durable spending outcome unknown"))?;
        let code = response.status().as_u16();
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| Refused::new(503, "durable spending reply incomplete"))?
        {
            if bytes.len().saturating_add(chunk.len()) > 65536 {
                return Err(Refused::new(502, "durable spending reply exceeds limit"));
            }
            bytes.extend_from_slice(&chunk);
        }
        if !check() || bounded_acls(&self.path).await.is_err() {
            return Err(Refused::new(503, "private spending backend changed"));
        }
        if !(200..300).contains(&code) {
            return Err(Refused::new(
                if matches!(code, 400 | 403 | 404 | 409 | 410 | 429) {
                    code
                } else {
                    502
                },
                "durable spending rejected; outcome retained",
            ));
        }
        if bytes.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&bytes)
            .map_err(|_| Refused::new(502, "invalid durable spending reply"))
    }
}

async fn bounded_acls(path: &Path) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), check_acls(path)).await?
}
fn check_socket(path: &Path, uid: u32) -> anyhow::Result<(u64, u64)> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    anyhow::ensure!(path.is_absolute(), "absolute spending socket required");
    let m = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        m.file_type().is_socket() && m.uid() == uid && m.mode() & 0o777 == 0o600,
        "private spending socket must be service-owned0600"
    );
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("missing spending socket parent"))?;
    let p = std::fs::symlink_metadata(parent)?;
    anyhow::ensure!(
        p.is_dir() && p.uid() == uid && p.mode() & 0o777 == 0o700,
        "private spending parent must be service-owned0700"
    );
    for ancestor in parent.ancestors() {
        let m = std::fs::symlink_metadata(ancestor)?;
        anyhow::ensure!(
            m.is_dir()
                && !m.file_type().is_symlink()
                && (m.uid() == 0 || m.uid() == uid)
                && m.mode() & 0o022 == 0,
            "untrusted spending socket ancestor"
        );
    }
    Ok((m.dev(), m.ino()))
}
#[cfg(target_os = "macos")]
async fn check_acls(path: &Path) -> anyhow::Result<()> {
    for entry in path.ancestors() {
        let text = entry
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("invalid spending socket path"))?;
        anyhow::ensure!(
            !text.chars().any(char::is_control),
            "invalid spending socket path"
        );
        let mut command = tokio::process::Command::new("/bin/ls");
        command.args(["-lde", text]).env_clear().kill_on_drop(true);
        let output = tokio::time::timeout(Duration::from_secs(3), command.output()).await??;
        anyhow::ensure!(
            output.status.success() && output.stdout.len() <= 16384,
            "spending ACL inspection failed"
        );
        anyhow::ensure!(
            std::str::from_utf8(&output.stdout)?
                .lines()
                .skip(1)
                .all(|l| l.trim() == "0: group:everyone deny delete"),
            "spending ACL needs review"
        );
    }
    Ok(())
}
#[cfg(target_os = "linux")]
async fn check_acls(path: &Path) -> anyhow::Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    for entry in path.ancestors() {
        let raw = entry.as_os_str().as_bytes();
        anyhow::ensure!(
            !raw.iter().any(u8::is_ascii_control),
            "invalid spending socket path"
        );
        let entry = CString::new(raw)?;
        let mut fs = std::mem::MaybeUninit::<libc::statfs>::uninit();
        anyhow::ensure!(
            unsafe { libc::statfs(entry.as_ptr(), fs.as_mut_ptr()) } == 0,
            "spending filesystem unavailable"
        );
        anyhow::ensure!(
            unsafe { fs.assume_init() }.f_type == 0xef53,
            "unsupported spending filesystem"
        );
        for name in [c"system.posix_acl_access", c"system.posix_acl_default"] {
            anyhow::ensure!(
                unsafe { libc::lgetxattr(entry.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) }
                    < 0
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA),
                "spending ACL needs review"
            );
        }
    }
    Ok(())
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
async fn check_acls(_: &Path) -> anyhow::Result<()> {
    anyhow::bail!("private spending ACL unsupported")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;
    struct Backend(AtomicUsize);
    impl Journal for Backend {
        fn owner(&self) -> &str {
            "factory"
        }
        async fn call(&self, _: &'static str, _: Value) -> Result<Value, Refused> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(Value::Null)
        }
    }
    fn policy() -> Policy {
        Policy::new(1000, 1001, 1002, 1003, "factory".into()).unwrap()
    }
    fn call_body() -> String {
        serde_json::json!({"call_id":"call","scope_sha256":"a".repeat(64),"request_sha256":"b".repeat(64),"sequence":0,"request_bytes":1,"output_tokens":1}).to_string()
    }
    fn bootstrap_body(owner: &str) -> String {
        serde_json::json!({"owner":owner,"policy_sha256":"a".repeat(64),"predecessor_fence_sha256":"b".repeat(64),"inventory_sha256":"c".repeat(64),"observed_at_ms":100,"approved_daily_cap_microusd":5000000,"daily_cap_microusd":5000000,"opening_tasks":{"task":0},"opening_days":{"0":0},"scopes":[]}).to_string()
    }
    fn receipt_body() -> String {
        serde_json::json!({"call_id":"call","scope_sha256":"a".repeat(64),"request_sha256":"b".repeat(64),"route_sha256":"c".repeat(64),"manifest_sha256":"d".repeat(64),"components":{},"generation_ids":[],"billed_microusd":0}).to_string()
    }
    async fn request(app: Router, uid: Option<u32>, method: &str, body: &str) -> StatusCode {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("/spending/{method}"))
            .header("x-peer-uid", "0")
            .body(Body::from(body.to_owned()))
            .unwrap();
        if let Some(uid) = uid {
            request
                .extensions_mut()
                .insert(ConnectInfo(Peer { uid: Some(uid) }));
        }
        app.oneshot(request).await.unwrap().status()
    }
    #[tokio::test]
    async fn roles_deny_before_body_and_never_forward_owner_or_worker_overrides() {
        let backend = Arc::new(Backend(AtomicUsize::new(0)));
        let app = scoped_router(policy(), backend.clone());
        for uid in [None, Some(1000), Some(1003), Some(1999)] {
            assert_eq!(
                request(app.clone(), uid, "reserve", "not-json").await,
                StatusCode::FORBIDDEN
            );
        }
        assert_eq!(
            request(app.clone(), Some(1001), "complete", "{}").await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            request(app.clone(), Some(1002), "begin", "{}").await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            request(app.clone(), Some(0), "initialize", &bootstrap_body("other")).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(backend.0.load(Ordering::SeqCst), 0);
        assert_eq!(
            request(app.clone(), Some(1001), "reserve", &call_body()).await,
            StatusCode::OK
        );
        assert_eq!(
            request(app.clone(), Some(1002), "complete", &receipt_body()).await,
            StatusCode::OK
        );
        assert_eq!(
            request(app, Some(0), "initialize", &bootstrap_body("factory")).await,
            StatusCode::OK
        );
        assert_eq!(backend.0.load(Ordering::SeqCst), 3);
    }
    #[test]
    fn identity_configuration_cannot_alias_roles_or_encode_owner_paths() {
        assert!(Policy::new(1000, 1000, 1002, 1003, "factory".into()).is_err());
        assert!(Policy::new(1000, 1001, 1002, 1003, "../other".into()).is_err());
    }
    #[tokio::test]
    async fn inflight_verification_is_broker_only_and_strictly_typed() {
        let backend = Arc::new(Backend(AtomicUsize::new(0)));
        let app = scoped_router(policy(), backend.clone());
        for uid in [None, Some(0), Some(1000), Some(1002), Some(1003), Some(1999)] {
            assert_eq!(request(app.clone(), uid, "verify_inflight", &call_body()).await, StatusCode::FORBIDDEN);
        }
        for invalid in ["{}".to_owned(), call_body().replacen('{', "{\"owner\":\"other\",", 1)] {
            assert_eq!(request(app.clone(), Some(1001), "verify_inflight", &invalid).await, StatusCode::BAD_REQUEST);
        }
        assert_eq!(backend.0.load(Ordering::SeqCst), 0);
        assert_eq!(request(app, Some(1001), "verify_inflight", &call_body()).await, StatusCode::OK);
        assert_eq!(backend.0.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn typed_inputs_reject_duplicate_fields_unknown_keys_and_oversize_before_journal() {
        let backend = Arc::new(Backend(AtomicUsize::new(0)));
        let app = scoped_router(policy(), backend.clone());
        let body = call_body();
        let duplicate = format!("{{\"sequence\":2,{}", &body[1..]);
        for invalid in [
            "{}".to_owned(),
            duplicate,
            body.replacen('{', "{\"owner\":\"other\",", 1),
        ] {
            assert_eq!(
                request(app.clone(), Some(1001), "reserve", &invalid).await,
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(
            request(app, Some(1001), "reserve", &" ".repeat(BODY_LIMIT + 1)).await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(backend.0.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn disconnected_requests_retain_inflight_capacity_until_durable_job_finishes() {
        struct Blocking {
            started: AtomicUsize,
            completed: AtomicUsize,
            release: Semaphore,
        }
        impl Journal for Blocking {
            fn owner(&self) -> &str {
                "factory"
            }
            async fn call(&self, _: &'static str, _: Value) -> Result<Value, Refused> {
                self.started.fetch_add(1, Ordering::SeqCst);
                let permit = self.release.acquire().await.unwrap();
                permit.forget();
                self.completed.fetch_add(1, Ordering::SeqCst);
                Ok(Value::Null)
            }
        }
        let backend = Arc::new(Blocking {
            started: AtomicUsize::new(0),
            completed: AtomicUsize::new(0),
            release: Semaphore::new(0),
        });
        let app = scoped_router(policy(), backend.clone());
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let app = app.clone();
                tokio::spawn(async move { request(app, Some(1001), "reserve", &call_body()).await })
            })
            .collect();
        tokio::time::timeout(Duration::from_secs(3), async {
            while backend.started.load(Ordering::SeqCst) != 8 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        for task in tasks {
            task.abort();
        }
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(3),
                request(app.clone(), Some(1001), "reserve", &call_body())
            )
            .await
            .expect("busy ingress must refuse without waiting on a new journal job"),
            StatusCode::TOO_MANY_REQUESTS
        );
        backend.release.add_permits(8);
        tokio::time::timeout(Duration::from_secs(3), async {
            while backend.completed.load(Ordering::SeqCst) != 8 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        backend.release.add_permits(1);
        assert_eq!(
            request(app, Some(1001), "reserve", &call_body()).await,
            StatusCode::OK
        );
    }
    #[tokio::test]
    async fn real_unix_socket_uses_kernel_peer_and_ignores_forged_privileged_header() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let uid = unsafe { libc::geteuid() };
        let backend = Arc::new(Backend(AtomicUsize::new(0)));
        let policy = if uid == 0 {
            Policy::new(1, 2, 3, 4, "factory".into()).unwrap()
        } else {
            Policy::new(uid + 1, uid + 2, uid + 3, uid, "factory".into()).unwrap()
        };
        let forged_uid = policy.broker_uid;
        let app = scoped_router(policy, backend.clone());
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("hr-{}", ulid::Ulid::new()));
        std::fs::create_dir(&root).unwrap();
        let socket = root.join("s");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(serve(listener, app));
        let mut stream = UnixStream::connect(&socket).await.unwrap();
        let body = call_body();
        let wire = format!(
            "POST /spending/reserve HTTP/1.1\r\nHost: localhost\r\nX-Peer-Uid: {forged_uid}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(wire.as_bytes()).await.unwrap();
        let mut reply = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert!(reply.starts_with(b"HTTP/1.1 403"));
        assert_eq!(backend.0.load(Ordering::SeqCst), 0);
        server.abort();
        std::fs::remove_file(socket).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
    #[tokio::test]
    async fn private_backend_uses_actual_unix_peer_and_refuses_socket_replacement() {
        use std::os::unix::fs::PermissionsExt;
        let uid = unsafe { libc::geteuid() };
        if uid == 0 {
            eprintln!("private backend same-UID fixture requires non-root test user");
            return;
        }
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("hb-{}", ulid::Ulid::new()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = root.join("s");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let app = Router::new().route(
            "/restate/call/HarnessSpending/factory/reserve",
            post(|| async { Json("Reserved") }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let backend = PrivateUnixJournal::new(socket.clone(), uid, "factory".into())
            .await
            .unwrap();
        assert_eq!(
            backend
                .call("reserve", serde_json::from_str(&call_body()).unwrap())
                .await
                .unwrap(),
            Value::String("Reserved".into())
        );
        std::fs::remove_file(&socket).unwrap();
        let replacement = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            backend.call("reserve", Value::Null).await.unwrap_err().0,
            503
        );
        server.abort();
        drop(replacement);
        std::fs::remove_file(socket).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
