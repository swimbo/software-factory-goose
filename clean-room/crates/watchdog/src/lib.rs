//! Independent stop-only brake component. No control-plane, journal, gateway or DB dependency.
//! No production daemon is enabled. The optional binary is a disposable verification fixture.
//! Only children spawned by this registry can be targeted; no PID registration API exists.
pub mod broker;
use anyhow::{Context, Result, ensure};
use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Request, State, connect_info::Connected},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
    serve::IncomingStream,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    os::unix::process::{CommandExt, ExitStatusExt},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::net::UnixListener;
type CapturedPipes = (
    std::process::ChildStdin,
    std::process::ChildStdout,
    std::process::ChildStderr,
);
const MAX_REGISTERED: usize = 64;
const STOP_WAIT: Duration = Duration::from_secs(2);

/// Never Debug/Serialize; provision through a separate trusted channel, not argv or models.
/// This type does not prove entropy, protected storage, human presence, or MFA.
pub struct BrakeSecret([u8; 32]);
impl BrakeSecret {
    pub fn new(bytes: [u8; 32]) -> Result<Self> {
        ensure!(bytes.iter().any(|b| *b != 0), "empty brake credential");
        Ok(Self(bytes))
    }
    fn matches(&self, provided: Option<&str>) -> bool {
        let Some(text) = provided else {
            return false;
        };
        let mut decoded = [0u8; 32];
        let mut valid = text.len() == 64;
        for (index, out) in decoded.iter_mut().enumerate() {
            let pair = text
                .as_bytes()
                .get(index * 2..index * 2 + 2)
                .unwrap_or(&[0, 0]);
            let decode = |b: u8| match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                _ => None,
            };
            let a = decode(pair[0]);
            let b = decode(pair[1]);
            valid &= a.is_some() && b.is_some();
            *out = (a.unwrap_or(0) << 4) | b.unwrap_or(0);
        }
        // Fixed-size secret comparison uses the existing constant-time primitive.
        bool::from(self.0.ct_eq(&decoded)) && valid
    }
}
#[derive(Clone)]
pub struct BrakePolicy {
    service_uid: u32,
    brake_uid: u32,
    secret: Arc<BrakeSecret>,
}
impl BrakePolicy {
    /// Ordinary service/operator/generator/evaluator UIDs must all be excluded. Account and
    /// protected credential provisioning remain deployment gates; UID is not human presence.
    pub fn new(
        service_uid: u32,
        brake_uid: u32,
        ordinary_uids: Vec<u32>,
        secret: BrakeSecret,
    ) -> Result<Self> {
        let mut ids = BTreeSet::new();
        ensure!(
            ordinary_uids.len() >= 4 && ordinary_uids.len() <= 64,
            "explicit ordinary identity exclusions required"
        );
        for uid in [service_uid, brake_uid].into_iter().chain(ordinary_uids) {
            ensure!(
                uid > 0 && ids.insert(uid),
                "brake, watchdog and ordinary identities must be distinct non-root UIDs"
            );
        }
        Ok(Self {
            service_uid,
            brake_uid,
            secret: Arc::new(secret),
        })
    }
    fn authorized(&self, peer: Option<u32>, credential: Option<&str>) -> bool {
        let key_matches = self.secret.matches(credential);
        peer == Some(self.brake_uid) && key_matches
    }
}
/// Kernel-issued connection metadata. Never accepted from a request body or header.
#[derive(Clone, Debug)]
pub struct BrakePeer {
    uid: Option<u32>,
}
impl Connected<IncomingStream<'_, UnixListener>> for BrakePeer {
    fn connect_info(stream: IncomingStream<'_, UnixListener>) -> Self {
        Self {
            uid: stream.io().peer_cred().ok().map(|c| c.uid()),
        }
    }
}
async fn authenticate(State(policy): State<BrakePolicy>, request: Request, next: Next) -> Response {
    let uid = request
        .extensions()
        .get::<ConnectInfo<BrakePeer>>()
        .and_then(|peer| peer.0.uid);
    let mut credentials = request.headers().get_all("x-brake-key").iter();
    let credential = credentials.next().and_then(|v| v.to_str().ok());
    if credentials.next().is_some() || !policy.authorized(uid, credential) {
        return (StatusCode::FORBIDDEN, "brake authentication failed").into_response();
    }
    next.run(request).await
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StopRequest {
    pub target: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupStopResult {
    pub member: String,
    pub signal_sent: bool,
    pub leader_reaped: bool,
    pub group_absent: bool,
    pub leader_signal: Option<i32>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StopResult {
    pub target: String,
    /// Aggregate fields require every registered group, not merely the worker leader.
    pub signal_sent: bool,
    pub leader_reaped: bool,
    /// Observed registered group absence, not proof that an unregistered child never escaped.
    pub group_absent: bool,
    pub leader_signal: Option<i32>,
    pub groups: Vec<GroupStopResult>,
}
struct OwnedChild {
    child: Option<Child>,
    pgid: i32,
    attempted: bool,
    result: GroupStopResult,
    exit_code: Option<i32>,
}
struct OwnedFamily {
    children: Vec<OwnedChild>,
    closed: bool,
}
impl OwnedFamily {
    fn snapshot(&self, target: &str) -> StopResult {
        let groups: Vec<_> = self
            .children
            .iter()
            .map(|child| child.result.clone())
            .collect();
        let signal = groups.first().and_then(|group| group.leader_signal);
        StopResult {
            target: target.into(),
            signal_sent: !groups.is_empty() && groups.iter().all(|g| g.signal_sent),
            leader_reaped: groups.iter().all(|g| g.leader_reaped),
            group_absent: groups.iter().all(|g| g.group_absent),
            leader_signal: signal.filter(|_| groups.iter().all(|g| g.leader_signal == signal)),
            groups,
        }
    }
}
/// Dedicated-process ownership registry. Never share this process with a generic SIGCHLD
/// reaper or call waitpid on these children outside this type. SIGCHLD auto-reap is refused.
/// Each target is a managed family of directly spawned group roots, not a discovered PID tree.
/// Records never evict or reuse IDs. Restart recovery is deliberately not implemented.
pub struct Registry {
    entries: Mutex<BTreeMap<String, OwnedFamily>>,
}
impl Registry {
    pub fn new() -> Result<Self> {
        check_reaping_policy()?;
        Ok(Self {
            entries: Mutex::new(BTreeMap::new()),
        })
    }
    pub fn len(&self) -> usize {
        self.entries.lock().expect("registry mutex poisoned").len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Reserve a bounded family before any worker/tool launch. Only trusted in-process code
    /// can call this API; there is no network registration or caller-supplied process ID.
    pub fn create_family(&self) -> Result<String> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("registry unavailable"))?;
        ensure!(
            entries.len() < MAX_REGISTERED,
            "registry capacity exhausted; no tombstones evicted"
        );
        let target = ulid::Ulid::new().to_string();
        entries.insert(
            target.clone(),
            OwnedFamily {
                children: Vec::new(),
                closed: false,
            },
        );
        Ok(target)
    }
    /// Directly spawn another root (worker, Goose or tool) under the watchdog's ownership.
    /// Admission and stop share the same mutex: either the child is retained before stop,
    /// or stop closes admission before any spawn. There is no post-spawn registration gap.
    pub fn spawn_in_family(&self, target: &str, command: &mut Command) -> Result<String> {
        self.spawn_in_family_before(target, command, u64::MAX)
    }
    pub(crate) fn spawn_in_family_before(
        &self,
        target: &str,
        command: &mut Command,
        expires_ms: u64,
    ) -> Result<String> {
        self.spawn_with_io(target, command, expires_ms, None)
            .map(|(member, _)| member)
    }
    fn spawn_with_io(
        &self,
        target: &str,
        command: &mut Command,
        expires_ms: u64,
        environment: Option<&BTreeMap<String, String>>,
    ) -> Result<(String, Option<CapturedPipes>)> {
        check_reaping_policy()?;
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("registry unavailable"))?;
        let family = entries.get_mut(target).context("unknown managed family")?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis();
        ensure!(
            now < u128::from(expires_ms),
            "launch deadline elapsed while waiting for family admission"
        );
        ensure!(!family.closed, "family is closed to further launches");
        ensure!(
            family.children.len() < 16,
            "family group capacity exhausted; no ownership records evicted"
        );
        command.env_clear();
        if let Some(environment) = environment {
            command
                .envs(environment)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
        } else {
            command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
        }
        let mut child = command.process_group(0).spawn()?;
        let pipes = environment.map(|_| {
            (
                child.stdin.take().expect("piped stdin"),
                child.stdout.take().expect("piped stdout"),
                child.stderr.take().expect("piped stderr"),
            )
        });
        let pgid = i32::try_from(child.id()).context("invalid owned PID")?;
        ensure!(pgid > 1, "unsafe owned process group");
        let member = ulid::Ulid::new().to_string();
        family.children.push(OwnedChild {
            child: Some(child),
            pgid,
            attempted: false,
            exit_code: None,
            result: GroupStopResult {
                member: member.clone(),
                signal_sent: false,
                leader_reaped: false,
                group_absent: false,
                leader_signal: None,
            },
        });
        Ok((member, pipes))
    }
    /// Fixture-only pipes, never Child/wait ownership. Exact environment belongs to trusted
    /// in-process admission. The default and production broker keep null stdio/env cleared.
    #[cfg(feature = "fixture")]
    pub(crate) fn spawn_fixture_capture(
        &self,
        target: &str,
        command: &mut Command,
        expires_ms: u64,
        environment: &BTreeMap<String, String>,
    ) -> Result<(String, CapturedPipes)> {
        let (member, pipes) = self.spawn_with_io(target, command, expires_ms, Some(environment))?;
        Ok((member, pipes.expect("requested captured pipes")))
    }
    #[cfg(feature = "fixture")]
    pub(crate) fn poll_fixture_capture(
        &self,
        target: &str,
        member: &str,
    ) -> Result<Option<(Option<i32>, Option<i32>)>> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("registry unavailable"))?;
        let record = entries
            .get_mut(target)
            .context("unknown family")?
            .children
            .iter_mut()
            .find(|r| r.result.member == member)
            .context("unknown member")?;
        if !record.attempted {
            let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
            ensure!(
                unsafe {
                    libc::waitid(
                        libc::P_PID,
                        record.pgid as libc::id_t,
                        &mut info,
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    )
                } == 0,
                "owned child status unavailable"
            );
            if unsafe { info.si_pid() } == 0 {
                return Ok(None);
            }
            // Natural exit still requires cleaning remaining group members BEFORE reaping.
            if signal_owned_group(record).is_err() && !record.attempted {
                anyhow::bail!("group ownership could not be established");
            }
            // macOS may report EPERM for a zombie-only group. Do not infer success:
            // reap this already-exited owned leader, never signal again, and require
            // observed ESRCH for the group below before releasing captured output.
        }
        if let Some(child) = record.child.as_mut()
            && let Some(status) = child.try_wait()?
        {
            record.exit_code = status.code();
            record.result.leader_signal = status.signal();
            record.result.leader_reaped = true;
            record.child = None;
        }
        if record.result.leader_reaped && !record.result.group_absent {
            record.result.group_absent = unsafe { libc::kill(-record.pgid, 0) } == -1
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
        }
        Ok((record.result.leader_reaped && record.result.group_absent)
            .then_some((record.exit_code, record.result.leader_signal)))
    }
    /// Compatibility convenience for a family with a single initial group root.
    pub fn spawn_owned(&self, command: &mut Command) -> Result<String> {
        let target = self.create_family()?;
        self.spawn_in_family(&target, command)?;
        Ok(target)
    }
    pub fn stop(&self, target: &str) -> Result<StopResult> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("registry unavailable"))?;
        let family = entries
            .get_mut(target)
            .context("target is not owned by this watchdog")?;
        family.closed = true; // Permanent and atomic with spawn admission, including failures.
        let mut fault = false;
        // Signal ALL owned groups before waiting on any member. A hung worker must not
        // delay signalling separately owned Goose/tool groups or require cooperation.
        for record in &mut family.children {
            if !record.attempted && signal_owned_group(record).is_err() {
                fault = true;
            }
        }
        let deadline = Instant::now() + STOP_WAIT;
        loop {
            for record in &mut family.children {
                // Do not release a child PID if group signalling never became safe.
                if !record.attempted {
                    continue;
                }
                if let Some(child) = record.child.as_mut()
                    && let Some(status) = child.try_wait()?
                {
                    record.result.leader_signal = status.signal();
                    record.exit_code = status.code();
                    record.result.leader_reaped = true;
                    record.child = None;
                }
                if record.result.leader_reaped && !record.result.group_absent {
                    // Zero observes only; never kill a potentially recycled numeric ID.
                    let found = unsafe { libc::kill(-record.pgid, 0) };
                    record.result.group_absent = found == -1
                        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
                }
            }
            let result = family.snapshot(target);
            if (result.leader_reaped && result.group_absent) || Instant::now() >= deadline {
                ensure!(!fault, "at least one owned group stop is unresolved");
                return Ok(result);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
fn signal_owned_group(record: &mut OwnedChild) -> Result<()> {
    check_reaping_policy()?;
    ensure!(record.child.is_some(), "ownership handle missing");
    // Do NOT reap before signalling. The retained Child keeps the PID reserved even if its
    // leader exited naturally. Child ownership validation does not accept arbitrary PIDs.
    ensure!(
        owned_group_is_safe(record.pgid),
        "owned process left its registered group; manual recovery required"
    );
    record.attempted = true;
    let result = unsafe { libc::kill(-record.pgid, libc::SIGKILL) };
    if result == 0 {
        record.result.signal_sent = true;
    } else {
        let error = std::io::Error::last_os_error();
        ensure!(
            error.raw_os_error() == Some(libc::ESRCH),
            "owned group signal failed: {error}; outcome unresolved"
        );
    }
    Ok(())
}
fn owned_group_is_safe(pid: i32) -> bool {
    // WNOWAIT proves the retained child relationship without releasing its PID. macOS
    // getpgid returns ESRCH for a zombie, so getpgid alone cannot validate that safe case.
    // SAFETY: positive PID from our private Child registry, initialized output buffer.
    let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
    let owned = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    } == 0;
    owned && (unsafe { info.si_pid() } == pid || unsafe { libc::getpgid(pid) } == pid)
}
fn check_reaping_policy() -> Result<()> {
    // SAFETY: sigaction with a null new action only reads this process's disposition.
    let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
    ensure!(
        unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } == 0,
        "SIGCHLD inspection failed"
    );
    ensure!(
        action.sa_sigaction == libc::SIG_DFL && action.sa_flags & libc::SA_NOCLDWAIT == 0,
        "dedicated watchdog requires default SIGCHLD and no external reaper"
    );
    Ok(())
}
impl Drop for Registry {
    fn drop(&mut self) {
        let Ok(entries) = self.entries.get_mut() else {
            return;
        };
        for record in entries.values_mut().flat_map(|family| &mut family.children) {
            if let Some(mut child) = record.child.take() {
                // Best-effort owned-child cleanup, never a success report. No nonzero signal
                // after an attempted stop; the background reap cannot target another PID.
                if !record.attempted
                    && check_reaping_policy().is_ok()
                    && owned_group_is_safe(record.pgid)
                {
                    unsafe { libc::kill(-record.pgid, libc::SIGKILL) };
                }
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
            }
        }
    }
}
#[derive(Clone)]
struct ServerState {
    registry: Arc<Registry>,
    permit: Arc<tokio::sync::Semaphore>,
}
/// Construct only in a separately supervised process with a separately provisioned private
/// Unix listener. No registration/start route or dependency on main-service auth exists.
pub fn brake_router(policy: BrakePolicy, registry: Arc<Registry>) -> Result<Router> {
    // SAFETY: geteuid reads the current process identity and cannot mutate it.
    ensure!(
        unsafe { libc::geteuid() } == policy.service_uid,
        "watchdog service UID mismatch"
    );
    Ok(scoped_router(policy, registry))
}
fn scoped_router(policy: BrakePolicy, registry: Arc<Registry>) -> Router {
    Router::new()
        .route("/stop", post(stop_handler))
        .layer(DefaultBodyLimit::max(1024))
        .layer(middleware::from_fn_with_state(policy, authenticate))
        .layer(middleware::from_fn(bounded_request))
        .with_state(ServerState {
            registry,
            permit: Arc::new(tokio::sync::Semaphore::new(1)),
        })
}
async fn bounded_request(request: Request, next: Next) -> Response {
    match tokio::time::timeout(Duration::from_secs(4), next.run(request)).await {
        Ok(response) => response,
        Err(_) => (
            StatusCode::REQUEST_TIMEOUT,
            "brake request timed out; retry same target",
        )
            .into_response(),
    }
}
async fn stop_handler(
    State(state): State<ServerState>,
    Json(request): Json<StopRequest>,
) -> Response {
    if ulid::Ulid::from_string(&request.target).is_err() || request.target.len() != 26 {
        return (
            StatusCode::BAD_REQUEST,
            "invalid registered target identity",
        )
            .into_response();
    }
    let Ok(permit) = state.permit.try_acquire_owned() else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "stop already in progress; retry same target",
        )
            .into_response();
    };
    let stopped = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        state.registry.stop(&request.target)
    });
    match tokio::time::timeout(Duration::from_secs(3), stopped).await {
        Ok(Ok(Ok(result))) => (
            if result.leader_reaped && result.group_absent {
                StatusCode::OK
            } else {
                StatusCode::ACCEPTED
            },
            Json(result),
        )
            .into_response(),
        Ok(Ok(Err(_))) => (
            StatusCode::CONFLICT,
            "target unowned or stop unverified; no termination claim",
        )
            .into_response(),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            "stop outcome unknown; retry same target",
        )
            .into_response(),
    }
}

/// Explicit disposable fixture surface only. Production policy has no same-UID bypass.
#[cfg(feature = "fixture")]
pub fn fixture_router(secret: BrakeSecret, registry: Arc<Registry>) -> Router {
    let uid = unsafe { libc::geteuid() };
    scoped_router(
        BrakePolicy {
            service_uid: uid,
            brake_uid: uid,
            secret: Arc::new(secret),
        },
        registry,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registry_rejects_unowned_target_without_signalling() {
        let registry = Registry::new().unwrap();
        assert!(registry.stop("forged").is_err());
        assert_eq!(registry.len(), 0);
    }
    #[test]
    fn actual_owned_child_is_killed_reaped_and_repeat_is_idempotent() {
        let registry = Registry::new().unwrap();
        let mut command = std::process::Command::new("/bin/sleep");
        command.arg("60");
        let target = registry.spawn_owned(&mut command).unwrap();
        let first = registry.stop(&target).unwrap();
        assert!(first.leader_reaped && first.group_absent && first.signal_sent);
        assert_eq!(registry.stop(&target).unwrap(), first);
    }
    #[test]
    fn ordinary_identity_and_wrong_brake_key_cannot_authenticate() {
        let key = BrakeSecret::new([7; 32]).unwrap();
        let policy = BrakePolicy::new(1001, 1002, vec![1003, 1004, 1005, 1006], key).unwrap();
        let credential = "07".repeat(32);
        assert!(policy.authorized(Some(1002), Some(&credential)));
        assert!(!policy.authorized(Some(1003), Some(&credential)));
        assert!(!policy.authorized(Some(1002), Some(&"08".repeat(32))));
        assert!(!policy.authorized(None, Some(&credential)));
        assert!(!policy.authorized(Some(1002), None));
    }
    #[test]
    fn naturally_exited_leader_is_not_reaped_before_group_signal() {
        let registry = Registry::new().unwrap();
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "/bin/sleep 60 & exit 0"]);
        let target = registry.spawn_owned(&mut command).unwrap();
        let pid = registry.entries.lock().unwrap()[&target].children[0].pgid;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let output = Command::new("/bin/ps")
                .args(["-o", "stat=", "-p", &pid.to_string()])
                .output()
                .unwrap();
            if String::from_utf8_lossy(&output.stdout).contains('Z') {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "owned leader did not become unreaped zombie"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            registry.entries.lock().unwrap()[&target].children[0]
                .child
                .is_some()
        );
        let result = registry.stop(&target).unwrap();
        assert!(result.leader_reaped && result.group_absent && result.signal_sent);
        assert_eq!(
            result.leader_signal, None,
            "leader exited naturally; group signal still killed descendant"
        );
        assert_eq!(registry.stop(&target).unwrap(), result);
    }
    #[test]
    fn post_reap_numeric_pid_reuse_never_sends_another_kill() {
        let registry = Registry::new().unwrap();
        let mut old = Command::new("/bin/sleep");
        old.arg("60");
        let target = registry.spawn_owned(&mut old).unwrap();
        assert!(registry.stop(&target).unwrap().leader_reaped);
        let other = Registry::new().unwrap();
        let mut fresh = Command::new("/bin/sleep");
        fresh.arg("60");
        let fresh_target = other.spawn_owned(&mut fresh).unwrap();
        let fresh_pid = other.entries.lock().unwrap()[&fresh_target].children[0].pgid;
        // Fault injection simulates a recycled numeric group ID after the original reap.
        // The survivor is also this test's own child, never an existing user process.
        {
            let mut entries = registry.entries.lock().unwrap();
            let old = &mut entries.get_mut(&target).unwrap().children[0];
            old.pgid = fresh_pid;
            old.result.group_absent = false;
        }
        let unverified = registry.stop(&target).unwrap();
        assert!(unverified.leader_reaped && !unverified.group_absent);
        assert_eq!(
            unsafe { libc::kill(fresh_pid, 0) },
            0,
            "repeated stop killed a replacement process"
        );
        assert!(other.stop(&fresh_target).unwrap().group_absent);
    }
    #[tokio::test]
    async fn real_kernel_peer_mismatch_and_missing_connection_info_deny() {
        use std::os::unix::fs::PermissionsExt;
        use tower::ServiceExt;
        let uid = unsafe { libc::geteuid() };
        let policy = BrakePolicy::new(
            uid,
            uid + 1,
            vec![uid + 2, uid + 3, uid + 4, uid + 5],
            BrakeSecret::new([7; 32]).unwrap(),
        )
        .unwrap();
        let router = brake_router(policy, Arc::new(Registry::new().unwrap())).unwrap();
        let no_peer = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/stop")
                    .header("x-brake-key", "07".repeat(32))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(format!(
                        r#"{{"target":"{}"}}"#,
                        ulid::Ulid::new()
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(no_peer.status(), StatusCode::FORBIDDEN);
        let root = std::path::PathBuf::from(format!(
            "/tmp/sfwd-auth-{}",
            &ulid::Ulid::new().to_string()[10..]
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("s");
        let listener = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<BrakePeer>(),
            )
            .await
            .unwrap();
        });
        struct Cleanup(std::path::PathBuf, tokio::task::JoinHandle<()>);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                self.1.abort();
                let _ = std::fs::remove_file(self.0.join("s"));
                let _ = std::fs::remove_dir(&self.0);
            }
        }
        let _cleanup = Cleanup(root, server);
        let client = reqwest::Client::builder()
            .unix_socket(path)
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let response = client
            .post("http://localhost/stop")
            .header("x-brake-key", "07".repeat(32))
            .header("x-brake-uid", uid + 1)
            .json(&StopRequest {
                target: ulid::Ulid::new().to_string(),
            })
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            403,
            "actual peer UID must beat forged header and valid key"
        );
    }
    #[test]
    fn family_stop_covers_multiple_owned_groups_and_closes_admission() {
        let registry = Registry::new().unwrap();
        let family = registry.create_family().unwrap();
        for _ in 0..3 {
            let mut command = Command::new("/bin/sleep");
            command.arg("60");
            registry.spawn_in_family(&family, &mut command).unwrap();
        }
        let result = registry.stop(&family).unwrap();
        assert_eq!(result.groups.len(), 3);
        assert!(
            result
                .groups
                .iter()
                .all(|group| group.leader_reaped && group.group_absent)
        );
        let mut late = Command::new("/bin/sleep");
        late.arg("60");
        assert!(registry.spawn_in_family(&family, &mut late).is_err());
        assert_eq!(registry.stop(&family).unwrap(), result);
    }
    #[test]
    fn racing_spawn_and_stop_never_leaves_an_unregistered_group() {
        for _ in 0..8 {
            let registry = Arc::new(Registry::new().unwrap());
            let family = registry.create_family().unwrap();
            let barrier = Arc::new(std::sync::Barrier::new(3));
            let (launch_registry, launch_family, launch_barrier) =
                (registry.clone(), family.clone(), barrier.clone());
            let launcher = std::thread::spawn(move || {
                launch_barrier.wait();
                let mut command = Command::new("/bin/sleep");
                command.arg("60");
                launch_registry.spawn_in_family(&launch_family, &mut command)
            });
            let (stop_registry, stop_family, stop_barrier) =
                (registry.clone(), family.clone(), barrier.clone());
            let stopper = std::thread::spawn(move || {
                stop_barrier.wait();
                stop_registry.stop(&stop_family).unwrap()
            });
            barrier.wait();
            let launched = launcher.join().unwrap();
            let stopped = stopper.join().unwrap();
            assert_eq!(stopped.groups.len(), usize::from(launched.is_ok()));
            assert!(stopped.leader_reaped && stopped.group_absent);
            assert_eq!(registry.stop(&family).unwrap(), stopped);
        }
    }
}
