//! Independent stop-only brake component. No control-plane, journal, gateway or DB dependency.
//! No production daemon is enabled. The optional binary is a disposable verification fixture.
//! Only children spawned by this registry can be targeted; no PID registration API exists.
pub mod broker;
#[cfg(feature = "fixture")]
pub mod guarded_release;
#[cfg(feature = "fixture")]
pub mod recovery_latch;
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
    /// Launches admitted before stop but still inside the OS spawn operation.
    pub pending_launches: usize,
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
    pending_launches: usize,
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
            pending_launches: self.pending_launches,
            signal_sent: self.pending_launches == 0
                && !groups.is_empty()
                && groups.iter().all(|g| g.signal_sent),
            leader_reaped: self.pending_launches == 0 && groups.iter().all(|g| g.leader_reaped),
            group_absent: self.pending_launches == 0 && groups.iter().all(|g| g.group_absent),
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
    entries: Mutex<BTreeMap<String, Arc<Mutex<OwnedFamily>>>>,
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
        ensure!(
            !entries.contains_key(&target),
            "family identifier collision"
        );
        entries.insert(
            target.clone(),
            Arc::new(Mutex::new(OwnedFamily {
                children: Vec::new(),
                closed: false,
                pending_launches: 0,
            })),
        );
        Ok(target)
    }
    /// Directly spawn another root (worker, Goose or tool) under the watchdog's ownership.
    /// Admission reserves a pending slot before spawning. A stop closes admission without
    /// waiting for a stalled spawn and reports the unresolved reservation. A late child is
    /// retained and stopped, but can briefly execute before spawn returns; this is not a
    /// containment boundary and must not be used to claim that an unresolved stop succeeded.
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
        let entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("registry unavailable"))?;
        let family = entries
            .get(target)
            .context("unknown managed family")?
            .clone();
        drop(entries);
        let mut family_state = family
            .lock()
            .map_err(|_| anyhow::anyhow!("family unavailable"))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis();
        ensure!(
            now < u128::from(expires_ms),
            "launch deadline elapsed while waiting for family admission"
        );
        ensure!(!family_state.closed, "family is closed to further launches");
        ensure!(
            family_state.children.len() + family_state.pending_launches < 16,
            "family group capacity exhausted; no ownership records evicted"
        );
        family_state.pending_launches += 1;
        drop(family_state);
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
        let spawned = command.process_group(0).spawn();
        // A poisoned registry must not cause a successfully spawned Child to be dropped.
        // Retain it in the recovered allocation, close admission, and attempt cleanup
        // using only owned Child handles. The registry remains poisoned afterwards.
        let (mut family_state, poisoned) = match family.lock() {
            Ok(family) => (family, false),
            Err(error) => (error.into_inner(), true),
        };
        let family = &mut *family_state;
        family.pending_launches = family.pending_launches.saturating_sub(1);
        let registry_poisoned = self.entries.is_poisoned();
        if poisoned || registry_poisoned {
            family.closed = true;
        }
        let mut child = match spawned {
            Ok(child) => child,
            Err(error) => {
                if poisoned || registry_poisoned {
                    let _ = stop_family(target, family);
                }
                return Err(error.into());
            }
        };
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
        // Admission can expire while the kernel or child setup is stalled. Quarantine
        // the entire family rather than accepting an action after its deadline.
        let expired = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(true, |now| now.as_millis() >= u128::from(expires_ms));
        if expired {
            family.closed = true;
        }
        if poisoned || registry_poisoned {
            drop(pipes);
            let cleanup = stop_family(target, family);
            anyhow::bail!(
                "registry unavailable after launch; owned cleanup: {}",
                if cleanup
                    .as_ref()
                    .is_ok_and(|result| result.leader_reaped && result.group_absent)
                {
                    "completed"
                } else {
                    "unresolved"
                }
            );
        }
        let stopped_during_spawn = family.closed;
        if stopped_during_spawn {
            drop(pipes);
            let result = stop_family(target, family)?;
            ensure!(
                result.leader_reaped && result.group_absent,
                "late launch cleanup unresolved"
            );
            anyhow::bail!("family stopped or launch expired while launch was pending");
        }
        drop(family_state);
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
        let entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("registry unavailable"))?;
        let family = entries.get(target).context("unknown family")?.clone();
        drop(entries);
        let mut family_state = family
            .lock()
            .map_err(|_| anyhow::anyhow!("family unavailable"))?;
        let record = family_state
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
            if let Err(error) = signal_owned_group(record) {
                // Fixture-only availability concession: XNU returns EPERM when the
                // unreaped zombie is the sole group member. Require positive complete
                // enumeration and later absence. This is not an atomic containment proof.
                let only_zombie = error.chain().any(|cause| {
                    cause
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.raw_os_error() == Some(libc::EPERM))
                }) && fixture_sole_unreaped_member(record.pgid);
                if !only_zombie {
                    return Err(error.context("group signal unresolved"));
                }
                record.attempted = true;
            }
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
        let entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("registry unavailable"))?;
        let family = entries
            .get(target)
            .context("target is not owned by this watchdog")?
            .clone();
        drop(entries);
        let mut family_state = family
            .lock()
            .map_err(|_| anyhow::anyhow!("family unavailable"))?;
        stop_family(target, &mut family_state)
    }
    fn try_stop(&self, target: &str) -> Result<StopResult> {
        let entries = self
            .entries
            .try_lock()
            .map_err(|_| anyhow::anyhow!("registry busy or unavailable"))?;
        let family = entries
            .get(target)
            .context("target is not owned by this watchdog")?
            .clone();
        drop(entries);
        let mut family_state = family
            .try_lock()
            .map_err(|_| anyhow::anyhow!("family busy or unavailable"))?;
        stop_family(target, &mut family_state)
    }
}
fn stop_family(target: &str, family: &mut OwnedFamily) -> Result<StopResult> {
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
        // A stalled spawn has no Child handle yet. Do not hold the registry lock waiting
        // for it and do not present an empty group set as successful termination.
        if result.pending_launches != 0
            && (result
                .groups
                .iter()
                .all(|group| group.leader_reaped && group.group_absent)
                || Instant::now() >= deadline)
        {
            ensure!(!fault, "at least one owned group stop is unresolved");
            return Ok(result);
        }
        if (result.leader_reaped && result.group_absent) || Instant::now() >= deadline {
            ensure!(!fault, "at least one owned group stop is unresolved");
            return Ok(result);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn signal_owned_group(record: &mut OwnedChild) -> Result<()> {
    signal_owned_group_with(record, |pgid| {
        if unsafe { libc::kill(-pgid, libc::SIGKILL) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    })
}
fn signal_owned_group_with(
    record: &mut OwnedChild,
    signal: impl FnOnce(i32) -> std::io::Result<()>,
) -> Result<()> {
    check_reaping_policy()?;
    ensure!(record.child.is_some(), "ownership handle missing");
    // Do NOT reap before signalling. The retained Child keeps the PID reserved even if its
    // leader exited naturally. Child ownership validation does not accept arbitrary PIDs.
    ensure!(
        owned_group_is_safe(record.pgid),
        "owned process left its registered group; manual recovery required"
    );
    match signal(record.pgid) {
        Ok(()) => record.result.signal_sent = true,
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {}
        Err(error) => {
            return Err(
                anyhow::Error::new(error).context("owned group signal failed; outcome unresolved")
            );
        }
    }
    // Only release the owned leader for reaping once signalling succeeded or the
    // group was already absent. Failed signals retain the handle for a safe retry.
    record.attempted = true;
    Ok(())
}
#[cfg(all(feature = "fixture", target_os = "macos"))]
fn fixture_sole_unreaped_member(pid: i32) -> bool {
    let mut members = [0_i32; 1024];
    let bytes = unsafe {
        libc::proc_listpids(
            2,
            pid as u32,
            members.as_mut_ptr().cast(),
            std::mem::size_of_val(&members) as i32,
        )
    };
    bytes == std::mem::size_of::<i32>() as i32 && members[0] == pid
}
#[cfg(all(feature = "fixture", not(target_os = "macos")))]
fn fixture_sole_unreaped_member(_pid: i32) -> bool {
    false
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
        let entries = self
            .entries
            .get_mut()
            .unwrap_or_else(|error| error.into_inner());
        for family in entries.values_mut() {
            let mut family_state = family.lock().unwrap_or_else(|error| error.into_inner());
            for record in &mut family_state.children {
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
            permit: Arc::new(tokio::sync::Semaphore::new(16)),
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
            "brake capacity exhausted; retry same target",
        )
            .into_response();
    };
    let stopped = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        state.registry.try_stop(&request.target)
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
    fn failed_group_signal_keeps_owned_leader_for_retry() {
        let registry = Registry::new().unwrap();
        let target = registry
            .spawn_owned(Command::new("/bin/sleep").arg("30"))
            .unwrap();
        let family = registry.entries.lock().unwrap()[&target].clone();
        let (attempted, retained) = {
            let mut state = family.lock().unwrap();
            let record = &mut state.children[0];
            assert!(
                signal_owned_group_with(record, |_| Err(std::io::Error::from_raw_os_error(
                    libc::EPERM
                )))
                .is_err()
            );
            let attempted = record.attempted;
            let retained = record.child.is_some();
            // Restore this owned fixture so even the red test cleans up safely.
            record.attempted = false;
            (attempted, retained)
        };
        let stopped = registry.stop(&target).unwrap();
        assert!(stopped.signal_sent && stopped.leader_reaped && stopped.group_absent);
        assert!(!attempted, "failed kill must not permit reap");
        assert!(retained, "owned wait handle was lost");
        let mut state = family.lock().unwrap();
        let record = &mut state.children[0];
        let called = std::cell::Cell::new(false);
        assert!(
            signal_owned_group_with(record, |_| {
                called.set(true);
                Ok(())
            })
            .is_err()
        );
        assert!(
            !called.get(),
            "must never signal after the owned leader is reaped"
        );
    }
    #[test]
    fn registry_rejects_unowned_target_without_signalling() {
        let registry = Registry::new().unwrap();
        assert!(registry.stop("forged").is_err());
        assert_eq!(registry.len(), 0);
    }
    #[test]
    fn slow_family_cleanup_does_not_block_another_family() {
        let registry = Arc::new(Registry::new().unwrap());
        let slow = registry
            .spawn_owned(Command::new("/bin/sleep").arg("30"))
            .unwrap();
        let fast = registry
            .spawn_owned(Command::new("/bin/sleep").arg("30"))
            .unwrap();
        assert!(registry.stop(&slow).unwrap().leader_reaped);
        {
            let family = registry.entries.lock().unwrap()[&slow].clone();
            let mut state = family.lock().unwrap();
            let record = &mut state.children[0];
            // Simulate unresolved observation only; never signal this already reaped PID.
            record.result.leader_reaped = false;
            record.result.group_absent = false;
        }
        let slow_registry = registry.clone();
        let slow_target = slow.clone();
        let thread = std::thread::spawn(move || slow_registry.stop(&slow_target).unwrap());
        let deadline = Instant::now() + Duration::from_secs(1);
        let slow_family = registry.entries.lock().unwrap()[&slow].clone();
        while slow_family.try_lock().is_ok() {
            assert!(Instant::now() < deadline, "slow stop did not start");
            std::thread::yield_now();
        }
        let started = Instant::now();
        let result = registry.stop(&fast).unwrap();
        let elapsed = started.elapsed();
        let slow_result = thread.join().unwrap();
        assert!(!slow_result.group_absent);
        assert!(result.leader_reaped && result.group_absent);
        assert!(
            elapsed < Duration::from_secs(1),
            "unrelated stop waited {elapsed:?}"
        );
    }
    #[tokio::test]
    async fn brake_request_capacity_is_bounded_and_recovers() {
        let registry = Arc::new(Registry::new().unwrap());
        let target = registry
            .spawn_owned(Command::new("/bin/sleep").arg("30"))
            .unwrap();
        let permit = Arc::new(tokio::sync::Semaphore::new(16));
        let held = permit.clone().try_acquire_many_owned(16).unwrap();
        let state = ServerState { registry, permit };
        let response = stop_handler(
            State(state.clone()),
            Json(StopRequest {
                target: target.clone(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        drop(held);
        let response = stop_handler(State(state), Json(StopRequest { target })).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    #[tokio::test]
    async fn busy_family_request_does_not_consume_brake_capacity() {
        let registry = Arc::new(Registry::new().unwrap());
        let busy = registry.create_family().unwrap();
        let fast = registry
            .spawn_owned(Command::new("/bin/sleep").arg("30"))
            .unwrap();
        let family = registry.entries.lock().unwrap()[&busy].clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let holder = std::thread::spawn(move || {
            let _guard = family.lock().unwrap();
            ready_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        ready_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let state = ServerState {
            registry: registry.clone(),
            permit: Arc::new(tokio::sync::Semaphore::new(16)),
        };
        for _ in 0..32 {
            let response = stop_handler(
                State(state.clone()),
                Json(StopRequest {
                    target: busy.clone(),
                }),
            )
            .await;
            assert_eq!(response.status(), StatusCode::CONFLICT);
        }
        let response = stop_handler(State(state), Json(StopRequest { target: fast })).await;
        assert_eq!(response.status(), StatusCode::OK);
        release_tx.send(()).unwrap();
        holder.join().unwrap();
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
        let family = registry.entries.lock().unwrap()[&target].clone();
        let pid = family.lock().unwrap().children[0].pgid;
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
        assert!(family.lock().unwrap().children[0].child.is_some());
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
        let fresh_family = other.entries.lock().unwrap()[&fresh_target].clone();
        let fresh_pid = fresh_family.lock().unwrap().children[0].pgid;
        // Fault injection simulates a recycled numeric group ID after the original reap.
        // The survivor is also this test's own child, never an existing user process.
        {
            let family = registry.entries.lock().unwrap()[&target].clone();
            let mut state = family.lock().unwrap();
            let old = &mut state.children[0];
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
            if stopped.pending_launches != 0 {
                assert!(!stopped.leader_reaped && !stopped.group_absent);
                assert!(launched.is_err());
            }
            let final_stop = registry.stop(&family).unwrap();
            assert_eq!(final_stop.pending_launches, 0);
            assert!(final_stop.leader_reaped && final_stop.group_absent);
            if launched.is_ok() {
                assert_eq!(final_stop.groups.len(), 1);
            }
        }
    }
    #[test]
    fn deadline_expiring_during_child_setup_quarantines_late_launch() {
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;
        let registry = Arc::new(Registry::new().unwrap());
        let family = registry.create_family().unwrap();
        let (mut parent, child) = UnixStream::pair().unwrap();
        parent
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let fd = child.as_raw_fd();
        let parent_fd = parent.as_raw_fd();
        let deadline = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 500;
        let launch_registry = registry.clone();
        let launch_family = family.clone();
        let launcher = std::thread::spawn(move || {
            let _socket = child;
            let mut command = Command::new("/bin/sleep");
            command.arg("30");
            unsafe {
                command.pre_exec(move || {
                    libc::close(parent_fd);
                    let b = [1_u8];
                    if libc::write(fd, b.as_ptr().cast(), 1) != 1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    let mut release = [0_u8];
                    if libc::read(fd, release.as_mut_ptr().cast(), 1) != 1 {
                        return Err(std::io::Error::other("probe release failed"));
                    }
                    Ok(())
                });
            }
            launch_registry.spawn_in_family_before(&launch_family, &mut command, deadline)
        });
        let mut ready = [0];
        parent.read_exact(&mut ready).unwrap();
        while std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            <= u128::from(deadline)
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        parent.write_all(&[1]).unwrap();
        assert!(launcher.join().unwrap().is_err());
        let stopped = registry.stop(&family).unwrap();
        assert_eq!(stopped.pending_launches, 0);
        assert!(stopped.leader_reaped && stopped.group_absent);
        assert!(
            registry
                .spawn_in_family(&family, &mut Command::new("/bin/true"))
                .is_err()
        );
    }
    #[test]
    fn poisoned_registry_keeps_and_stops_child_returning_from_spawn() {
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;
        let registry = Arc::new(Registry::new().unwrap());
        let family = registry.create_family().unwrap();
        let (mut control, child_control) = UnixStream::pair().unwrap();
        let (mut output, child_output) = UnixStream::pair().unwrap();
        control
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        output
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let control_fd = child_control.as_raw_fd();
        let output_fd = child_output.as_raw_fd();
        let parent_control_fd = control.as_raw_fd();
        let parent_output_fd = output.as_raw_fd();
        let launch_registry = registry.clone();
        let launch_family = family.clone();
        let launcher = std::thread::spawn(move || {
            let _sockets = (child_control, child_output);
            let mut command = Command::new("/bin/sh");
            command.args(["-c", "sleep 30 & echo ready; wait"]);
            unsafe {
                command.pre_exec(move || {
                    libc::close(parent_control_fd);
                    libc::close(parent_output_fd);
                    let b = [1_u8];
                    if libc::write(control_fd, b.as_ptr().cast(), 1) != 1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    let mut release = [0_u8];
                    if libc::read(control_fd, release.as_mut_ptr().cast(), 1) != 1 {
                        return Err(std::io::Error::other("probe release failed"));
                    }
                    if libc::dup2(output_fd, libc::STDOUT_FILENO) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            launch_registry.spawn_in_family(&launch_family, &mut command)
        });
        let mut ready = [0];
        control.read_exact(&mut ready).unwrap();
        let poison_family = registry.entries.lock().unwrap()[&family].clone();
        let (locked_tx, locked_rx) = std::sync::mpsc::sync_channel(0);
        let (observed_tx, observed_rx) = std::sync::mpsc::sync_channel(0);
        let poisoner = std::thread::spawn(move || {
            let _guard = poison_family.lock().unwrap();
            locked_tx.send(()).unwrap();
            let mut line = [0_u8; 6];
            let observed = output.read_exact(&mut line).is_ok() && &line == b"ready\n";
            observed_tx.send((observed, output)).unwrap();
            panic!("intentional registry poison");
        });
        locked_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        control.write_all(&[1]).unwrap();
        let (observed, mut output) = observed_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(poisoner.join().is_err());
        let result = launcher.join().unwrap();
        assert!(result.is_err());
        assert!(observed, "shell did not start its descendant");
        let mut after = [0];
        assert_eq!(
            output.read(&mut after).unwrap(),
            0,
            "owned group still holds output open"
        );
        let poisoned_family = registry.entries.lock().unwrap()[&family].clone();
        let state = match poisoned_family.lock() {
            Err(error) => error.into_inner(),
            Ok(_) => panic!("registry was not poisoned"),
        };
        let record = &state.children[0];
        assert!(record.result.leader_reaped && record.result.group_absent);
        assert!(record.child.is_none());
    }
    #[test]
    fn poisoned_index_quarantines_a_child_returning_from_spawn() {
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;
        let registry = Arc::new(Registry::new().unwrap());
        let family = registry.create_family().unwrap();
        let owned_family = registry.entries.lock().unwrap()[&family].clone();
        let (mut control, child_control) = UnixStream::pair().unwrap();
        control
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let fd = child_control.as_raw_fd();
        let parent_fd = control.as_raw_fd();
        let launch_registry = registry.clone();
        let launcher = std::thread::spawn(move || {
            let _socket = child_control;
            let mut command = Command::new("/bin/sleep");
            command.arg("30");
            unsafe {
                command.pre_exec(move || {
                    libc::close(parent_fd);
                    let b = [1_u8];
                    if libc::write(fd, b.as_ptr().cast(), 1) != 1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    let mut release = [0_u8];
                    if libc::read(fd, release.as_mut_ptr().cast(), 1) != 1 {
                        return Err(std::io::Error::other("probe release failed"));
                    }
                    Ok(())
                });
            }
            launch_registry.spawn_in_family(&family, &mut command)
        });
        let mut ready = [0];
        control.read_exact(&mut ready).unwrap();
        let poison_registry = registry.clone();
        assert!(
            std::thread::spawn(move || {
                let _guard = poison_registry.entries.lock().unwrap();
                panic!("intentional index poison");
            })
            .join()
            .is_err()
        );
        control.write_all(&[1]).unwrap();
        assert!(launcher.join().unwrap().is_err());
        let state = owned_family.lock().unwrap();
        assert!(
            state.closed
                && state.children[0].result.leader_reaped
                && state.children[0].result.group_absent
        );
    }
}
