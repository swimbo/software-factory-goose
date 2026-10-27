//! Unregistered trusted launch adapter. Requests contain only server-issued launch IDs.
//! No model-facing command admission, PID registration, output channel or production daemon.
use crate::{BrakePeer, BrakeSecret, Registry};
use anyhow::{Context, Result, ensure};
use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    os::unix::{fs::MetadataExt, process::CommandExt},
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
const MAX_LAUNCHES: usize = 1024;
fn now_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LaunchRole {
    Worker,
    Goose,
    Tool,
}
#[derive(PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
    mode: u32,
    uid: u32,
    gid: u32,
}
impl FileIdentity {
    fn read(path: &Path) -> Result<Self> {
        let m = std::fs::symlink_metadata(path)?;
        ensure!(
            !m.file_type().is_symlink(),
            "launch path replaced by symlink"
        );
        Ok(Self {
            dev: m.dev(),
            ino: m.ino(),
            len: m.len(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_ns: m.ctime_nsec(),
            mode: m.mode(),
            uid: m.uid(),
            gid: m.gid(),
        })
    }
}
/// Trusted in-process admission only: deliberately no Deserialize, getters or mutable fields.
/// Approval/claim/evidence eligibility must be established by the admitting adapter. This
/// captures configuration; it does not independently prove a journal claim or executable seal.
pub struct ApprovedLaunch {
    family: String,
    role: LaunchRole,
    program: PathBuf,
    arguments: Vec<OsString>,
    cwd: PathBuf,
    uid: u32,
    gid: u32,
    not_before_ms: u64,
    expires_ms: u64,
    executable: FileIdentity,
    directory: (u64, u64),
    #[cfg(feature = "fixture")]
    io: Option<FixtureIo>,
}
impl ApprovedLaunch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        family: String,
        role: LaunchRole,
        program: PathBuf,
        arguments: Vec<OsString>,
        cwd: PathBuf,
        uid: u32,
        gid: u32,
        not_before_ms: u64,
        expires_ms: u64,
    ) -> Result<Self> {
        ensure!(
            ulid::Ulid::from_string(&family).is_ok_and(|id| id.to_string() == family),
            "invalid family"
        );
        ensure!(
            program.is_absolute() && cwd.is_absolute(),
            "absolute launch paths required"
        );
        ensure!(
            arguments.len() <= 64 && arguments.iter().map(|a| a.len()).sum::<usize>() <= 65536,
            "arguments exceed bound"
        );
        ensure!(uid > 0 && gid > 0, "root launch denied");
        ensure!(
            expires_ms > not_before_ms && expires_ms - not_before_ms <= 300_000,
            "invalid launch validity window"
        );
        let program = program.canonicalize()?;
        let cwd = cwd.canonicalize()?;
        ensure!(
            program.is_file() && cwd.is_dir(),
            "launch paths have wrong type"
        );
        let executable = FileIdentity::read(&program)?;
        ensure!(
            executable.mode & 0o022 == 0 && executable.mode & 0o111 != 0,
            "executable must not be group/world writable"
        );
        let dir = FileIdentity::read(&cwd)?;
        Ok(Self {
            family,
            role,
            program,
            arguments,
            cwd,
            uid,
            gid,
            not_before_ms,
            expires_ms,
            executable,
            directory: (dir.dev, dir.ino),
            #[cfg(feature = "fixture")]
            io: None,
        })
    }
    #[cfg(feature = "fixture")]
    pub fn with_fixture_io(
        mut self,
        environment: BTreeMap<String, String>,
        stdin: Vec<u8>,
    ) -> Result<Self> {
        ensure!(
            environment.len() <= 32
                && environment
                    .iter()
                    .map(|(k, v)| k.len() + v.len())
                    .sum::<usize>()
                    <= 65536
                && stdin.len() <= 65536,
            "fixture IO bound exceeded"
        );
        self.io = Some(FixtureIo { environment, stdin });
        Ok(self)
    }
    fn validate(&self) -> Result<()> {
        let now = now_ms()?;
        ensure!(
            now >= self.not_before_ms && now < self.expires_ms,
            "launch is not currently valid"
        );
        ensure!(
            FileIdentity::read(&self.program)? == self.executable,
            "approved executable changed"
        );
        let dir = FileIdentity::read(&self.cwd)?;
        ensure!(
            (dir.dev, dir.ino) == self.directory,
            "approved directory changed"
        );
        Ok(())
    }
}
/// Separate trusted adapter identity and credential. UID config is not account provisioning.
/// No production router may share its identity with watchdog, brake, or child roles.
pub struct BrokerPolicy {
    service_uid: u32,
    adapter_uid: u32,
    child_uids: BTreeSet<u32>,
    secret: BrakeSecret,
}
impl BrokerPolicy {
    pub fn new(
        service_uid: u32,
        adapter_uid: u32,
        brake_uid: u32,
        child_uids: Vec<u32>,
        secret: BrakeSecret,
    ) -> Result<Self> {
        ensure!(
            !child_uids.is_empty() && child_uids.len() <= 64,
            "explicit child identities required"
        );
        let mut ids = BTreeSet::new();
        for uid in [service_uid, adapter_uid, brake_uid]
            .into_iter()
            .chain(child_uids.iter().copied())
        {
            ensure!(
                uid > 0 && ids.insert(uid),
                "spawn identities must be distinct non-root accounts"
            );
        }
        Ok(Self {
            service_uid,
            adapter_uid,
            child_uids: child_uids.into_iter().collect(),
            secret,
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SpawnReply {
    pub launch_id: String,
    pub target: String,
    pub member: String,
    pub role: LaunchRole,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchRequest {
    launch_id: String,
}
enum LaunchState {
    Approved,
    Failed,
    Spawned(SpawnReply),
}
struct Entry {
    spec: ApprovedLaunch,
    state: LaunchState,
    #[cfg(feature = "fixture")]
    capture: Option<FixtureCapture>,
}
pub struct SpawnBroker {
    registry: Arc<Registry>,
    policy: BrokerPolicy,
    entries: Mutex<BTreeMap<String, Entry>>,
    fixture: bool,
    permit: Arc<tokio::sync::Semaphore>,
}
impl SpawnBroker {
    pub fn new(registry: Arc<Registry>, policy: BrokerPolicy) -> Result<Self> {
        ensure!(
            unsafe { libc::geteuid() } == policy.service_uid,
            "broker service UID mismatch"
        );
        Ok(Self {
            registry,
            policy,
            entries: Mutex::new(BTreeMap::new()),
            fixture: false,
            permit: Arc::new(tokio::sync::Semaphore::new(1)),
        })
    }
    /// The publisher is trusted in-process code, never a serialized admission endpoint.
    /// Specs cannot be updated, reset, evicted or retried under the same ID after failure.
    pub fn admit(&self, spec: ApprovedLaunch) -> Result<String> {
        #[cfg(feature = "fixture")]
        ensure!(
            self.fixture || spec.io.is_none(),
            "captured IO is fixture-only"
        );
        ensure!(
            self.policy.child_uids.contains(&spec.uid),
            "child identity not admitted"
        );
        if !self.fixture {
            // OS ACLs, file sealing and an actual least-privilege launcher remain activation gates.
            for path in spec.program.ancestors() {
                let m = FileIdentity::read(path)?;
                ensure!(
                    (m.uid == 0 || m.uid == self.policy.service_uid) && m.mode & 0o022 == 0,
                    "executable ancestry is not protected"
                );
            }
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("broker unavailable"))?;
        ensure!(entries.len() < MAX_LAUNCHES, "launch capacity exhausted");
        let id = ulid::Ulid::new().to_string();
        entries.insert(
            id.clone(),
            Entry {
                spec,
                state: LaunchState::Approved,
                #[cfg(feature = "fixture")]
                capture: None,
            },
        );
        Ok(id)
    }
    fn launch(&self, id: &str) -> Result<SpawnReply> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("broker unavailable"))?;
        let entry = entries.get_mut(id).context("unknown launch")?;
        match &entry.state {
            LaunchState::Spawned(reply) => return Ok(reply.clone()),
            LaunchState::Failed => anyhow::bail!("launch failed; no automatic retry"),
            LaunchState::Approved => {}
        }
        // A lost HTTP reply cannot cause another spawn. Failure tombstones do not reset.
        entry.state = LaunchState::Failed;
        entry.spec.validate()?;
        let mut command = Command::new(&entry.spec.program);
        command
            .args(&entry.spec.arguments)
            .current_dir(&entry.spec.cwd);
        if !self.fixture {
            let uid = entry.spec.uid;
            let gid = entry.spec.gid;
            // Only async-signal-safe syscalls before exec; no allocation/locks. Current
            // non-root service cannot establish another UID: EPERM fails closed. A reviewed
            // platform launcher is still required, not privilege escalation in this library.
            unsafe {
                command.pre_exec(move || {
                    if libc::setgroups(0, std::ptr::null()) != 0
                        || libc::setgid(gid) != 0
                        || libc::setuid(uid) != 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        #[cfg(feature = "fixture")]
        let captured = if let Some(io) = &entry.spec.io {
            let (member, pipes) = self.registry.spawn_fixture_capture(
                &entry.spec.family,
                &mut command,
                entry.spec.expires_ms,
                &io.environment,
            )?;
            entry.capture = Some(FixtureCapture::start(pipes, io.stdin.clone()));
            Some(member)
        } else {
            None
        };
        #[cfg(not(feature = "fixture"))]
        let captured: Option<String> = None;
        let member = match captured {
            Some(member) => member,
            None => self.registry.spawn_in_family_before(
                &entry.spec.family,
                &mut command,
                entry.spec.expires_ms,
            )?,
        };
        let reply = SpawnReply {
            launch_id: id.into(),
            target: entry.spec.family.clone(),
            member,
            role: entry.spec.role,
        };
        entry.state = LaunchState::Spawned(reply.clone());
        Ok(reply)
    }
    pub fn router(self: &Arc<Self>) -> Result<Router> {
        ensure!(!self.fixture, "fixture cannot produce production router");
        Ok(self.scoped_router())
    }
    fn scoped_router(self: &Arc<Self>) -> Router {
        let router = Router::new().route("/launch", post(launch_handler));
        #[cfg(feature = "fixture")]
        let router = if self.fixture {
            router.route("/result", post(fixture_result_handler))
        } else {
            router
        };
        router
            .layer(DefaultBodyLimit::max(1024))
            .layer(middleware::from_fn_with_state(self.clone(), authenticate))
            .layer(middleware::from_fn(crate::bounded_request))
            .with_state(self.clone())
    }
    #[cfg(feature = "fixture")]
    pub fn fixture_launch(&self, id: &str) -> Result<SpawnReply> {
        ensure!(self.fixture, "fixture required");
        self.launch(id)
    }
    #[cfg(feature = "fixture")]
    pub fn fixture_result(&self, id: &str) -> Result<FixtureCaptureResult> {
        ensure!(self.fixture, "fixture required");
        let entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("broker unavailable"))?;
        let entry = entries.get(id).context("unknown launch")?;
        let LaunchState::Spawned(reply) = &entry.state else {
            anyhow::bail!("launch has not completed admission")
        };
        let capture = entry
            .capture
            .as_ref()
            .context("launch has no captured IO")?;
        let Some((exit_code, signal)) = self
            .registry
            .poll_fixture_capture(&entry.spec.family, &reply.member)?
        else {
            return Ok(FixtureCaptureResult::Running);
        };
        let stdout = capture
            .stdout
            .lock()
            .map_err(|_| anyhow::anyhow!("capture unavailable"))?;
        let stderr = capture
            .stderr
            .lock()
            .map_err(|_| anyhow::anyhow!("capture unavailable"))?;
        let stdin = capture
            .stdin_result
            .lock()
            .map_err(|_| anyhow::anyhow!("capture unavailable"))?;
        match (&*stdout, &*stderr, &*stdin) {
            (Some(Ok(stdout)), Some(Ok(stderr)), Some(Ok(()))) => {
                Ok(FixtureCaptureResult::Finished {
                    exit_code,
                    signal,
                    stdout: stdout.clone(),
                    stderr: stderr.clone(),
                })
            }
            (None, _, _) | (_, None, _) | (_, _, None) => Ok(FixtureCaptureResult::Running),
            _ => Ok(FixtureCaptureResult::Withheld),
        }
    }
    #[cfg(feature = "fixture")]
    pub fn fixture(registry: Arc<Registry>, secret: BrakeSecret) -> Self {
        let uid = unsafe { libc::geteuid() };
        Self {
            registry,
            policy: BrokerPolicy {
                service_uid: uid,
                adapter_uid: uid,
                child_uids: [uid].into_iter().collect(),
                secret,
            },
            entries: Mutex::new(BTreeMap::new()),
            fixture: true,
            permit: Arc::new(tokio::sync::Semaphore::new(1)),
        }
    }
    #[cfg(feature = "fixture")]
    pub fn fixture_router(self: &Arc<Self>) -> Router {
        self.scoped_router()
    }
}
#[cfg(feature = "fixture")]
struct FixtureIo {
    environment: BTreeMap<String, String>,
    stdin: Vec<u8>,
}
#[cfg(feature = "fixture")]
type CaptureBuffer = Arc<Mutex<Option<std::result::Result<String, ()>>>>;
#[cfg(feature = "fixture")]
struct FixtureCapture {
    stdout: CaptureBuffer,
    stderr: CaptureBuffer,
    stdin_result: Arc<Mutex<Option<std::result::Result<(), ()>>>>,
}
#[cfg(feature = "fixture")]
impl FixtureCapture {
    fn start(
        pipes: (
            std::process::ChildStdin,
            std::process::ChildStdout,
            std::process::ChildStderr,
        ),
        input: Vec<u8>,
    ) -> Self {
        use std::io::{Read, Write};
        fn reader(pipe: impl Read + Send + 'static) -> CaptureBuffer {
            let output = Arc::new(Mutex::new(None));
            let target = output.clone();
            std::thread::spawn(move || {
                let mut bytes = Vec::new();
                let mut bounded = pipe.take(1024 * 1024 + 1);
                let result = bounded
                    .read_to_end(&mut bytes)
                    .map_err(|_| ())
                    .and_then(|_| {
                        if bytes.len() > 1024 * 1024 {
                            Err(())
                        } else {
                            String::from_utf8(bytes).map_err(|_| ())
                        }
                    });
                if let Ok(mut slot) = target.lock() {
                    *slot = Some(result);
                }
            });
            output
        }
        let (mut stdin, stdout, stderr) = pipes;
        let stdin_result = Arc::new(Mutex::new(None));
        let input_result = stdin_result.clone();
        std::thread::spawn(move || {
            let result = stdin.write_all(&input).map_err(|_| ());
            if let Ok(mut slot) = input_result.lock() {
                *slot = Some(result);
            }
        });
        Self {
            stdout: reader(stdout),
            stderr: reader(stderr),
            stdin_result,
        }
    }
}
/// Fixture transport only: complete bounded UTF-8 output, never a production tool receipt.
#[cfg(feature = "fixture")]
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum FixtureCaptureResult {
    Running,
    Finished {
        exit_code: Option<i32>,
        signal: Option<i32>,
        stdout: String,
        stderr: String,
    },
    Withheld,
}
#[cfg(feature = "fixture")]
async fn fixture_result_handler(
    State(broker): State<Arc<SpawnBroker>>,
    Json(request): Json<LaunchRequest>,
) -> Response {
    match broker.fixture_result(&request.launch_id) {
        Ok(result) => Json(result).into_response(),
        Err(_) => (StatusCode::CONFLICT, "capture unavailable").into_response(),
    }
}

async fn authenticate(
    State(broker): State<Arc<SpawnBroker>>,
    request: Request,
    next: Next,
) -> Response {
    let uid = request
        .extensions()
        .get::<ConnectInfo<BrakePeer>>()
        .and_then(|p| p.0.uid);
    let mut headers = request.headers().get_all("x-spawn-key").iter();
    let key = headers.next().and_then(|h| h.to_str().ok());
    let valid = broker.policy.secret.matches(key);
    if headers.next().is_some() || uid != Some(broker.policy.adapter_uid) || !valid {
        return (StatusCode::FORBIDDEN, "spawn authentication failed").into_response();
    }
    next.run(request).await
}
async fn launch_handler(
    State(broker): State<Arc<SpawnBroker>>,
    Json(request): Json<LaunchRequest>,
) -> Response {
    if !ulid::Ulid::from_string(&request.launch_id)
        .is_ok_and(|id| id.to_string() == request.launch_id)
    {
        return (StatusCode::BAD_REQUEST, "invalid launch identity").into_response();
    }
    let Ok(permit) = broker.permit.clone().try_acquire_owned() else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "launch in progress; retry same identity",
        )
            .into_response();
    };
    let outcome = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            broker.launch(&request.launch_id)
        }),
    )
    .await;
    match outcome {
        Ok(Ok(Ok(reply))) => Json(reply).into_response(),
        Ok(Ok(Err(_))) => {
            (StatusCode::CONFLICT, "launch rejected or previously failed").into_response()
        }
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            "launch outcome unknown; retry same identity",
        )
            .into_response(),
    }
}

#[cfg(all(test, feature = "fixture"))]
mod tests {
    use super::*;
    fn broker() -> (Arc<Registry>, SpawnBroker, String) {
        let registry = Arc::new(Registry::new().unwrap());
        let family = registry.create_family().unwrap();
        let broker = SpawnBroker::fixture(registry.clone(), BrakeSecret::new([3; 32]).unwrap());
        (registry, broker, family)
    }
    fn spec(family: &str, program: PathBuf, until: u64) -> ApprovedLaunch {
        ApprovedLaunch::new(
            family.into(),
            LaunchRole::Tool,
            program,
            vec!["60".into()],
            PathBuf::from("/tmp"),
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            until - 10_000,
            until,
        )
        .unwrap()
    }
    #[test]
    fn expired_approval_is_permanently_rejected_without_spawning() {
        let (registry, broker, family) = broker();
        let id = broker
            .admit(spec(&family, "/bin/sleep".into(), now_ms().unwrap() - 1))
            .unwrap();
        assert!(broker.launch(&id).is_err());
        assert!(broker.launch(&id).is_err());
        assert!(matches!(
            broker.entries.lock().unwrap()[&id].state,
            LaunchState::Failed
        ));
        assert!(registry.stop(&family).unwrap().groups.is_empty());
    }
    #[test]
    fn changed_executable_is_rejected_and_restoring_it_does_not_reset_approval() {
        use std::os::unix::fs::PermissionsExt;
        let (registry, broker, family) = broker();
        let path = std::env::temp_dir().join(format!("sfbroker-{}", ulid::Ulid::new()));
        std::fs::write(&path, b"#!/bin/sh\nsleep 60\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let id = broker
            .admit(spec(&family, path.clone(), now_ms().unwrap() + 10_000))
            .unwrap();
        std::fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
        assert!(broker.launch(&id).is_err());
        std::fs::write(&path, b"#!/bin/sh\nsleep 60\n").unwrap();
        assert!(broker.launch(&id).is_err());
        assert!(registry.stop(&family).unwrap().groups.is_empty());
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn identity_overlap_and_missing_children_are_rejected() {
        assert!(
            BrokerPolicy::new(501, 502, 503, vec![501], BrakeSecret::new([1; 32]).unwrap())
                .is_err()
        );
        assert!(
            BrokerPolicy::new(501, 502, 503, vec![], BrakeSecret::new([1; 32]).unwrap()).is_err()
        );
        assert!(
            BrokerPolicy::new(501, 502, 503, vec![504], BrakeSecret::new([1; 32]).unwrap()).is_ok()
        );
    }
    #[test]
    fn fixture_cannot_open_production_router() {
        let (_, broker, _) = broker();
        assert!(Arc::new(broker).router().is_err());
    }
}
