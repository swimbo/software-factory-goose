//! Local trusted-fixture execution, intentionally unregistered and not a hidden-store service.
//!
//! The caller must authenticate manifest provenance outside this module. Scripts are trusted
//! evaluator code, supplied over stdin to a fixed shell; never accept generator-provided
//! manifests. Every run uses a fresh exact candidate snapshot and Seatbelt process boundary.
//! This is same-UID fixture evidence, not distinct-UID/store isolation, hostile process escape
//! containment, or an independent supervisor-death watchdog. Raw scripts/logs never become
//! feedback. Git/toolchain preparation retains the verifier's local trust assumptions.

use crate::{
    holdout::{PrefilterReport, PrefilterSession, RunOutcome},
    verification::{RestrictedRunner, Scratch, clean_at, export_fixture_snapshot},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fmt,
    path::Path,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub(crate) const MAX_MANIFEST_BYTES: usize = 131_072;
const MAX_SCRIPT_BYTES: usize = 8192;
const MAX_SCENARIOS: usize = 32;
const EXECUTION_BUDGET: Duration = Duration::from_secs(30);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestWire {
    version: u32,
    scenarios: Vec<ScenarioWire>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScenarioWire {
    script: String,
}

/// Immutable parsed fixture selection. No Debug/Serialize implementation exposes its contents.
pub struct FixtureManifest {
    digest: String,
    scenarios: Vec<ScenarioWire>,
    source: Vec<u8>,
}
impl FixtureManifest {
    /// Parse bytes already obtained by a trusted fixture loader. Naming this method "trusted"
    /// describes the caller obligation; parsing alone does not establish authenticity.
    pub fn parse_trusted(bytes: &[u8]) -> Result<Self, FixtureError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(FixtureError::InvalidManifest);
        }
        let wire: ManifestWire =
            serde_json::from_slice(bytes).map_err(|_| FixtureError::InvalidManifest)?;
        if wire.version != 1
            || !(1..=MAX_SCENARIOS).contains(&wire.scenarios.len())
            || wire.scenarios.iter().any(|s| {
                s.script.trim().is_empty()
                    || s.script.len() > MAX_SCRIPT_BYTES
                    || s.script.contains('\0')
            })
        {
            return Err(FixtureError::InvalidManifest);
        }
        Ok(Self {
            digest: format!("{:x}", Sha256::digest(bytes)),
            scenarios: wire.scenarios,
            source: bytes.to_vec(),
        })
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn source_bytes(&self) -> &[u8] {
        &self.source
    }
}

#[derive(Clone, Copy)]
pub struct FixtureLimits {
    pub per_run_timeout: Duration,
    pub output_limit: usize,
}
impl Default for FixtureLimits {
    fn default() -> Self {
        Self {
            per_run_timeout: Duration::from_secs(2),
            output_limit: 4096,
        }
    }
}
impl FixtureLimits {
    fn valid(self) -> bool {
        (Duration::from_millis(10)..=Duration::from_secs(5)).contains(&self.per_run_timeout)
            && (64..=16_384).contains(&self.output_limit)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum FixtureError {
    InvalidManifest,
    InvalidLimits,
    Unavailable,
}
impl fmt::Display for FixtureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidManifest => "invalid fixture manifest",
            Self::InvalidLimits => "invalid fixture runner limits",
            Self::Unavailable => "local holdout runner unavailable",
        })
    }
}
impl std::error::Error for FixtureError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultWire {
    passed: bool,
}

/// A dropped async future requests cleanup; the owning blocking task retains the child
/// until it kills the group and reaps it. It never signals a reaped numeric PID.
struct CancelOnDrop(Arc<AtomicBool>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

async fn execute(
    runner: &RestrictedRunner,
    source: &Path,
    script: &str,
    limits: FixtureLimits,
) -> RunOutcome {
    let command = runner.command(source, Path::new("/bin/sh"), &["-s"]);
    run_owned_async(command, script.as_bytes().to_vec(), limits).await
}

async fn run_owned_async(
    command: std::process::Command,
    script: Vec<u8>,
    limits: FixtureLimits,
) -> RunOutcome {
    let Some(deadline) = Instant::now().checked_add(limits.per_run_timeout) else {
        return RunOutcome::Unavailable;
    };
    let canceled = Arc::new(AtomicBool::new(false));
    let guard = CancelOnDrop(canceled.clone());
    let job = tokio::task::spawn_blocking(move || {
        run_owned_command(command, &script, limits, canceled, deadline)
    });
    let result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), job).await;
    drop(guard);
    result
        .ok()
        .and_then(Result::ok)
        .unwrap_or(RunOutcome::Unavailable)
}

#[cfg(all(unix, any(target_os = "macos", target_os = "linux")))]
fn run_owned_command(
    mut command: std::process::Command,
    input: &[u8],
    limits: FixtureLimits,
    canceled: Arc<AtomicBool>,
    deadline: Instant,
) -> RunOutcome {
    use std::{
        io::{Read, Write},
        os::fd::AsRawFd,
    };
    fn nonblocking(fd: i32) -> std::io::Result<()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    fn collect(pipe: &mut impl Read, output: &mut Vec<u8>, limit: usize) -> std::io::Result<bool> {
        let mut buf = [0; 8192];
        for _ in 0..8 {
            match pipe.read(&mut buf) {
                Ok(0) => return Ok(true),
                Ok(n) if output.len() + n <= limit => output.extend_from_slice(&buf[..n]),
                Ok(_) => return Err(std::io::Error::other("output limit")),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(false)
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // The task may have spent its entire lifetime queued behind blocking work. A
    // cancellation after this check is in flight and is cleaned up by the owned loop.
    if canceled.load(Ordering::SeqCst) || Instant::now() >= deadline {
        return RunOutcome::Unavailable;
    }
    let Ok(mut child) = command.spawn() else {
        return RunOutcome::Unavailable;
    };
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let mut group = crate::bounded_git::OwnedGroup::new(child);
    let (Some(stdin), Some(mut stdout), Some(mut stderr)) = (stdin, stdout, stderr) else {
        return RunOutcome::Unavailable;
    };
    if [stdin.as_raw_fd(), stdout.as_raw_fd(), stderr.as_raw_fd()]
        .into_iter()
        .any(|fd| nonblocking(fd).is_err())
    {
        return RunOutcome::Unavailable;
    }
    let mut stdin = Some(stdin);
    let mut written = 0;
    let mut stdout_data = Vec::new();
    let mut stderr_data = Vec::new();
    let (mut out_eof, mut err_eof) = (false, false);
    let mut status = None;
    loop {
        if canceled.load(Ordering::SeqCst) || Instant::now() >= deadline {
            return RunOutcome::Unavailable;
        }
        if let Some(pipe) = &mut stdin
            && written < input.len()
        {
            match pipe.write(&input[written..]) {
                Ok(0) => return RunOutcome::Unavailable,
                Ok(n) => written += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return RunOutcome::Unavailable,
            }
        }
        if stdin.is_some() && written == input.len() {
            // Closing the actual pipe, rather than flushing, delivers EOF to the shell.
            stdin = None;
        }
        match collect(&mut stdout, &mut stdout_data, limits.output_limit) {
            Ok(eof) => out_eof |= eof,
            Err(_) => return RunOutcome::Unavailable,
        }
        match collect(&mut stderr, &mut stderr_data, limits.output_limit) {
            Ok(eof) => err_eof |= eof,
            Err(_) => return RunOutcome::Unavailable,
        }
        if status.is_none() {
            match group.exited() {
                Ok(true) => match group.cleanup() {
                    Ok(value) => status = Some(value),
                    Err(_) => return RunOutcome::Unavailable,
                },
                Ok(false) => {}
                Err(_) => return RunOutcome::Unavailable,
            }
        }
        if out_eof
            && err_eof
            && let Some(status) = status
        {
            if !status.success() || written != input.len() {
                return RunOutcome::Unavailable;
            }
            return match serde_json::from_slice::<ResultWire>(&stdout_data) {
                Ok(result) if result.passed => RunOutcome::Pass,
                Ok(_) => RunOutcome::Fail,
                Err(_) => RunOutcome::Unavailable,
            };
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[cfg(not(all(unix, any(target_os = "macos", target_os = "linux"))))]
fn run_owned_command(
    _command: std::process::Command,
    _input: &[u8],
    _limits: FixtureLimits,
    _canceled: Arc<AtomicBool>,
    _deadline: Instant,
) -> RunOutcome {
    RunOutcome::Unavailable
}

/// Execute every fixture three times, with independent scratch state, then emit opaque
/// feedback. Missing isolation/setup aborts with a static error; timeout, malformed output,
/// nonzero exit and output overflow become unavailable observations and fail the prefilter.
/// The 30-second budget covers scenario execution; trusted Git/toolchain/canary preparation
/// is separate and is not represented as a fully resource-bounded hostile repository loader.
pub async fn run_fixture_holdouts(
    candidate: &Path,
    candidate_sha: &str,
    manifest: &FixtureManifest,
    limits: FixtureLimits,
) -> Result<PrefilterReport, FixtureError> {
    if !limits.valid() {
        return Err(FixtureError::InvalidLimits);
    }
    if !cfg!(target_os = "macos") || !Path::new("/usr/bin/sandbox-exec").is_file() {
        return Err(FixtureError::Unavailable);
    }
    clean_at(candidate, candidate_sha).map_err(|_| FixtureError::Unavailable)?;
    let mut collector =
        PrefilterSession::begin(candidate_sha, &manifest.digest, manifest.scenarios.len())
            .map_err(|_| FixtureError::Unavailable)?;
    let mut elapsed = Duration::ZERO;
    for (scenario, handle) in manifest
        .scenarios
        .iter()
        .zip(collector.scenarios().to_vec())
    {
        for slot in 0..3 {
            let Some(remaining) = EXECUTION_BUDGET.checked_sub(elapsed) else {
                return Ok(collector.finish());
            };
            if remaining.is_zero() {
                return Ok(collector.finish());
            }
            let scratch = Scratch::new().map_err(|_| FixtureError::Unavailable)?;
            let source = scratch.0.join("source");
            export_fixture_snapshot(candidate, candidate_sha, &source)
                .map_err(|_| FixtureError::Unavailable)?;
            let runner =
                RestrictedRunner::new(&scratch.0).map_err(|_| FixtureError::Unavailable)?;
            runner.canary().map_err(|_| FixtureError::Unavailable)?;
            let started = Instant::now();
            let bounded = FixtureLimits {
                per_run_timeout: limits.per_run_timeout.min(remaining),
                ..limits
            };
            let outcome = execute(&runner, &source, &scenario.script, bounded).await;
            elapsed = elapsed.saturating_add(started.elapsed());
            collector
                .record(candidate_sha, &manifest.digest, &handle, slot, outcome)
                .map_err(|_| FixtureError::Unavailable)?;
            // A timeout or cancellation can leave asynchronous cleanup in flight. Never
            // start another scenario while that process might still exist.
            if outcome == RunOutcome::Unavailable {
                return Ok(collector.finish());
            }
        }
    }
    clean_at(candidate, candidate_sha).map_err(|_| FixtureError::Unavailable)?;
    Ok(collector.finish())
}

#[cfg(all(test, unix, any(target_os = "macos", target_os = "linux")))]
mod ownership_tests {
    use super::*;
    use std::os::unix::process::CommandExt;
    use std::sync::{Arc, atomic::AtomicBool};

    fn command(script: &str) -> std::process::Command {
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.args(["-c", script]).process_group(0);
        cmd
    }

    #[test]
    fn exited_leader_is_held_until_descendant_group_cleanup() {
        let dir = std::env::temp_dir().join(format!("sf-holdout-{}", shared::new_id()));
        std::fs::create_dir(&dir).unwrap();
        let marker = dir.join("escaped");
        let script = format!(
            "(sleep 0.5; touch '{}') & printf '{{\"passed\":true}}'",
            marker.display()
        );
        let result = run_owned_command(
            command(&script),
            b"",
            FixtureLimits::default(),
            Arc::new(AtomicBool::new(false)),
            Instant::now() + Duration::from_secs(2),
        );
        assert_eq!(result, RunOutcome::Pass);
        std::thread::sleep(Duration::from_millis(700));
        assert!(!marker.exists(), "descendant survived leader exit");
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn canceled_owned_process_cannot_complete_side_effect() {
        let dir = std::env::temp_dir().join(format!("sf-holdout-{}", shared::new_id()));
        std::fs::create_dir(&dir).unwrap();
        let marker = dir.join("escaped");
        let script = format!("sleep 0.5; touch '{}'", marker.display());
        let canceled = Arc::new(AtomicBool::new(false));
        let child_cancel = canceled.clone();
        let worker = std::thread::spawn(move || {
            run_owned_command(
                command(&script),
                b"",
                FixtureLimits::default(),
                child_cancel,
                Instant::now() + Duration::from_secs(2),
            )
        });
        std::thread::sleep(Duration::from_millis(50));
        canceled.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(worker.join().unwrap(), RunOutcome::Unavailable);
        std::thread::sleep(Duration::from_millis(700));
        assert!(!marker.exists(), "canceled child remained running");
        std::fs::remove_dir(dir).unwrap();
    }
    #[tokio::test]
    async fn aborting_async_caller_cancels_owned_process() {
        let dir = std::env::temp_dir().join(format!("sf-holdout-{}", shared::new_id()));
        std::fs::create_dir(&dir).unwrap();
        let started = dir.join("started");
        let escaped = dir.join("escaped");
        let script = format!(
            "touch '{}'; sleep 0.7; touch '{}'",
            started.display(),
            escaped.display()
        );
        let task = tokio::spawn(run_owned_async(
            command(&script),
            vec![],
            FixtureLimits::default(),
        ));
        let deadline = Instant::now() + Duration::from_secs(2);
        while !started.exists() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(started.exists(), "child did not start");
        task.abort();
        let _ = task.await;
        tokio::time::sleep(Duration::from_millis(850)).await;
        assert!(!escaped.exists(), "child survived future cancellation");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn queued_cancellation_and_deadline_never_spawn() {
        use std::{io::Read, os::fd::FromRawFd, sync::mpsc};
        for cancel in [true, false] {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .max_blocking_threads(1)
                .build()
                .unwrap();
            runtime.block_on(async {
                let (entered_tx, entered_rx) = mpsc::channel();
                let (release_tx, release_rx) = mpsc::channel();
                let blocker = tokio::task::spawn_blocking(move || {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                });
                entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                let mut fds = [0; 2];
                assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
                let write_fd = fds[1];
                let mut cmd = command("printf '{\"passed\":true}'");
                unsafe {
                    cmd.pre_exec(move || {
                        let byte = [1u8];
                        if libc::write(write_fd, byte.as_ptr().cast(), 1) != 1 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                let task = tokio::spawn(run_owned_async(
                    cmd,
                    vec![],
                    FixtureLimits {
                        per_run_timeout: Duration::from_millis(100),
                        output_limit: 4096,
                    },
                ));
                tokio::task::yield_now().await;
                let timely = if cancel {
                    task.abort();
                    let _ = task.await;
                    true
                } else {
                    let result = tokio::time::timeout(Duration::from_millis(500), task).await;
                    matches!(result, Ok(Ok(RunOutcome::Unavailable)))
                };
                release_tx.send(()).unwrap();
                blocker.await.unwrap();
                tokio::task::spawn_blocking(|| ()).await.unwrap();
                assert!(timely, "queued timeout must return before pool is released");
                unsafe {
                    libc::close(write_fd);
                }
                let mut reader = unsafe { std::fs::File::from_raw_fd(fds[0]) };
                let mut bytes = Vec::new();
                reader.read_to_end(&mut bytes).unwrap();
                assert!(
                    bytes.is_empty(),
                    "canceled or expired queued task spawned a process"
                );
            });
        }
    }
}
