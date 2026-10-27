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
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

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

/// A best-effort process-group cleanup backstop, including future cancellation. This does
/// not claim containment of descendants deliberately escaping their process group.
struct GroupGuard(u32);
impl Drop for GroupGuard {
    fn drop(&mut self) {
        let _ = std::process::Command::new("/bin/kill")
            .args(["-KILL", &format!("-{}", self.0)])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

async fn capture(reader: impl AsyncRead + Unpin, limit: usize) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(limit + 1);
    reader
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    Ok(bytes)
}

async fn execute(
    runner: &RestrictedRunner,
    source: &Path,
    script: &str,
    limits: FixtureLimits,
) -> RunOutcome {
    let command = runner.command(source, Path::new("/bin/sh"), &["-s"]);
    let mut command = tokio::process::Command::from(command);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let Ok(mut child) = command.spawn() else {
        return RunOutcome::Unavailable;
    };
    let Some(pid) = child.id() else {
        return RunOutcome::Unavailable;
    };
    let guard = GroupGuard(pid);
    let (Some(mut stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        return RunOutcome::Unavailable;
    };
    let result = tokio::time::timeout(limits.per_run_timeout, async {
        tokio::join!(
            async move {
                stdin.write_all(script.as_bytes()).await?;
                stdin.shutdown().await?;
                drop(stdin);
                Ok::<(), std::io::Error>(())
            },
            capture(stdout, limits.output_limit),
            capture(stderr, limits.output_limit),
            child.wait()
        )
    })
    .await;
    drop(guard); // Clear ordinary descendants even when the shell exits before its children.
    let _ = child.start_kill();
    let reaped = tokio::time::timeout(Duration::from_secs(1), child.wait()).await;
    if !matches!(reaped, Ok(Ok(_))) {
        return RunOutcome::Unavailable;
    }
    match result {
        Ok((Ok(()), Ok(stdout), Ok(stderr), Ok(status)))
            if status.success()
                && stdout.len() <= limits.output_limit
                && stderr.len() <= limits.output_limit =>
        {
            match serde_json::from_slice::<ResultWire>(&stdout) {
                Ok(result) if result.passed => RunOutcome::Pass,
                Ok(_) => RunOutcome::Fail,
                Err(_) => RunOutcome::Unavailable,
            }
        }
        _ => RunOutcome::Unavailable,
    }
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
        }
    }
    clean_at(candidate, candidate_sha).map_err(|_| FixtureError::Unavailable)?;
    Ok(collector.finish())
}
