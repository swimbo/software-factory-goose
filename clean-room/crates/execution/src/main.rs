//! Worker execution and local subprocess supervision.
//!
//! Live Goose execution is intentionally disabled until the planned distinct-UID Seatbelt
//! launcher and the installed CLI's completion protocol are verified. The supervisor is also
//! used by the opt-in shell shim; that shim is not an OS isolation or universal tool boundary.

use shared::Receipt;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::Stdio;
use std::time::{Duration, Instant};

mod mask;
mod policy;
mod tool_boundary;
#[cfg_attr(not(test), allow(dead_code))]
mod tool_output;

const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

static TERMINATION_REQUESTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(feature = "fixture-inherited-group")]
static FIXTURE_INHERITED_GROUP: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn termination_requested() -> bool {
    TERMINATION_REQUESTED.load(std::sync::atomic::Ordering::Relaxed)
}

extern "C" fn request_termination(_: libc::c_int) {
    // Atomic flag only: cleanup happens in normal control flow, never in the handler.
    TERMINATION_REQUESTED.store(true, std::sync::atomic::Ordering::Relaxed);
}

fn install_termination_handlers() -> std::io::Result<()> {
    // SAFETY: zero-initialized sigaction with a C-ABI handler; no shared mutable data.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = request_termination as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        for signal in [libc::SIGTERM, libc::SIGINT] {
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

/// No environment toggle substitutes for verified UID/Seatbelt/network isolation.
pub fn run_goose(
    prompt: &str,
    worktree: &std::path::Path,
    _timeout: Duration,
) -> anyhow::Result<Receipt> {
    let binary = std::env::var_os("GOOSE_BIN").unwrap_or_else(|| "goose".into());
    let _command = goose_command(&binary, prompt, worktree);
    anyhow::bail!(
        "live Goose execution blocked: distinct-UID Seatbelt launcher, empty home, network restrictions, mandatory tool interception, and compatible JSON CLI have not been verified"
    )
}

fn goose_command(
    binary: &std::ffi::OsStr,
    prompt: &str,
    worktree: &std::path::Path,
) -> std::process::Command {
    let mut cmd = std::process::Command::new(binary);
    cmd.args([
        "run",
        "--no-session",
        "--output-format",
        "json",
        "--text",
        prompt,
    ])
    .current_dir(worktree)
    .env_clear()
    .env("PATH", "/usr/bin:/bin");
    cmd
}

#[derive(Default)]
struct Capture {
    bytes: Vec<u8>,
    truncated: bool,
    eof: bool,
}

impl Capture {
    fn drain(&mut self, pipe: &mut impl Read) -> std::io::Result<()> {
        // Interleave bounded reads of both pipes; an endlessly writing child cannot starve
        // the other pipe or the deadline check. Excess output is drained but not retained.
        let mut block = [0u8; 8192];
        for _ in 0..8 {
            match pipe.read(&mut block) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(n) => {
                    let retained = n.min(MAX_OUTPUT_BYTES.saturating_sub(self.bytes.len()));
                    self.bytes.extend_from_slice(&block[..retained]);
                    self.truncated |= retained < n;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

struct Captured {
    status: std::process::ExitStatus,
    stdout: Capture,
    stderr: Capture,
    timed_out: bool,
}

/// Sole waiter for this child. Keep the leader unreaped until group cleanup.
struct ProcessGroup(Option<std::process::Child>);
impl ProcessGroup {
    fn exited(&self) -> std::io::Result<bool> {
        let child = self.0.as_ref().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "child already reaped")
        })?;
        // SAFETY: this object is the sole waiter. WNOWAIT observes without releasing
        // the child PID, so the private process-group id cannot be recycled before kill.
        unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            loop {
                if libc::waitid(
                    libc::P_PID,
                    child.id(),
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                ) == 0
                {
                    return Ok(info.si_pid() != 0);
                }
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
    }

    fn cleanup_and_wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        // If ownership was lost (ECHILD), never signal a possibly recycled group id.
        self.exited()?;
        let mut child = self.0.take().expect("ownership checked above");
        kill_process_group(child.id());
        child.wait()
    }
}
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        if self.0.is_some() {
            let _ = self.cleanup_and_wait();
        }
    }
}

fn nonblocking(pipe: &impl AsRawFd) -> std::io::Result<()> {
    // SAFETY: pipe owns the valid descriptor; preserve all existing descriptor flags.
    unsafe {
        let flags = libc::fcntl(pipe.as_raw_fd(), libc::F_GETFL);
        if flags < 0 || libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn require_child_wait_ownership() -> std::io::Result<()> {
    // This binary never installs another child reaper. Fail before spawning if inherited
    // signal disposition could auto-reap children and invalidate the PID ownership fence.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if action.sa_sigaction != libc::SIG_DFL || action.sa_flags & libc::SA_NOCLDWAIT != 0 {
            return Err(std::io::Error::other(
                "exclusive child wait ownership unavailable",
            ));
        }
    }
    Ok(())
}

fn supervise(cmd: &mut std::process::Command, timeout: Duration) -> anyhow::Result<Captured> {
    #[cfg(feature = "fixture-inherited-group")]
    if FIXTURE_INHERITED_GROUP.load(std::sync::atomic::Ordering::Relaxed) {
        return supervise_inherited_fixture(cmd, timeout);
    }
    anyhow::ensure!(!termination_requested(), "execution cancelled");
    require_child_wait_ownership()?;
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = ProcessGroup(Some(cmd.spawn()?));
    let mut stdout_pipe = child
        .0
        .as_mut()
        .unwrap()
        .stdout
        .take()
        .expect("piped stdout");
    let mut stderr_pipe = child
        .0
        .as_mut()
        .unwrap()
        .stderr
        .take()
        .expect("piped stderr");
    nonblocking(&stdout_pipe)?;
    nonblocking(&stderr_pipe)?;
    let start = Instant::now();
    let mut stdout = Capture::default();
    let mut stderr = Capture::default();
    let mut timed_out = false;
    let status = loop {
        anyhow::ensure!(!termination_requested(), "execution cancelled");
        stdout.drain(&mut stdout_pipe)?;
        stderr.drain(&mut stderr_pipe)?;
        if child.exited()? {
            break child.cleanup_and_wait()?;
        }
        if start.elapsed() >= timeout {
            timed_out = true;
            break child.cleanup_and_wait()?;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    // Group cleanup occurred while the leader was still unreaped. Never signal its
    // numeric id again. Bound pipes held by descendants that escaped the group.
    let cleanup = Instant::now();
    while !(stdout.eof && stderr.eof) && cleanup.elapsed() < Duration::from_millis(250) {
        stdout.drain(&mut stdout_pipe)?;
        stderr.drain(&mut stderr_pipe)?;
        std::thread::sleep(Duration::from_millis(1));
    }
    stdout.truncated |= !stdout.eof;
    stderr.truncated |= !stderr.eof;
    anyhow::ensure!(!termination_requested(), "execution cancelled");
    Ok(Captured {
        status,
        stdout,
        stderr,
        timed_out,
    })
}

/// Fixture only: an external live parent is responsible for the inherited process
/// group. This function may signal only its own direct child and cannot prove group
/// cleanup. The launcher must withhold all results until it stops the complete group.
#[cfg(feature = "fixture-inherited-group")]
fn supervise_inherited_fixture(
    cmd: &mut std::process::Command,
    timeout: Duration,
) -> anyhow::Result<Captured> {
    struct DirectChild(Option<std::process::Child>);
    impl Drop for DirectChild {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                match child.try_wait() {
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                    Err(_) => {} // ownership cannot be confirmed; never signal a numeric PID
                }
            }
        }
    }
    anyhow::ensure!(!termination_requested(), "execution cancelled");
    require_child_wait_ownership()?;
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = DirectChild(Some(cmd.spawn()?));
    let mut stdout_pipe = child
        .0
        .as_mut()
        .unwrap()
        .stdout
        .take()
        .expect("piped stdout");
    let mut stderr_pipe = child
        .0
        .as_mut()
        .unwrap()
        .stderr
        .take()
        .expect("piped stderr");
    nonblocking(&stdout_pipe)?;
    nonblocking(&stderr_pipe)?;
    let start = Instant::now();
    let mut stdout = Capture::default();
    let mut stderr = Capture::default();
    let mut timed_out = false;
    let status = loop {
        anyhow::ensure!(!termination_requested(), "execution cancelled");
        stdout.drain(&mut stdout_pipe)?;
        stderr.drain(&mut stderr_pipe)?;
        if let Some(status) = child.0.as_mut().unwrap().try_wait()? {
            child.0 = None;
            break status;
        }
        if start.elapsed() >= timeout {
            timed_out = true;
            let owned = child.0.as_mut().unwrap();
            owned.kill()?;
            let status = owned.wait()?;
            child.0 = None;
            break status;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let cleanup = Instant::now();
    while !(stdout.eof && stderr.eof) && cleanup.elapsed() < Duration::from_millis(250) {
        stdout.drain(&mut stdout_pipe)?;
        stderr.drain(&mut stderr_pipe)?;
        std::thread::sleep(Duration::from_millis(1));
    }
    stdout.truncated |= !stdout.eof;
    stderr.truncated |= !stderr.eof;
    anyhow::ensure!(!termination_requested(), "execution cancelled");
    Ok(Captured {
        status,
        stdout,
        stderr,
        timed_out,
    })
}

fn kill_process_group(pgid: u32) {
    // SAFETY: negative child pid selects its private process group.
    unsafe {
        libc::kill(-(pgid as i32), libc::SIGKILL);
    }
}

// Current upstream schema, not a claim about the incompatible installed CLI. See README.
#[derive(serde::Deserialize)]
struct Completion {
    messages: Vec<CompletionMessage>,
    metadata: CompletionMetadata,
}
#[derive(serde::Deserialize)]
struct CompletionMessage {
    role: String,
    content: Vec<serde_json::Value>,
}
#[derive(serde::Deserialize)]
struct CompletionMetadata {
    status: String,
    cost_usd: f64,
}
struct CompletionMetrics {
    turn_count: u32,
    spend_usd: f64,
}

fn parse_completion(stdout: &str) -> anyhow::Result<CompletionMetrics> {
    let output: Completion = serde_json::from_str(stdout)?;
    anyhow::ensure!(
        output.metadata.status == "completed",
        "no positive completion status"
    );
    anyhow::ensure!(
        output.metadata.cost_usd.is_finite() && output.metadata.cost_usd >= 0.0,
        "invalid cost"
    );
    anyhow::ensure!(
        output
            .messages
            .iter()
            .all(|m| matches!(m.role.as_str(), "assistant" | "user")
                && m.content.iter().all(serde_json::Value::is_object)),
        "invalid messages"
    );
    let turns = output
        .messages
        .iter()
        .filter(|m| m.role == "assistant")
        .count();
    anyhow::ensure!(turns > 0, "no assistant completion");
    Ok(CompletionMetrics {
        turn_count: u32::try_from(turns)?,
        spend_usd: output.metadata.cost_usd,
    })
}

#[cfg_attr(not(test), allow(dead_code))]
fn finish(output: Captured, worktree: &std::path::Path, start: Instant) -> Receipt {
    let wall_time_ms = start.elapsed().as_millis() as u64;
    if output.timed_out {
        return Receipt::TimedOut {
            sha: current_sha(worktree),
            turn_count: 0,
            wall_time_ms,
        };
    }
    if let Some(signal) = output.status.signal() {
        return Receipt::Crashed {
            signal,
            core_dumped: output.status.core_dumped(),
        };
    }
    if !output.status.success() {
        let stderr = mask::mask(&String::from_utf8_lossy(&output.stderr.bytes)).text;
        return Receipt::Failed {
            exit_code: output.status.code().unwrap_or(-1),
            stderr_tail: stderr
                .chars()
                .rev()
                .take(400)
                .collect::<String>()
                .chars()
                .rev()
                .collect(),
        };
    }
    // A truncated stream or missing cost cannot silently become zero-cost success.
    if output.stdout.truncated || output.stderr.truncated {
        return protocol_failure("worker output exceeded capture limit or did not close");
    }
    let metrics = match std::str::from_utf8(&output.stdout.bytes)
        .ok()
        .and_then(|s| parse_completion(s).ok())
    {
        Some(metrics) => metrics,
        None => return protocol_failure("invalid JSON completion or missing verified cost"),
    };
    let sha = current_sha(worktree);
    let diff = std::process::Command::new("git")
        .args(["diff", "HEAD"])
        .current_dir(worktree)
        .output();
    match diff {
        Ok(diff) if diff.status.success() && !sha.is_empty() => Receipt::Completed {
            sha,
            diff: String::from_utf8_lossy(&diff.stdout).into_owned(),
            turn_count: metrics.turn_count,
            exit_code: 0,
            wall_time_ms,
            spend_usd: metrics.spend_usd,
        },
        _ => protocol_failure("unable to recover worktree payload"),
    }
}

fn protocol_failure(message: &str) -> Receipt {
    Receipt::Failed {
        exit_code: 65,
        stderr_tail: message.to_string(),
    }
}

fn current_sha(worktree: &std::path::Path) -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(worktree)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// Resolve the workflow's durable promise by POSTing the receipt to its `complete` handler.
///
/// This is the R5 handoff: the Goose subprocess ran *outside* the Restate journal; this call
/// delivers only its *outcome* (the typed Receipt JSON) back to the workflow.
async fn resolve_workflow(
    restate_url: &str,
    work_package_id: &str,
    receipt: &Receipt,
) -> anyhow::Result<()> {
    let body = serde_json::to_string(receipt)?;
    let url = format!("{restate_url}/restate/call/WorkPackageWorkflow/{work_package_id}/complete");
    let resp = reqwest::Client::new()
        .post(url)
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("resolve_workflow failed: {}", resp.status());
    }
    Ok(())
}

/// Report the receipt to the control plane's pipeline so it can run the wall + gates.
async fn report_result(
    control_url: &str,
    work_package_id: &str,
    pipeline_id: &str,
    receipt: &Receipt,
    worktree: &str,
) -> anyhow::Result<()> {
    let body = serde_json::json!({
        "pipeline_id": pipeline_id,
        "receipt": receipt,
        "worktree": worktree,
    });
    let url = format!("{control_url}/v1/work-packages/{work_package_id}/result");
    let resp = reqwest::Client::new().post(url).json(&body).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("report_result failed: {}", resp.status());
    }
    Ok(())
}

fn load_policy() -> anyhow::Result<policy::RuleSet> {
    match std::env::var_os("SFACTORY_POLICY") {
        Some(path) => policy::RuleSet::from_toml(&std::fs::read_to_string(path)?),
        None => Ok(policy::RuleSet::default_rules(
            &std::env::current_dir()?.to_string_lossy(),
        )),
    }
}

/// Worker entry: read config from env, run Goose in the worktree, resolve the workflow promise.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    // Only the supported `sh -c <command>` route is accepted by the shim.
    let args: Vec<String> = std::env::args().collect();
    #[cfg(feature = "fixture-inherited-group")]
    let inherited_fixture =
        args.get(1).map(String::as_str) == Some("--fixture-inherited-tool-request");
    #[cfg(not(feature = "fixture-inherited-group"))]
    let inherited_fixture = false;
    if args.get(1).map(String::as_str) == Some("--tool-request") || inherited_fixture {
        #[cfg(feature = "fixture-inherited-group")]
        if inherited_fixture {
            let parent = unsafe { libc::getppid() };
            anyhow::ensure!(
                parent > 1
                    && unsafe { libc::getpgrp() } == parent
                    && unsafe { libc::getpgid(parent) } == parent,
                "fixture requires direct live process-group leader parent"
            );
            FIXTURE_INHERITED_GROUP.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        install_termination_handlers()?;
        // Opt-in one-request local transport. JSON cannot supply execution authority.
        let response = (|| -> Result<tool_boundary::Response, tool_boundary::Response> {
            if args.len() != 2 {
                return Err(tool_boundary::Response::refused("invalid_request"));
            }
            use std::os::fd::AsFd;
            let request = tool_boundary::read_local_request(std::io::stdin().as_fd())?;
            let rules = load_policy()
                .map_err(|_| tool_boundary::Response::refused("configuration_unavailable"))?;
            let cwd = std::env::current_dir()
                .map_err(|_| tool_boundary::Response::refused("configuration_unavailable"))?;
            let boundary = tool_boundary::ShellBoundary::new(
                &cwd,
                rules,
                Duration::from_secs(180),
                MAX_OUTPUT_BYTES,
            )?;
            Ok(boundary.execute(request))
        })()
        .unwrap_or_else(|refusal| refusal);
        println!("{}", serde_json::to_string(&response)?);
        return Ok(());
    }
    if matches!(
        args.get(1).map(String::as_str),
        Some("--check-policy" | "--run-shell")
    ) {
        anyhow::ensure!(args.len() == 3, "expected one shell command");
        let command = &args[2];
        let rules = load_policy()?;
        if let policy::Decision::Deny(reason) = policy::evaluate(&rules, command) {
            eprintln!("policy denied: {}", mask::mask(&reason).text);
            std::process::exit(126);
        }
        if args[1] == "--check-policy" {
            return Ok(());
        }
        let mut shell = std::process::Command::new("/bin/sh");
        shell
            .args(["-c", command])
            .env_clear()
            .env("PATH", "/usr/bin:/bin");
        let result = supervise(&mut shell, Duration::from_secs(180))?;
        if result.timed_out || result.stdout.truncated || result.stderr.truncated {
            eprintln!("shell output withheld: timeout, incomplete pipe, or output limit");
            std::process::exit(if result.timed_out { 124 } else { 74 });
        }
        use std::io::Write;
        std::io::stdout().write_all(
            mask::mask(&String::from_utf8_lossy(&result.stdout.bytes))
                .text
                .as_bytes(),
        )?;
        std::io::stderr().write_all(
            mask::mask(&String::from_utf8_lossy(&result.stderr.bytes))
                .text
                .as_bytes(),
        )?;
        std::process::exit(
            result
                .status
                .code()
                .unwrap_or(128 + result.status.signal().unwrap_or(0)),
        );
    }

    let prompt = std::env::var("SFACTORY_PROMPT").unwrap_or_default();
    let work_package_id = std::env::var("SFACTORY_WORK_PACKAGE_ID").unwrap_or_default();
    let worktree = std::env::var("SFACTORY_WORKTREE").unwrap_or_else(|_| ".".to_string());
    let restate_url =
        std::env::var("RESTATE_URL").unwrap_or_else(|_| "http://localhost:8090".to_string());
    let timeout = std::env::var("SFACTORY_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(180));

    let receipt = run_goose(&prompt, std::path::Path::new(&worktree), timeout)?;
    tracing::info!(work_package_id, "goose finished; receipt ready");

    if !work_package_id.is_empty() {
        resolve_workflow(&restate_url, &work_package_id, &receipt).await?;
        // Report to the pipeline so it runs the wall + gates (the build→evaluate callback).
        let control_url = std::env::var("SFACTORY_CONTROL_URL")
            .unwrap_or_else(|_| "http://localhost:8081".to_string());
        let pipeline_id = std::env::var("SFACTORY_PIPELINE_ID").unwrap_or_default();
        if !pipeline_id.is_empty() {
            report_result(
                &control_url,
                &work_package_id,
                &pipeline_id,
                &receipt,
                &worktree,
            )
            .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod worker_tests;
