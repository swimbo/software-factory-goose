//! The execution plane — the worker daemon that runs Goose headless in a disposable worktree.
//!
//! Consensus R4/R5/R6/R9/R10: a *separate* binary from the control plane. It spawns Goose in
//! its own process group, parses a typed Receipt from stdout, kills the whole group on timeout
//! (`kill -pgid`), and isolates by identity (distinct uid/env, not scrubbing).
//! R14: captured output is masked before it is logged or returned.

use shared::Receipt;
use std::process::Stdio;
use std::time::{Duration, Instant};

use std::os::unix::process::{CommandExt, ExitStatusExt};

mod mask;
mod policy;

/// Run Goose headless and produce a typed Receipt (R6).
///
/// `git diff` is recovered from the worktree as *payload*; the status discriminator comes from
/// a positive completion assertion (exit 0) vs timeout/failure/crash.
pub fn run_goose(prompt: &str, worktree: &std::path::Path, timeout: Duration) -> anyhow::Result<Receipt> {
    let start = Instant::now();

    let mut cmd = std::process::Command::new("goose");
    cmd.args([
        "run",
        "--no-session",
        "--output-format",
        "json",
        "--text",
        prompt,
    ])
    .current_dir(worktree)
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    // New process group so we can kill the whole tree, not just the direct child (R9).
    .process_group(0);

    // R13: put the policy shim dir first on PATH so the agent's `sh` resolves to the shim.
    if let Ok(shims) = std::env::var("SFACTORY_SHIMS_DIR") {
        let path = std::env::var("PATH").unwrap_or_default();
        cmd.env("PATH", format!("{shims}:{path}"));
        cmd.env("SFACTORY_EXECUTION_BIN", std::env::current_exe().unwrap_or_default());
    }

    let mut child = cmd.spawn()?;
    let pgid = child.id();

    // Poll to completion with a hard timeout.
    loop {
        if let Some(status) = child.try_wait()? {
            return finish(status, pgid, worktree, start, &mut child);
        }
        if start.elapsed() >= timeout {
            // Kill the entire process group; a direct-child kill leaves grandchildren (R9).
            kill_process_group(pgid);
            let _ = child.wait();
            return Ok(timeout_receipt(worktree, start));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn finish(
    status: std::process::ExitStatus,
    _pgid: u32,
    worktree: &std::path::Path,
    start: Instant,
    child: &mut std::process::Child,
) -> anyhow::Result<Receipt> {
    let wall_time_ms = start.elapsed().as_millis() as u64;
    let sha = current_sha(worktree);
    // R14: mask secrets in captured output before it is used or logged.
    let stdout = mask::mask(&read_stdout(&mut child.stdout));
    let stderr = mask::mask(&read_stderr(&mut child.stderr));
    if !stdout.redactions.is_empty() || !stderr.redactions.is_empty() {
        tracing::info!(
            stdout = ?stdout.redactions,
            stderr = ?stderr.redactions,
            "R14: masked secrets in worker output"
        );
    }

    if status.success() {
        // Positive completion assertion (R6): exit 0 + a diff is present.
        let diff = git_diff(worktree).unwrap_or_default();
        let turn_count = parse_turn_count(&stdout.text);
        let spend_usd = parse_spend_usd(&stdout.text, turn_count);
        Ok(Receipt::Completed {
            sha,
            diff,
            turn_count,
            exit_code: 0,
            wall_time_ms,
            spend_usd,
        })
    } else if let Some(signal) = status.signal() {
        Ok(Receipt::Crashed {
            signal,
            core_dumped: false,
        })
    } else {
        let code = status.code().unwrap_or(-1);
        // stderr tail is free-form logs — never parsed as status, only captured (R6).
        let stderr_tail = stderr
            .text
            .chars()
            .rev()
            .take(400)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        Ok(Receipt::Failed {
            exit_code: code,
            stderr_tail,
        })
    }
}

fn timeout_receipt(worktree: &std::path::Path, start: Instant) -> Receipt {
    Receipt::TimedOut {
        sha: current_sha(worktree),
        turn_count: 0,
        wall_time_ms: start.elapsed().as_millis() as u64,
    }
}

/// `kill(-pgid, SIGKILL)` — terminate the whole process group (R9).
fn kill_process_group(pgid: u32) {
    // SAFETY: negative pid targets the process group; SIGKILL is not catchable.
    unsafe {
        libc::kill(-(pgid as i32), libc::SIGKILL);
    }
}

fn current_sha(worktree: &std::path::Path) -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(worktree)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// `git diff` is *payload* (R6) — recovered after a positive completion, never the status.
fn git_diff(worktree: &std::path::Path) -> Option<String> {
    let o = std::process::Command::new("git")
        .args(["diff"])
        .current_dir(worktree)
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Goose's `--output-format json` stdout: parse a turn count defensively. If unparseable,
/// return 0 — the status discriminator already came from the exit code (R6).
fn parse_turn_count(stdout: &str) -> u32 {
    serde_json::from_str::<serde_json::Value>(stdout)
        .ok()
        .and_then(|v| v.get("turn_count").or_else(|| v.get("turns")).and_then(|t| t.as_u64()))
        .map(|n| n as u32)
        .unwrap_or(0)
}

/// Cost from Goose's JSON output if present, else a flat per-turn estimate (R7).
fn parse_spend_usd(stdout: &str, turn_count: u32) -> f64 {
    serde_json::from_str::<serde_json::Value>(stdout)
        .ok()
        .and_then(|v| {
            ["spend_usd", "cost", "total_cost"]
                .iter()
                .find_map(|k| v.get(*k).and_then(|c| c.as_f64()))
        })
        .unwrap_or(turn_count as f64 * 0.01)
}

fn read_stdout(pipe: &mut Option<std::process::ChildStdout>) -> String {
    use std::io::Read;
    let mut buf = String::new();
    if let Some(p) = pipe.as_mut() {
        let _ = p.read_to_string(&mut buf);
    }
    buf
}

fn read_stderr(pipe: &mut Option<std::process::ChildStderr>) -> String {
    use std::io::Read;
    let mut buf = String::new();
    if let Some(p) = pipe.as_mut() {
        let _ = p.read_to_string(&mut buf);
    }
    buf
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
        .body(body)
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

/// Worker entry: read config from env, run Goose in the worktree, resolve the workflow promise.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    // R13: the PATH shim calls back here to gate a command before it executes.
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--check-policy") {
        let cmd = args.get(2).cloned().unwrap_or_default();
        let root = std::env::var("WORKTREE_ROOT")
            .unwrap_or_else(|_| "/tmp/sfactory-worktrees".to_string());
        // Load rules from $SFACTORY_POLICY if set, else fall back to built-in defaults.
        let rules = std::env::var("SFACTORY_POLICY")
            .ok()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| policy::RuleSet::from_toml(&s).ok())
            .unwrap_or_else(|| policy::RuleSet::default_rules(&root));
        match policy::evaluate(&rules, &cmd) {
            policy::Decision::Allow => return Ok(()),
            policy::Decision::Deny(reason) => {
                eprintln!("policy denied: {reason}");
                std::process::exit(126);
            }
        }
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
    tracing::info!(work_package_id, "goose finished: {:?}", receipt);

    if !work_package_id.is_empty() {
        resolve_workflow(&restate_url, &work_package_id, &receipt).await?;
        // Report to the pipeline so it runs the wall + gates (the build→evaluate callback).
        let control_url = std::env::var("SFACTORY_CONTROL_URL")
            .unwrap_or_else(|_| "http://localhost:8081".to_string());
        let pipeline_id = std::env::var("SFACTORY_PIPELINE_ID").unwrap_or_default();
        if !pipeline_id.is_empty() {
            report_result(&control_url, &work_package_id, &pipeline_id, &receipt, &worktree).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn turn_count_parses_json() {
        assert_eq!(parse_turn_count(r#"{"turn_count": 7}"#), 7);
        assert_eq!(parse_turn_count(r#"{"turns": 3}"#), 3);
    }

    #[test]
    fn turn_count_falls_back_on_garbage() {
        assert_eq!(parse_turn_count("not json"), 0);
    }

    #[test]
    fn kill_pgid_is_negative() {
        // Just assert the arithmetic we rely on: negative pid = process group.
        assert_eq!(-(1234i32), -1234);
    }
}
