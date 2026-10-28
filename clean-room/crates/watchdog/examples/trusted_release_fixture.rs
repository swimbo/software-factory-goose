//! Disposable trusted-launcher result gate; never a production containment boundary.
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    io::{Read, Write},
    os::{fd::AsRawFd, unix::fs::PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
const CAP: usize = 4096;
struct Root(PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        for name in ["masked", "slow", "ready", "marker"] {
            let _ = fs::remove_file(self.0.join(name));
        }
        for lane in [
            "normal",
            "oversize",
            "slow-positive",
            "slow-timeout",
            "dead",
        ] {
            let _ = fs::remove_file(self.0.join(lane).join("recovery-required"));
            let _ = fs::remove_dir(self.0.join(lane));
        }
        let _ = fs::remove_dir(&self.0);
    }
}
fn nonblock(fd: &impl AsRawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    ensure!(
        flags >= 0
            && unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0,
        "nonblocking failed"
    );
    Ok(())
}
fn start(
    root: &Path,
    execution: &Path,
    mode: &str,
    lane: &str,
) -> Result<watchdog::guarded_release::FixtureGroup> {
    let reservation = root.join(lane);
    fs::create_dir(&reservation)?;
    fs::set_permissions(&reservation, fs::Permissions::from_mode(0o700))?;
    let spec = watchdog::guarded_admission::FixtureSpec::new(
        std::env::current_exe()?,
        [
            std::ffi::OsString::from("guard"),
            root.as_os_str().to_owned(),
            execution.as_os_str().to_owned(),
            std::ffi::OsString::from(mode),
        ],
        root,
    )?;
    let mut launcher = watchdog::guarded_admission::FixtureLauncher::new(&reservation, spec)?;
    launcher.launch()
}
fn guard(root: &Path, execution: &Path, mode: &str) -> Result<()> {
    if mode == "oversize" {
        std::io::stdout().write_all(b"SFR1\x00\x00\x10\x01")?;
        std::io::stdout().flush()?;
        let mut b = [0];
        let _ = std::io::stdin().read(&mut b);
        return Ok(());
    }
    ensure!(
        matches!(mode, "normal" | "slow" | "die"),
        "unknown fixture mode"
    );
    let mut process = Command::new(execution)
        .arg("--fixture-inherited-tool-request")
        .current_dir(root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    process
        .stdin
        .take()
        .context("request pipe")?
        .write_all(if mode == "slow" {
            br#"{"command":"./slow"}"#
        } else {
            br#"{"command":"./masked"}"#
        })?;
    let mut stdout = process.stdout.take().context("result pipe")?;
    nonblock(&stdout)?;
    let mut body = Vec::new();
    let mut buf = [0u8; 1024];
    let mut status = None;
    let mut eof = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while !eof || status.is_none() {
        match stdout.read(&mut buf) {
            Ok(0) => eof = true,
            Ok(n) => {
                body.extend_from_slice(&buf[..n]);
                ensure!(body.len() <= CAP, "execution result too large");
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
        if status.is_none() {
            status = process.try_wait()?;
        }
        ensure!(Instant::now() < deadline, "execution result deadline");
        if !eof || status.is_none() {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    ensure!(status.unwrap().success(), "fixture execution failed");
    std::io::stdout().write_all(b"SFR1")?;
    std::io::stdout().write_all(&(body.len() as u32).to_be_bytes())?;
    std::io::stdout().write_all(&body)?;
    std::io::stdout().flush()?;
    if mode == "die" {
        return Ok(());
    }
    let mut b = [0];
    let _ = std::io::stdin().read(&mut b);
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.get(1).is_some_and(|arg| arg == "guard") {
        ensure!(args.len() == 5, "bad fixture args");
        return guard(
            Path::new(&args[2]),
            Path::new(&args[3]),
            args[4].to_str().context("mode")?,
        );
    }
    let bin = std::env::current_exe()?
        .parent()
        .context("examples")?
        .parent()
        .context("debug")?
        .join("execution");
    ensure!(bin.is_file(), "build fixture execution binary first");
    let path = std::env::temp_dir().join(format!("sf-release-{}", ulid::Ulid::new()));
    fs::create_dir(&path)?;
    let root = Root(path);
    fs::write(root.0.join("masked"), b"#!/bin/sh\nprintf sk-OFF\nsleep 0.01\nprintf LINE0123456789ABCDEFGHIJKLMN\nprintf ' SFR1FAKE'\nprintf 'password=fixture-only' >&2\n")?;
    fs::write(
        root.0.join("slow"),
        b"#!/bin/sh\nprintf ready > ready\nsleep 2\nprintf survived > marker\n",
    )?;
    for name in ["masked", "slow"] {
        fs::set_permissions(root.0.join(name), fs::Permissions::from_mode(0o700))?;
    }
    let mut leader = start(&root.0, &bin, "normal", "normal")?;
    let released = leader
        .complete(Duration::from_secs(5))
        .context("normal release")?;
    let response: serde_json::Value = serde_json::from_slice(&released)?;
    ensure!(
        response["status"] == "executed"
            && response["stdout"] == "[REDACTED] SFR1FAKE"
            && response["stderr"] == "[REDACTED]",
        "masked response invalid"
    );
    let mut malformed = start(&root.0, &bin, "oversize", "oversize")?;
    ensure!(
        malformed.complete(Duration::from_secs(3)).is_err(),
        "oversize frame accepted"
    );
    ensure!(malformed.is_reaped(), "malformed guard not reaped");
    let mut positive = start(&root.0, &bin, "slow", "slow-positive")?;
    let completed = positive
        .complete(Duration::from_secs(5))
        .context("slow positive release")?;
    let completed: serde_json::Value = serde_json::from_slice(&completed)?;
    ensure!(
        completed["status"] == "executed" && root.0.join("marker").is_file(),
        "slow positive control did not run"
    );
    fs::remove_file(root.0.join("ready"))?;
    fs::remove_file(root.0.join("marker"))?;
    let mut slow = start(&root.0, &bin, "slow", "slow-timeout")?;
    let deadline = Instant::now() + Duration::from_secs(3);
    while !root.0.join("ready").is_file() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
    }
    ensure!(root.0.join("ready").is_file(), "slow fixture not ready");
    ensure!(
        slow.complete(Duration::from_millis(100)).is_err(),
        "timed-out output released"
    );
    ensure!(slow.is_reaped(), "timeout leader not reaped");
    std::thread::sleep(Duration::from_millis(2400));
    ensure!(!root.0.join("marker").exists(), "timed-out child survived");
    let mut dead = start(&root.0, &bin, "die", "dead")?;
    std::thread::sleep(Duration::from_millis(500));
    ensure!(
        dead.complete(Duration::from_secs(1)).is_err(),
        "dead owner released output"
    );
    println!("PASS: bounded result released only after owned-group stop");
    Ok(())
}
