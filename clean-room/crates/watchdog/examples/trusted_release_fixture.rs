//! Disposable trusted-launcher result gate; never a production containment boundary.
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::PermissionsExt,
            process::{CommandExt, ExitStatusExt},
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
const CAP: usize = 4096;
struct Root(PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        for name in ["masked", "slow", "ready", "marker"] {
            let _ = fs::remove_file(self.0.join(name));
        }
        let _ = fs::remove_dir(&self.0);
    }
}
struct Leader(Option<Child>);
impl Leader {
    fn live(&self) -> Result<bool> {
        let child = self.0.as_ref().context("leader reaped")?;
        let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        ensure!(
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    child.id(),
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            } == 0,
            "leader ownership unavailable"
        );
        Ok(unsafe { info.si_pid() } == 0
            && unsafe { libc::getpgid(child.id() as i32) } == child.id() as i32)
    }
    fn release_with(
        &mut self,
        bytes: Vec<u8>,
        signal: impl FnOnce(i32) -> std::io::Result<()>,
    ) -> Result<Vec<u8>> {
        ensure!(self.live()?, "leader is not live");
        let pgid = self.0.as_ref().unwrap().id() as i32;
        signal(pgid)?;
        let status = self.0.as_mut().unwrap().wait()?;
        ensure!(
            status.signal() == Some(libc::SIGKILL),
            "leader was not killed"
        );
        self.0 = None;
        // Observe only after reap; never send a nonzero signal to this number again.
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let absent = unsafe { libc::kill(-pgid, 0) } == -1
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
            if absent {
                break;
            }
            ensure!(Instant::now() < deadline, "group absence unverified");
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(bytes)
    }
    fn release(&mut self, bytes: Vec<u8>) -> Result<Vec<u8>> {
        self.release_with(bytes, |pid| {
            if unsafe { libc::kill(-pid, libc::SIGKILL) } == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        })
    }
}
impl Drop for Leader {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            child.stdin.take();
        }
        if self.live().unwrap_or(false) {
            let _ = self.release(Vec::new());
        }
        if let Some(mut child) = self.0.take() {
            let _ = child.wait();
        }
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
fn read_frame(leader: &Leader, input: &mut impl Read, timeout: Duration) -> Result<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    let mut data = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match input.read(&mut chunk) {
            Ok(0) => anyhow::bail!("incomplete frame"),
            Ok(n) => {
                data.extend_from_slice(&chunk[..n]);
                ensure!(data.len() <= CAP + 8, "frame too large");
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
        if data.len() >= 8 {
            ensure!(&data[..4] == b"SFR1", "bad frame magic");
            let n = u32::from_be_bytes(data[4..8].try_into().unwrap()) as usize;
            ensure!(n <= CAP, "declared frame exceeds cap");
            if data.len() == n + 8 {
                ensure!(leader.live()?, "leader died before release");
                return Ok(data[8..].to_vec());
            }
            ensure!(data.len() < n + 8, "trailing frame data");
        }
        ensure!(leader.live()?, "leader died with incomplete frame");
        ensure!(Instant::now() < deadline, "frame timeout");
        std::thread::sleep(Duration::from_millis(2));
    }
}
fn start(root: &Path, execution: &Path, mode: &str) -> Result<(Leader, std::process::ChildStdout)> {
    let mut child = Command::new(std::env::current_exe()?)
        .arg("guard")
        .arg(root)
        .arg(execution)
        .arg(mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()?;
    let stdout = child.stdout.take().context("frame pipe")?;
    nonblock(&stdout)?;
    Ok((Leader(Some(child)), stdout))
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
    let (mut leader, mut output) = start(&root.0, &bin, "normal")?;
    let frame = read_frame(&leader, &mut output, Duration::from_secs(5))?;
    let released = leader.release(frame).context("normal release")?;
    let response: serde_json::Value = serde_json::from_slice(&released)?;
    ensure!(
        response["status"] == "executed"
            && response["stdout"] == "[REDACTED] SFR1FAKE"
            && response["stderr"] == "[REDACTED]",
        "masked response invalid"
    );
    let (mut denied, mut output) = start(&root.0, &bin, "normal")?;
    let frame = read_frame(&denied, &mut output, Duration::from_secs(5))?;
    ensure!(
        denied
            .release_with(frame, |_| Err(std::io::Error::from_raw_os_error(
                libc::EPERM
            )))
            .is_err(),
        "failed signal released output"
    );
    ensure!(denied.live()?, "failed signal lost owner");
    denied.release(Vec::new()).context("signal retry cleanup")?;
    let (mut malformed, mut output) = start(&root.0, &bin, "oversize")?;
    ensure!(
        read_frame(&malformed, &mut output, Duration::from_secs(3)).is_err(),
        "oversize frame accepted"
    );
    malformed.release(Vec::new()).context("malformed cleanup")?;
    let (mut positive, mut output) = start(&root.0, &bin, "slow")?;
    let completed = read_frame(&positive, &mut output, Duration::from_secs(5))?;
    let completed = positive
        .release(completed)
        .context("slow positive release")?;
    let completed: serde_json::Value = serde_json::from_slice(&completed)?;
    ensure!(
        completed["status"] == "executed" && root.0.join("marker").is_file(),
        "slow positive control did not run"
    );
    fs::remove_file(root.0.join("ready"))?;
    fs::remove_file(root.0.join("marker"))?;
    let (mut slow, mut output) = start(&root.0, &bin, "slow")?;
    let deadline = Instant::now() + Duration::from_secs(3);
    while !root.0.join("ready").is_file() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
    }
    ensure!(root.0.join("ready").is_file(), "slow fixture not ready");
    ensure!(
        read_frame(&slow, &mut output, Duration::from_millis(100)).is_err(),
        "timed-out output released"
    );
    slow.release(Vec::new()).context("timeout cleanup")?;
    std::thread::sleep(Duration::from_millis(2400));
    ensure!(!root.0.join("marker").exists(), "timed-out child survived");
    let (mut dead, mut output) = start(&root.0, &bin, "die")?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while dead.live()? && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
    }
    ensure!(!dead.live()?, "premature guardian still running");
    ensure!(
        read_frame(&dead, &mut output, Duration::from_secs(1)).is_err(),
        "dead owner released output"
    );
    ensure!(
        dead.release(Vec::new()).is_err(),
        "dead owner was signalled"
    );
    let mut child = dead.0.take().context("dead child missing")?;
    child.wait()?;
    println!("PASS: bounded result released only after owned-group stop");
    Ok(())
}
