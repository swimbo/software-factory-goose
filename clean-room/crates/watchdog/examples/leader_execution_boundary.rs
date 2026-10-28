//! Disposable negative control for wrapping the real execution fixture in a group leader.
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    io::Write,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
struct Root(PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        for name in ["delayed", "masked", "ready", "marker", "complete"] {
            let _ = fs::remove_file(self.0.join(name));
        }
        let _ = fs::remove_dir(&self.0);
    }
}
struct Leader(Option<Child>);
impl Leader {
    fn live(&self) -> Result<bool> {
        let child = self.0.as_ref().context("leader already reaped")?;
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
            "ownership unavailable"
        );
        Ok(unsafe { info.si_pid() } == 0
            && unsafe { libc::getpgid(child.id() as i32) } == child.id() as i32)
    }
    fn stop(&mut self) -> Result<()> {
        ensure!(self.live()?, "leader not live");
        let child = self.0.as_mut().unwrap();
        ensure!(
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) } == 0,
            "group signal failed"
        );
        let mut child = self.0.take().unwrap();
        child.wait()?;
        Ok(())
    }
}
impl Drop for Leader {
    fn drop(&mut self) {
        if let Some(c) = self.0.as_mut() {
            c.stdin.take();
        }
        if self.live().unwrap_or(false) {
            let _ = self.stop();
        }
        if let Some(mut c) = self.0.take() {
            let _ = c.wait();
        }
    }
}
fn guard(root: &Path, execution: &Path, inherited: bool, positive: bool) -> Result<()> {
    let mut process = Command::new(execution)
        .arg(if inherited {
            "--fixture-inherited-tool-request"
        } else {
            "--tool-request"
        })
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
        .write_all(if positive {
            br#"{"command":"./masked"}"#
        } else {
            br#"{"command":"./delayed"}"#
        })?;
    let output = process.wait_with_output()?;
    ensure!(output.status.success(), "execution fixture failed");
    let response: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let expected = if positive { "[REDACTED]" } else { "" };
    ensure!(
        response["status"] == "executed"
            && response["exit_code"] == 0
            && response["stdout"] == expected
            && response["stderr"] == expected,
        "execution did not return the expected completed response"
    );
    fs::write(root.join("complete"), b"fixture-validated")?;
    let mut b = [0u8];
    let _ = std::io::Read::read(&mut std::io::stdin(), &mut b);
    Ok(())
}
fn start(root: &Path, execution: &Path, inherited: bool, positive: bool) -> Result<Leader> {
    let child = Command::new(std::env::current_exe()?)
        .arg("guard")
        .arg(root)
        .arg(execution)
        .arg(if inherited { "inherited" } else { "separate" })
        .arg(if positive { "positive" } else { "negative" })
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()?;
    Ok(Leader(Some(child)))
}
fn wait_file(path: &Path, max: Duration) -> Result<()> {
    let until = Instant::now() + max;
    while !path.is_file() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(5));
    }
    ensure!(
        path.is_file(),
        "fixture file not observed: {}",
        path.display()
    );
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.get(1).is_some_and(|a| a == "guard") {
        ensure!(args.len() == 6, "bad fixture args");
        return guard(
            Path::new(&args[2]),
            Path::new(&args[3]),
            args[4] == "inherited",
            args[5] == "positive",
        );
    }
    let bin = std::env::current_exe()?
        .parent()
        .context("examples")?
        .parent()
        .context("debug")?
        .join("execution");
    ensure!(bin.is_file(), "build task-owned execution binary first");
    let path = std::env::temp_dir().join(format!("sf-execution-group-{}", ulid::Ulid::new()));
    fs::create_dir(&path)?;
    let root = Root(path);
    fs::write(
        root.0.join("delayed"),
        b"#!/bin/sh\nprintf '%s' $$ > ready\nsleep 2\nprintf done > marker\n",
    )?;
    fs::write(
        root.0.join("masked"),
        b"#!/bin/sh\nprintf '%s' $$ > ready\nprintf sk-OFF\nsleep 0.01\nprintf LINE0123456789ABCDEFGHIJKLMN\nprintf 'password=fixture-only' >&2\nsleep 2\nprintf done > marker\n",
    )?;
    fs::set_permissions(root.0.join("delayed"), fs::Permissions::from_mode(0o700))?;
    fs::set_permissions(root.0.join("masked"), fs::Permissions::from_mode(0o700))?;
    let mut positive = start(&root.0, &bin, false, true)?;
    wait_file(&root.0.join("ready"), Duration::from_secs(5))?;
    wait_file(&root.0.join("marker"), Duration::from_secs(5))?;
    wait_file(&root.0.join("complete"), Duration::from_secs(5))?;
    positive.stop()?;
    fs::remove_file(root.0.join("ready"))?;
    fs::remove_file(root.0.join("marker"))?;
    fs::remove_file(root.0.join("complete"))?;
    let mut separate_control = start(&root.0, &bin, false, false)?;
    wait_file(&root.0.join("marker"), Duration::from_secs(5))?;
    wait_file(&root.0.join("complete"), Duration::from_secs(5))?;
    separate_control.stop()?;
    fs::remove_file(root.0.join("ready"))?;
    fs::remove_file(root.0.join("marker"))?;
    fs::remove_file(root.0.join("complete"))?;
    let mut negative = start(&root.0, &bin, false, false)?;
    wait_file(&root.0.join("ready"), Duration::from_secs(5))?;
    ensure!(!root.0.join("marker").exists(), "marker predates stop");
    let pid_deadline = Instant::now() + Duration::from_secs(1);
    let inner_pid: i32 = loop {
        if let Ok(pid) = fs::read_to_string(root.0.join("ready"))
            .unwrap_or_default()
            .parse()
        {
            break pid;
        }
        ensure!(Instant::now() < pid_deadline, "fixture PID was not written");
        std::thread::sleep(Duration::from_millis(2));
    };
    ensure!(inner_pid > 1, "invalid synthetic child pid");
    let outer_pgid = negative.0.as_ref().context("leader missing")?.id() as i32;
    // Observation only: this PID is never used as signaling authority.
    let inner_pgid = unsafe { libc::getpgid(inner_pid) };
    ensure!(
        inner_pgid > 1 && inner_pgid != outer_pgid,
        "inner shell group was not observed distinct"
    );
    negative.stop()?;
    // The fixed-duration inner shell is allowed to finish. Do not signal its numeric PID.
    wait_file(&root.0.join("marker"), Duration::from_secs(5))?;
    println!("CONFIRMED GAP: execution shell group survived outer leader stop");
    fs::remove_file(root.0.join("ready"))?;
    fs::remove_file(root.0.join("marker"))?;
    let mut inherited_positive = start(&root.0, &bin, true, true)?;
    wait_file(&root.0.join("ready"), Duration::from_secs(5))?;
    wait_file(&root.0.join("marker"), Duration::from_secs(5))?;
    wait_file(&root.0.join("complete"), Duration::from_secs(5))?;
    inherited_positive.stop()?;
    fs::remove_file(root.0.join("ready"))?;
    fs::remove_file(root.0.join("marker"))?;
    fs::remove_file(root.0.join("complete"))?;
    let mut inherited_control = start(&root.0, &bin, true, false)?;
    wait_file(&root.0.join("marker"), Duration::from_secs(5))?;
    wait_file(&root.0.join("complete"), Duration::from_secs(5))?;
    inherited_control.stop()?;
    fs::remove_file(root.0.join("ready"))?;
    fs::remove_file(root.0.join("marker"))?;
    fs::remove_file(root.0.join("complete"))?;
    let mut inherited_negative = start(&root.0, &bin, true, false)?;
    wait_file(&root.0.join("ready"), Duration::from_secs(5))?;
    ensure!(
        !root.0.join("marker").exists(),
        "inherited marker predates stop"
    );
    let deadline = Instant::now() + Duration::from_secs(1);
    let pid: i32 = loop {
        if let Ok(pid) = fs::read_to_string(root.0.join("ready"))
            .unwrap_or_default()
            .parse()
        {
            break pid;
        }
        ensure!(Instant::now() < deadline, "inherited PID was not written");
        std::thread::sleep(Duration::from_millis(2));
    };
    ensure!(
        pid > 1
            && unsafe { libc::getpgid(pid) } == inherited_negative.0.as_ref().unwrap().id() as i32,
        "fixture shell was not in the leader group"
    );
    inherited_negative.stop()?;
    std::thread::sleep(Duration::from_millis(2400));
    ensure!(
        !root.0.join("marker").exists(),
        "inherited shell survived leader stop"
    );
    println!("PASS: inherited fixture shell stopped with leader");
    Ok(())
}
