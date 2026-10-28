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
        for name in ["delayed", "ready", "marker"] {
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
fn guard(root: &Path, execution: &Path) -> Result<()> {
    let mut process = Command::new(execution)
        .arg("--tool-request")
        .current_dir(root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    process
        .stdin
        .take()
        .context("request pipe")?
        .write_all(br#"{"command":"./delayed"}"#)?;
    let status = process.wait()?;
    ensure!(status.success(), "execution fixture failed");
    let mut b = [0u8];
    let _ = std::io::Read::read(&mut std::io::stdin(), &mut b);
    Ok(())
}
fn start(root: &Path, execution: &Path) -> Result<Leader> {
    let child = Command::new(std::env::current_exe()?)
        .arg("guard")
        .arg(root)
        .arg(execution)
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
        ensure!(args.len() == 4, "bad fixture args");
        return guard(Path::new(&args[2]), Path::new(&args[3]));
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
    fs::set_permissions(root.0.join("delayed"), fs::Permissions::from_mode(0o700))?;
    let mut positive = start(&root.0, &bin)?;
    wait_file(&root.0.join("ready"), Duration::from_secs(5))?;
    wait_file(&root.0.join("marker"), Duration::from_secs(5))?;
    positive.stop()?;
    fs::remove_file(root.0.join("ready"))?;
    fs::remove_file(root.0.join("marker"))?;
    let mut negative = start(&root.0, &bin)?;
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
    Ok(())
}
