//! Disposable same-UID experiment. This is not an execution or containment implementation.
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::{
        fs::PermissionsExt,
        process::{CommandExt, ExitStatusExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Root(PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        for name in ["positive", "stopped", "premature"] {
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
            "leader ownership unavailable"
        );
        Ok(unsafe { info.si_pid() } == 0
            && unsafe { libc::getpgid(child.id() as i32) } == child.id() as i32)
    }
    fn signal_with(&mut self, signal: impl FnOnce(i32) -> std::io::Result<()>) -> Result<()> {
        ensure!(self.live()?, "leader is not live in its private group");
        signal(self.0.as_ref().unwrap().id() as i32)?;
        Ok(())
    }
    fn signal(&mut self) -> Result<()> {
        self.signal_with(|pid| {
            if unsafe { libc::kill(-pid, libc::SIGKILL) } == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        })
    }
    fn wait(&mut self) -> Result<std::process::ExitStatus> {
        Ok(self.0.take().context("leader already reaped")?.wait()?)
    }
}
impl Drop for Leader {
    fn drop(&mut self) {
        if self.0.is_some() {
            // On any fixture error, EOF also gives the benign guard a way to exit
            // if a group signal fails; its synthetic descendant has a one-second bound.
            self.0.as_mut().unwrap().stdin.take();
            if self.live().unwrap_or(false) {
                let _ = self.signal();
            }
            if let Some(mut child) = self.0.take() {
                let _ = child.wait();
            }
        }
    }
}
fn guard(marker: &Path, premature: bool) -> Result<()> {
    // No model-controlled args; target never inherits the private control/stdout channels.
    let status = Command::new("/bin/sh")
        .args([
            "-c",
            "printf 'EXIT 99\\n'; (sleep 1; printf done > \"$1\") & exit 7",
            "fixture",
        ])
        .arg(marker)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    ensure!(status.code() == Some(7), "target exit not observed");
    println!("EXIT 7");
    std::io::stdout().flush()?;
    if premature {
        return Ok(());
    }
    let mut line = String::new();
    let _ = BufReader::new(std::io::stdin()).read_line(&mut line);
    Ok(())
}
fn start(
    root: &Root,
    name: &str,
    premature: bool,
) -> Result<(Leader, BufReader<std::process::ChildStdout>)> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("guard")
        .arg(root.0.join(name))
        .arg(if premature { "die" } else { "live" })
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    let mut child = command.spawn()?;
    let stdout = BufReader::new(child.stdout.take().context("control stdout missing")?);
    Ok((Leader(Some(child)), stdout))
}
fn status(out: &mut BufReader<std::process::ChildStdout>) -> Result<()> {
    let mut line = String::new();
    out.read_line(&mut line)?;
    ensure!(
        line == "EXIT 7\n",
        "guard did not report exact target status"
    );
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.get(1).is_some_and(|a| a == "guard") {
        ensure!(args.len() == 4, "invalid guard invocation");
        return guard(Path::new(&args[2]), args[3] == "die");
    }
    let path = std::env::temp_dir().join(format!("sf-live-guard-{}", ulid::Ulid::new()));
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let root = Root(path);
    // Positive control: the in-group descendant really produces its delayed effect.
    let (mut positive, mut out) = start(&root, "positive", false)?;
    status(&mut out)?;
    std::thread::sleep(Duration::from_millis(1400));
    ensure!(
        root.0.join("positive").is_file(),
        "positive descendant did not run"
    );
    positive.signal()?;
    ensure!(
        positive.wait()?.signal() == Some(libc::SIGKILL),
        "positive guard was not killed"
    );
    // Failed signal is withheld while the owned leader remains live; a later real
    // signal can safely retry before the owned leader is reaped.
    let (mut stopped, mut out) = start(&root, "stopped", false)?;
    status(&mut out)?;
    ensure!(
        stopped
            .signal_with(|_| Err(std::io::Error::from_raw_os_error(libc::EPERM)))
            .is_err(),
        "injected failure accepted"
    );
    ensure!(stopped.live()?, "failed signal released leader ownership");
    stopped.signal()?;
    ensure!(
        stopped.wait()?.signal() == Some(libc::SIGKILL),
        "guard not killed"
    );
    ensure!(stopped.signal().is_err(), "signal after reap accepted");
    std::thread::sleep(Duration::from_millis(1400));
    ensure!(
        !root.0.join("stopped").exists(),
        "in-group descendant survived"
    );
    // Premature guard death is not a completed stop; do not signal its numeric PID.
    let (mut lost, mut out) = start(&root, "premature", true)?;
    status(&mut out)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    while lost.live()? && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    ensure!(!lost.live()?, "premature guard did not exit");
    ensure!(lost.signal().is_err(), "dead leader was signalled");
    ensure!(lost.wait()?.success(), "unexpected guard exit");
    std::thread::sleep(Duration::from_millis(1400));
    ensure!(
        root.0.join("premature").is_file(),
        "premature loss control did not run"
    );
    println!(
        "PASS: normal status, descendant suppression, EPERM retention, and premature-owner negative control"
    );
    Ok(())
}
