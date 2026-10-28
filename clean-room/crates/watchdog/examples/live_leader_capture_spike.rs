//! Disposable group-leader capture experiment, not production execution or containment.
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::process::{CommandExt, ExitStatusExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
const CAP: usize = 4096;
const MAGIC: &[u8; 4] = b"SFC1";
struct Root(PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.join("timeout-marker"));
        let _ = fs::remove_file(self.0.join("timeout-ready"));
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
            "lost leader ownership"
        );
        Ok(unsafe { info.si_pid() } == 0
            && unsafe { libc::getpgid(child.id() as i32) } == child.id() as i32)
    }
    fn signal_with(&self, signal: impl FnOnce(i32) -> std::io::Result<()>) -> Result<()> {
        ensure!(self.live()?, "leader is not live in its group");
        signal(self.0.as_ref().unwrap().id() as i32)?;
        Ok(())
    }
    fn kill(&self) -> Result<()> {
        self.signal_with(|pid| {
            if unsafe { libc::kill(-pid, libc::SIGKILL) } == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        })
    }
    fn wait(&mut self) -> Result<std::process::ExitStatus> {
        Ok(self.0.take().context("leader reaped")?.wait()?)
    }
}
impl Drop for Leader {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            child.stdin.take();
        }
        if self.live().unwrap_or(false) {
            let _ = self.kill();
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
        "nonblocking setup failed"
    );
    Ok(())
}
struct Capture {
    bytes: Vec<u8>,
    eof: bool,
    truncated: bool,
}
impl Capture {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            eof: false,
            truncated: false,
        }
    }
    fn drain(&mut self, fd: &mut impl Read) -> Result<()> {
        let mut bytes = [0u8; 2048];
        for _ in 0..4 {
            match fd.read(&mut bytes) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(n) => {
                    let keep = n.min(CAP - self.bytes.len());
                    self.bytes.extend_from_slice(&bytes[..keep]);
                    self.truncated |= keep < n;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}
fn guard(mode: &str, root: &Path) -> Result<()> {
    if mode == "malformed" {
        // One stream declares CAP + 1; no payload or target is spawned.
        std::io::stdout().write_all(b"SFC1\x00\x00\x10\x01\x00\x00")?;
        std::io::stdout().flush()?;
        let mut byte = [0];
        let _ = std::io::stdin().read(&mut byte);
        return Ok(());
    }
    let script = match mode {
        "capture" | "dead" => {
            "printf 'SFC1 forged-out\\n'; printf 'SFC1 forged-err\\n' >&2; head -c 65536 /dev/zero & head -c 65536 /dev/zero >&2 & wait; exit 7"
        }
        "timeout" => "printf ready > \"$2\"; sleep 1; printf survived > \"$1\"; exit 0",
        _ => anyhow::bail!("invalid fixture mode"),
    };
    let mut child = Command::new("/bin/sh")
        .args(["-c", script, "fixture"])
        .arg(root.join("timeout-marker"))
        .arg(root.join("timeout-ready"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if mode == "dead" {
        // A truncated frame and a finite direct child; the parent may not signal
        // this group once it has observed the leader's exit.
        std::io::stdout().write_all(b"SFC1\0")?;
        std::io::stdout().flush()?;
        // Capture command children have a fixed finite workload and no fixture marker.
        return Ok(());
    }
    let mut out = child.stdout.take().context("stdout unavailable")?;
    let mut err = child.stderr.take().context("stderr unavailable")?;
    nonblock(&out)?;
    nonblock(&err)?;
    let (mut a, mut b) = (Capture::new(), Capture::new());
    let deadline = Instant::now() + Duration::from_secs(6);
    let mut status = None;
    loop {
        a.drain(&mut out)?;
        b.drain(&mut err)?;
        if status.is_none() {
            status = child.try_wait()?;
        }
        if status.is_some() && a.eof && b.eof {
            break;
        }
        ensure!(Instant::now() < deadline, "guard capture deadline");
        std::thread::sleep(Duration::from_millis(2));
    }
    let code = status
        .unwrap()
        .code()
        .context("signal exit unsupported in fixture")?;
    let mut frame = Vec::with_capacity(10 + a.bytes.len() + b.bytes.len());
    frame.extend_from_slice(MAGIC);
    frame.push(u8::try_from(code)?);
    frame.push(u8::from(a.truncated) | (u8::from(b.truncated) << 1));
    frame.extend_from_slice(&(a.bytes.len() as u16).to_be_bytes());
    frame.extend_from_slice(&(b.bytes.len() as u16).to_be_bytes());
    frame.extend_from_slice(&a.bytes);
    frame.extend_from_slice(&b.bytes);
    std::io::stdout().write_all(&frame)?;
    std::io::stdout().flush()?;
    let mut byte = [0];
    let _ = std::io::stdin().read(&mut byte);
    Ok(())
}
fn start(mode: &str, root: &Path) -> Result<(Leader, std::process::ChildStdout)> {
    let mut child = Command::new(std::env::current_exe()?)
        .arg("guard")
        .arg(mode)
        .arg(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()?;
    let stdout = child.stdout.take().context("private pipe unavailable")?;
    nonblock(&stdout)?;
    Ok((Leader(Some(child)), stdout))
}
fn read_frame(leader: &Leader, pipe: &mut impl Read, timeout: Duration) -> Result<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    let mut bytes = Vec::new();
    let mut buf = [0u8; 2048];
    loop {
        match pipe.read(&mut buf) {
            Ok(0) => anyhow::bail!("private frame ended before acceptance"),
            Ok(n) => {
                bytes.extend_from_slice(&buf[..n]);
                ensure!(bytes.len() <= 10 + 2 * CAP, "frame exceeds limit");
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
        if bytes.len() >= 10 {
            ensure!(&bytes[..4] == MAGIC, "invalid frame magic");
            let a = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;
            let b = u16::from_be_bytes([bytes[8], bytes[9]]) as usize;
            ensure!(a <= CAP && b <= CAP, "frame stream limit exceeded");
            if bytes.len() == 10 + a + b {
                ensure!(leader.live()?, "leader died before frame acceptance");
                return Ok(bytes);
            }
            ensure!(bytes.len() < 10 + a + b, "trailing frame data");
        }
        ensure!(leader.live()?, "leader died with incomplete frame");
        ensure!(Instant::now() < deadline, "frame deadline expired");
        std::thread::sleep(Duration::from_millis(2));
    }
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.get(1).is_some_and(|a| a == "guard") {
        ensure!(args.len() == 4, "invalid fixture args");
        return guard(args[2].to_str().context("mode")?, Path::new(&args[3]));
    }
    let path = std::env::temp_dir().join(format!("sf-capture-{}", ulid::Ulid::new()));
    fs::create_dir(&path)?;
    let root = Root(path);
    let (mut leader, mut pipe) = start("capture", &root.0)?;
    let frame = read_frame(&leader, &mut pipe, Duration::from_secs(8))?;
    ensure!(
        leader
            .signal_with(|_| Err(std::io::Error::from_raw_os_error(libc::EPERM)))
            .is_err()
            && leader.live()?,
        "signal failure was accepted or ownership released"
    );
    leader.kill()?;
    ensure!(
        leader.wait()?.signal() == Some(libc::SIGKILL),
        "leader did not stop"
    );
    // Captured bytes are inspected only after successful kill and sole reap.
    ensure!(frame[4] == 7 && frame[5] == 3, "wrong status or truncation");
    let a = u16::from_be_bytes([frame[6], frame[7]]) as usize;
    let b = u16::from_be_bytes([frame[8], frame[9]]) as usize;
    ensure!(
        a == CAP
            && b == CAP
            && frame[10..].starts_with(b"SFC1 forged-out\n")
            && frame[10 + a..].starts_with(b"SFC1 forged-err\n"),
        "capture did not isolate both streams"
    );
    // A no-timeout control proves the target really can produce its delayed effect.
    let (mut positive, mut pipe) = start("timeout", &root.0)?;
    let positive_frame = read_frame(&positive, &mut pipe, Duration::from_secs(4))?;
    positive.kill()?;
    ensure!(
        positive.wait()?.signal() == Some(libc::SIGKILL),
        "positive leader survived"
    );
    ensure!(
        positive_frame[4] == 0 && root.0.join("timeout-marker").is_file(),
        "timeout positive control did not execute"
    );
    fs::remove_file(root.0.join("timeout-marker"))?;
    fs::remove_file(root.0.join("timeout-ready"))?;
    let (mut timeout, mut pipe) = start("timeout", &root.0)?;
    let ready_deadline = Instant::now() + Duration::from_secs(3);
    while !root.0.join("timeout-ready").is_file() && Instant::now() < ready_deadline {
        std::thread::sleep(Duration::from_millis(2));
    }
    ensure!(
        root.0.join("timeout-ready").is_file() && !root.0.join("timeout-marker").exists(),
        "timeout target was not observed before its effect"
    );
    ensure!(
        read_frame(&timeout, &mut pipe, Duration::from_millis(150)).is_err(),
        "timeout released output"
    );
    timeout.kill()?;
    ensure!(
        timeout.wait()?.signal() == Some(libc::SIGKILL),
        "timeout leader survived"
    );
    std::thread::sleep(Duration::from_millis(1400));
    ensure!(
        !root.0.join("timeout-marker").exists(),
        "timeout descendant survived"
    );
    let (mut malformed, mut pipe) = start("malformed", &root.0)?;
    ensure!(
        read_frame(&malformed, &mut pipe, Duration::from_secs(3)).is_err(),
        "oversized declared frame accepted"
    );
    malformed.kill()?;
    ensure!(
        malformed.wait()?.signal() == Some(libc::SIGKILL),
        "malformed leader survived"
    );
    let (mut dead, mut pipe) = start("dead", &root.0)?;
    ensure!(
        read_frame(&dead, &mut pipe, Duration::from_secs(3)).is_err(),
        "premature frame accepted"
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    while dead.live()? && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
    }
    ensure!(!dead.live()?, "premature leader survived");
    ensure!(dead.kill().is_err(), "dead leader signalled");
    let _ = dead.wait()?;
    // The dead-guard target has only finite output generators. Do not signal an orphan.
    std::thread::sleep(Duration::from_secs(2));
    println!(
        "PASS: bounded separate streams, forged status, timeout, signal failure, and truncated dead-leader frame"
    );
    Ok(())
}
