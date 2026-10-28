//! Reusable disposable result gate. Not an authenticated production launcher.
use anyhow::{Context, Result, ensure};
use std::{
    io::Read,
    os::{
        fd::AsRawFd,
        unix::process::{CommandExt, ExitStatusExt},
    },
    process::{Child, ChildStdout, Command, Stdio},
    time::{Duration, Instant},
};
const CAP: usize = 4096;
const CLEANUP: Duration = Duration::from_secs(2);

/// Owns the direct group leader and never accepts an existing numeric process ID.
/// Caller-supplied commands and their configuration must be trusted fixture inputs.
pub struct FixtureGroup {
    child: Option<Child>,
    stdout: ChildStdout,
    signalled: bool,
}
impl FixtureGroup {
    pub fn launch(command: &mut Command) -> Result<Self> {
        crate::check_reaping_policy()?;
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()?;
        let stdout = child.stdout.take().context("private frame pipe missing")?;
        let group = Self {
            child: Some(child),
            stdout,
            signalled: false,
        };
        let flags = unsafe { libc::fcntl(group.stdout.as_raw_fd(), libc::F_GETFL) };
        ensure!(
            flags >= 0
                && unsafe {
                    libc::fcntl(
                        group.stdout.as_raw_fd(),
                        libc::F_SETFL,
                        flags | libc::O_NONBLOCK,
                    )
                } == 0,
            "private frame pipe setup failed"
        );
        Ok(group)
    }
    pub fn is_reaped(&self) -> bool {
        self.child.is_none()
    }
    // WNOWAIT proves the direct child remains ours, including an exited zombie whose
    // PID still anchors the original group. Never reap it before the signal attempt.
    fn owned_leader_alive(&self) -> Result<bool> {
        crate::check_reaping_policy()?;
        let child = self.child.as_ref().context("owned leader unavailable")?;
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
        let alive = unsafe { info.si_pid() } == 0;
        if alive {
            ensure!(
                unsafe { libc::getpgid(child.id() as i32) } == child.id() as i32,
                "live leader group identity changed"
            );
        }
        Ok(alive)
    }
    fn live(&self) -> Result<bool> {
        self.owned_leader_alive()
    }
    fn read_frame(
        &mut self,
        timeout: Duration,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<Vec<u8>> {
        ensure!(
            !timeout.is_zero() && timeout <= Duration::from_secs(30),
            "invalid frame deadline"
        );
        let deadline = Instant::now() + timeout;
        let mut data = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            check()?;
            match self.stdout.read(&mut chunk) {
                Ok(0) => anyhow::bail!("frame incomplete"),
                Ok(n) => {
                    data.extend_from_slice(&chunk[..n]);
                    ensure!(data.len() <= CAP + 8, "frame too large");
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
            if data.len() >= 8 {
                ensure!(&data[..4] == b"SFR1", "frame magic invalid");
                let n = u32::from_be_bytes(data[4..8].try_into().unwrap()) as usize;
                ensure!(n <= CAP, "declared frame exceeds cap");
                if data.len() == n + 8 {
                    ensure!(self.live()?, "leader died before completion");
                    return Ok(data[8..].to_vec());
                }
                ensure!(data.len() < n + 8, "trailing frame bytes");
            }
            ensure!(self.live()?, "leader unavailable before completion");
            ensure!(Instant::now() < deadline, "frame deadline exceeded");
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    fn stop_with(&mut self, signal: impl FnOnce(i32) -> std::io::Result<()>) -> Result<()> {
        if !self.signalled {
            // An exited but unreaped leader still anchors the original group ID.
            // An error (including EPERM) preserves ownership and prevents release.
            let _ = self.owned_leader_alive()?;
            let pid = self.child.as_ref().unwrap().id() as i32;
            signal(pid)?;
            self.signalled = true;
        }
        let pid = self.child.as_ref().context("leader reaped")?.id() as i32;
        let deadline = Instant::now() + CLEANUP;
        let status = loop {
            if let Some(status) = self.child.as_mut().unwrap().try_wait()? {
                break status;
            }
            ensure!(Instant::now() < deadline, "leader reap unresolved");
            std::thread::sleep(Duration::from_millis(5));
        };
        self.child = None;
        ensure!(
            status.signal() == Some(libc::SIGKILL),
            "leader termination unverified"
        );
        confirm_absence(CLEANUP, || {
            if unsafe { libc::kill(-pid, 0) } == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        })
    }
    fn stop(&mut self) -> Result<()> {
        self.stop_with(|pid| {
            if unsafe { libc::kill(-pid, libc::SIGKILL) } == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        })
    }
    /// No frame bytes escape unless owned group stop and absence both succeed.
    pub fn complete(&mut self, timeout: Duration) -> Result<Vec<u8>> {
        self.complete_with(timeout, |pid| {
            if unsafe { libc::kill(-pid, libc::SIGKILL) } == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        })
    }
    /// Fixture guardian: EOF denies output and stops the owned group. The caller
    /// must supply the sole read end of a controller pipe and keep it open.
    pub fn complete_with_controller(
        &mut self,
        timeout: Duration,
        controller: &impl AsRawFd,
    ) -> Result<Option<Vec<u8>>> {
        self.complete_controller_with(timeout, controller, |pid| {
            if unsafe { libc::kill(-pid, libc::SIGKILL) } == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        })
    }
    fn complete_controller_with(
        &mut self,
        timeout: Duration,
        controller: &impl AsRawFd,
        signal: impl FnOnce(i32) -> std::io::Result<()>,
    ) -> Result<Option<Vec<u8>>> {
        let fd = controller.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
            self.stop_with(signal)?;
            anyhow::bail!("controller pipe setup failed");
        }
        let mut eof = false;
        let mut check = || -> Result<()> {
            let mut byte = 0u8;
            let n = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
            if n == 0 {
                eof = true;
                anyhow::bail!("controller EOF");
            }
            if n > 0 {
                anyhow::bail!("unexpected controller data");
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(());
            }
            Err(error.into())
        };
        let frame = self.read_frame(timeout, &mut check);
        self.stop_with(signal)?;
        let final_check = if frame.is_ok() { check() } else { Ok(()) };
        if eof {
            return Ok(None);
        }
        final_check?;
        frame.map(Some)
    }
    fn complete_with(
        &mut self,
        timeout: Duration,
        signal: impl FnOnce(i32) -> std::io::Result<()>,
    ) -> Result<Vec<u8>> {
        let frame = self.read_frame(timeout, || Ok(()));
        let stopped = self.stop_with(signal);
        match (frame, stopped) {
            (Ok(frame), Ok(())) => Ok(frame),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }
}
fn confirm_absence(
    timeout: Duration,
    mut observe: impl FnMut() -> std::io::Result<()>,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let observed = observe();
        if observed
            .as_ref()
            .err()
            .and_then(std::io::Error::raw_os_error)
            == Some(libc::ESRCH)
        {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "group absence unverified: signal-zero result={:?}",
            observed
                .as_ref()
                .err()
                .and_then(std::io::Error::raw_os_error)
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
impl Drop for FixtureGroup {
    fn drop(&mut self) {
        if self.child.is_some() {
            let _ = self.stop();
        }
        if let Some(child) = self.child.as_mut() {
            child.stdin.take();
            let _ = child.try_wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn controller_failure_paths_stop_or_retain_owned_group() {
        use std::{io::Write, os::unix::net::UnixStream};
        // Unexpected data and an open but silent controller both deny release.
        for invalid in [true, false] {
            let (reader, mut writer) = UnixStream::pair().unwrap();
            if invalid {
                writer.write_all(b"x").unwrap();
            }
            let mut group = FixtureGroup::launch(Command::new("/bin/sleep").arg("5")).unwrap();
            assert!(
                group
                    .complete_with_controller(Duration::from_millis(100), &reader)
                    .is_err()
            );
            assert!(group.is_reaped());
        }
        let (reader, writer) = UnixStream::pair().unwrap();
        drop(writer);
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf 'SFR1\\000\\000\\000\\003yes'; exec sleep 5"]);
        let mut group = FixtureGroup::launch(&mut command).unwrap();
        assert_eq!(
            group
                .complete_with_controller(Duration::from_secs(1), &reader)
                .unwrap(),
            None
        );
        assert!(group.is_reaped());
        let (reader, writer) = UnixStream::pair().unwrap();
        drop(writer);
        let mut group = FixtureGroup::launch(Command::new("/bin/sleep").arg("5")).unwrap();
        assert!(
            group
                .complete_controller_with(Duration::from_secs(1), &reader, |_| Err(
                    std::io::Error::from_raw_os_error(libc::EPERM)
                ))
                .is_err()
        );
        assert!(!group.is_reaped() && group.live().unwrap());
        group.stop().unwrap();
        assert!(group.is_reaped());
    }
    #[test]
    fn live_controller_allows_only_stopped_group_frame() {
        use std::os::unix::net::UnixStream;
        let (reader, _writer) = UnixStream::pair().unwrap();
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf 'SFR1\\000\\000\\000\\003yes'; exec sleep 5"]);
        let mut group = FixtureGroup::launch(&mut command).unwrap();
        assert_eq!(
            group
                .complete_with_controller(Duration::from_secs(3), &reader)
                .unwrap(),
            Some(b"yes".to_vec())
        );
        assert!(group.is_reaped());
    }
    #[test]
    fn signal_failure_withholds_frame_and_retains_live_owned_leader() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf 'SFR1\\000\\000\\000\\003yes'; exec sleep 5"]);
        let mut group = FixtureGroup::launch(&mut command).unwrap();
        let result = group.complete_with(Duration::from_secs(3), |_| {
            Err(std::io::Error::from_raw_os_error(libc::EPERM))
        });
        assert!(result.is_err());
        assert!(!group.is_reaped() && group.live().unwrap());
        group.stop().unwrap();
        assert!(group.is_reaped());
    }
    #[test]
    fn signal_failure_after_leader_exit_preserves_unreaped_ownership() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "/bin/sleep 2 & exit 0"]);
        let mut group = FixtureGroup::launch(&mut command).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while !matches!(group.live(), Ok(false)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(matches!(group.live(), Ok(false)), "leader did not exit");
        assert!(
            group
                .stop_with(|_| Err(std::io::Error::from_raw_os_error(libc::EPERM)))
                .is_err()
        );
        assert!(
            !group.is_reaped(),
            "failed signal must preserve leader ownership"
        );
        assert!(!group.live().unwrap());
        // The group signal succeeds, but a naturally exited leader is never a release proof.
        assert!(group.stop().is_err());
        assert!(group.is_reaped());
    }

    #[test]
    fn absence_observation_fails_closed_on_present_or_eperm() {
        assert!(confirm_absence(Duration::ZERO, || Ok(())).is_err());
        assert!(
            confirm_absence(Duration::ZERO, || Err(std::io::Error::from_raw_os_error(
                libc::EPERM
            )))
            .is_err()
        );
        assert!(
            confirm_absence(Duration::ZERO, || Err(std::io::Error::from_raw_os_error(
                libc::ESRCH
            )))
            .is_ok()
        );
    }
}
