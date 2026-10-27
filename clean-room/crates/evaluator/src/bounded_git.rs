//! Fixed-command subprocess bounds, including non-reaping process-group ownership.
use anyhow::{Result, bail, ensure};
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[cfg(all(unix, any(target_os = "macos", target_os = "linux")))]
mod platform {
    use super::*;
    use std::{
        os::{fd::AsRawFd, unix::process::CommandExt},
        process::{Child, ExitStatus},
    };
    pub(crate) struct OwnedGroup(Option<Child>);
    impl OwnedGroup {
        pub(crate) fn new(child: Child) -> Self {
            Self(Some(child))
        }
        pub(crate) fn exited(&self) -> std::io::Result<bool> {
            let child = self
                .0
                .as_ref()
                .ok_or_else(|| std::io::Error::other("child already reaped"))?;
            loop {
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                // WNOWAIT retains the leader PID until the sole owner signals its group.
                let result = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        child.id(),
                        &mut info,
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    )
                };
                if result == 0 {
                    return Ok(unsafe { info.si_pid() } != 0);
                }
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
        pub(crate) fn cleanup(&mut self) -> std::io::Result<ExitStatus> {
            // ECHILD/unsupported ownership means never signal a potentially recycled PGID.
            self.exited()?;
            let child = self
                .0
                .as_ref()
                .ok_or_else(|| std::io::Error::other("child absent"))?;
            let pid = i32::try_from(child.id())
                .map_err(|_| std::io::Error::other("invalid child PID"))?;
            if unsafe { libc::kill(-pid, libc::SIGKILL) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH)
                    && !(error.raw_os_error() == Some(libc::EPERM)
                        && self.exited()?
                        && sole_unreaped_member(pid))
                {
                    return Err(error);
                }
            }
            let deadline = Instant::now() + Duration::from_millis(500);
            while !self.exited()? {
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "child reap deadline exceeded",
                    ));
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            // Observation above retained an exited child, so this wait cannot block on it.
            self.0.take().expect("owned child").wait()
        }
    }
    impl Drop for OwnedGroup {
        fn drop(&mut self) {
            if self.0.is_some() {
                let _ = self.cleanup();
            }
        }
    }
    #[cfg(target_os = "macos")]
    fn sole_unreaped_member(pid: i32) -> bool {
        // XNU killpg1 filters zombies and can return EPERM for a zombie-only group.
        // Accept only a complete positive enumeration containing exactly our unreaped
        // leader. Empty/error/truncated results and every other member fail closed.
        let mut members = [0i32; 1024];
        let bytes = unsafe {
            libc::proc_listpids(
                2,
                pid as u32,
                members.as_mut_ptr().cast(),
                std::mem::size_of_val(&members) as i32,
            )
        };
        bytes == std::mem::size_of::<i32>() as i32 && members[0] == pid
    }
    #[cfg(not(target_os = "macos"))]
    fn sole_unreaped_member(_pid: i32) -> bool {
        false
    }
    fn nonblocking(pipe: &impl AsRawFd) -> Result<()> {
        let flags = unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_GETFL) };
        ensure!(
            flags >= 0
                && unsafe {
                    libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK)
                } == 0,
            "pipe setup failed"
        );
        Ok(())
    }
    pub(super) fn run(
        mut command: Command,
        input: Option<&[u8]>,
        deadline: Instant,
        limit: usize,
    ) -> Result<Vec<u8>> {
        ensure!(
            input.is_none_or(|bytes| bytes.len() <= limit),
            "Git input limit exceeded"
        );
        ensure!(Instant::now() < deadline, "Git deadline exceeded");
        command
            .process_group(0)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn()?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("missing stdout"))?;
        let mut stdin = child.stdin.take();
        let mut group = OwnedGroup::new(child);
        nonblocking(&stdout)?;
        if let Some(pipe) = &stdin {
            nonblocking(pipe)?;
        }
        let mut output = Vec::new();
        let mut written = 0;
        let mut eof = false;
        let mut status = None;
        loop {
            ensure!(Instant::now() < deadline, "Git deadline exceeded");
            let mut block = [0u8; 8192];
            // Limit work per iteration even when a process continuously fills its pipe.
            for _ in 0..8 {
                match stdout.read(&mut block) {
                    Ok(0) => {
                        eof = true;
                        break;
                    }
                    Ok(n) => {
                        ensure!(output.len() + n <= limit, "Git output limit exceeded");
                        output.extend_from_slice(&block[..n]);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error.into()),
                }
            }
            if let Some(pipe) = &mut stdin {
                let bytes = input.unwrap_or_default();
                if written < bytes.len() {
                    match pipe.write(&bytes[written..bytes.len().min(written + 8192)]) {
                        Ok(0) => bail!("Git input closed"),
                        Ok(n) => written += n,
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                            ) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                if written == bytes.len() {
                    stdin = None;
                }
            }
            if status.is_none() && group.exited()? {
                status = Some(
                    group
                        .cleanup()
                        .map_err(|error| anyhow::anyhow!("owned group cleanup: {error}"))?,
                );
            }
            if eof && let Some(status) = status {
                ensure!(
                    status.success() && written == input.map_or(0, <[u8]>::len),
                    "Git operation failed"
                );
                return Ok(output);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}
#[cfg(all(unix, any(target_os = "macos", target_os = "linux")))]
pub(crate) use platform::OwnedGroup;
pub(crate) fn run(
    command: Command,
    input: Option<&[u8]>,
    deadline: Instant,
    limit: usize,
) -> Result<Vec<u8>> {
    #[cfg(all(unix, any(target_os = "macos", target_os = "linux")))]
    {
        platform::run(command, input, deadline, limit)
    }
    #[cfg(not(all(unix, any(target_os = "macos", target_os = "linux"))))]
    {
        let _ = (command, input, deadline, limit);
        bail!("bounded Git subprocess unsupported")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn shell(script: &str) -> Command {
        let mut c = Command::new("/bin/sh");
        c.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .args(["-c", script]);
        c
    }
    #[test]
    fn real_stalled_input_and_output_overflow_are_bounded() {
        let start = Instant::now();
        assert!(
            run(
                shell("sleep 30"),
                Some(&vec![b'x'; 262144]),
                Instant::now() + Duration::from_millis(100),
                262144
            )
            .is_err()
        );
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(
            run(
                shell("while :; do printf '12345678'; done"),
                None,
                Instant::now() + Duration::from_secs(2),
                64
            )
            .is_err()
        );
        assert_eq!(
            run(
                shell("cat"),
                Some(b"fixture"),
                Instant::now() + Duration::from_secs(2),
                64
            )
            .unwrap(),
            b"fixture"
        );
    }
    #[test]
    fn exited_leader_retains_group_ownership_until_descendant_cleanup() {
        let root = std::env::temp_dir().join(format!("git-group-{}", shared::new_id()));
        std::fs::create_dir(&root).unwrap();
        let pidfile = root.join("pid");
        let mut command = shell("sleep 30 & echo $! > \"$1\"; exit 0");
        command.arg("fixture").arg(&pidfile);
        let start = Instant::now();
        run(command, None, Instant::now() + Duration::from_secs(2), 64).unwrap();
        assert!(start.elapsed() < Duration::from_secs(2));
        let pid: i32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while unsafe { libc::kill(pid, 0) } == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
