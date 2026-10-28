//! Disposable NUC-only integration; not a production Docker authority.
use anyhow::{Context, Result, ensure};
use std::{
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use watchdog::{
    BrakePeer, BrakePolicy, BrakeSecret,
    brake_authority::{StopAuthority, StopDisposition},
};
#[derive(Clone, Copy)]
enum StopState {
    Idle,
    Pending,
    Verified,
    Unknown,
}
type Cleanup = Box<dyn Fn() -> Result<()> + Send + Sync>;
struct Owner {
    target: String,
    state: Mutex<StopState>,
    cleanup: Cleanup,
}
impl Owner {
    fn new(target: String, cleanup: Cleanup) -> Self {
        Self {
            target,
            state: Mutex::new(StopState::Idle),
            cleanup,
        }
    }
}
impl StopAuthority for Owner {
    fn stop(&self, target: &str) -> Result<StopDisposition> {
        ensure!(target == self.target, "unknown target");
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("owner unavailable"))?;
            match *state {
                StopState::Pending => return Ok(StopDisposition::Pending),
                StopState::Verified => return Ok(StopDisposition::Verified),
                StopState::Unknown => anyhow::bail!("cleanup outcome unknown"),
                StopState::Idle => *state = StopState::Pending,
            }
        }
        // Cancellation of an HTTP waiter does not cancel this owned blocking task.
        // A panic or error is unknown forever; the same request never launches again.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.cleanup)()));
        let verified = matches!(outcome, Ok(Ok(())));
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("owner unavailable"))?;
        *state = if verified {
            StopState::Verified
        } else {
            StopState::Unknown
        };
        if verified {
            Ok(StopDisposition::Verified)
        } else {
            anyhow::bail!("cleanup outcome unknown")
        }
    }
}

// Fixture-only fixed command runner. Timeout means unknown, never proof of cancellation.
// The direct child is held until observed exited or the owned group signal is attempted.
fn run_bounded(command: &mut Command, timeout: Duration) -> Result<()> {
    let mut action = std::mem::MaybeUninit::<libc::sigaction>::uninit();
    ensure!(
        unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), action.as_mut_ptr()) } == 0,
        "child reaping policy unavailable"
    );
    let action = unsafe { action.assume_init() };
    ensure!(
        action.sa_sigaction == libc::SIG_DFL && action.sa_flags & libc::SA_NOCLDWAIT == 0,
        "unsupported child reaping policy"
    );
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            ensure!(status.success(), "fixture cleanup failed");
            return Ok(());
        }
        if Instant::now() >= deadline {
            // `try_wait` has not reaped this child. Verify ownership with WNOWAIT before
            // signaling its group. Failed signals are unknown, never evidence of cleanup.
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
                "cleanup ownership unavailable"
            );
            ensure!(
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) } == 0,
                "cleanup termination unresolved"
            );
            let reap_deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < reap_deadline {
                if child.try_wait()?.is_some() {
                    anyhow::bail!("cleanup timed out; outcome unknown");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            anyhow::bail!("cleanup reaping unresolved");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 4,
        "fixture needs socket, private root, token and opaque target"
    );
    let socket = PathBuf::from(&args[0]);
    let root = PathBuf::from(&args[1]);
    let token = args[2].to_str().context("token")?.to_owned();
    let target = args[3].to_str().context("target")?.to_owned();
    ensure!(
        token.len() == 32 && token.bytes().all(|b| b.is_ascii_hexdigit()),
        "bad fixture token"
    );
    let key: [u8; 32] = std::fs::read(root.join("brake-key"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid fixture key"))?;
    let uid = unsafe { libc::geteuid() };
    let policy = BrakePolicy::new(
        uid,
        1002,
        vec![1003, 1004, 1005, 1006],
        BrakeSecret::new(key)?,
    )?;
    let router = watchdog::brake_authority::router(
        policy,
        Arc::new(Owner::new(
            target,
            Box::new(move || {
                // A prior receipt cannot be attributed to this attempt. Never delete it or
                // accept it as evidence for a new cleanup.
                match std::fs::symlink_metadata(root.join("cleanup-result")) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    _ => anyhow::bail!("prior cleanup result requires reconciliation"),
                }
                let mut command = Command::new("/usr/bin/python3");
                command
                    .arg(root.join("cleanup.py"))
                    .arg(&root)
                    .arg(&token)
                    .env_clear()
                    .env(
                        "SFACTORY_CGROUP_PARENT",
                        "sfactory6a2ae9a8ef374a84b94c15a1b1d4d7f0-worker.slice",
                    );
                run_bounded(&mut command, Duration::from_secs(45))?;
                let result = std::fs::read_to_string(root.join("cleanup-result"))?;
                ensure!(
                    result.starts_with("OK COMMITTED "),
                    "fixture proof unavailable"
                );
                Ok(())
            }),
        )),
    )?;
    let listener = tokio::net::UnixListener::bind(&socket)?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666))?;
    println!("READY");
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<BrakePeer>(),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    #[test]
    fn delayed_cleanup_is_pending_then_verified_without_duplicate_execution() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let owner = Arc::new(Owner::new(
            "target".into(),
            Box::new(move || {
                seen.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(150));
                Ok(())
            }),
        ));
        let worker = owner.clone();
        let first = std::thread::spawn(move || worker.stop("target"));
        while calls.load(Ordering::SeqCst) == 0 {
            std::thread::yield_now();
        }
        assert_eq!(owner.stop("target").unwrap(), StopDisposition::Pending);
        assert!(owner.stop("other").is_err());
        assert_eq!(first.join().unwrap().unwrap(), StopDisposition::Verified);
        assert_eq!(owner.stop("target").unwrap(), StopDisposition::Verified);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn expired_cleanup_is_unknown_and_never_reissued() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let owner = Owner::new(
            "target".into(),
            Box::new(move || {
                seen.fetch_add(1, Ordering::SeqCst);
                let mut cmd = Command::new("/bin/sh");
                cmd.args(["-c", "exec /bin/sleep 5"]);
                run_bounded(&mut cmd, Duration::from_millis(100))
            }),
        );
        assert!(owner.stop("target").is_err());
        assert!(owner.stop("target").is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
