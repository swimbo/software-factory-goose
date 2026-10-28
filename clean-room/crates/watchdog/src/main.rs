//! Opt-in disposable fixture only. No production serve mode or existing-PID registration.
use anyhow::{Context, Result, ensure};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};
use tokio::{io::AsyncReadExt, net::UnixListener};
use watchdog::{BrakePeer, BrakeSecret, Registry};
fn write_new(path: &Path, value: &serde_json::Value) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(serde_json::to_string(value)?.as_bytes())?;
    Ok(())
}
fn main() -> Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    match arguments.first().and_then(|a| a.to_str()) {
        Some("--fixture-admission-owner") => {
            ensure!(arguments.len() == 2, "fixture requires private root");
            let root = Path::new(&arguments[1]);
            let spec = watchdog::guarded_admission::FixtureSpec::new(
                "/bin/sh",
                ["-c", "printf ready > ready; exec sleep 2"],
                root,
            )?;
            let mut launcher = watchdog::guarded_admission::FixtureLauncher::new(root, spec)?;
            let _group = launcher.launch()?;
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            while !root.join("ready").is_file() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            ensure!(root.join("ready").is_file(), "fixture child not ready");
            println!("armed");
            std::io::stdout().flush()?;
            std::thread::sleep(Duration::from_secs(3));
            Ok(())
        }
        Some("--fixture-guarded-controller-loss") => {
            ensure!(arguments.len() == 2, "fixture requires private root");
            let root = Path::new(&arguments[1]);
            let spec = watchdog::guarded_admission::FixtureSpec::new(
                "/bin/sh",
                ["-c", "exec sleep 5"],
                root,
            )?;
            let mut launcher = watchdog::guarded_admission::FixtureLauncher::new(root, spec)?;
            let mut group = launcher.launch()?;
            println!("READY");
            std::io::stdout().flush()?;
            let result =
                group.complete_with_controller(Duration::from_secs(4), &std::io::stdin())?;
            ensure!(result.is_none(), "unexpected frame released");
            println!("STOPPED");
            Ok(())
        }
        Some("--fixture-controller-loss") => {
            ensure!(
                arguments.len() == 1,
                "fixture requires only a controller pipe"
            );
            let registry = Registry::new()?;
            // This fixed-duration benign child limits fixture lifetime even if its
            // guardian is forcibly killed; no restored PID is ever signalled.
            let target = registry.spawn_owned(Command::new("/bin/sleep").arg("5"))?;
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            std::thread::spawn(move || {
                let mut byte = [0_u8];
                let _ = tx.send(std::io::stdin().read(&mut byte));
            });
            println!("READY");
            std::io::stdout().flush()?;
            let input = rx.recv_timeout(Duration::from_secs(4));
            let stopped = registry.stop(&target)?;
            ensure!(
                stopped.leader_reaped && stopped.group_absent,
                "fixture group stop unresolved"
            );
            if matches!(input, Err(std::sync::mpsc::RecvTimeoutError::Timeout)) {
                println!("TIMEOUT_STOPPED");
                std::io::stdout().flush()?;
                anyhow::bail!("controller pipe deadline expired; EOF unverified");
            }
            if !matches!(input, Ok(Ok(0))) {
                println!("INVALID_STOPPED");
                std::io::stdout().flush()?;
                anyhow::bail!("controller pipe produced data or failed; EOF unverified");
            }
            println!("STOPPED");
            Ok(())
        }
        Some("--fixture-recovery-latch") => {
            ensure!(arguments.len() == 2, "fixture latch requires private root");
            watchdog::recovery_latch::arm(Path::new(&arguments[1]))?;
            println!("armed");
            std::io::stdout().flush()?;
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        Some("--fixture-descendant") => loop {
            std::thread::sleep(Duration::from_secs(1));
        },
        Some("--fixture-child") => {
            ensure!(
                matches!(arguments.len(), 2 | 3),
                "fixture child requires private ready path"
            );
            let descendant = Command::new(std::env::current_exe()?)
                .arg("--fixture-descendant")
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            write_new(
                Path::new(&arguments[1]),
                &serde_json::json!({"leader":std::process::id(),"descendant":descendant.id()}),
            )?;
            if arguments.get(2).and_then(|a| a.to_str()) == Some("--stop-self") {
                // Disposable hung-worker fixture: cannot cooperate with cleanup handlers.
                unsafe { libc::raise(libc::SIGSTOP) };
            }
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        Some("--fixture-server" | "--fixture-family-server") => {
            ensure!(
                arguments.len() == 2,
                "fixture server requires a new private directory"
            );
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()?
                .block_on(serve_fixture(
                    Path::new(&arguments[1]),
                    arguments[0] == "--fixture-family-server",
                ))
        }
        _ => anyhow::bail!(
            "no production mode: explicitly use --fixture-server for a disposable fixture"
        ),
    }
}
struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}
impl Drop for SocketGuard {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path)
            .is_ok_and(|m| m.dev() == self.device && m.ino() == self.inode)
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}
async fn serve_fixture(root: &Path, family_fixture: bool) -> Result<()> {
    // Synthetic key arrives only on the inherited pipe, never argv, environment or logs.
    let mut bytes = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(3),
        tokio::io::stdin().take(33).read_to_end(&mut bytes),
    )
    .await??;
    ensure!(
        bytes.len() == 32,
        "fixture requires exactly 32 private stdin bytes"
    );
    let secret = BrakeSecret::new(
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid key length"))?,
    )?;
    let metadata = fs::symlink_metadata(root)?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o777 == 0o700,
        "fixture root must be owned private directory"
    );
    // The fixture makes its durable unresolved-run marker before listener creation
    // or process launch. There is intentionally no automatic recovery/reset.
    watchdog::recovery_latch::arm(root)?;
    let socket = root.join("brake.sock");
    ensure!(
        !socket.try_exists()? && fs::symlink_metadata(&socket).is_err(),
        "existing socket path preserved"
    );
    let listener = UnixListener::bind(&socket)?;
    let metadata = fs::symlink_metadata(&socket)?;
    let _guard = SocketGuard {
        path: socket.clone(),
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    let registry = Arc::new(Registry::new()?);
    let target = registry.create_family()?;
    let roles: Vec<&str> = if family_fixture {
        vec!["worker", "goose", "tool"]
    } else {
        vec!["single"]
    };
    let mut files = Vec::new();
    for role in &roles {
        let ready = if *role == "single" {
            root.join("children.json")
        } else {
            root.join(format!("children-{role}.json"))
        };
        let mut command = Command::new(std::env::current_exe()?);
        command.arg("--fixture-child").arg(&ready).current_dir(root);
        if *role == "worker" {
            command.arg("--stop-self");
        }
        registry.spawn_in_family(&target, &mut command)?;
        files.push(ready);
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while files.iter().any(|path| !path.exists()) {
        ensure!(
            tokio::time::Instant::now() < deadline,
            "fixture child readiness timed out"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    write_new(
        &root.join("registry.json"),
        &serde_json::json!({"target":target,"watchdog":std::process::id(),"fixture_only":true,"groups":roles}),
    )?;
    let router = watchdog::fixture_router(secret, registry.clone());
    let shutdown_registry = registry.clone();
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let shutdown = async move {
        tokio::select! {_=terminate.recv()=>{},_=tokio::time::sleep(Duration::from_secs(30))=>{}}
        let _ = tokio::task::spawn_blocking(move || shutdown_registry.stop(&target)).await;
    };
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<BrakePeer>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
    .context("fixture brake server failed")?;
    Ok(())
}
