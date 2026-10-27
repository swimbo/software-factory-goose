//! Disposable same-UID catalogue fixture, never an admission API or production daemon.
use anyhow::{Result, ensure};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use watchdog::broker::{ApprovedLaunch, LaunchRole, SpawnBroker};
use watchdog::{BrakePeer, BrakeSecret, Registry};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    program: PathBuf,
    arguments: Vec<String>,
    cwd: PathBuf,
    environment: BTreeMap<String, String>,
    stdin: String,
}
struct SocketGuard(PathBuf, u64, u64);
impl Drop for SocketGuard {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.0).is_ok_and(|m| m.dev() == self.1 && m.ino() == self.2) {
            let _ = fs::remove_file(&self.0);
        }
    }
}
fn bind(root: &std::path::Path, name: &str) -> Result<(tokio::net::UnixListener, SocketGuard)> {
    let path = root.join(name);
    ensure!(
        fs::symlink_metadata(&path).is_err(),
        "existing socket path preserved"
    );
    let listener = tokio::net::UnixListener::bind(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let metadata = fs::symlink_metadata(&path)?;
    Ok((listener, SocketGuard(path, metadata.dev(), metadata.ino())))
}
#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 1,
        "requires private disposable fixture directory"
    );
    let root = PathBuf::from(&args[0]);
    let metadata = fs::symlink_metadata(&root)?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o777 == 0o700,
        "fixture directory must be private and owned"
    );
    let path = root.join("catalogue.json");
    let metadata = fs::symlink_metadata(&path)?;
    ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o777 == 0o600
            && metadata.len() <= 262144,
        "invalid fixture catalogue"
    );
    let catalogue: BTreeMap<String, Spec> = serde_json::from_slice(&fs::read(path)?)?;
    ensure!(
        !catalogue.is_empty() && catalogue.len() <= 8,
        "fixture catalogue bound"
    );
    let registry = Arc::new(Registry::new()?);
    let family = registry.create_family()?;
    // Fixed synthetic fixture values only. No production secrets are accepted by this binary.
    let broker = Arc::new(SpawnBroker::fixture(
        registry.clone(),
        BrakeSecret::new([0x69; 32])?,
    ));
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
    let mut ids = BTreeMap::new();
    for (name, spec) in catalogue {
        let role = match name.as_str() {
            "goose" => LaunchRole::Goose,
            "worker" => LaunchRole::Worker,
            "tool" => LaunchRole::Tool,
            _ => anyhow::bail!("unsupported fixture role"),
        };
        let launch = ApprovedLaunch::new(
            family.clone(),
            role,
            spec.program,
            spec.arguments.into_iter().map(Into::into).collect(),
            spec.cwd,
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            now,
            now + 90000,
        )?
        .with_fixture_io(spec.environment, spec.stdin.into_bytes())?;
        ids.insert(name, broker.admit(launch)?);
    }
    let (broker_listener, _broker_guard) = bind(&root, "broker.sock")?;
    let (brake_listener, _brake_guard) = bind(&root, "brake.sock")?;
    let broker_router = broker.fixture_router();
    let brake_router = watchdog::fixture_router(BrakeSecret::new([0x5a; 32])?, registry.clone());
    let broker_server = tokio::spawn(async move {
        axum::serve(
            broker_listener,
            broker_router.into_make_service_with_connect_info::<BrakePeer>(),
        )
        .await
    });
    let brake_server = tokio::spawn(async move {
        axum::serve(
            brake_listener,
            brake_router.into_make_service_with_connect_info::<BrakePeer>(),
        )
        .await
    });
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut ready = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("registry.json"))?;
    ready.write_all(&serde_json::to_vec(
        &serde_json::json!({"family": family, "launches": ids}),
    )?)?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! { _ = terminate.recv() => {}, _ = tokio::time::sleep(Duration::from_secs(90)) => {} }
    let stopped = registry.stop(&family);
    broker_server.abort();
    brake_server.abort();
    let stopped = stopped?;
    ensure!(
        stopped.leader_reaped && stopped.group_absent,
        "fixture cleanup incomplete"
    );
    Ok(())
}
