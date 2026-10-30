//! Fixed root-only journal grant preparation; never starts an engine or timer.
//! Uninstalled and unexposed until the real root catalogue/service are reviewed.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../root_launch_docker.rs"]
mod root_launch_docker;
#[cfg(target_os = "linux")]
use watchdog::root_cgroup;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../root_grant.rs"]
mod root_grant;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../root_grant_attestor.rs"]
mod root_grant_attestor;
#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};
    // SAFETY: geteuid only reads current process credentials.
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let mut args = std::env::args();
    let _ = args.next();
    let generation = args.next().context("generation required")?;
    ensure!(args.next().is_none(), "unexpected arguments");
    let catalog = root_grant::load_root_catalog(&generation)?;
    let state = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/var/lib/software-factory-goose/stop")?;
    let intent = root_grant::begin_reservation(&state, &catalog)?;
    let reservation = root_grant::request_reserved(intent, &root_grant_attestor::RootAttestor)?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let grant = root_grant::persist_verified(
        &state,
        reservation,
        &catalog,
        boot.trim(),
        root_grant::now_ms()?,
    )?;
    println!(
        "{{\"generation\":\"{}\",\"binding_sha256\":\"{}\",\"expires_at_ms\":{},\"engine_effects\":false}}",
        generation,
        grant.binding_sha256(),
        grant.expires_at_ms()
    );
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("Linux required")
}
