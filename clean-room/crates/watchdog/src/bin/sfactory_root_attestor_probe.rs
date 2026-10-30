//! Read-only fixed sidecar attestation; never requests or consumes a grant.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../root_grant.rs"]
mod root_grant;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../root_grant_attestor.rs"]
mod root_grant_attestor;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../root_launch_docker.rs"]
mod root_launch_docker;
#[cfg(target_os = "linux")]
use watchdog::root_cgroup;
#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use root_grant::ServiceAttestation;
    // SAFETY: geteuid only reads the current effective user ID.
    anyhow::ensure!(unsafe { libc::geteuid() } == 0, "root required");
    anyhow::ensure!(std::env::args_os().count() == 1, "arguments forbidden");
    root_grant_attestor::RootAttestor.verify()?;
    println!("{{\"service_attested\":true,\"grant_requested\":false}}");
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("Linux required")
}
