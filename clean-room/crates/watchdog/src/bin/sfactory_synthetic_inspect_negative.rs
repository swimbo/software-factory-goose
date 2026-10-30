//! Review-only created-container negative check; accepts no engine options or commands.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../root_launch_docker.rs"]
mod root_launch_docker;
#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    // SAFETY: geteuid only reads current credentials.
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let mut args = std::env::args();
    let _ = args.next();
    let generation = args.next().context("generation required")?;
    let id = args.next().context("full ID required")?;
    ensure!(args.next().is_none(), "unexpected arguments");
    let error =
        root_launch_docker::verify_stopped(&root_launch_docker::BoundedCli, &generation, &id)
            .err()
            .context("unexpected acceptance")?;
    ensure!(
        error.to_string() == "synthetic container identity mismatch",
        "inspection unavailable or ambiguous"
    );
    println!("EXPECTED_CONFIG_REFUSAL");
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("Linux required")
}
