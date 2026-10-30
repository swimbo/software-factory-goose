//! Review-only fixed systemd deadline handler; no installation or timer arming here.
#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use anyhow::ensure;
    use watchdog::root_cgroup::{StopBackend, linux::KernelStop, stop_kernel};
    // SAFETY: geteuid only reads current process credentials.
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let mut args = std::env::args();
    let _ = args.next();
    let target = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("generation required"))?;
    ensure!(args.next().is_none(), "unexpected arguments");
    let backend = KernelStop::open(&target)?;
    // Closure is established even if another stop currently owns stop.lock.
    backend.close_admission()?;
    backend.record_observation(None)?;
    let result = stop_kernel(&backend)?;
    backend.record_observation(Some(result))?;
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("Linux required")
}
