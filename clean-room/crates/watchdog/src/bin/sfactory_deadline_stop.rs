//! Fixed stop client for a root-installed per-generation systemd deadline.
//! It has no credential, launch, path selection or engine dependency.
#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use anyhow::ensure;
    use std::{io::Read, net::Shutdown, os::unix::net::UnixStream, time::Duration};
    use watchdog::{
        activated_unix::peer_uid,
        stop_wire::{RootOperation, RootStopReply, RootStopRequest},
    };
    // SAFETY: these calls only read process credentials.
    ensure!(
        unsafe { libc::getuid() == 2003 && libc::geteuid() == 2003 },
        "deadline identity required"
    );
    let mut args = std::env::args().skip(1);
    let target = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("generation required"))?;
    ensure!(args.next().is_none(), "unexpected argument");
    ensure!(
        ulid::Ulid::from_string(&target).is_ok_and(|id| id.to_string() == target),
        "invalid generation"
    );
    let mut socket = UnixStream::connect("/run/software-factory-goose/root-stop.sock")?;
    socket.set_read_timeout(Some(Duration::from_secs(8)))?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    ensure!(peer_uid(&socket)? == 0, "untrusted stop authority");
    serde_json::to_writer(
        &mut socket,
        &RootStopRequest {
            target,
            operation: RootOperation::Stop,
        },
    )?;
    socket.shutdown(Shutdown::Write)?;
    let mut raw = Vec::new();
    socket.take(2049).read_to_end(&mut raw)?;
    ensure!(raw.len() <= 2048, "oversized stop reply");
    let reply: RootStopReply = serde_json::from_slice(&raw)?;
    let proof = reply
        .containment
        .ok_or_else(|| anyhow::anyhow!("deadline stop unresolved"))?;
    ensure!(
        reply.outcome == "kernel_stopped"
            && reply.observation.is_none()
            && proof.closed
            && proof.frozen
            && proof.empty
            && !proof.engine_reconciled,
        "deadline stop unresolved"
    );
    println!("kernel stop observed; engine reconciliation pending");
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("Linux required")
}
