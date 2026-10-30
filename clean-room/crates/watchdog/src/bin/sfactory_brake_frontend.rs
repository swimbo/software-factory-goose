//! Non-root, bearer-authenticated stop frontend. It cannot issue launch operations.
#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use anyhow::{Context, Result, ensure};
    use std::{
        io::Read, net::Shutdown, os::unix::net::UnixStream, path::Path, sync::Arc, time::Duration,
    };
    use watchdog::{
        BrakePeer, BrakeSecret, OperatorBrakePolicy,
        activated_unix::{activated_listener, peer_uid},
        brake_authority::{self, StopAuthority, StopDisposition, StopStatusAuthority},
        root_cgroup::StopObservation,
        stop_wire::{RootOperation, RootStopReply, RootStopRequest},
    };
    const ROOT_SOCKET: &str = "/run/software-factory-goose/root-stop.sock";
    const FRONT_SOCKET: &str = "/run/software-factory-goose/brake.sock";
    const SECRET: &str = "/etc/software-factory-goose/brake.key";
    struct RootClient;
    impl RootClient {
        fn call(&self, target: &str, operation: RootOperation) -> Result<RootStopReply> {
            ensure!(
                ulid::Ulid::from_string(target).is_ok_and(|id| id.to_string() == target),
                "invalid target"
            );
            let mut socket = UnixStream::connect(ROOT_SOCKET)?;
            socket.set_read_timeout(Some(Duration::from_secs(6)))?;
            socket.set_write_timeout(Some(Duration::from_secs(2)))?;
            ensure!(peer_uid(&socket)? == 0, "untrusted root stop peer");
            serde_json::to_writer(
                &mut socket,
                &RootStopRequest {
                    target: target.into(),
                    operation,
                },
            )?;
            socket.shutdown(Shutdown::Write)?;
            let mut raw = Vec::new();
            socket.take(2049).read_to_end(&mut raw)?;
            ensure!(raw.len() <= 2048, "reply too large");
            Ok(serde_json::from_slice(&raw)?)
        }
    }
    impl StopAuthority for RootClient {
        fn stop(&self, target: &str) -> Result<StopDisposition> {
            let r = self.call(target, RootOperation::Stop)?;
            ensure!(r.observation.is_none(), "invalid stop reply");
            match (r.outcome.as_str(), r.containment) {
                ("kernel_stopped", Some(s))
                    if s.closed && s.frozen && s.empty && !s.engine_reconciled =>
                {
                    Ok(StopDisposition::Pending)
                }
                ("unresolved", None) => Ok(StopDisposition::Pending),
                _ => anyhow::bail!("untrusted stop result"),
            }
        }
    }
    impl StopStatusAuthority for RootClient {
        fn status(&self, target: &str) -> Result<StopObservation> {
            let r = self.call(target, RootOperation::Status)?;
            ensure!(
                r.outcome == "status" && r.containment.is_none(),
                "status unavailable"
            );
            let o = r.observation.context("status unavailable")?;
            ensure!(
                o.target_id == target
                    && !o.engine_reconciled
                    && ((o.observed
                        && o.closed
                        && o.frozen
                        && o.empty
                        && o.observed_at_unix.is_some())
                        || (!o.observed && !o.frozen && !o.empty && o.observed_at_unix.is_none())),
                "invalid status"
            );
            Ok(o)
        }
    }
    // SAFETY: geteuid only reads process credentials.
    ensure!(
        unsafe { libc::geteuid() } == 2003,
        "brake service identity required"
    );
    let mut key = watchdog::brake_key::read_brake_key(Path::new(SECRET), 2003)?;
    let secret = BrakeSecret::new(key)?;
    key.fill(0);
    let policy = OperatorBrakePolicy::new(2003, 1000, 2000, 2001, 2002, 2004, secret)?;
    let listener = activated_listener(FRONT_SOCKET, 1000)?;
    listener.set_nonblocking(true)?;
    let listener = tokio::net::UnixListener::from_std(listener)?;
    let client = Arc::new(RootClient);
    let app = brake_authority::operator_router_with_status(policy, client.clone(), client)?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<BrakePeer>(),
    )
    .await?;
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("Linux required")
}
