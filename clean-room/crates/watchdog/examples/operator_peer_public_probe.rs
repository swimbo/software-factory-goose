//! Review-only identity probe. The fixed key is public and the backend has no side effects.
#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use std::sync::Arc;
    use watchdog::{
        BrakePeer, BrakeSecret, OperatorBrakePolicy,
        activated_unix::activated_listener,
        brake_authority::{self, StopAuthority, StopDisposition, StopStatusAuthority},
        root_cgroup::StopObservation,
    };
    struct Fixture;
    impl StopAuthority for Fixture {
        fn stop(&self, _: &str) -> anyhow::Result<StopDisposition> {
            Ok(StopDisposition::Pending)
        }
    }
    impl StopStatusAuthority for Fixture {
        fn status(&self, _: &str) -> anyhow::Result<StopObservation> {
            anyhow::bail!("fixture status unavailable")
        }
    }
    let policy = OperatorBrakePolicy::new(
        2003,
        1000,
        2000,
        2001,
        2002,
        2004,
        BrakeSecret::new([9; 32])?,
    )?;
    let listener = activated_listener("/run/software-factory-goose/public-brake-probe.sock", 1000)?;
    listener.set_nonblocking(true)?;
    let listener = tokio::net::UnixListener::from_std(listener)?;
    let fixture = Arc::new(Fixture);
    let app = brake_authority::operator_router_with_status(policy, fixture.clone(), fixture)?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<BrakePeer>(),
    )
    .await?;
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("Linux only");
}
