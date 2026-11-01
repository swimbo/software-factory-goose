//! Explicit disposable SDK or Unix-ingress fixture. No provider, key or activation.
#[cfg(feature = "registry-sidecar")]
use control_plane::registry_journal_gate;
#[cfg(feature = "restate")]
#[path = "../src/harness_spending.rs"]
mod harness_spending;
#[cfg(feature = "restate")]
#[path = "../src/harness_spending_ingress.rs"]
mod harness_spending_ingress;

#[cfg(feature = "restate")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use restate_sdk::prelude::*;
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("sdk") if args.len() == 2 => {
            let address: std::net::SocketAddr = args[1].parse()?;
            anyhow::ensure!(
                address.ip().is_loopback() && address.port() != 0,
                "explicit loopback fixture address required"
            );
            HttpServer::new(
                Endpoint::builder()
                    .bind(harness_spending::HarnessSpending)
                    .build(),
            )
            .listen_and_serve(address)
            .await;
        }
        Some("ingress") if args.len() == 8 => {
            let policy = harness_spending_ingress::Policy::new(
                args[3].parse()?,
                args[4].parse()?,
                args[5].parse()?,
                args[6].parse()?,
                args[7].clone(),
            )?;
            let backend = harness_spending_ingress::PrivateUnixJournal::new(
                args[2].clone().into(),
                args[3].parse()?,
                args[7].clone(),
            )
            .await?;
            let app = harness_spending_ingress::router(policy, std::sync::Arc::new(backend))?;
            // Parent/socket ownership and shared role-group traversal must be
            // provisioned privately before launch. Existing paths are not removed.
            let listener = tokio::net::UnixListener::bind(&args[1])?;
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&args[1], std::fs::Permissions::from_mode(0o660))?;
            harness_spending_ingress::serve(listener, app).await?;
        }
        _ => anyhow::bail!(
            "expected sdk ADDRESS or ingress SOCKET BACKEND_SOCKET SERVICE_UID BROKER_UID COLLECTOR_UID WORKER_UID OWNER"
        ),
    }
    Ok(())
}
#[cfg(not(feature = "restate"))]
fn main() {
    eprintln!("harness runtime fixture requires restate feature");
    std::process::exit(1);
}
