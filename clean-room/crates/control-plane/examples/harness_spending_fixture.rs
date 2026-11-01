//! Disposable loopback journal fixture only; contains no provider or worker ingress.
#[cfg(feature = "registry-sidecar")]
use control_plane::registry_journal_gate;
#[cfg(feature = "restate")]
#[path = "../src/harness_spending.rs"]
mod harness_spending;

#[cfg(feature = "restate")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use restate_sdk::prelude::*;
    let address: std::net::SocketAddr = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("explicit disposable fixture address required"))?
        .parse()?;
    anyhow::ensure!(
        address.ip().is_loopback() && address.port() != 0,
        "loopback fixture address required"
    );
    HttpServer::new(
        Endpoint::builder()
            .bind(harness_spending::HarnessSpending)
            .build(),
    )
    .listen_and_serve(address)
    .await;
    Ok(())
}

#[cfg(not(feature = "restate"))]
fn main() {
    eprintln!("disposable fixture requires restate feature");
    std::process::exit(1);
}
