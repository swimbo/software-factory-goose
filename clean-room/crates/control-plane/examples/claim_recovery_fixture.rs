//! Disposable loopback recovery harness only; no production registration or private-ingress proof.
#[cfg(feature = "restate")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use restate_sdk::prelude::*;
    let address: std::net::SocketAddr = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("missing fixture address"))?
        .parse()?;
    anyhow::ensure!(
        address.ip().is_loopback() && address.port() != 0,
        "loopback fixture address required"
    );
    let database_url = std::env::var("SFACTORY_FIXTURE_DATABASE_URL")?;
    let url = reqwest::Url::parse(&database_url)?;
    anyhow::ensure!(
        url.scheme() == "postgres"
            && url.host_str() == Some("127.0.0.1")
            && url.port().is_some()
            && url.path() == "/sfactory_verification"
            && url.password().is_none()
            && url.query().is_none(),
        "explicit disposable loopback fixture database required"
    );
    let pool = sqlx::PgPool::connect(&database_url).await?;
    control_plane::projection::migrate(&pool).await?;
    let endpoint = Endpoint::builder()
        .bind(
            control_plane::workflow::ClaimLeaseJournal::new_for_private_ingress(
                "fixture-worker".into(),
                pool,
            )?,
        )
        .build();
    HttpServer::new(endpoint).listen_and_serve(address).await;
    Ok(())
}
#[cfg(not(feature = "restate"))]
fn main() {
    eprintln!("fixture requires restate feature");
    std::process::exit(1);
}
