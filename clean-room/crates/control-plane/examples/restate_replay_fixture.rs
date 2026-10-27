//! Disposable loopback-only fixture; never register this endpoint in a real deployment.
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
    let operator = control_plane::approval::authenticate_operator(1001, 1001, &[1002, 1003, 1004])?;
    let approvals = control_plane::approval_workflow::ApprovalJournal::new_for_private_ingress(
        operator.clone(),
        "fixture".into(),
    )?;
    let mut decisions =
        control_plane::promotion_decision::PromotionDecisionJournal::new_for_private_ingress(
            operator,
            "fixture".into(),
        )?;
    if let Ok(root) = std::env::var("SFACTORY_FIXTURE_PROMOTION_ROOT") {
        let home = std::path::PathBuf::from(std::env::var("HOME")?).canonicalize()?;
        let root = std::path::PathBuf::from(root);
        anyhow::ensure!(
            root == home.join("promotion-execution"),
            "owned disposable promotion fixture required"
        );
        let bindings = [
            ("fixture-execution", "target.git"),
            ("fixture-refusal", "refusal.git"),
        ]
        .into_iter()
        .map(
            |(repository, target)| control_plane::promotion_execution::RepositoryBinding {
                repository: repository.into(),
                target_ref: "refs/heads/main".into(),
                bare_target: root.join(target),
                candidate_snapshot: root.join("candidate"),
                owner_uid: unsafe { libc::geteuid() },
            },
        )
        .collect();
        decisions = decisions.with_private_execution_registry(std::sync::Arc::new(
            control_plane::promotion_execution::TrustedPromotionRepositories::new(bindings)?,
        ));
    }
    let mut builder = Endpoint::builder()
        .bind(control_plane::workflow::BudgetCounter)
        .bind(
            control_plane::intake_workflow::IntakeJournal::new_for_private_ingress(
                "fixture-submitter".into(),
            )?,
        )
        .bind(approvals)
        .bind(decisions);
    if let Ok(database_url) = std::env::var("SFACTORY_FIXTURE_DATABASE_URL") {
        let url = reqwest::Url::parse(&database_url)?;
        anyhow::ensure!(
            url.scheme() == "postgres"
                && url.host_str() == Some("127.0.0.1")
                && url.port().is_some()
                && url.path() == "/sfactory_verification"
                && url.password().is_none()
                && url.query().is_none(),
            "explicit loopback fixture database required"
        );
        let pool = sqlx::PgPool::connect(&database_url).await?;
        control_plane::projection::migrate(&pool).await?;
        builder = builder
            .bind(
                control_plane::workflow::ClaimLeaseJournal::new_for_private_ingress(
                    "fixture-worker".into(),
                    pool,
                )?,
            )
            .bind(
                control_plane::worker_queue::WorkerQueueJournal::new_for_private_ingress(
                    "fixture-worker".into(),
                )?,
            );
    }
    let endpoint = builder.build();
    HttpServer::new(endpoint).listen_and_serve(address).await;
    Ok(())
}
#[cfg(not(feature = "restate"))]
fn main() {
    eprintln!("fixture requires restate feature");
    std::process::exit(1);
}
