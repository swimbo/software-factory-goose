//! Disposable loopback integration only; never deploy as a trusted ingress.
#[cfg(feature = "restate")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use control_plane::{
        intake::{INTAKE_SCHEMA_VERSION, IntakeRequest},
        intake_workflow::IntakeJournal,
        launch_reservation::LaunchScope,
        qualifier::IntentFeatures,
        runtime_intake::{Catalog, RuntimeIntakeJournal},
        worker_queue::WorkerQueueJournal,
        workflow::{ClaimLeaseJournal, LeaseSpec},
    };
    use restate_sdk::prelude::*;
    let address: std::net::SocketAddr = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("fixture address required"))?
        .parse()?;
    anyhow::ensure!(address.ip().is_loopback(), "loopback fixture only");
    let database_url = std::env::var("SFACTORY_FIXTURE_DATABASE_URL")?;
    let url = reqwest::Url::parse(&database_url)?;
    anyhow::ensure!(
        url.scheme() == "postgres"
            && url.host_str() == Some("127.0.0.1")
            && url.port().is_some()
            && url.path() == "/sfactory_verification"
            && url.password().is_none()
            && url.query().is_none(),
        "fixture database scope"
    );
    let pool = sqlx::PgPool::connect(&database_url).await?;
    control_plane::projection::migrate(&pool).await?;
    let request = IntakeRequest {
        schema_version: INTAKE_SCHEMA_VERSION,
        repository: "fixture".into(),
        target_ref: "refs/heads/main".into(),
        base_revision: "a".repeat(40),
        intent: "build fixture".into(),
        acceptance_criteria: vec!["passes fixture".into()],
    };
    let features = IntentFeatures {
        spec_clarity: 1.0,
        blast_radius: 0.0,
        novelty: 0.0,
        reversibility: 0.0,
        has_codified_knowledge: true,
        fatal: false,
    };
    let old = Catalog::new(
        "fixture-submitter".into(),
        "runtime-queue".into(),
        "01ARZ3NDEKTSV4RRFFQ69G5FAZ".into(),
        "01ARZ3NDEKTSV4RRFFQ69G5FAY".into(),
        request.clone(),
        features.clone(),
        "a".repeat(64),
    )?;
    let new = Catalog::new(
        "fixture-submitter".into(),
        "new-queue".into(),
        "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
        "01ARZ3NDEKTSV4RRFFQ69G5FAS".into(),
        request.clone(),
        features.clone(),
        "b".repeat(64),
    )?;
    let third = Catalog::new(
        "fixture-submitter".into(),
        "third-queue".into(),
        "01ARZ3NDEKTSV4RRFFQ69G5FAQ".into(),
        "01ARZ3NDEKTSV4RRFFQ69G5FAR".into(),
        request.clone(),
        features.clone(),
        "c".repeat(64),
    )?;
    let fourth = Catalog::new(
        "fixture-submitter".into(),
        "fourth-queue".into(),
        "01ARZ3NDEKTSV4RRFFQ69G5FAN".into(),
        "01ARZ3NDEKTSV4RRFFQ69G5FAM".into(),
        request,
        features,
        "d".repeat(64),
    )?;
    let scope = LaunchScope {
        task_id: "01ARZ3NDEKTSV4RRFFQ69G5FAS".into(),
        intent_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
        queue_id: "new-queue".into(),
        generation: "owned-generation".into(),
        spec: LeaseSpec {
            repository: "fixture".into(),
            base_revision: "a".repeat(40),
        },
        worker_id: "new-worker".into(),
        catalog_sha256: "b".repeat(64),
    };
    let third_scope = LaunchScope {
        task_id: "01ARZ3NDEKTSV4RRFFQ69G5FAR".into(),
        intent_id: "01ARZ3NDEKTSV4RRFFQ69G5FAQ".into(),
        queue_id: "third-queue".into(),
        generation: "third-generation".into(),
        spec: scope.spec.clone(),
        worker_id: "third-worker".into(),
        catalog_sha256: "c".repeat(64),
    };
    let fourth_scope = LaunchScope {
        task_id: "01ARZ3NDEKTSV4RRFFQ69G5FAM".into(),
        intent_id: "01ARZ3NDEKTSV4RRFFQ69G5FAN".into(),
        queue_id: "fourth-queue".into(),
        generation: "fourth-generation".into(),
        spec: scope.spec.clone(),
        worker_id: "fourth-worker".into(),
        catalog_sha256: "d".repeat(64),
    };
    let endpoint = Endpoint::builder()
        .bind(IntakeJournal::new_for_private_ingress(
            "fixture-submitter".into(),
        )?)
        .bind(ClaimLeaseJournal::new_with_catalog_scopes(
            pool,
            vec![
                ("01ARZ3NDEKTSV4RRFFQ69G5FAY".into(), "fixture-worker".into()),
                ("01ARZ3NDEKTSV4RRFFQ69G5FAS".into(), "new-worker".into()),
                ("01ARZ3NDEKTSV4RRFFQ69G5FAR".into(), "third-worker".into()),
                ("01ARZ3NDEKTSV4RRFFQ69G5FAM".into(), "fourth-worker".into()),
            ],
            vec![scope, third_scope, fourth_scope],
        )?)
        .bind(WorkerQueueJournal::new_with_queue_scopes(vec![
            ("runtime-queue".into(), "fixture-worker".into()),
            ("new-queue".into(), "new-worker".into()),
            ("third-queue".into(), "third-worker".into()),
            ("fourth-queue".into(), "fourth-worker".into()),
        ])?)
        .bind(RuntimeIntakeJournal::new_with_catalogs(vec![
            old, new, third, fourth,
        ])?)
        .build();
    HttpServer::new(endpoint).listen_and_serve(address).await;
    Ok(())
}
#[cfg(not(feature = "restate"))]
fn main() {
    eprintln!("fixture requires restate feature");
}
