//! Disposable loopback test of the private backend; not a deployed identity proof.
#[cfg(all(feature = "restate", unix))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use control_plane::{
        intake::{INTAKE_SCHEMA_VERSION, IntakeRequest},
        intake_adapter::IntakeBackend,
        runtime_loopback_backend::RuntimeLoopbackBackend,
        worker_adapter::WorkerBackend,
        worker_queue::{PullOutcome, PullRequest},
        workflow::LeaseSpec,
    };
    let mut args = std::env::args().skip(1);
    let port: u16 = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("port required"))?
        .parse()?;
    let mode = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("mode required"))?;
    anyhow::ensure!(
        args.next().is_none() && matches!(mode.as_str(), "deny" | "verify"),
        "fixture mode"
    );
    let backend = RuntimeLoopbackBackend::new(
        port,
        "fixture-submitter".into(),
        "01ARZ3NDEKTSV4RRFFQ69G5FAZ".into(),
        "01ARZ3NDEKTSV4RRFFQ69G5FAY".into(),
        "runtime-queue".into(),
        LeaseSpec {
            repository: "fixture".into(),
            base_revision: "a".repeat(40),
        },
    )?;
    let pull = PullRequest {
        request_id: "01ARZ3NDEKTSV4RRFFQ69G5FAW".into(),
        ttl_ms: 300000,
    };
    if mode == "deny" {
        anyhow::ensure!(
            backend.pull("runtime-queue".into(), pull).await.is_err(),
            "unqualified pull allowed"
        );
        println!("PASS: unqualified pull denied");
        return Ok(());
    }
    let request = IntakeRequest {
        schema_version: INTAKE_SCHEMA_VERSION,
        repository: "fixture".into(),
        target_ref: "refs/heads/main".into(),
        base_revision: "a".repeat(40),
        intent: "build fixture".into(),
        acceptance_criteria: vec!["passes fixture".into()],
    };
    let result = backend
        .submit("01ARZ3NDEKTSV4RRFFQ69G5FAZ".into(), request)
        .await
        .map_err(|_| anyhow::anyhow!("handoff rejected"))?;
    anyhow::ensure!(
        result.intent_id == "01ARZ3NDEKTSV4RRFFQ69G5FAZ",
        "intake scope mismatch"
    );
    let result = backend
        .pull("runtime-queue".into(), pull)
        .await
        .map_err(|_| anyhow::anyhow!("pull rejected"))?;
    anyhow::ensure!(
        matches!(result,PullOutcome::Assigned{work_package_id,..} if work_package_id=="01ARZ3NDEKTSV4RRFFQ69G5FAY"),
        "assignment mismatch"
    );
    println!("PASS: private-backend scope uses published handoff");
    Ok(())
}
#[cfg(not(all(feature = "restate", unix)))]
fn main() {
    eprintln!("fixture requires Unix and restate feature");
}
