//! Synthetic integration fixture only. No production listener or worker is activated.
#[cfg(all(feature = "restate", unix))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use control_plane::{
        worker_adapter::{UnixRestateBackend, WorkerBackend},
        worker_queue::{PullOutcome, PullRequest, QueueCompletion, ScheduleRequest},
        workflow::{LeaseProof, LeaseSpec, LeaseStage},
    };
    use std::{path::PathBuf, time::Duration};

    let path = PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("missing fixture socket"))?,
    );
    let port: u16 = std::env::args()
        .nth(2)
        .ok_or_else(|| anyhow::anyhow!("missing loopback port"))?
        .parse()?;
    anyhow::ensure!(port != 0, "fixture port must be nonzero");
    let (a, b) = tokio::net::UnixStream::pair()?;
    let uid = a.peer_cred()?.uid();
    drop((a, b));
    let backend = UnixRestateBackend::new(path, uid).await?;
    let id = shared::new_id();
    let queue = format!("unix-fixture-{id}");
    let task = format!("unix-fixture-task-{id}");
    let request = PullRequest {
        request_id: shared::new_id(),
        ttl_ms: 300_000,
    };
    // The SDK no-argument status handler requires an absent body, not JSON null.
    anyhow::ensure!(
        backend
            .status(task.clone())
            .await
            .map_err(|e| anyhow::anyhow!("status before schedule: {e:?}"))?
            .is_none(),
        "unexpected existing fixture state"
    );
    anyhow::ensure!(
        backend
            .lookup_pull(queue.clone(), request.request_id.clone())
            .await
            .map_err(|e| anyhow::anyhow!("lookup before pull: {e:?}"))?
            .is_none(),
        "unexpected existing fixture delivery"
    );
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()?;
    let scheduled = ScheduleRequest {
        work_package_id: task.clone(),
        spec: LeaseSpec {
            repository: "synthetic-unix-fixture".into(),
            base_revision: "a".repeat(40),
        },
    };
    client
        .post(format!(
            "http://127.0.0.1:{port}/restate/call/WorkerQueueJournal/{queue}/schedule"
        ))
        .json(&scheduled)
        .send()
        .await?
        .error_for_status()?;
    let assigned = backend
        .pull(queue.clone(), request.clone())
        .await
        .map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
    let PullOutcome::Assigned {
        work_package_id,
        spec,
        lease,
    } = &assigned
    else {
        anyhow::bail!("fixture was not assigned");
    };
    anyhow::ensure!(
        *work_package_id == task
            && *spec == scheduled.spec
            && lease.attempt == 1
            && lease.worker_id == "fixture-worker",
        "wrong authoritative delivery"
    );
    anyhow::ensure!(
        backend
            .lookup_pull(queue.clone(), request.request_id.clone())
            .await
            .map_err(|e| anyhow::anyhow!("lookup assigned: {e:?}"))?
            == Some(assigned.clone()),
        "lookup changed delivery"
    );
    anyhow::ensure!(
        backend
            .pull(queue.clone(), request.clone())
            .await
            .map_err(|e| anyhow::anyhow!("repeat pull: {e:?}"))?
            == assigned,
        "pull replay changed delivery"
    );
    let state = backend
        .status(task.clone())
        .await
        .map_err(|e| anyhow::anyhow!("status leased: {e:?}"))?
        .ok_or_else(|| anyhow::anyhow!("missing claimed state"))?;
    anyhow::ensure!(
        state.stage == LeaseStage::Leased && state.active.as_ref() == Some(lease),
        "status does not match authoritative lease"
    );
    let completion = QueueCompletion {
        request_id: request.request_id,
        proof: LeaseProof {
            attempt: lease.attempt,
            token: lease.token.clone(),
        },
        receipt: shared::Receipt::Failed {
            exit_code: 1,
            stderr_tail: "synthetic fixture failure".into(),
        },
    };
    let completed = backend
        .complete(queue.clone(), completion.clone())
        .await
        .map_err(|e| anyhow::anyhow!("complete: {e:?}"))?;
    anyhow::ensure!(
        completed.stage == LeaseStage::CoolingDown && completed.active.is_none(),
        "completion did not cool claim"
    );
    anyhow::ensure!(
        backend
            .complete(queue.clone(), completion.clone())
            .await
            .map_err(|e| anyhow::anyhow!("repeat complete: {e:?}"))?
            == completed,
        "completion replay changed result"
    );
    anyhow::ensure!(
        backend
            .status(task)
            .await
            .map_err(|e| anyhow::anyhow!("status completed: {e:?}"))?
            == Some(completed),
        "status lost completion"
    );
    let mut forged = completion;
    forged.proof.token = shared::new_id();
    anyhow::ensure!(
        backend.complete(queue, forged).await.is_err(),
        "forged completion accepted"
    );
    println!(
        "PASS: real UnixRestateBackend status (absent body), pull, lookup, completion, exact retries and forged-token refusal against disposable Restate + PostgreSQL; same-UID fixture only"
    );
    Ok(())
}

#[cfg(not(all(feature = "restate", unix)))]
fn main() {
    eprintln!("fixture requires restate feature and Unix");
    std::process::exit(1);
}
