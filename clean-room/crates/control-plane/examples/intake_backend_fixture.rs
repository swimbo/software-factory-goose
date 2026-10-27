//! Synthetic same-UID integration fixture. Does not register a production service.
#[cfg(all(feature = "restate", unix))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use control_plane::{
        intake::IntakeRequest,
        intake_adapter::{IntakeBackend, UnixIntakeBackend},
        worker_adapter::UnixRestateBackend,
    };
    use std::path::PathBuf;
    let mut args = std::env::args().skip(1);
    let normal = PathBuf::from(
        args.next()
            .ok_or_else(|| anyhow::anyhow!("missing normal socket"))?,
    );
    let lossy = PathBuf::from(
        args.next()
            .ok_or_else(|| anyhow::anyhow!("missing lossy socket"))?,
    );
    let (a, _peer) = tokio::net::UnixStream::pair()?;
    let uid = a.peer_cred()?.uid();
    let make = |backend| UnixIntakeBackend::new(backend, "fixture-submitter".into());
    let normal = make(UnixRestateBackend::new(normal, uid).await?)?;
    let lossy = make(UnixRestateBackend::new(lossy, uid).await?)?;
    let key = shared::new_id();
    let request = IntakeRequest {
        schema_version: 1,
        repository: "synthetic-fixture".into(),
        target_ref: "refs/heads/main".into(),
        base_revision: "a".repeat(40),
        intent: "fixture admission".into(),
        acceptance_criteria: vec!["fixture criterion".into()],
    };
    anyhow::ensure!(
        normal
            .inspect(key.clone())
            .await
            .map_err(|e| anyhow::anyhow!("inspect: {e:?}"))?
            .is_none(),
        "unexpected state"
    );
    anyhow::ensure!(
        lossy.submit(key.clone(), request.clone()).await.is_err(),
        "lost acknowledgement unexpectedly returned"
    );
    let stored = normal
        .inspect(key.clone())
        .await
        .map_err(|e| anyhow::anyhow!("inspect after lost reply: {e:?}"))?
        .ok_or_else(|| anyhow::anyhow!("request was not committed before reply loss"))?;
    anyhow::ensure!(
        stored.submitted_by == "fixture-submitter"
            && stored.idempotency_key == key
            && stored.request == request,
        "wrong committed binding"
    );
    anyhow::ensure!(
        normal
            .submit(key.clone(), request.clone())
            .await
            .map_err(|e| anyhow::anyhow!("retry: {e:?}"))?
            == stored,
        "retry changed record"
    );
    let mut different = request;
    different.intent = "different fixture".into();
    anyhow::ensure!(
        normal.submit(key.clone(), different).await.is_err(),
        "conflict accepted"
    );
    anyhow::ensure!(
        normal
            .inspect(key)
            .await
            .map_err(|e| anyhow::anyhow!("final inspect: {e:?}"))?
            == Some(stored),
        "conflict mutated record"
    );
    println!(
        "PASS: synthetic UnixIntakeBackend inspected, committed before discarded acknowledgement, recovered same-key retry, and rejected conflict; same-UID fixture only"
    );
    Ok(())
}
#[cfg(not(all(feature = "restate", unix)))]
fn main() {
    eprintln!("fixture requires restate feature and Unix");
    std::process::exit(1);
}
