//! Isolated test adapter for a disposable Restate journal. Never register on the host runtime.
#[cfg(all(unix, feature = "restate"))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use control_plane::{
        launch_reservation::LaunchScope,
        root_launch_grant::{self, FixedJournalBackend, Peer},
        workflow::LeaseSpec,
    };
    use std::{os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc};
    let mut args = std::env::args().skip(1);
    let dir = PathBuf::from(
        args.next()
            .ok_or_else(|| anyhow::anyhow!("fixture directory missing"))?,
    );
    let port: u16 = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("fixture port missing"))?
        .parse()?;
    anyhow::ensure!(
        args.next().is_none()
            && dir
                .to_string_lossy()
                .starts_with("/tmp/sfactory-grant-journal-")
            && !dir.to_string_lossy().contains(".."),
        "fixture scope"
    );
    let path = dir.join("grant.sock");
    let listener = tokio::net::UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
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
    let backend = Arc::new(FixedJournalBackend::new(port, &scope)?);
    let router = root_launch_grant::router(scope, backend)?;
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<Peer>(),
    )
    .await?;
    Ok(())
}
#[cfg(not(all(unix, feature = "restate")))]
fn main() {
    std::process::exit(1)
}
