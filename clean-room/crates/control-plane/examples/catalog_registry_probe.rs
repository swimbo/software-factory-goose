//! Read-only loader probe for disposable root-provisioned registry files.
#[cfg(all(target_os = "linux", feature = "registry-sidecar"))]
fn main() -> anyhow::Result<()> {
    let (registry, catalogs) = control_plane::private_runtime::load_catalog_registry()?;
    anyhow::ensure!(catalogs.len() == 4, "fixture catalog count");
    anyhow::ensure!(
        catalogs.len() >= 4 && catalogs.len() <= 16,
        "fixture catalog count"
    );
    let active: Vec<_> = catalogs
        .iter()
        .filter(|(c, _)| c.intent_id == registry.active_intent)
        .collect();
    anyhow::ensure!(active.len() == 1, "active fixture missing");
    let cfg = &active[0].0;
    let scope = cfg
        .launch_scope
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("active scope missing"))?;
    println!(
        "{}",
        serde_json::json!({"catalogs":catalogs.len(),"intent":cfg.intent_id,"task":cfg.task_id,"generation":scope.generation,"catalog_sha256":cfg.catalog()?.fingerprint()?})
    );
    Ok(())
}
#[cfg(not(all(target_os = "linux", feature = "registry-sidecar")))]
fn main() {
    std::process::exit(1);
}
