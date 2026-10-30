//! Read-only native identity and registry prerequisite; never requests a grant.
#[cfg(all(target_os = "linux", feature = "registry-sidecar"))]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use std::collections::BTreeMap;
    // SAFETY: identity queries have no side effects.
    ensure!(
        unsafe { libc::geteuid() } == 0 && unsafe { libc::getegid() } == 0,
        "root required"
    );
    let status = std::fs::read_to_string("/proc/self/status")?;
    let fields: BTreeMap<_, _> = status.lines().filter_map(|s| s.split_once(':')).collect();
    for key in ["CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb"] {
        let value = fields.get(key).context("capability missing")?.trim();
        ensure!(u64::from_str_radix(value, 16)? == 0, "unexpected {key}");
    }
    ensure!(
        fields.get("NoNewPrivs").map(|v| v.trim()) == Some("1"),
        "no-new-privileges required"
    );
    let (registry, catalogs) = control_plane::private_runtime::load_catalog_registry()?;
    let active: Vec<_> = catalogs
        .iter()
        .filter(|(cfg, _)| cfg.intent_id == registry.active_intent)
        .collect();
    ensure!(active.len() == 1, "active catalog is ambiguous");
    let cfg = &active[0].0;
    let scope = cfg
        .launch_scope
        .as_ref()
        .context("active launch scope absent")?;
    ensure!(
        scope.intent_id == registry.active_intent && scope.task_id == cfg.task_id,
        "active scope mismatch"
    );
    ensure!(cfg.sdk_port == 9084, "unexpected registry port");
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    ensure!(cfg.boot_id == boot.trim(), "boot changed");
    println!(
        "{}",
        serde_json::json!({"intent_id":cfg.intent_id,"task_id":cfg.task_id,"generation":scope.generation,"catalog_sha256":scope.catalog_sha256,"registry_validated":true,"capabilities_empty":true,"grant_requested":false})
    );
    Ok(())
}
#[cfg(not(all(target_os = "linux", feature = "registry-sidecar")))]
fn main() {
    std::process::exit(1);
}
