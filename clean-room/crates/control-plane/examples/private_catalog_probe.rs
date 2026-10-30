//! Read-only probe of the fixed root catalog; no routes or journal mutation.
#[cfg(all(target_os = "linux", feature = "restate"))]
fn main() -> anyhow::Result<()> {
    let (catalog, evidence) = control_plane::private_runtime::load_root_catalog()?;
    anyhow::ensure!(
        evidence == catalog.evidence_sha256,
        "evidence digest mismatch"
    );
    println!("PASS: protected catalog and evidence loaded");
    Ok(())
}
#[cfg(not(all(target_os = "linux", feature = "restate")))]
fn main() {
    std::process::exit(1);
}
