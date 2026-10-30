//! Offline fingerprint check only; input is not deployment authority.
#[cfg(all(feature = "restate", unix))]
fn main() -> anyhow::Result<()> {
    use std::io::Read;
    let mut raw = Vec::new();
    std::io::stdin().take(65537).read_to_end(&mut raw)?;
    anyhow::ensure!(raw.len() <= 65536, "input too large");
    let config: control_plane::private_runtime::PrivateRuntimeConfig =
        serde_json::from_slice(&raw)?;
    println!("{}", config.catalog()?.fingerprint()?);
    Ok(())
}
#[cfg(not(all(feature = "restate", unix)))]
fn main() {
    std::process::exit(1);
}
