//! Unactivated, create-only root publication of an independently verified unknown result.
#[cfg(all(target_os = "linux", feature = "restate"))]
fn main() -> anyhow::Result<()> {
    use control_plane::{
        launch_reservation::LaunchScope,
        root_finalization::record_digest,
        root_finalization_authorization::{Authorization, publish_root},
        root_finalization_evidence::read_root_config,
        root_finalization_ingress::{FixedEvidence, UnknownCleanupVerifier},
    };
    use serde::Deserialize;
    use std::path::PathBuf;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Config {
        schema: u32,
        generation: String,
        scope: LaunchScope,
        boot_id: String,
        namespace_dev: u64,
        namespace_ino: u64,
        host_namespace_dev: u64,
        host_namespace_ino: u64,
        request_sha256: String,
        grant_sha256: String,
        catalog_sha256: String,
        recipe_sha256: String,
        observation_sha256: String,
    }
    let args: Vec<_> = std::env::args().collect();
    anyhow::ensure!(
        args.len() == 2
            && ulid::Ulid::from_string(&args[1]).is_ok_and(|x| x.to_string() == args[1])
            && unsafe { libc::geteuid() } == 0
            && unsafe { libc::getegid() } == 0,
        "root and canonical generation required"
    );
    let g = &args[1];
    let status = std::fs::read_to_string("/proc/self/status")?;
    for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        let line = status
            .lines()
            .find(|s| s.starts_with(&format!("{key}:")))
            .ok_or_else(|| anyhow::anyhow!("capabilities unavailable"))?;
        anyhow::ensure!(
            line.split_whitespace().nth(1) == Some("0000000000000000"),
            "nonempty capabilities"
        );
    }
    anyhow::ensure!(
        status
            .lines()
            .any(|s| s.split_whitespace().collect::<Vec<_>>() == ["NoNewPrivs:", "1"]),
        "no-new-privileges required"
    );
    let config_path = PathBuf::from(format!(
        "/etc/software-factory-goose/finalization/{g}.runtime.json"
    ));
    let config: Config = serde_json::from_slice(&read_root_config(&config_path)?)?;
    config.scope.validate()?;
    anyhow::ensure!(
        config.schema == 1
            && config.generation == *g
            && config.scope.generation == *g
            && std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() == config.boot_id
            && config.namespace_dev != 0
            && config.namespace_ino != 0
            && config.host_namespace_dev != 0
            && config.host_namespace_ino != 0
            && (config.namespace_dev, config.namespace_ino)
                != (config.host_namespace_dev, config.host_namespace_ino),
        "bootstrap scope mismatch"
    );
    let fixed = |dir: &str, suffix: &str| PathBuf::from(format!("{dir}/{g}{suffix}"));
    let verifier = UnknownCleanupVerifier {
        grant: (
            fixed("/var/lib/software-factory-goose/stop", ".grant-verified"),
            config.grant_sha256,
        ),
        catalog: (
            fixed("/etc/software-factory-goose/launch-catalog", ".json"),
            config.catalog_sha256,
        ),
        recipe: (
            fixed("/etc/software-factory-goose/launch-catalog", ".recipe.json"),
            config.recipe_sha256,
        ),
        observation: (
            fixed("/var/lib/software-factory-goose/stop", ".observation"),
            config.observation_sha256,
        ),
    };
    let evidence = FixedEvidence::new(
        config.scope.clone(),
        fixed(
            "/var/lib/software-factory-goose/stop",
            ".root-finalization-request.json",
        ),
        config.request_sha256,
        verifier,
    )?;
    let authorization = publish_root(g, || {
        let request = evidence.load()?;
        Ok(Authorization {
            schema: 1,
            task_id: config.scope.task_id.clone(),
            generation: g.clone(),
            request_sha256: record_digest(&request)?,
        })
    })?;
    println!(
        "authorized generation={} request_sha256={}",
        authorization.generation, authorization.request_sha256
    );
    Ok(())
}
#[cfg(not(all(target_os = "linux", feature = "restate")))]
fn main() {
    eprintln!("Linux with restate feature required");
    std::process::exit(1);
}
