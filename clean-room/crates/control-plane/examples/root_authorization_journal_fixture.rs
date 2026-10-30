//! Synthetic journal fixture publisher. Never use this to authorize real evidence.
#[cfg(all(target_os = "linux", feature = "root-authorization-canary"))]
fn main() -> anyhow::Result<()> {
    use control_plane::{
        root_finalization::{parse_request, record_digest},
        root_finalization_authorization::{Authorization, publish_root},
        root_finalization_evidence::read_root_config,
    };
    const ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAM";
    const INPUT: &str =
        "/etc/software-factory-goose/finalization-authorization/journal-fixture-request.json";
    anyhow::ensure!(
        std::env::args_os().len() == 1
            && unsafe { libc::geteuid() } == 0
            && unsafe { libc::getegid() } == 0,
        "fixed root fixture only"
    );
    let status = std::fs::read_to_string("/proc/self/status")?;
    for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        anyhow::ensure!(
            status
                .lines()
                .find(|s| s.starts_with(&format!("{key}:")))
                .and_then(|s| s.split_whitespace().nth(1))
                == Some("0000000000000000"),
            "capabilities not empty"
        );
    }
    anyhow::ensure!(
        status
            .lines()
            .any(|s| s.split_whitespace().collect::<Vec<_>>() == ["NoNewPrivs:", "1"]),
        "no-new-privileges required"
    );
    publish_root(ID, || {
        let request = parse_request(&read_root_config(std::path::Path::new(INPUT))?)?;
        anyhow::ensure!(
            request.reservation.generation == ID
                && request.reservation.scope.generation == ID
                && request.reservation.scope.task_id == ID,
            "fixture scope mismatch"
        );
        Ok(Authorization {
            schema: 1,
            task_id: ID.into(),
            generation: ID.into(),
            request_sha256: record_digest(&request)?,
        })
    })?;
    println!("PASS: fixed synthetic journal authorization published");
    Ok(())
}
#[cfg(not(all(target_os = "linux", feature = "root-authorization-canary")))]
fn main() {
    eprintln!("Linux synthetic fixture feature required");
    std::process::exit(1);
}
