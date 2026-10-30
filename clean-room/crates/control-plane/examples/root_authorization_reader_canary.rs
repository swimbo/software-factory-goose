//! Fixed synthetic read-only UID-2000 canary. Root fixture provisioning is separate.
#[cfg(all(target_os = "linux", feature = "restate"))]
fn main() -> anyhow::Result<()> {
    use control_plane::root_finalization_authorization::{Authorization, read_authorization};
    let args: Vec<_> = std::env::args().collect();
    let worker = args.len() == 2 && args[1] == "--worker";
    anyhow::ensure!(
        args.len() == if worker { 2 } else { 1 }
            && unsafe { libc::geteuid() } == if worker { 2001 } else { 2000 },
        "fixture principal required"
    );
    let status = std::fs::read_to_string("/proc/self/status")?;
    for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        let line = status
            .lines()
            .find(|s| s.starts_with(&format!("{key}:")))
            .ok_or_else(|| anyhow::anyhow!("capabilities unavailable"))?;
        anyhow::ensure!(
            line.split_whitespace().nth(1) == Some("0000000000000000"),
            "nonempty capability set"
        );
    }
    anyhow::ensure!(
        status
            .lines()
            .any(|s| s.split_whitespace().collect::<Vec<_>>() == ["NoNewPrivs:", "1"]),
        "no-new-privileges required"
    );
    if worker {
        let path = "/etc/software-factory-goose/finalization-authorization/5CDTQ2S41Z8SMJG8V1JTJGSR4P.lock";
        let error = std::fs::File::open(path).expect_err("worker opened SDK lock");
        anyhow::ensure!(
            error.kind() == std::io::ErrorKind::PermissionDenied,
            "lock denial unavailable"
        );
        println!("PASS: UID2001 denied authorization lock; no capabilities; no-new-privileges");
        return Ok(());
    }
    let make = |generation: &str, hash: &str| Authorization {
        schema: 1,
        task_id: "67J0MV0HTHADF1K7JP9F9XC578".into(),
        generation: generation.into(),
        request_sha256: hash.into(),
    };
    let good = make("5CDTQ2S41Z8SMJG8V1JTJGSR4P", &"a".repeat(64));
    read_authorization(&good)?;
    anyhow::ensure!(
        read_authorization(&make(&good.generation, &"b".repeat(64))).is_err(),
        "changed digest admitted"
    );
    anyhow::ensure!(
        read_authorization(&make("76VR8GQDSWWEC5YDNEP0FG61XT", &"a".repeat(64))).is_err(),
        "pending publication admitted"
    );
    anyhow::ensure!(
        read_authorization(&make("6ZDKDZWDQQMWR3XZAD9J7TNRFM", &"a".repeat(64))).is_err(),
        "unsafe publication admitted"
    );
    anyhow::ensure!(
        read_authorization(&make("117WW1Z87X76TZJSVN11Q6FH0F", &"a".repeat(64))).is_err(),
        "absent publication admitted"
    );
    println!(
        "PASS: UID2000 exact authorization accepted; changed digest, pending, unsafe mode and missing authorization refused; no capabilities; no-new-privileges"
    );
    Ok(())
}
#[cfg(not(all(target_os = "linux", feature = "restate")))]
fn main() {
    eprintln!("Linux with restate feature required");
    std::process::exit(1);
}
