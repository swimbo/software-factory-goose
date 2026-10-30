//! Test-only synthetic publication and a deterministic self-SIGKILL barrier.
#[cfg(all(target_os = "linux", feature = "root-authorization-canary"))]
fn main() -> anyhow::Result<()> {
    use control_plane::root_finalization_authorization::{
        Authorization, publish_root, publish_root_canary,
    };
    anyhow::ensure!(
        unsafe { libc::geteuid() } == 0 && unsafe { libc::getegid() } == 0,
        "root required"
    );
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
    let args: Vec<_> = std::env::args().collect();
    let g = match args.as_slice() {
        [_, mode] if mode == "--valid" => "5CDTQ2S41Z8SMJG8V1JTJGSR4P",
        [_, mode] if mode == "--crash" => "76VR8GQDSWWEC5YDNEP0FG61XT",
        _ => anyhow::bail!("fixed synthetic case required"),
    };
    let record = || {
        Ok(Authorization {
            schema: 1,
            task_id: "67J0MV0HTHADF1K7JP9F9XC578".into(),
            generation: g.into(),
            request_sha256: "a".repeat(64),
        })
    };
    if g == "5CDTQ2S41Z8SMJG8V1JTJGSR4P" {
        publish_root(g, record)?;
        println!("PASS: synthetic authorization published");
    } else {
        publish_root_canary(g, record, || {
            const MARKER: &[u8] = b"SFACTORY_CANARY_AUTH_FSYNC_BEFORE_PARENT_FSYNC\n";
            let written = unsafe { libc::write(2, MARKER.as_ptr().cast(), MARKER.len()) };
            assert_eq!(written as usize, MARKER.len());
            unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
            unreachable!("self SIGKILL failed")
        })?;
        anyhow::bail!("crash barrier did not stop publisher");
    }
    Ok(())
}
#[cfg(not(all(target_os = "linux", feature = "root-authorization-canary")))]
fn main() {
    eprintln!("Linux and root-authorization-canary feature required");
    std::process::exit(1);
}
