//! Fixed public-synthetic Linux canary. Never reads any production evidence or credentials.
#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use control_plane::root_finalization_evidence::read_fixed;
    use std::path::Path;
    anyhow::ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let status = std::fs::read_to_string("/proc/self/status")?;
    for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        let line = status
            .lines()
            .find(|s| s.starts_with(&format!("{key}:")))
            .ok_or_else(|| anyhow::anyhow!("capability status unavailable"))?;
        anyhow::ensure!(
            line.split_whitespace().nth(1) == Some("0000000000000000"),
            "capabilities not empty"
        );
    }
    anyhow::ensure!(
        status
            .lines()
            .any(|s| s.split_whitespace().collect::<Vec<_>>() == ["NoNewPrivs:", "1"]),
        "no-new-privileges required"
    );
    const ROOT: &str = "/etc/software-factory-goose/evidence-reader-canary";
    const DIGEST: &str = "45dab8f7d110fea75d07ba86f539b9ab23464da186ffc642c7f1a61b12452806";
    let read = |name: &str, digest: &str| read_fixed(&Path::new(ROOT).join(name), digest);
    anyhow::ensure!(
        read("valid.json", DIGEST)? == b"{\"canary\":true}\n",
        "positive evidence mismatch"
    );
    anyhow::ensure!(
        read("valid.json", &"0".repeat(64)).is_err(),
        "wrong digest accepted"
    );
    for name in [
        "bad-mode.json",
        "bad-acl.json",
        "hardlink.json",
        "final-link.json",
        "ancestor-link/valid.json",
    ] {
        anyhow::ensure!(
            read(name, DIGEST).is_err(),
            "negative evidence accepted: {name}"
        );
    }
    println!(
        "PASS: root public evidence positive; wrong digest/mode/ACL/hardlink/final and ancestor symlink refused; no capabilities; no-new-privileges"
    );
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("Linux-only canary");
    std::process::exit(1);
}
