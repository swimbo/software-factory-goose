//! Fixed generation, read-only historical structural diagnostic; no socket or engine.
#[cfg(target_os = "linux")]
use watchdog::root_cgroup;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../root_grant.rs"]
mod root_grant;
#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, Result, ensure};
    use serde::Deserialize;
    use std::{
        fs::OpenOptions,
        io::Read,
        os::{
            fd::AsRawFd,
            unix::fs::{MetadataExt, OpenOptionsExt},
        },
        path::Path,
    };
    const G: &str = "01M65NEH5T767H8Q5X71TTFR5S";
    const BOOT: &str = "98b86bb5-c04c-46f5-951d-22e497102f29";
    const ROOT: &str = "/etc/software-factory-goose/launch-catalog";
    const STATE: &str = "/var/lib/software-factory-goose/stop";
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Record {
        schema: u32,
        generation: String,
        binding_sha256: String,
        reservation: root_grant::Reservation,
    }
    fn read(path: &Path) -> Result<Vec<u8>> {
        let mut f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?;
        let m = f.metadata()?;
        ensure!(
            m.is_file()
                && m.uid() == 0
                && m.gid() == 0
                && m.nlink() == 1
                && m.mode() & 0o7777 == 0o600
                && m.len() <= 16384,
            "record unavailable"
        );
        let attr = std::ffi::CString::new("system.posix_acl_access")?;
        // SAFETY: descriptor and terminated attribute name are valid.
        let rc = unsafe { libc::fgetxattr(f.as_raw_fd(), attr.as_ptr(), std::ptr::null_mut(), 0) };
        ensure!(
            rc < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA),
            "ACL unavailable"
        );
        let mut data = Vec::new();
        Read::by_ref(&mut f).take(16385).read_to_end(&mut data)?;
        ensure!(data.len() as u64 == m.len(), "record changed");
        Ok(data)
    }
    // SAFETY: geteuid only reads current credentials.
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    ensure!(std::env::args().count() == 1, "no arguments allowed");
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    ensure!(boot.trim() == BOOT, "boot changed");
    let cat: root_grant::LaunchCatalog =
        serde_json::from_slice(&read(&Path::new(ROOT).join(format!("{G}.json")))?)?;
    let record: Record = serde_json::from_slice(&read(
        &Path::new(STATE).join(format!("{G}.grant-verified")),
    )?)?;
    ensure!(
        record.schema == 1 && record.generation == G && cat.scope.generation == G,
        "target mismatch"
    );
    let intent = read(&Path::new(STATE).join(format!("{G}.grant-request")))?;
    ensure!(
        intent == format!("{G}\n{}\n", cat.scope.catalog_sha256).as_bytes(),
        "intent mismatch"
    );
    let historical = record
        .reservation
        .expires_at_ms
        .checked_sub(1)
        .context("invalid expiry")?;
    let binding = root_grant::validate_and_bind(&cat, &record.reservation, BOOT, historical)?;
    ensure!(
        binding == record.binding_sha256,
        "structural binding mismatch"
    );
    println!(
        "{{\"generation\":\"{G}\",\"binding_sha256\":\"{binding}\",\"historical_now_ms\":{historical},\"socket_called\":false,\"engine_called\":false}}"
    );
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("Linux required")
}
