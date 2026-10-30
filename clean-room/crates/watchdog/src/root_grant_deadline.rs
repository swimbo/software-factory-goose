//! Grant-bound production deadline verification; no timer installation here.
use crate::{
    root_grant::{VerifiedGrant, now_ms},
    root_launch_docker::BoundedCli,
};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    time::Duration,
};
const STATE: &str = "/var/lib/software-factory-goose/stop";
const BINARY: &str = "/usr/local/libexec/software-factory-goose/sfactory_deadline_kernel_stop";
const BINARY_SHA: &str = "e286a8daab464f29e14e11beed0147cf24a11b585b4dfc50e48cb8615d0a325a";
fn no_acl(f: &std::fs::File) -> Result<()> {
    let attr = std::ffi::CString::new("system.posix_acl_access")?;
    // SAFETY: descriptor and terminated attribute name are valid; null buffer queries size.
    let n = unsafe { libc::fgetxattr(f.as_raw_fd(), attr.as_ptr(), std::ptr::null_mut(), 0) };
    ensure!(
        n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA),
        "ACL present or unavailable"
    );
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Armed {
    schema: u32,
    target: String,
    boot_id: String,
    binding_sha256: String,
    verified_grant_sha256: String,
    wake_monotonic_ns: u64,
    expiry_ms: u64,
    engine_effects: bool,
}
fn root_bytes(path: &Path) -> Result<Vec<u8>> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    no_acl(&f)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o600
            && m.len() <= 16384,
        "untrusted deadline record"
    );
    let mut b = Vec::new();
    Read::by_ref(&mut f).take(16385).read_to_end(&mut b)?;
    ensure!(b.len() as u64 == m.len(), "deadline record changed");
    Ok(b)
}
fn monotonic_ns() -> Result<u64> {
    let mut t = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: kernel writes a timespec to the valid pointer on success.
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, t.as_mut_ptr()) } == 0,
        "clock unavailable"
    );
    // SAFETY: clock_gettime initialized the timespec.
    let t = unsafe { t.assume_init() };
    u64::try_from(t.tv_sec)?
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(t.tv_nsec as u64))
        .context("clock overflow")
}
fn prop(cli: &BoundedCli, unit: &str, key: &str) -> Result<String> {
    Ok(cli
        .run_program(
            "/usr/bin/systemctl",
            &[
                "show".into(),
                unit.into(),
                "-p".into(),
                key.into(),
                "--value".into(),
            ],
            Duration::from_secs(8),
        )?
        .trim()
        .to_owned())
}
/// Checks the actual current timer and its already-fsynced grant-bound receipt.
/// Errors must deny admission and leave the generation closed/quarantined.
pub fn verify_deadline(g: &str, grant: &VerifiedGrant) -> Result<()> {
    ensure!(
        ulid::Ulid::from_string(g).is_ok_and(|u| u.to_string() == g),
        "invalid target"
    );
    let root = Path::new(STATE);
    for p in root.ancestors() {
        let m = fs::symlink_metadata(p)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
            "untrusted state directory"
        );
    }
    let _ = crate::root_cgroup::linux::KernelStop::open(g)?;
    match fs::symlink_metadata(root.join(format!("{g}.closed"))) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
        Ok(_) => anyhow::bail!("generation closed"),
    }
    let arm: Armed =
        serde_json::from_slice(&root_bytes(&root.join(format!("{g}.deadline-armed.json")))?)?;
    let verified = root_bytes(&root.join(format!("{g}.grant-verified")))?;
    let actual_hash = format!("{:x}", Sha256::digest(&verified));
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    ensure!(
        arm.schema == 1
            && arm.target == g
            && arm.boot_id == boot.trim()
            && arm.binding_sha256 == grant.binding_sha256()
            && arm.verified_grant_sha256 == actual_hash
            && arm.expiry_ms == grant.expires_at_ms()
            && !arm.engine_effects
            && monotonic_ns()? < arm.wake_monotonic_ns
            && now_ms()? < arm.expiry_ms,
        "deadline receipt invalid"
    );
    let base = format!("sfactorydeadline{}", g.to_lowercase());
    let timer = format!("{base}.timer");
    let service = format!("{base}.service");
    let cli = BoundedCli;
    let mut binary = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(BINARY)?;
    let bm = binary.metadata()?;
    no_acl(&binary)?;
    ensure!(
        bm.is_file()
            && bm.uid() == 0
            && bm.gid() == 0
            && bm.nlink() == 1
            && bm.mode() & 0o7777 == 0o755
            && bm.len() <= 64 * 1024 * 1024,
        "deadline executable untrusted"
    );
    let mut bb = Vec::new();
    Read::by_ref(&mut binary)
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bb)?;
    ensure!(
        bb.len() as u64 == bm.len() && format!("{:x}", Sha256::digest(&bb)) == BINARY_SHA,
        "deadline executable changed"
    );
    for (unit, key, value) in [
        (&timer, "LoadState", "loaded"),
        (&timer, "ActiveState", "active"),
        (&timer, "Names", timer.as_str()),
        (&timer, "Transient", "yes"),
        (&timer, "DropInPaths", ""),
        (&timer, "Unit", service.as_str()),
        (&service, "LoadState", "loaded"),
        (&service, "Names", service.as_str()),
        (&service, "Transient", "yes"),
        (&service, "DropInPaths", ""),
        (&service, "User", "root"),
        (&service, "Group", "root"),
        (&service, "NoNewPrivileges", "yes"),
        (&service, "CapabilityBoundingSet", ""),
        (&service, "RestrictAddressFamilies", "AF_UNIX"),
        (&service, "TasksMax", "16"),
        (&service, "MemoryMax", "134217728"),
        (&service, "CPUQuotaPerSecUSec", "500ms"),
        (&service, "Restart", "on-failure"),
        (&service, "StartLimitIntervalUSec", "0"),
    ] {
        ensure!(
            prop(&cli, unit, key)? == value,
            "deadline manager property changed"
        );
    }
    for unit in [&timer, &service] {
        ensure!(
            prop(&cli, unit, "FragmentPath")? == format!("/run/systemd/transient/{unit}"),
            "deadline unit path changed"
        );
    }
    let cmd = prop(&cli, &service, "ExecStart")?;
    ensure!(
        cmd.starts_with(&format!(
            "{{ path={BINARY} ; argv[]={BINARY} {g} ; ignore_errors=no ;"
        )) && cmd.matches("{ path=").count() == 1,
        "deadline command changed"
    );
    let object = format!("/org/freedesktop/systemd1/unit/{base}_2etimer");
    let wake = cli.run_program(
        "/usr/bin/busctl",
        &[
            "get-property".into(),
            "org.freedesktop.systemd1".into(),
            object,
            "org.freedesktop.systemd1.Timer".into(),
            "NextElapseUSecMonotonic".into(),
        ],
        Duration::from_secs(8),
    )?;
    ensure!(
        wake.trim() == format!("t {}", arm.wake_monotonic_ns / 1000)
            && monotonic_ns()? < arm.wake_monotonic_ns
            && now_ms()? < arm.expiry_ms,
        "deadline wake changed"
    );
    Ok(())
}
