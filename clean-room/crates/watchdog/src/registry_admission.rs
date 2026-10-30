//! Registry-transition shared admission fence. Root-only, fixed paths; no recovery API.
//! Gate provisioning and transition completion are separate reviewed authorities.
use anyhow::{Result, ensure};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::Read,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
};
const DIR: &str = "/var/lib/software-factory-goose/registry-admission";
const REGISTRY: &str = "/etc/software-factory-goose/catalog-registry.json";
#[cfg(not(feature = "registry-v5-grant"))]
const ATTEST: &str = "/etc/software-factory-goose/registry-process-attestation.json";
#[cfg(feature = "registry-v5-grant")]
const ATTEST: &str = "/etc/software-factory-goose/registry-v5-process-attestation.json";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    schema: u32,
    boot_id: String,
    manifest_sha256: String,
    attestation_sha256: String,
    transition_id: String,
    completion_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Completion {
    schema: u32,
    transition_id: String,
    boot_id: String,
    manifest_sha256: String,
    attestation_sha256: String,
    replay_sha256: String,
    intent_sha256: String,
}
#[derive(Deserialize)]
struct Attestation {
    boot_id: String,
    config_sha256: String,
}
fn no_acl(f: &File, dir: bool) -> Result<()> {
    for attr in if dir {
        &["system.posix_acl_access", "system.posix_acl_default"][..]
    } else {
        &["system.posix_acl_access"][..]
    } {
        let n = CString::new(*attr)?;
        let rc = unsafe { libc::fgetxattr(f.as_raw_fd(), n.as_ptr(), std::ptr::null_mut(), 0) };
        ensure!(
            rc < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA),
            "ACL present or unavailable"
        );
    }
    Ok(())
}
fn directory(path: &str, mode: Option<u32>, gid: u32) -> Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_dir()
            && m.uid() == 0
            && m.gid() == gid
            && m.mode() & 0o022 == 0
            && mode.is_none_or(|v| m.mode() & 0o7777 == v),
        "untrusted gate directory"
    );
    no_acl(&f, true)?;
    Ok(f)
}
fn read(path: &str, mode: u32, max: u64, gid: u32) -> Result<Vec<u8>> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.gid() == gid
            && m.nlink() == 1
            && m.mode() & 0o7777 == mode
            && m.len() > 0
            && m.len() <= max,
        "untrusted gate file"
    );
    no_acl(&f, false)?;
    let mut b = Vec::new();
    Read::by_ref(&mut f).take(max + 1).read_to_end(&mut b)?;
    ensure!(b.len() as u64 == m.len(), "gate file changed");
    Ok(b)
}
fn hash(v: &[u8]) -> String {
    format!("{:x}", Sha256::digest(v))
}
/// Holds a shared lock for the entire root grant or launch transaction.
pub struct SharedAdmission {
    _lock: File,
}
impl SharedAdmission {
    pub fn acquire() -> Result<Self> {
        ensure!(unsafe { libc::geteuid() } == 0, "root required");
        for p in [
            "/",
            "/var",
            "/var/lib",
            "/var/lib/software-factory-goose",
            "/etc",
            "/etc/software-factory-goose",
        ] {
            directory(p, None, 0)?;
        }
        directory(DIR, Some(0o710), 2000)?;
        let lock = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(format!("{DIR}/gate.lock"))?;
        let m = lock.metadata()?;
        ensure!(
            m.is_file()
                && m.uid() == 0
                && m.gid() == 2000
                && m.nlink() == 1
                && m.mode() & 0o7777 == 0o440,
            "untrusted gate lock"
        );
        no_acl(&lock, false)?;
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0,
            "registry transition busy"
        );
        match std::fs::symlink_metadata(format!("{DIR}/transition.json")) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            _ => anyhow::bail!("registry transition unresolved"),
        };
        let h: Head =
            serde_json::from_slice(&read(&format!("{DIR}/head.json"), 0o440, 65536, 2000)?)?;
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        let reg = read(REGISTRY, 0o644, 65536, 0)?;
        let att = read(ATTEST, 0o600, 16384, 0)?;
        let a: Attestation = serde_json::from_slice(&att)?;
        ensure!(
            ulid::Ulid::from_string(&h.transition_id)
                .is_ok_and(|u| u.to_string() == h.transition_id),
            "invalid transition id"
        );
        directory(&format!("{DIR}/history"), Some(0o700), 0)?;
        let completion_raw = read(
            &format!("{DIR}/history/{}.complete.json", h.transition_id),
            0o600,
            16384,
            0,
        )?;
        let completion: Completion = serde_json::from_slice(&completion_raw)?;
        let intent_raw = read(
            &format!("{DIR}/history/{}.intent.json", h.transition_id),
            0o600,
            4096,
            0,
        )?;
        let replay_raw = read(
            &format!("{DIR}/history/{}.replay.json", h.transition_id),
            0o600,
            16384,
            0,
        )?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Intent {
            schema: u32,
            transition_id: String,
            old_manifest_sha256: String,
            new_manifest_sha256: String,
        }
        let intent: Intent = serde_json::from_slice(&intent_raw)?;
        ensure!(
            intent.schema == 1
                && intent.transition_id == h.transition_id
                && intent.new_manifest_sha256 == h.manifest_sha256
                && intent.old_manifest_sha256.len() == 64
                && hash(&intent_raw) == completion.intent_sha256
                && hash(&replay_raw) == completion.replay_sha256,
            "transition history mismatch"
        );
        ensure!(
            completion.schema == 1
                && completion.transition_id == h.transition_id
                && completion.boot_id == h.boot_id
                && completion.manifest_sha256 == h.manifest_sha256
                && completion.attestation_sha256 == h.attestation_sha256
                && completion.replay_sha256.len() == 64
                && completion
                    .replay_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && hash(&completion_raw) == h.completion_sha256,
            "completion proof mismatch"
        );
        ensure!(
            h.schema == 1
                && h.boot_id == boot.trim()
                && a.boot_id == h.boot_id
                && h.manifest_sha256 == hash(&reg)
                && a.config_sha256 == h.manifest_sha256
                && h.attestation_sha256 == hash(&att)
                && ulid::Ulid::from_string(&h.transition_id)
                    .is_ok_and(|u| u.to_string() == h.transition_id),
            "registry head mismatch"
        );
        Ok(Self { _lock: lock })
    }
}
