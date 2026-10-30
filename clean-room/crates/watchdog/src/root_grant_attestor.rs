//! Fixed real-grant sidecar attestation. No installer or service activation.
//! The trusted root/systemd manager binds protected ExecStart/MainPID and the
//! namespace join; the root anchor self-observes its namespace. No independent
//! running-ELF or UID-2000 /proc namespace-inode attestation is claimed.
use crate::{root_grant::ServiceAttestation, root_launch_docker::BoundedCli};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::Read,
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    },
    path::Path,
    time::Duration,
};
const ATTEST: &str = "/etc/software-factory-goose/real-process-attestation.json";
const UNIT: &str = "software-factory-goose-real-runtime.service";
const UNITFILE: &str = "/etc/systemd/system/software-factory-goose-real-runtime.service";
const BIN: &str = "/usr/local/libexec/software-factory-goose/private-real-sidecar";
const CONFIG: &str = "/etc/software-factory-goose/real-runtime.json";
const SOCKET: &str = "/run/software-factory-goose/real-launch-grant.sock";
const CGROUP: &str = "/sys/fs/cgroup/system.slice/software-factory-goose-real-runtime.service";
const ANCHOR_UNIT: &str = "software-factory-goose-private-net.service";
const ANCHOR_UNITFILE: &str = "/etc/systemd/system/software-factory-goose-private-net.service";
const ANCHOR_DROPIN: &str =
    "/etc/systemd/system/software-factory-goose-private-net.service.d/50-resources.conf";
const ANCHOR_BIN: &str = "/usr/local/libexec/software-factory-goose/private-netns-anchor.py";
const PRIVATE_NS: &str = "/run/software-factory-goose/private-netns.json";
const HOST_NS: &str = "/run/software-factory-goose/host-netns.json";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    schema: u32,
    boot_id: String,
    pid: u32,
    start_ticks: u64,
    binary_sha256: String,
    unit_sha256: String,
    config_sha256: String,
    netns_dev: u64,
    netns_ino: u64,
    cgroup_dev: u64,
    cgroup_ino: u64,
    socket_dev: u64,
    socket_ino: u64,
    anchor_pid: u32,
    anchor_start_ticks: u64,
    anchor_unit_sha256: String,
    anchor_dropin_sha256: String,
    anchor_binary_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NamespaceObservation {
    version: u32,
    role: String,
    pid: u32,
    uid: u32,
    netns_dev: u64,
    netns_ino: u64,
}
fn no_acl(f: &File) -> Result<()> {
    let n = CString::new("system.posix_acl_access")?;
    // SAFETY: descriptor is live and no buffer is supplied when querying xattr size.
    let rc = unsafe { libc::fgetxattr(f.as_raw_fd(), n.as_ptr(), std::ptr::null_mut(), 0) };
    ensure!(
        rc < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA),
        "ACL present or unavailable"
    );
    Ok(())
}
fn fixed_file(path: &str, mode: u32, max: u64) -> Result<(Vec<u8>, std::fs::Metadata)> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.mode() & 0o7777 == mode
            && m.len() <= max,
        "untrusted root file"
    );
    no_acl(&f)?;
    let mut b = Vec::new();
    Read::by_ref(&mut f).take(max + 1).read_to_end(&mut b)?;
    ensure!(b.len() as u64 == m.len(), "root file changed");
    Ok((b, m))
}
fn sha(v: &[u8]) -> String {
    format!("{:x}", Sha256::digest(v))
}
fn prop_for(cli: &BoundedCli, unit: &str, key: &str) -> Result<String> {
    let value = cli.run_program(
        "/usr/bin/systemctl",
        &[
            "show".into(),
            unit.into(),
            "-p".into(),
            key.into(),
            "--value".into(),
        ],
        Duration::from_secs(8),
    )?;
    Ok(value.trim().to_owned())
}
fn prop(cli: &BoundedCli, key: &str) -> Result<String> {
    prop_for(cli, UNIT, key)
}
fn start_ticks(pid: u32) -> Result<u64> {
    let data = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    ensure!(data.len() < 8192, "proc stat oversized");
    let (_, tail) = data.rsplit_once(')').context("invalid proc stat")?;
    Ok(tail
        .split_whitespace()
        .nth(19)
        .context("missing start ticks")?
        .parse()?)
}
fn status(pid: u32, expected_uid: &str, expected_gid: &str) -> Result<()> {
    let text = fs::read_to_string(format!("/proc/{pid}/status"))?;
    validate_status(&text, expected_uid, expected_gid)
}
fn validate_status(text: &str, expected_uid: &str, expected_gid: &str) -> Result<()> {
    ensure!(text.len() < 65536, "status oversized");
    let mut uid = None;
    let mut gid = None;
    let mut caps = None;
    let mut nnp = None;
    for line in text.lines() {
        let (k, v) = match line.split_once(':') {
            Some(v) => v,
            None => continue,
        };
        match k {
            "Uid" => uid = Some(v.split_whitespace().collect::<Vec<_>>()),
            "Gid" => gid = Some(v.split_whitespace().collect::<Vec<_>>()),
            "CapEff" => caps = Some(v.trim()),
            "NoNewPrivs" => nnp = Some(v.trim()),
            _ => {}
        }
    }
    ensure!(
        uid == Some(vec![expected_uid; 4])
            && gid == Some(vec![expected_gid; 4])
            && caps == Some("0000000000000000")
            && nnp == Some("1"),
        "service process identity mismatch"
    );
    Ok(())
}
/// Attestation is re-read for every call; restart requires a newly provisioned
/// root-owned binding. Failure is unknown and cannot be treated as no grant.
pub struct RootAttestor;
impl ServiceAttestation for RootAttestor {
    fn verify(&self) -> Result<()> {
        for root in [
            "/",
            "/etc",
            "/etc/software-factory-goose",
            "/etc/systemd",
            "/etc/systemd/system",
            "/etc/systemd/system/software-factory-goose-private-net.service.d",
            "/usr",
            "/usr/local",
            "/usr/local/libexec",
            "/usr/local/libexec/software-factory-goose",
            "/run",
            "/run/software-factory-goose",
        ] {
            let p = Path::new(root);
            let m = fs::symlink_metadata(p)?;
            ensure!(
                m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
                "untrusted service ancestor"
            );
            let f = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(p)?;
            no_acl(&f)?;
        }
        let (raw, _) = fixed_file(ATTEST, 0o600, 16384)?;
        let b: Binding = serde_json::from_slice(&raw)?;
        ensure!(
            b.schema == 1
                && b.pid > 1
                && b.start_ticks > 0
                && b.boot_id == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
            "binding boot or process invalid"
        );
        let (binary, _) = fixed_file(BIN, 0o755, 100_000_000)?;
        let (unit, _) = fixed_file(UNITFILE, 0o644, 65536)?;
        let (config, _) = fixed_file(CONFIG, 0o644, 65536)?;
        ensure!(
            sha(&binary) == b.binary_sha256
                && sha(&unit) == b.unit_sha256
                && sha(&config) == b.config_sha256,
            "service pinned file mismatch"
        );
        let cli = BoundedCli;
        let expected = [
            ("LoadState", "loaded"),
            ("ActiveState", "active"),
            ("Names", UNIT),
            ("FragmentPath", UNITFILE),
            ("DropInPaths", ""),
            (
                "ControlGroup",
                "/system.slice/software-factory-goose-real-runtime.service",
            ),
            ("User", "sfgoose-control"),
            ("Group", "sfgoose-control"),
            ("NoNewPrivileges", "yes"),
            ("CapabilityBoundingSet", ""),
            ("PrivateNetwork", "yes"),
            ("BindsTo", "software-factory-goose-private-net.service"),
            (
                "JoinsNamespaceOf",
                "software-factory-goose-private-net.service",
            ),
            ("ExecStartPre", ""),
            ("ExecStartPost", ""),
            ("Environment", ""),
            ("EnvironmentFiles", ""),
        ];
        for (key, value) in expected {
            ensure!(prop(&cli, key)? == value, "service property mismatch");
        }
        ensure!(
            prop(&cli, "MainPID")? == b.pid.to_string(),
            "service PID changed"
        );
        let cmd = prop(&cli, "ExecStart")?;
        ensure!(
            cmd.starts_with(&format!(
                "{{ path={BIN} ; argv[]={BIN} ; ignore_errors=no ;"
            )) && cmd.matches("{ path=").count() == 1,
            "service exec mismatch"
        );
        ensure!(
            start_ticks(b.pid)? == b.start_ticks,
            "service process replaced"
        );
        status(b.pid, "2000", "2000")?;
        let (anchor_bin, _) = fixed_file(ANCHOR_BIN, 0o755, 65536)?;
        let (anchor_unit, _) = fixed_file(ANCHOR_UNITFILE, 0o644, 65536)?;
        let (anchor_dropin, _) = fixed_file(ANCHOR_DROPIN, 0o644, 65536)?;
        ensure!(
            sha(&anchor_bin) == b.anchor_binary_sha256
                && sha(&anchor_unit) == b.anchor_unit_sha256
                && sha(&anchor_dropin) == b.anchor_dropin_sha256,
            "anchor file mismatch"
        );
        let (private_raw, _) = fixed_file(PRIVATE_NS, 0o600, 16384)?;
        let (host_raw, _) = fixed_file(HOST_NS, 0o600, 16384)?;
        let private: NamespaceObservation = serde_json::from_slice(&private_raw)?;
        let host: NamespaceObservation = serde_json::from_slice(&host_raw)?;
        ensure!(
            private.version == 1
                && private.role == "private"
                && private.uid == 0
                && private.pid == b.anchor_pid
                && private.netns_dev == b.netns_dev
                && private.netns_ino == b.netns_ino
                && host.version == 1
                && host.role == "host"
                && host.uid == 0
                && (host.netns_dev, host.netns_ino) != (private.netns_dev, private.netns_ino),
            "namespace observation mismatch"
        );
        for (key, value) in [
            ("LoadState", "loaded"),
            ("ActiveState", "active"),
            ("Names", ANCHOR_UNIT),
            ("FragmentPath", ANCHOR_UNITFILE),
            ("DropInPaths", ANCHOR_DROPIN),
            ("User", "root"),
            ("NoNewPrivileges", "yes"),
            ("PrivateNetwork", "yes"),
            ("CapabilityBoundingSet", ""),
        ] {
            ensure!(
                prop_for(&cli, ANCHOR_UNIT, key)? == value,
                "anchor manager property mismatch"
            );
        }
        ensure!(
            prop_for(&cli, ANCHOR_UNIT, "MainPID")? == b.anchor_pid.to_string()
                && start_ticks(b.anchor_pid)? == b.anchor_start_ticks,
            "anchor process changed"
        );
        let anchor_cmd = prop_for(&cli, ANCHOR_UNIT, "ExecStart")?;
        ensure!(anchor_cmd.starts_with(&format!("{{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B {ANCHOR_BIN} private ; ignore_errors=no ;"))&&anchor_cmd.matches("{ path=").count()==1,"anchor command mismatch");
        status(b.anchor_pid, "0", "0")?;
        let cg = fs::metadata(CGROUP)?;
        ensure!(
            (cg.dev(), cg.ino()) == (b.cgroup_dev, b.cgroup_ino),
            "service cgroup differs"
        );
        let membership = fs::read_to_string(format!("/proc/{}/cgroup", b.pid))?;
        ensure!(
            membership.trim() == "0::/system.slice/software-factory-goose-real-runtime.service",
            "process cgroup differs"
        );
        let sock = fs::symlink_metadata(SOCKET)?;
        ensure!(
            sock.file_type().is_socket()
                && sock.uid() == 0
                && sock.gid() == 0
                && sock.mode() & 0o7777 == 0o600
                && (sock.dev(), sock.ino()) == (b.socket_dev, b.socket_ino),
            "grant socket differs"
        );
        let path = CString::new(SOCKET)?;
        let attr = CString::new("system.posix_acl_access")?;
        // SAFETY: both C strings are terminated and a null buffer queries only size.
        let acl = unsafe { libc::lgetxattr(path.as_ptr(), attr.as_ptr(), std::ptr::null_mut(), 0) };
        ensure!(
            acl < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA),
            "socket ACL present or unavailable"
        );
        ensure!(
            start_ticks(b.pid)? == b.start_ticks
                && start_ticks(b.anchor_pid)? == b.anchor_start_ticks
                && prop_for(&cli, ANCHOR_UNIT, "MainPID")? == b.anchor_pid.to_string()
                && prop(&cli, "MainPID")? == b.pid.to_string()
                && prop(&cli, "ActiveState")? == "active",
            "service changed during verification"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_changed_uid_gid_capabilities_and_nnp() {
        let good = "Uid:\t2000\t2000\t2000\t2000\nGid:\t2000\t2000\t2000\t2000\nCapEff:\t0000000000000000\nNoNewPrivs:\t1\n";
        assert!(validate_status(good, "2000", "2000").is_ok());
        for bad in [
            good.replace("Uid:\t2000", "Uid:\t0"),
            good.replace("Gid:\t2000", "Gid:\t0"),
            good.replace("0000000000000000", "0000000000000001"),
            good.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
        ] {
            assert!(validate_status(&bad, "2000", "2000").is_err());
        }
    }
}
