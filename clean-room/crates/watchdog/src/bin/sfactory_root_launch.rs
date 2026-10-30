//! Root-only fixed launch transaction. No public socket or caller-supplied recipe.
//! The fixed helper, runtime catalogue, service attestation and deadline must be
//! reviewed and installed separately. Errors retain all durable state as unknown.
#[cfg(target_os = "linux")]
use watchdog::root_cgroup;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../root_grant.rs"]
mod root_grant;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../root_grant_deadline.rs"]
mod root_grant_deadline;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../root_launch.rs"]
mod root_launch;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../root_launch_docker.rs"]
mod root_launch_docker;
#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, Result, ensure};
    use root_grant::{VerifiedGrant, load_root_catalog, load_verified, now_ms};
    use root_launch::{LaunchAuthority, RootLaunchState};
    use root_launch_docker::BoundedCli;
    use serde::Deserialize;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{File, OpenOptions},
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        sync::Mutex,
        time::Duration,
    };
    const STATE: &str = "/var/lib/software-factory-goose/stop";
    const HELPER: &str = "/usr/local/libexec/software-factory-goose/root-launch-host.py";
    const MANIFEST: &str = "/etc/software-factory-goose/root-launch-host.json";
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Manifest {
        schema: u32,
        boot_id: String,
        helper_sha256: String,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct BindingReply {
        binding_sha256: String,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ArmedReply {
        binding_sha256: String,
        armed: bool,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct IdReply {
        id: String,
    }
    fn protected(path: &str, mode: u32, max: u64) -> Result<Vec<u8>> {
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
                && m.mode() & 0o7777 == mode
                && m.len() <= max,
            "untrusted helper file"
        );
        use std::os::fd::AsRawFd;
        let attr = std::ffi::CString::new("system.posix_acl_access")?;
        // SAFETY: live fd and NUL-terminated attribute; null buffer queries size.
        let rc = unsafe { libc::fgetxattr(f.as_raw_fd(), attr.as_ptr(), std::ptr::null_mut(), 0) };
        ensure!(
            rc < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA),
            "helper ACL present or unknown"
        );
        let mut b = Vec::new();
        Read::by_ref(&mut f).take(max + 1).read_to_end(&mut b)?;
        ensure!(b.len() as u64 == m.len(), "helper file changed");
        Ok(b)
    }
    fn helper_digest() -> Result<String> {
        use std::os::fd::AsRawFd;
        for path in [
            "/",
            "/etc",
            "/etc/software-factory-goose",
            "/usr",
            "/usr/local",
            "/usr/local/libexec",
            "/usr/local/libexec/software-factory-goose",
        ] {
            let m = std::fs::symlink_metadata(path)?;
            ensure!(
                m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
                "untrusted helper ancestor"
            );
            let d = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)?;
            for name in ["system.posix_acl_access", "system.posix_acl_default"] {
                let attr = std::ffi::CString::new(name)?;
                // SAFETY: live directory fd and terminated xattr name; null buffer queries size.
                let n = unsafe {
                    libc::fgetxattr(d.as_raw_fd(), attr.as_ptr(), std::ptr::null_mut(), 0)
                };
                ensure!(
                    n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA),
                    "helper directory ACL present or unknown"
                );
            }
        }
        let manifest: Manifest = serde_json::from_slice(&protected(MANIFEST, 0o600, 16384)?)?;
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        ensure!(
            manifest.schema == 1
                && manifest.boot_id == boot.trim()
                && manifest.helper_sha256.len() == 64
                && manifest
                    .helper_sha256
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "invalid helper manifest"
        );
        let bytes = protected(HELPER, 0o755, 1_000_000)?;
        ensure!(
            format!("{:x}", Sha256::digest(bytes)) == manifest.helper_sha256,
            "helper digest mismatch"
        );
        Ok(manifest.helper_sha256)
    }
    struct Authority {
        target: String,
        binding: String,
        helper_sha: String,
        state: File,
        cli: BoundedCli,
        id: Mutex<Option<String>>,
    }
    impl Authority {
        fn grant(&self) -> Result<VerifiedGrant> {
            ensure!(
                helper_digest()? == self.helper_sha,
                "helper identity changed"
            );
            let catalog = load_root_catalog(&self.target)?;
            let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
            let grant = load_verified(&self.state, &catalog, boot.trim(), now_ms()?)?;
            ensure!(
                grant.binding_sha256() == self.binding,
                "grant binding changed"
            );
            Ok(grant)
        }
        fn phase<T: for<'de> Deserialize<'de>>(&self, name: &str) -> Result<T> {
            ensure!(
                ["verify", "arm", "create", "verify-created", "start"].contains(&name),
                "invalid phase"
            );
            ensure!(
                helper_digest()? == self.helper_sha,
                "helper identity changed"
            );
            let output = self.cli.run_program(
                "/usr/bin/python3",
                &[
                    "-I".into(),
                    "-B".into(),
                    HELPER.into(),
                    name.into(),
                    self.target.clone(),
                ],
                Duration::from_secs(150),
            )?;
            Ok(serde_json::from_str(&output)?)
        }
        fn matched_id(&self, r: IdReply) -> Result<String> {
            ensure!(
                r.id.len() == 64
                    && r.id
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "invalid full ID"
            );
            let mut slot = self
                .id
                .lock()
                .map_err(|_| anyhow::anyhow!("identity lock poisoned"))?;
            match slot.as_ref() {
                Some(id) => ensure!(*id == r.id, "helper changed primary ID"),
                None => *slot = Some(r.id.clone()),
            }
            Ok(r.id)
        }
    }
    impl LaunchAuthority for Authority {
        fn verify_bound_reservation(&self, g: &str) -> Result<String> {
            ensure!(g == self.target, "target mismatch");
            let grant = self.grant()?;
            let reply: BindingReply = self.phase("verify")?;
            ensure!(
                reply.binding_sha256 == grant.binding_sha256(),
                "helper binding differs"
            );
            Ok(self.binding.clone())
        }
        fn arm_independent_deadline(&self, g: &str) -> Result<()> {
            ensure!(g == self.target, "target mismatch");
            let reply: ArmedReply = self.phase("arm")?;
            ensure!(
                reply.armed && reply.binding_sha256 == self.binding,
                "deadline arm unresolved"
            );
            root_grant_deadline::verify_deadline(g, &self.grant()?)
        }
        fn verify_deadline_and_reservation(&self, g: &str) -> Result<()> {
            ensure!(g == self.target, "target mismatch");
            root_grant_deadline::verify_deadline(g, &self.grant()?)
        }
        fn create_stopped(&self, g: &str) -> Result<String> {
            ensure!(g == self.target, "target mismatch");
            self.matched_id(self.phase("create")?)
        }
        fn verify_owned_stopped(&self, g: &str, id: &str) -> Result<()> {
            ensure!(g == self.target, "target mismatch");
            ensure!(
                self.matched_id(self.phase("verify-created")?)? == id,
                "created identity mismatch"
            );
            Ok(())
        }
        fn start(&self, g: &str, id: &str) -> Result<()> {
            ensure!(g == self.target, "target mismatch");
            ensure!(
                self.matched_id(self.phase("start")?)? == id,
                "started identity mismatch"
            );
            Ok(())
        }
    }
    // SAFETY: geteuid only reads current credentials.
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let mut args = std::env::args();
    let _ = args.next();
    let target = args.next().context("generation required")?;
    ensure!(args.next().is_none(), "unexpected arguments");
    let state = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(STATE)?;
    let catalog = load_root_catalog(&target)?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let grant = load_verified(&state, &catalog, boot.trim(), now_ms()?)?;
    let authority = Authority {
        target: target.clone(),
        binding: grant.binding_sha256().to_owned(),
        helper_sha: helper_digest()?,
        state: state.try_clone()?,
        cli: BoundedCli,
        id: Mutex::new(None),
    };
    let id = RootLaunchState::from_root_owned_directory(state)?.launch_once(&authority, &target)?;
    println!("{{\"generation\":\"{}\",\"id\":\"{}\"}}", target, id);
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("Linux required")
}
