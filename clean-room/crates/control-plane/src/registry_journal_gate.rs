//! Proposed read-only journal participant in the root registry admission gate.
//! Not active until directory modes, root participants, and old SDK draining are reviewed.
#[cfg(target_os = "linux")]
mod linux {
    use anyhow::{Result, ensure};
    use serde::Deserialize;
    use sha2::{Digest, Sha256};
    use std::{
        ffi::CString,
        fs::{File, OpenOptions},
        io::Read,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::{MetadataExt, OpenOptionsExt},
        },
    };
    const DIR: &str = "/var/lib/software-factory-goose/registry-admission";
    const REGISTRY: &str = "/etc/software-factory-goose/catalog-registry.json";
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
    fn acl_fd(fd: i32, dir: bool) -> Result<()> {
        for name in if dir {
            &["system.posix_acl_access", "system.posix_acl_default"][..]
        } else {
            &["system.posix_acl_access"][..]
        } {
            let n = CString::new(*name)?;
            let rc = if dir {
                let p = CString::new(format!("/proc/self/fd/{fd}"))?;
                unsafe { libc::getxattr(p.as_ptr(), n.as_ptr(), std::ptr::null_mut(), 0) }
            } else {
                unsafe { libc::fgetxattr(fd, n.as_ptr(), std::ptr::null_mut(), 0) }
            };
            ensure!(
                rc < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA),
                "gate ACL unavailable"
            );
        }
        Ok(())
    }
    fn digest(raw: &[u8]) -> String {
        format!("{:x}", Sha256::digest(raw))
    }
    fn hex(s: &str) -> bool {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
    fn read_file(mut f: File, uid: u32, gid: u32, mode: u32, max: u64) -> Result<Vec<u8>> {
        let m = f.metadata()?;
        ensure!(
            m.is_file()
                && m.uid() == uid
                && m.gid() == gid
                && m.nlink() == 1
                && m.mode() & 0o7777 == mode
                && m.len() > 0
                && m.len() <= max,
            "untrusted gate file"
        );
        acl_fd(f.as_raw_fd(), false)?;
        let mut b = Vec::new();
        Read::by_ref(&mut f).take(max + 1).read_to_end(&mut b)?;
        ensure!(b.len() as u64 == m.len(), "gate file changed");
        Ok(b)
    }
    fn child(dir: i32, name: &str, flags: i32) -> Result<File> {
        let n = CString::new(name)?;
        let fd =
            unsafe { libc::openat(dir, n.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        ensure!(fd >= 0, "gate entry unavailable");
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    /// Hold until the mutating handler has completed all durable writes and effects.
    pub struct JournalAdmission {
        _lock: File,
    }
    impl JournalAdmission {
        pub fn acquire() -> Result<Self> {
            ensure!(
                unsafe { libc::geteuid() } == 2000 && unsafe { libc::getegid() } == 2000,
                "control identity required"
            );
            for path in [
                "/",
                "/var",
                "/var/lib",
                "/var/lib/software-factory-goose",
                "/etc",
                "/etc/software-factory-goose",
            ] {
                let f = OpenOptions::new()
                    .read(true)
                    .custom_flags(
                        libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                    .open(path)?;
                let m = f.metadata()?;
                ensure!(
                    m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
                    "untrusted ancestor"
                );
                acl_fd(f.as_raw_fd(), true)?;
            }
            let d = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(DIR)?;
            let m = d.metadata()?;
            ensure!(
                m.is_dir() && m.uid() == 0 && m.gid() == 2000 && m.mode() & 0o7777 == 0o710,
                "untrusted gate directory"
            );
            acl_fd(d.as_raw_fd(), true)?;
            let lock = child(
                d.as_raw_fd(),
                "gate.lock",
                libc::O_RDONLY | libc::O_NONBLOCK,
            )?;
            let lm = lock.metadata()?;
            ensure!(
                lm.is_file()
                    && lm.uid() == 0
                    && lm.gid() == 2000
                    && lm.nlink() == 1
                    && lm.mode() & 0o7777 == 0o440,
                "untrusted gate lock"
            );
            acl_fd(lock.as_raw_fd(), false)?;
            ensure!(
                unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0,
                "transition busy"
            );
            let n = CString::new("transition.json")?;
            let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
            let rc = unsafe {
                libc::fstatat(
                    d.as_raw_fd(),
                    n.as_ptr(),
                    st.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            ensure!(
                rc < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound,
                "transition pending or unavailable"
            );
            let raw = read_file(
                child(
                    d.as_raw_fd(),
                    "head.json",
                    libc::O_RDONLY | libc::O_NONBLOCK,
                )?,
                0,
                2000,
                0o440,
                16384,
            )?;
            let h: Head = serde_json::from_slice(&raw)?;
            let registry = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(REGISTRY)?;
            let bytes = read_file(registry, 0, 0, 0o644, 65536)?;
            let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
            ensure!(
                h.schema == 1
                    && h.boot_id == boot.trim()
                    && h.manifest_sha256 == digest(&bytes)
                    && hex(&h.attestation_sha256)
                    && hex(&h.completion_sha256)
                    && ulid::Ulid::from_string(&h.transition_id)
                        .is_ok_and(|x| x.to_string() == h.transition_id),
                "head unavailable"
            );
            Ok(Self { _lock: lock })
        }
    }
}
#[cfg(target_os = "linux")]
pub use linux::JournalAdmission;

#[cfg(not(target_os = "linux"))]
pub struct JournalAdmission;
#[cfg(not(target_os = "linux"))]
impl JournalAdmission {
    pub fn acquire() -> anyhow::Result<Self> {
        anyhow::bail!("production registry admission requires Linux")
    }
}
/// Production registry builds always participate; unregistered non-registry fixtures
/// do not claim this deployed authority. The gate is not held by shared read handlers.
pub fn enter_production() -> anyhow::Result<Option<JournalAdmission>> {
    if cfg!(feature = "registry-sidecar") {
        JournalAdmission::acquire().map(Some)
    } else {
        Ok(None)
    }
}
