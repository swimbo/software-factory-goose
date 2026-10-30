//! Internal launch transaction. No network endpoint or production authorizer is provided.
//! A root-owned caller must authenticate the journal reservation, fixed catalogue, deadline
//! and recipe before implementing these traits; this module cannot establish those facts.
use anyhow::{Result, bail, ensure};
use std::{
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
};

/// The generation is the only caller-selected value. All other identity and recipe
/// checks belong to a trusted root verifier, not to the control peer.
pub trait LaunchAuthority {
    fn verify_bound_reservation(&self, generation: &str) -> Result<String>;
    /// Must durably arm an independently supervised stop before any engine effect.
    fn arm_independent_deadline(&self, generation: &str) -> Result<()>;
    fn verify_deadline_and_reservation(&self, generation: &str) -> Result<()>;
    /// Fixed, catalogue-derived operation only. Error means effect may have happened.
    fn create_stopped(&self, generation: &str) -> Result<String>;
    fn verify_owned_stopped(&self, generation: &str, id: &str) -> Result<()>;
    /// Fixed full-ID operation only. Error means effect may have happened.
    fn start(&self, generation: &str, id: &str) -> Result<()>;
}

/// Anchored root-only state directory. Existing state is never replaced or cleared.
pub struct RootLaunchState {
    dir: File,
    owner: u32,
    group: u32,
}
impl RootLaunchState {
    pub fn from_root_owned_directory(dir: File) -> Result<Self> {
        let m = dir.metadata()?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
            "untrusted launch state directory"
        );
        Ok(Self {
            dir,
            owner: 0,
            group: 0,
        })
    }
    fn name(g: &str, suffix: &str) -> Result<CString> {
        ensure!(
            ulid::Ulid::from_string(g).is_ok_and(|u| u.to_string() == g),
            "noncanonical generation"
        );
        Ok(CString::new(format!("{g}.{suffix}"))?)
    }
    fn open(&self, name: &CString, flags: i32, mode: libc::mode_t) -> Result<File> {
        // SAFETY: name is a valid C string and the trusted directory descriptor is live.
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                mode as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: openat returned a new owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn write_once(&self, g: &str, suffix: &str, bytes: &[u8]) -> Result<()> {
        let mut f = self.open(
            &Self::name(g, suffix)?,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        let m = f.metadata()?;
        ensure!(
            m.is_file()
                && m.uid() == self.owner
                && m.gid() == self.group
                && m.nlink() == 1
                && m.mode() & 0o7777 == 0o600,
            "bad new record"
        );
        f.write_all(bytes)?;
        f.sync_all()?;
        self.dir.sync_all()?;
        Ok(())
    }
    fn closed(&self, g: &str) -> Result<bool> {
        let n = Self::name(g, "closed")?;
        match self.open(&n, libc::O_RDONLY, 0) {
            Ok(mut f) => {
                let m = f.metadata()?;
                ensure!(
                    m.is_file()
                        && m.uid() == self.owner
                        && m.gid() == self.group
                        && m.nlink() == 1
                        && m.mode() & 0o777 == 0o600,
                    "bad closure"
                );
                let mut b = Vec::new();
                Read::by_ref(&mut f).take(128).read_to_end(&mut b)?;
                ensure!(b == format!("{g}\n").as_bytes(), "bad closure content");
                Ok(true)
            }
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }
    fn launch_lock(&self, g: &str) -> Result<File> {
        let f = self.open(&Self::name(g, "lock")?, libc::O_RDWR | libc::O_CREAT, 0o600)?;
        let m = f.metadata()?;
        ensure!(
            m.is_file()
                && m.uid() == self.owner
                && m.gid() == self.group
                && m.nlink() == 1
                && m.mode() & 0o777 == 0o600,
            "bad launch lock"
        );
        // SAFETY: f is a live owned descriptor. Never block the stop lock.
        ensure!(
            unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "launch busy"
        );
        Ok(f)
    }
    fn admit(&self, authority: &impl LaunchAuthority, g: &str, binding: &str) -> Result<()> {
        ensure!(!self.closed(g)?, "generation closed");
        ensure!(
            authority.verify_bound_reservation(g)? == binding,
            "grant binding changed"
        );
        authority.verify_deadline_and_reservation(g)?;
        ensure!(!self.closed(g)?, "generation closed");
        Ok(())
    }
    /// One attempt only. Any failure leaves durable state for root recovery; this
    /// method never retries an ambiguous effect and never clears a stop closure.
    pub fn launch_once(&self, authority: &impl LaunchAuthority, g: &str) -> Result<String> {
        Self::name(g, "lock")?;
        let binding = authority.verify_bound_reservation(g)?;
        ensure!(
            binding.len() == 64
                && binding
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "invalid grant digest"
        );
        let _lock = self.launch_lock(g)?;
        ensure!(!self.closed(g)?, "generation closed");
        ensure!(
            authority.verify_bound_reservation(g)? == binding,
            "grant binding changed"
        );
        authority.arm_independent_deadline(g)?;
        self.admit(authority, g, &binding)?;
        // Consumption is permanent even if the following fsync or process fails.
        self.write_once(g, "launch-consumed", format!("{g}\n{binding}\n").as_bytes())?;
        self.admit(authority, g, &binding)?;
        self.write_once(g, "create-intent", format!("{g}\n{binding}\n").as_bytes())?;
        self.admit(authority, g, &binding)?;
        let id = authority.create_stopped(g)?;
        if self.closed(g)? {
            bail!("closed after create; effect unresolved");
        }
        ensure!(
            id.len() == 64
                && id
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "invalid engine id"
        );
        authority.verify_owned_stopped(g, &id)?;
        self.admit(authority, g, &binding)?;
        self.write_once(
            g,
            "launch-seal",
            format!("{g}\n{binding}\n{id}\n").as_bytes(),
        )?;
        self.admit(authority, g, &binding)?;
        self.write_once(
            g,
            "start-intent",
            format!("{g}\n{binding}\n{id}\n").as_bytes(),
        )?;
        self.admit(authority, g, &binding)?;
        authority.start(g, &id)?;
        self.admit(authority, g, &binding)?;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::Cell,
        fs::{self, OpenOptions},
        os::unix::fs::{DirBuilderExt, OpenOptionsExt},
        path::PathBuf,
    };
    struct Fixture {
        dir: PathBuf,
        fail_create: bool,
        close_create: bool,
        close_start: bool,
        fail_start: bool,
        denied: bool,
        creates: Cell<u32>,
        starts: Cell<u32>,
    }
    impl LaunchAuthority for Fixture {
        fn verify_bound_reservation(&self, _: &str) -> Result<String> {
            ensure!(!self.denied, "denied");
            Ok("b".repeat(64))
        }
        fn arm_independent_deadline(&self, _: &str) -> Result<()> {
            Ok(())
        }
        fn verify_deadline_and_reservation(&self, _: &str) -> Result<()> {
            Ok(())
        }
        fn create_stopped(&self, g: &str) -> Result<String> {
            self.creates.set(self.creates.get() + 1);
            if self.close_create {
                let mut f = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(self.dir.join(format!("{g}.closed")))?;
                writeln!(f, "{g}")?;
                f.sync_all()?;
            }
            ensure!(!self.fail_create, "unknown create");
            Ok("a".repeat(64))
        }
        fn verify_owned_stopped(&self, _: &str, _: &str) -> Result<()> {
            Ok(())
        }
        fn start(&self, g: &str, _: &str) -> Result<()> {
            ensure!(
                self.dir.join(format!("{g}.launch-seal")).exists(),
                "start before seal"
            );
            self.starts.set(self.starts.get() + 1);
            if self.close_start {
                let mut f = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(self.dir.join(format!("{g}.closed")))?;
                writeln!(f, "{g}")?;
                f.sync_all()?;
            }
            ensure!(!self.fail_start, "unknown start");
            Ok(())
        }
    }
    fn fixture() -> (RootLaunchState, Fixture, String) {
        let id = ulid::Ulid::new().to_string();
        let dir = std::env::temp_dir().join(format!("sfactory-launch-test-{id}"));
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let f = File::open(&dir).unwrap();
        let m = f.metadata().unwrap();
        (
            RootLaunchState {
                dir: f,
                owner: m.uid(),
                group: m.gid(),
            },
            Fixture {
                dir,
                fail_create: false,
                close_create: false,
                close_start: false,
                fail_start: false,
                denied: false,
                creates: Cell::new(0),
                starts: Cell::new(0),
            },
            id,
        )
    }
    #[test]
    fn names_only_accept_canonical_generation_ids() {
        let g = ulid::Ulid::new().to_string();
        assert!(RootLaunchState::name(&g, "lock").is_ok());
        assert!(RootLaunchState::name(&g.to_lowercase(), "lock").is_err());
        assert!(RootLaunchState::name("../../other", "lock").is_err());
    }
    #[test]
    fn constructor_refuses_nonprivate_directory() {
        use std::os::unix::fs::PermissionsExt;
        let (_, a, _) = fixture();
        fs::set_permissions(&a.dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(RootLaunchState::from_root_owned_directory(File::open(&a.dir).unwrap()).is_err());
        fs::remove_dir_all(&a.dir).unwrap();
    }
    #[test]
    fn denied_reservation_creates_no_files() {
        let (s, mut a, g) = fixture();
        a.denied = true;
        assert!(s.launch_once(&a, &g).is_err());
        assert_eq!(fs::read_dir(&a.dir).unwrap().count(), 0);
        fs::remove_dir_all(&a.dir).unwrap();
    }
    #[test]
    fn ambiguous_create_is_consumed_and_never_retried() {
        let (s, mut a, g) = fixture();
        a.fail_create = true;
        assert!(s.launch_once(&a, &g).is_err());
        assert!(a.dir.join(format!("{g}.create-intent")).exists());
        a.fail_create = false;
        assert!(s.launch_once(&a, &g).is_err());
        assert_eq!(a.creates.get(), 1);
        assert_eq!(a.starts.get(), 0);
        fs::remove_dir_all(&a.dir).unwrap();
    }
    #[test]
    fn closure_during_create_prevents_seal_and_start() {
        let (s, mut a, g) = fixture();
        a.close_create = true;
        assert!(s.launch_once(&a, &g).is_err());
        assert!(!a.dir.join(format!("{g}.launch-seal")).exists());
        assert_eq!(a.creates.get(), 1);
        assert_eq!(a.starts.get(), 0);
        fs::remove_dir_all(&a.dir).unwrap();
    }
    #[test]
    fn positive_seals_before_start_and_replay_fails() {
        let (s, a, g) = fixture();
        assert_eq!(s.launch_once(&a, &g).unwrap(), "a".repeat(64));
        assert!(a.dir.join(format!("{g}.launch-seal")).exists());
        assert!(s.launch_once(&a, &g).is_err());
        assert_eq!(a.creates.get(), 1);
        assert_eq!(a.starts.get(), 1);
        fs::remove_dir_all(&a.dir).unwrap();
    }
    #[test]
    fn unknown_start_never_retries() {
        let (s, mut a, g) = fixture();
        a.fail_start = true;
        assert!(s.launch_once(&a, &g).is_err());
        assert!(a.dir.join(format!("{g}.start-intent")).exists());
        a.fail_start = false;
        assert!(s.launch_once(&a, &g).is_err());
        assert_eq!(a.creates.get(), 1);
        assert_eq!(a.starts.get(), 1);
        fs::remove_dir_all(&a.dir).unwrap();
    }
    #[test]
    fn closure_during_start_refuses_success_and_replay() {
        let (s, mut a, g) = fixture();
        a.close_start = true;
        assert!(s.launch_once(&a, &g).is_err());
        assert!(s.launch_once(&a, &g).is_err());
        assert_eq!(a.creates.get(), 1);
        assert_eq!(a.starts.get(), 1);
        fs::remove_dir_all(&a.dir).unwrap();
    }
}
