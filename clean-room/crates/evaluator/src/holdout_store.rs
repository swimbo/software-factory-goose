//! Protected local manifest reading on macOS. This is a store-owner component, not IPC.
//!
//! R1's store UID/0700 directory cannot be read directly by its distinct evaluator UID.
//! This reader must run as the configured store owner; an authenticated, private transfer
//! to the evaluator remains separate work. It creates/chmods nothing and accepts only a
//! configured canonical root plus a server-resolved expected content digest. No generator
//! request may choose the configuration or establish the authoritative expected digest.

use crate::holdout_runner::FixtureManifest;
use std::{fmt, path::PathBuf};

#[derive(Clone)]
pub struct StoreConfig {
    pub root: PathBuf,
    pub store_uid: u32,
    pub evaluator_uid: u32,
    pub generator_uid: u32,
}

/// Deliberately opaque: errors never reveal paths, manifest bodies, parse diagnostics or IDs.
#[derive(Debug, Clone, Copy)]
pub struct StoreError;
impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("protected holdout manifest unavailable")
    }
}
impl std::error::Error for StoreError {}

pub struct ProtectedHoldoutStore {
    config: StoreConfig,
    #[cfg(target_os = "macos")]
    inner: platform::Store,
}
impl ProtectedHoldoutStore {
    pub fn open(config: &StoreConfig) -> Result<Self, StoreError> {
        #[cfg(target_os = "macos")]
        {
            Ok(Self {
                config: config.clone(),
                inner: platform::Store::open(config)?,
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = config;
            Err(StoreError)
        }
    }
    pub(crate) fn config(&self) -> &StoreConfig {
        &self.config
    }
    /// Read `<sha256>.json` via the already-open protected directory. Never accept a path.
    pub fn load_digest(&self, expected_sha256: &str) -> Result<FixtureManifest, StoreError> {
        #[cfg(target_os = "macos")]
        {
            self.inner.load(expected_sha256)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = expected_sha256;
            Err(StoreError)
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use crate::holdout_runner::MAX_MANIFEST_BYTES;
    use sha2::{Digest, Sha256};
    use std::{
        ffi::CString,
        fs::{File, Metadata},
        io::Read,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, fs::MetadataExt},
        },
        path::{Component, Path},
    };

    // Signatures/constants are from the macOS SDK sys/acl.h. libc does not expose them.
    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut libc::c_void;
        fn acl_free(value: *mut libc::c_void) -> libc::c_int;
    }
    fn no_acl(file: &File) -> Result<(), StoreError> {
        // SAFETY: the descriptor is live for this call; returned ACL memory is freed exactly
        // once, and never dereferenced. An absent extended ACL returns null with ENOENT on
        // macOS; all other failures and even empty allocated ACLs are refused conservatively.
        let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), 0x100) };
        if !acl.is_null() {
            unsafe {
                acl_free(acl);
            }
            return Err(StoreError);
        }
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(())
        } else {
            Err(StoreError)
        }
    }
    fn open_at(parent: &File, name: &std::ffi::OsStr, directory: bool) -> Result<File, StoreError> {
        let name = CString::new(name.as_bytes()).map_err(|_| StoreError)?;
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK
            | if directory { libc::O_DIRECTORY } else { 0 };
        // SAFETY: parent is a live directory descriptor and name is a terminated, single
        // path component. File takes sole ownership only if openat returned a valid fd.
        let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(StoreError);
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn metadata(file: &File) -> Result<Metadata, StoreError> {
        file.metadata().map_err(|_| StoreError)
    }
    fn same_object(a: &Metadata, b: &Metadata) -> bool {
        a.dev() == b.dev() && a.ino() == b.ino()
    }
    fn same_file_state(a: &Metadata, b: &Metadata) -> bool {
        same_object(a, b)
            && a.uid() == b.uid()
            && a.gid() == b.gid()
            && a.mode() == b.mode()
            && a.nlink() == b.nlink()
            && a.size() == b.size()
            && a.mtime() == b.mtime()
            && a.mtime_nsec() == b.mtime_nsec()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
    }
    fn protected_directory(file: &File, uid: u32, exact: bool) -> Result<(), StoreError> {
        let m = metadata(file)?;
        let valid = m.is_dir()
            && if exact {
                m.uid() == uid && m.mode() & 0o7777 == 0o700
            } else {
                (m.uid() == 0 || m.uid() == uid) && m.mode() & 0o022 == 0
            };
        if !valid {
            return Err(StoreError);
        }
        no_acl(file)
    }
    fn protected_file(file: &File, uid: u32) -> Result<Metadata, StoreError> {
        let m = metadata(file)?;
        if !m.is_file()
            || m.uid() != uid
            || m.mode() & 0o7777 != 0o600
            || m.nlink() != 1
            || m.len() == 0
            || m.len() > MAX_MANIFEST_BYTES as u64
        {
            return Err(StoreError);
        }
        no_acl(file)?;
        Ok(m)
    }

    pub(super) struct Store {
        root: File,
        path: PathBuf,
        uid: u32,
    }
    impl Store {
        pub(super) fn open(config: &StoreConfig) -> Result<Self, StoreError> {
            let ids = [config.store_uid, config.evaluator_uid, config.generator_uid];
            // SAFETY: geteuid has no pointer arguments and no side effects.
            if ids.contains(&0)
                || ids.iter().collect::<std::collections::BTreeSet<_>>().len() != 3
                || unsafe { libc::geteuid() } != config.store_uid
            {
                return Err(StoreError);
            }
            if !config.root.is_absolute()
                || config.root == Path::new("/")
                || config.root.canonicalize().map_err(|_| StoreError)? != config.root
            {
                return Err(StoreError);
            }
            let mut parent = File::open("/").map_err(|_| StoreError)?;
            protected_directory(&parent, config.store_uid, false)?;
            let components: Vec<_> = config.root.components().collect();
            for (index, component) in components.iter().enumerate().skip(1) {
                let Component::Normal(name) = component else {
                    return Err(StoreError);
                };
                let directory = open_at(&parent, name, true)?;
                protected_directory(&directory, config.store_uid, index + 1 == components.len())?;
                parent = directory;
            }
            Ok(Self {
                root: parent,
                path: config.root.clone(),
                uid: config.store_uid,
            })
        }
        fn recheck_root(&self) -> Result<(), StoreError> {
            // SAFETY: geteuid has no pointer arguments or side effects. An open handle must
            // not become permission to read after changing to another effective principal.
            if unsafe { libc::geteuid() } != self.uid {
                return Err(StoreError);
            }
            protected_directory(&self.root, self.uid, true)?;
            let current = std::fs::symlink_metadata(&self.path).map_err(|_| StoreError)?;
            if !current.is_dir() || !same_object(&metadata(&self.root)?, &current) {
                return Err(StoreError);
            }
            Ok(())
        }
        pub(super) fn load(&self, expected: &str) -> Result<FixtureManifest, StoreError> {
            if expected.len() != 64
                || !expected
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(StoreError);
            }
            self.recheck_root()?;
            let name = format!("{expected}.json");
            let mut file = open_at(&self.root, std::ffi::OsStr::new(&name), false)?;
            let before = protected_file(&file, self.uid)?;
            let mut bytes = Vec::with_capacity(before.len() as usize);
            (&mut file)
                .take((MAX_MANIFEST_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| StoreError)?;
            if bytes.len() > MAX_MANIFEST_BYTES
                || !same_file_state(&before, &protected_file(&file, self.uid)?)
            {
                return Err(StoreError);
            }
            let current = open_at(&self.root, std::ffi::OsStr::new(&name), false)?;
            if !same_file_state(&before, &protected_file(&current, self.uid)?) {
                return Err(StoreError);
            }
            self.recheck_root()?;
            if format!("{:x}", Sha256::digest(&bytes)) != expected {
                return Err(StoreError);
            }
            FixtureManifest::parse_trusted(&bytes).map_err(|_| StoreError)
        }
    }
}
