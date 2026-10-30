//! Exact root-published authorization, not a replacement for root evidence validation.
//! The claim handler requires this check; the root publisher is a separate opt-in executable.
use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use std::{
    ffi::CString,
    fs::File,
    io::Read,
    os::fd::{AsRawFd, FromRawFd},
};

const LIMIT: u64 = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub schema: u8,
    pub task_id: String,
    pub generation: String,
    pub request_sha256: String,
}
impl Authorization {
    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.schema == 1
                && [self.task_id.as_str(), self.generation.as_str()]
                    .iter()
                    .all(|v| ulid::Ulid::from_string(v).is_ok_and(|id| id.to_string() == *v))
                && self.request_sha256.len() == 64
                && self
                    .request_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid authorization scope"
        );
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn no_acl(fd: i32, directory: bool) -> anyhow::Result<()> {
    let names: &[&std::ffi::CStr] = if directory {
        &[c"system.posix_acl_access", c"system.posix_acl_default"]
    } else {
        &[c"system.posix_acl_access"]
    };
    for name in names {
        // O_PATH pins searchable 0711 ancestors without requiring read access.
        let path = CString::new(format!("/proc/self/fd/{fd}"))?;
        let rc = unsafe { libc::getxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
        ensure!(
            rc < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA),
            "authorization ACL present or unavailable"
        );
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn no_acl(_: i32, _: bool) -> anyhow::Result<()> {
    anyhow::bail!("authorization requires Linux")
}

fn meta(file: &File) -> anyhow::Result<libc::stat> {
    let mut s = std::mem::MaybeUninit::<libc::stat>::uninit();
    ensure!(
        unsafe { libc::fstat(file.as_raw_fd(), s.as_mut_ptr()) } == 0,
        "authorization stat unavailable"
    );
    Ok(unsafe { s.assume_init() })
}
fn component(parent: &File, name: &str, directory: bool, traversal: bool) -> anyhow::Result<File> {
    let n = CString::new(name)?;
    #[cfg(target_os = "linux")]
    let access = if traversal {
        libc::O_PATH
    } else {
        libc::O_RDONLY
    };
    #[cfg(not(target_os = "linux"))]
    let access = {
        let _ = traversal;
        libc::O_RDONLY
    };
    let flags = access
        | libc::O_NOFOLLOW
        | libc::O_CLOEXEC
        | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 };
    let fd = unsafe { libc::openat(parent.as_raw_fd(), n.as_ptr(), flags) };
    ensure!(fd >= 0, "authorization open unavailable");
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn directory() -> anyhow::Result<File> {
    let mut parent = File::open("/")?;
    for (index, name) in [
        "etc",
        "software-factory-goose",
        "finalization-authorization",
    ]
    .iter()
    .enumerate()
    {
        let s = meta(&parent)?;
        ensure!(
            s.st_uid == 0
                && s.st_gid == 0
                && s.st_mode & libc::S_IFMT == libc::S_IFDIR
                && s.st_mode & 0o022 == 0,
            "untrusted authorization ancestor"
        );
        no_acl(parent.as_raw_fd(), true)?;
        parent = component(&parent, name, true, index < 2)?;
    }
    let s = meta(&parent)?;
    ensure!(
        s.st_uid == 0
            && s.st_gid == 0
            && s.st_mode & libc::S_IFMT == libc::S_IFDIR
            && s.st_mode & 0o7777 == 0o755,
        "authorization directory mismatch"
    );
    no_acl(parent.as_raw_fd(), true)?;
    Ok(parent)
}
fn safe_file(parent: &File, name: &str, gid: u32, mode: u32) -> anyhow::Result<File> {
    let file = component(parent, name, false, false)?;
    let s = meta(&file)?;
    ensure!(
        s.st_uid == 0
            && s.st_gid == gid
            && s.st_mode & libc::S_IFMT == libc::S_IFREG
            && s.st_mode & 0o7777 == mode as libc::mode_t
            && s.st_nlink == 1
            && s.st_size >= 0
            && s.st_size as u64 <= LIMIT,
        "authorization file metadata mismatch"
    );
    no_acl(file.as_raw_fd(), false)?;
    Ok(file)
}
fn read_record(parent: &File, name: &str) -> anyhow::Result<Authorization> {
    let mut file = safe_file(parent, name, 0, 0o444)?;
    let before = meta(&file)?;
    let mut bytes = Vec::new();
    (&mut file).take(LIMIT + 1).read_to_end(&mut bytes)?;
    let after = meta(&file)?;
    ensure!(
        bytes.len() as u64 <= LIMIT
            && bytes.len() as i64 == before.st_size
            && before.st_dev == after.st_dev
            && before.st_ino == after.st_ino
            && before.st_size == after.st_size
            && before.st_mtime == after.st_mtime
            && before.st_ctime == after.st_ctime
            && after.st_nlink == 1,
        "authorization changed during read"
    );
    let record: Authorization =
        serde_json::from_slice(&bytes).context("authorization JSON invalid")?;
    record.validate()?;
    Ok(record)
}

/// The caller must run under the provisioned SDK UID. Any busy/missing/unsafe state is
/// an error and must become a terminal handler refusal, not a retry waiting for publication.
pub fn read_authorization(expected: &Authorization) -> anyhow::Result<()> {
    expected.validate()?;
    ensure!(unsafe { libc::geteuid() } == 2000, "SDK UID mismatch");
    let parent = directory()?;
    let lock = safe_file(
        &parent,
        &format!("{}.lock", expected.generation),
        2000,
        0o440,
    )?;
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0,
        "authorization publication busy"
    );
    let pending = CString::new(format!("{}.pending", expected.generation))?;
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    let rc = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            pending.as_ptr(),
            status.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    ensure!(
        rc < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT),
        "authorization pending or unavailable"
    );
    let published = read_record(
        &parent,
        &format!("{}.authorization.json", expected.generation),
    )?;
    let completed = read_record(&parent, &format!("{}.complete.json", expected.generation))?;
    ensure!(
        &published == expected && &completed == expected,
        "authorization mismatch"
    );
    drop(lock);
    Ok(())
}

fn create_durable(
    parent: &File,
    name: &str,
    bytes: &[u8],
    after_file_sync: impl FnOnce(),
) -> anyhow::Result<()> {
    use std::io::Write;
    let name = CString::new(name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o444,
        )
    };
    ensure!(fd >= 0, "publication create unavailable");
    let mut file = unsafe { File::from_raw_fd(fd) };
    ensure!(
        unsafe { libc::fchmod(file.as_raw_fd(), 0o444) } == 0,
        "publication mode unavailable"
    );
    let s = meta(&file)?;
    ensure!(
        s.st_uid == 0 && s.st_gid == 0 && s.st_nlink == 1 && s.st_mode & 0o7777 == 0o444,
        "publication metadata mismatch"
    );
    no_acl(file.as_raw_fd(), false)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    after_file_sync();
    parent.sync_all()?;
    Ok(())
}

/// Root-only publication. The verifier executes *after* durable pending and under
/// the exclusive lock; it must independently validate immutable root evidence.
/// Any failure leaves pending in place and forbids automatic retry.
pub fn publish_root<F>(generation: &str, verify: F) -> anyhow::Result<Authorization>
where
    F: FnOnce() -> anyhow::Result<Authorization>,
{
    publish_inner(generation, verify, || {})
}

/// Test-only hook. The production feature set must not include this feature.
#[cfg(feature = "root-authorization-canary")]
pub fn publish_root_canary<F, H>(
    generation: &str,
    verify: F,
    after_auth_file_sync: H,
) -> anyhow::Result<Authorization>
where
    F: FnOnce() -> anyhow::Result<Authorization>,
    H: FnOnce(),
{
    publish_inner(generation, verify, after_auth_file_sync)
}

fn publish_inner<F, H>(
    generation: &str,
    verify: F,
    after_auth_file_sync: H,
) -> anyhow::Result<Authorization>
where
    F: FnOnce() -> anyhow::Result<Authorization>,
    H: FnOnce(),
{
    ensure!(
        unsafe { libc::geteuid() } == 0
            && ulid::Ulid::from_string(generation).is_ok_and(|id| id.to_string() == generation),
        "invalid publisher identity or generation"
    );
    let parent = directory()?;
    let lock = safe_file(&parent, &format!("{generation}.lock"), 2000, 0o440)?;
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "publication lock busy"
    );
    let pending = format!("{generation}.pending");
    create_durable(
        &parent,
        &pending,
        b"root finalization publication pending\n",
        || {},
    )?;
    let authorization = verify()?;
    authorization.validate()?;
    ensure!(
        authorization.generation == generation,
        "publication generation mismatch"
    );
    let bytes = serde_json::to_vec(&authorization)?;
    ensure!(bytes.len() as u64 <= LIMIT, "publication exceeds bound");
    create_durable(
        &parent,
        &format!("{generation}.authorization.json"),
        &bytes,
        after_auth_file_sync,
    )?;
    create_durable(
        &parent,
        &format!("{generation}.complete.json"),
        &bytes,
        || {},
    )?;
    let pending = CString::new(pending)?;
    ensure!(
        unsafe { libc::unlinkat(parent.as_raw_fd(), pending.as_ptr(), 0) } == 0,
        "pending removal unavailable"
    );
    parent.sync_all()?;
    drop(lock);
    Ok(authorization)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn valid() -> Authorization {
        Authorization {
            schema: 1,
            task_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            generation: "01ARZ3NDEKTSV4RRFFQ69G5FAW".into(),
            request_sha256: "a".repeat(64),
        }
    }
    #[test]
    fn scope_and_duplicate_fields_fail_closed() {
        let mut auth = valid();
        assert!(auth.validate().is_ok());
        auth.request_sha256 = "A".repeat(64);
        assert!(auth.validate().is_err());
        auth = valid();
        auth.generation = "../outside".into();
        assert!(auth.validate().is_err());
        assert!(
            serde_json::from_str::<Authorization>(
                r#"{"schema":1,"schema":1,"task_id":"x","generation":"y","request_sha256":"z"}"#
            )
            .is_err()
        );
    }
    #[test]
    fn outside_sdk_uid_never_reads_publication() {
        if unsafe { libc::geteuid() } != 2000 {
            assert!(read_authorization(&valid()).is_err());
        }
    }
}
