//! Linux-only, root-owned fixed evidence reader. No producer is authenticated by this module.
use anyhow::{Context, ensure};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::File,
    io::Read,
    os::fd::{AsRawFd, FromRawFd},
    path::{Component, Path},
};

const MAX_EVIDENCE: u64 = 256 * 1024;

#[cfg(target_os = "linux")]
fn check_acl(fd: i32) -> anyhow::Result<()> {
    for name in [c"system.posix_acl_access", c"system.posix_acl_default"] {
        // Reject an ACL as well as unknown/unsupported filesystem behavior.
        let n = unsafe { libc::fgetxattr(fd, name.as_ptr(), std::ptr::null_mut(), 0) };
        ensure!(
            n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA),
            "ACL unavailable or present"
        );
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn check_acl(_: i32) -> anyhow::Result<()> {
    anyhow::bail!("protected evidence requires Linux ACL checks")
}

fn stat(fd: i32) -> anyhow::Result<libc::stat> {
    let mut value = std::mem::MaybeUninit::<libc::stat>::uninit();
    ensure!(
        unsafe { libc::fstat(fd, value.as_mut_ptr()) } == 0,
        "evidence stat failed"
    );
    Ok(unsafe { value.assume_init() })
}

fn openat(parent: i32, name: &std::ffi::OsStr, directory: bool) -> anyhow::Result<File> {
    use std::os::unix::ffi::OsStrExt;
    let name = CString::new(name.as_bytes()).context("invalid evidence name")?;
    let flags = libc::O_RDONLY
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 };
    let fd = unsafe { libc::openat(parent, name.as_ptr(), flags) };
    ensure!(fd >= 0, "protected evidence open failed");
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Opens every ancestor without following symlinks; all are root-owned and non-writable
/// by group/other. The fixed final file is root-owned 0600 and single-link. The caller
/// supplies its digest from an independently validated root catalog, never request data.
pub fn read_fixed(path: &Path, expected_sha256: &str) -> anyhow::Result<Vec<u8>> {
    ensure!(
        path.is_absolute()
            && expected_sha256.len() == 64
            && expected_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid evidence scope"
    );
    let bytes = read_root_config(path)?;
    ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == expected_sha256,
        "evidence digest mismatch"
    );
    Ok(bytes)
}

/// Bootstrap only: the caller must supply a compiled-in path and treat root as trusted.
/// All data files selected by that config must still be read via `read_fixed`.
pub fn read_root_config(path: &Path) -> anyhow::Result<Vec<u8>> {
    ensure!(path.is_absolute(), "invalid configuration path");
    let components: Vec<_> = path.components().collect();
    ensure!(
        components.len() >= 2
            && components[0] == Component::RootDir
            && components[1..]
                .iter()
                .all(|v| matches!(v, Component::Normal(_))),
        "noncanonical evidence path"
    );
    let mut parent = File::open("/")?;
    for (index, part) in components[1..].iter().enumerate() {
        let s = stat(parent.as_raw_fd())?;
        ensure!(
            s.st_uid == 0 && s.st_mode & libc::S_IFMT == libc::S_IFDIR && s.st_mode & 0o022 == 0,
            "unprotected evidence ancestor"
        );
        check_acl(parent.as_raw_fd())?;
        let Component::Normal(name) = part else {
            unreachable!()
        };
        let is_dir = index + 1 < components.len() - 1;
        parent = openat(parent.as_raw_fd(), name, is_dir)?;
    }
    let before = stat(parent.as_raw_fd())?;
    ensure!(
        before.st_uid == 0
            && before.st_mode & libc::S_IFMT == libc::S_IFREG
            && before.st_mode & 0o7777 == 0o600
            && before.st_nlink == 1
            && before.st_size >= 0
            && before.st_size as u64 <= MAX_EVIDENCE,
        "unprotected evidence file"
    );
    check_acl(parent.as_raw_fd())?;
    let mut bytes = Vec::new();
    (&mut parent)
        .take(MAX_EVIDENCE + 1)
        .read_to_end(&mut bytes)?;
    let after = stat(parent.as_raw_fd())?;
    ensure!(
        bytes.len() as u64 <= MAX_EVIDENCE
            && before.st_dev == after.st_dev
            && before.st_ino == after.st_ino
            && before.st_size == after.st_size
            && before.st_mtime == after.st_mtime
            && before.st_ctime == after.st_ctime
            && after.st_nlink == 1,
        "evidence changed during read"
    );
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_relative_parent_traversal_and_invalid_digest() {
        assert!(read_fixed(Path::new("relative"), &"a".repeat(64)).is_err());
        assert!(read_fixed(Path::new("/tmp/../outside"), &"a".repeat(64)).is_err());
        assert!(read_fixed(Path::new("/tmp/evidence"), "invalid").is_err());
    }
    #[test]
    fn rejects_symlink_and_user_writable_ancestor() {
        use std::os::unix::fs::symlink;
        let path =
            std::env::temp_dir().join(format!("sfactory-evidence-test-{}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        let file = path.join("real");
        std::fs::write(&file, b"evidence").unwrap();
        let link = path.join("link");
        symlink(&file, &link).unwrap();
        let digest = format!("{:x}", Sha256::digest(b"evidence"));
        assert!(read_fixed(&file, &digest).is_err());
        assert!(read_fixed(&link, &digest).is_err());
        std::fs::remove_file(link).unwrap();
        std::fs::remove_file(file).unwrap();
        std::fs::remove_dir(path).unwrap();
    }
}
