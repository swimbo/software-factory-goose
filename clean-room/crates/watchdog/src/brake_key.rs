//! Linux brake-key reader. Fixed production identity and root-protected path.
//! Never emits key bytes or copies them into the environment or command line.
use anyhow::{Context, Result, ensure};
use std::{
    ffi::{CString, OsStr},
    fs::File,
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
};

fn has_acl(fd: i32) -> Result<bool> {
    // O_PATH allows traversal of an execute-only 0711 directory. This path
    // resolves the already pinned descriptor, not a caller-controlled pathname.
    let path = CString::new(format!("/proc/self/fd/{fd}"))?;
    let ret = unsafe {
        libc::getxattr(
            path.as_ptr(),
            c"system.posix_acl_access".as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    if ret >= 0 {
        return Ok(true);
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ENODATA) | Some(libc::EOPNOTSUPP) => Ok(false),
        _ => anyhow::bail!("unable to verify credential ACL"),
    }
}
fn open_child(dir: &File, name: &OsStr, directory: bool) -> Result<File> {
    let name = CString::new(name.as_bytes())?;
    let flags = libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | if directory {
            libc::O_PATH | libc::O_DIRECTORY
        } else {
            libc::O_RDONLY | libc::O_NONBLOCK
        };
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
    ensure!(fd >= 0, "unable to open protected credential path");
    Ok(unsafe { File::from_raw_fd(fd) })
}
/// The key must be root-owned, group-readable only by the separate brake UID,
/// single-link regular file, exactly 32 bytes, and have no extended ACL.
pub fn read_brake_key(path: &Path, brake_gid: u32) -> Result<[u8; 32]> {
    ensure!(
        path.is_absolute() && brake_gid > 0,
        "invalid credential configuration"
    );
    let parent = path.parent().context("credential parent missing")?;
    let mut dir = File::open("/")?;
    let root = dir.metadata()?;
    ensure!(
        root.uid() == 0 && root.mode() & 0o022 == 0 && !has_acl(dir.as_raw_fd())?,
        "untrusted credential parent"
    );
    for part in parent.components() {
        match part {
            Component::RootDir => (),
            Component::Normal(name) => {
                dir = open_child(&dir, name, true)?;
                let meta = dir.metadata()?;
                ensure!(
                    meta.is_dir()
                        && meta.uid() == 0
                        && meta.mode() & 0o022 == 0
                        && !has_acl(dir.as_raw_fd())?,
                    "untrusted credential parent"
                );
            }
            _ => anyhow::bail!("invalid credential path"),
        }
    }
    let mut file = open_child(
        &dir,
        path.file_name().context("credential name missing")?,
        false,
    )?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.uid() == 0
            && meta.gid() == brake_gid
            && meta.nlink() == 1
            && meta.mode() & 0o7777 == 0o440
            && meta.size() == 32
            && !has_acl(file.as_raw_fd())?,
        "untrusted brake credential"
    );
    let mut raw = [0u8; 33];
    let mut count = 0;
    while count < raw.len() {
        let n = file.read(&mut raw[count..])?;
        if n == 0 {
            break;
        }
        count += n;
    }
    ensure!(
        count == 32 && raw[..32].iter().any(|b| *b != 0),
        "invalid brake credential"
    );
    let mut key = [0u8; 32];
    key.copy_from_slice(&raw[..32]);
    raw.fill(0);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    #[test]
    fn execute_only_directory_can_be_pinned_and_acl_checked() {
        let path = std::env::temp_dir().join(format!("sf-brake-key-test-{}", ulid::Ulid::new()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o111)).unwrap();
        let parent = File::open(path.parent().unwrap()).unwrap();
        let fd = open_child(&parent, path.file_name().unwrap(), true).unwrap();
        assert!(!has_acl(fd.as_raw_fd()).unwrap());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir(path).unwrap();
    }
    #[test]
    fn refuses_key_beneath_world_writable_parent() {
        let path = std::env::temp_dir().join(format!("sf-brake-key-test-{}", ulid::Ulid::new()));
        fs::write(&path, [1u8; 32]).unwrap();
        assert!(read_brake_key(&path, 2003).is_err());
        fs::remove_file(path).unwrap();
    }
}
