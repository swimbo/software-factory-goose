//! Disposable fixture only: a durable unresolved-run latch, not a containment boundary.
use anyhow::{Context, Result, ensure};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

#[cfg(target_os = "macos")]
fn reject_extended_acl(directory: &File) -> Result<()> {
    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut libc::c_void;
        fn acl_free(value: *mut libc::c_void) -> libc::c_int;
    }
    let acl = unsafe { acl_get_fd_np(directory.as_raw_fd(), 0x100) };
    if !acl.is_null() {
        unsafe {
            acl_free(acl);
        }
        anyhow::bail!("fixture root has an extended ACL");
    }
    ensure!(
        std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT),
        "fixture root ACL inspection failed"
    );
    Ok(())
}
#[cfg(target_os = "linux")]
fn reject_extended_acl(directory: &File) -> Result<()> {
    for name in [c"system.posix_acl_access", c"system.posix_acl_default"] {
        let n = unsafe {
            libc::fgetxattr(
                directory.as_raw_fd(),
                name.as_ptr(),
                std::ptr::null_mut(),
                0,
            )
        };
        ensure!(
            n == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA),
            "fixture root ACL is present or unavailable"
        );
    }
    Ok(())
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn reject_extended_acl(_directory: &File) -> Result<()> {
    anyhow::bail!("fixture root ACL inspection unsupported")
}

/// Permanently reserve this fixture's single run. A previous reservation blocks all
/// later runs, including after clean exit. There is deliberately no automatic clear.
/// The caller must not start any work before this function returns successfully.
pub fn arm(root: &Path) -> Result<()> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)?;
    let metadata = directory.metadata()?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o7777 == 0o700,
        "fixture root must be an owned mode-0700 directory"
    );
    reject_extended_acl(&directory)?;
    let name = c"recovery-required";
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("run is already reserved or latch cannot be safely created");
    }
    let mut marker = unsafe { File::from_raw_fd(fd) };
    marker.write_all(b"fixture-unresolved\n")?;
    marker.sync_all()?;
    directory.sync_all()?;
    Ok(())
}
