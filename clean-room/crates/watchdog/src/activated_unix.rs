//! Linux systemd socket-activation validation for fixed privileged endpoints.
use anyhow::{Result, ensure};
use std::{
    fs,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{FileTypeExt, MetadataExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::Path,
};

pub fn activated_listener(path: &str, group: u32) -> Result<UnixListener> {
    ensure!(
        std::env::var("LISTEN_FDS").ok().as_deref() == Some("1"),
        "one activation socket required"
    );
    ensure!(
        std::env::var("LISTEN_PID")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            == Some(std::process::id()),
        "activation PID mismatch"
    );
    let socket = fs::symlink_metadata(path)?;
    ensure!(
        socket.file_type().is_socket()
            && socket.uid() == 0
            && socket.gid() == group
            && socket.mode() & 0o777 == 0o660,
        "untrusted socket"
    );
    for parent in Path::new(path)
        .parent()
        .into_iter()
        .flat_map(Path::ancestors)
    {
        let m = fs::symlink_metadata(parent)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "untrusted socket parent"
        );
    }
    // SAFETY: dup creates a separately owned descriptor; local_addr validates socket type.
    let fd = unsafe { libc::dup(3) };
    ensure!(fd >= 0, "activation descriptor unavailable");
    // SAFETY: successful dup returns a new owned descriptor.
    let listener = unsafe { UnixListener::from_raw_fd(fd) };
    let mut kind: libc::c_int = 0;
    let mut accepting: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: valid socket descriptor and correctly sized writable integer storage.
    ensure!(
        unsafe {
            libc::getsockopt(
                listener.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&mut kind as *mut libc::c_int).cast(),
                &mut len,
            )
        } == 0
            && kind == libc::SOCK_STREAM,
        "activation socket type mismatch"
    );
    len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: valid socket descriptor and correctly sized writable integer storage.
    ensure!(
        unsafe {
            libc::getsockopt(
                listener.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ACCEPTCONN,
                (&mut accepting as *mut libc::c_int).cast(),
                &mut len,
            )
        } == 0
            && accepting == 1,
        "activation socket not listening"
    );
    ensure!(
        listener.local_addr()?.as_pathname() == Some(Path::new(path)),
        "activation path mismatch"
    );
    listener.set_nonblocking(false)?;
    Ok(listener)
}

#[cfg(target_os = "linux")]
pub fn peer_uid(stream: &UnixStream) -> Result<u32> {
    let mut peer = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the kernel writes at most len bytes into the provided ucred storage.
    ensure!(
        unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                peer.as_mut_ptr().cast(),
                &mut len,
            )
        } == 0
            && len as usize == std::mem::size_of::<libc::ucred>(),
        "peer unavailable"
    );
    // SAFETY: getsockopt succeeded with a complete ucred.
    Ok(unsafe { peer.assume_init() }.uid)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unix_peer_credentials_are_kernel_derived() {
        let (left, _right) = UnixStream::pair().unwrap();
        // SAFETY: geteuid reads process credentials only.
        assert_eq!(peer_uid(&left).unwrap(), unsafe { libc::geteuid() });
    }
}
