//! Linux SDK5 inherited-descriptor boundary, before any async runtime exists.
#[cfg(target_os = "linux")]
pub fn verify() -> anyhow::Result<()> {
    verify_with_paths([
        "/run/software-factory-goose/registry-v5-intake.sock",
        "/run/software-factory-goose/registry-v5-worker.sock",
        "/run/software-factory-goose/registry-v5-launch-grant.sock",
    ])
}

#[cfg(all(target_os = "linux", feature = "sdk5-guard-canary"))]
pub fn verify_canary() -> anyhow::Result<()> {
    verify_with_paths([
        "/run/software-factory-goose/sdk5-guard-canary-intake.sock",
        "/run/software-factory-goose/sdk5-guard-canary-worker.sock",
        "/run/software-factory-goose/sdk5-guard-canary-launch.sock",
    ])
}

#[cfg(target_os = "linux")]
fn verify_with_paths(paths: [&str; 3]) -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use std::{
        collections::BTreeMap,
        os::unix::fs::{FileTypeExt, MetadataExt},
        path::Path,
    };
    // SAFETY: this process changes only its own dumpability, before descriptor inspection.
    ensure!(
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
        "dump protection unavailable"
    );
    ensure!(
        unsafe { libc::getuid() } == 2000
            && unsafe { libc::geteuid() } == 2000
            && unsafe { libc::getgid() } == 2000
            && unsafe { libc::getegid() } == 2000,
        "SDK5 identity unavailable"
    );
    let status = std::fs::read_to_string("/proc/self/status")?;
    for key in ["Uid", "Gid"] {
        let line = status
            .lines()
            .find(|line| line.starts_with(&format!("{key}:")))
            .context("identity fields unavailable")?;
        ensure!(
            line.split_whitespace().skip(1).collect::<Vec<_>>() == ["2000", "2000", "2000", "2000"],
            "identity fields invalid"
        );
    }
    for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        let line = status
            .lines()
            .find(|line| line.starts_with(&format!("{key}:")))
            .context("capabilities unavailable")?;
        ensure!(
            line.split_whitespace().nth(1) == Some("0000000000000000"),
            "capabilities not empty"
        );
    }
    ensure!(
        status
            .lines()
            .any(|line| line.split_whitespace().collect::<Vec<_>>() == ["NoNewPrivs:", "1"]),
        "no-new-privileges required"
    );
    ensure!(
        std::env::var("LISTEN_PID")?.parse::<u32>()? == std::process::id()
            && std::env::var("LISTEN_FDS")? == "3",
        "activation scope invalid"
    );
    let names = std::env::var("LISTEN_FDNAMES")?;
    let mut fds = BTreeMap::new();
    for (i, name) in names.split(':').enumerate() {
        ensure!(
            fds.insert(name, 3 + i as i32).is_none(),
            "duplicate activation name"
        );
    }
    ensure!(
        fds.len() == 3
            && fds.keys().copied().collect::<Vec<_>>() == ["intake", "launch-grant", "worker"],
        "activation names invalid"
    );
    verify_descriptor_inventory()?;
    let stdin = std::fs::metadata("/proc/self/fd/0")?;
    let null = std::fs::metadata("/dev/null")?;
    ensure!(
        stdin.file_type().is_char_device()
            && (stdin.dev(), stdin.ino()) == (null.dev(), null.ino()),
        "stdin is not dev null"
    );
    let flags = unsafe { libc::fcntl(0, libc::F_GETFL) };
    ensure!(
        flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
        "stdin access invalid"
    );
    for fd in [1, 2] {
        socket_stream(fd)?;
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of_val(&cred) as libc::socklen_t;
        ensure!(
            unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    &mut cred as *mut _ as *mut _,
                    &mut len,
                )
            } == 0
                && len as usize == std::mem::size_of_val(&cred)
                && cred.uid == 0
                && cred.pid > 0,
            "journal peer unavailable"
        );
    }
    for (name, path) in [
        ("intake", paths[0]),
        ("worker", paths[1]),
        ("launch-grant", paths[2]),
    ] {
        let fd = *fds.get(name).context("activation descriptor missing")?;
        socket_stream(fd)?;
        ensure!(
            unix_address(fd, false)? == path.as_bytes(),
            "activation address mismatch"
        );
        let mut accept = 0_i32;
        let mut len = std::mem::size_of_val(&accept) as libc::socklen_t;
        ensure!(
            unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_ACCEPTCONN,
                    &mut accept as *mut _ as *mut _,
                    &mut len,
                )
            } == 0
                && accept == 1,
            "activation listener unavailable"
        );
        ensure!(
            std::fs::symlink_metadata(Path::new(path))?
                .file_type()
                .is_socket(),
            "activation path unavailable"
        );
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn verify_descriptor_inventory() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use std::ffi::CStr;
    // SAFETY: the fixed path is NUL terminated and open has no variadic mode argument.
    let fd = unsafe {
        libc::open(
            c"/proc/self/fd".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    ensure!(fd >= 0, "descriptor inventory unavailable");
    let dir = unsafe { libc::fdopendir(fd) };
    if dir.is_null() {
        unsafe {
            libc::close(fd);
        }
        anyhow::bail!("descriptor inventory unavailable");
    }
    let result = (|| -> anyhow::Result<()> {
        let mut count = 0;
        loop {
            unsafe {
                *libc::__errno_location() = 0;
            }
            let entry = unsafe { libc::readdir(dir) };
            if entry.is_null() {
                ensure!(
                    std::io::Error::last_os_error().raw_os_error() == Some(0),
                    "descriptor enumeration failed"
                );
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_str()?;
            if name == "." || name == ".." {
                continue;
            }
            count += 1;
            ensure!(count <= 256, "descriptor inventory oversized");
            let number: i32 = name.parse().context("descriptor name invalid")?;
            ensure!(
                (0..=5).contains(&number) || number == fd,
                "unexpected inherited descriptor"
            );
        }
        Ok(())
    })();
    let closed = unsafe { libc::closedir(dir) };
    ensure!(closed == 0, "descriptor inventory close failed");
    result
}
#[cfg(target_os = "linux")]
fn socket_stream(fd: i32) -> anyhow::Result<()> {
    let mut kind = 0_i32;
    let mut len = std::mem::size_of_val(&kind) as libc::socklen_t;
    anyhow::ensure!(
        unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                &mut kind as *mut _ as *mut _,
                &mut len,
            )
        } == 0
            && kind == libc::SOCK_STREAM,
        "stream socket unavailable"
    );
    let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of_val(&addr) as libc::socklen_t;
    anyhow::ensure!(
        unsafe { libc::getsockname(fd, &mut addr as *mut _ as *mut _, &mut size) } == 0
            && addr.ss_family == libc::AF_UNIX as libc::sa_family_t,
        "Unix socket unavailable"
    );
    Ok(())
}
#[cfg(target_os = "linux")]
fn unix_address(fd: i32, peer: bool) -> anyhow::Result<Vec<u8>> {
    use anyhow::ensure;
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&addr) as libc::socklen_t;
    let result = unsafe {
        if peer {
            libc::getpeername(fd, &mut addr as *mut _ as *mut _, &mut len)
        } else {
            libc::getsockname(fd, &mut addr as *mut _ as *mut _, &mut len)
        }
    };
    ensure!(
        result == 0 && addr.sun_family == libc::AF_UNIX as libc::sa_family_t,
        "Unix descriptor unavailable"
    );
    let start = std::mem::offset_of!(libc::sockaddr_un, sun_path);
    let count = (len as usize)
        .saturating_sub(start)
        .min(addr.sun_path.len());
    let bytes: Vec<u8> = addr.sun_path[..count]
        .iter()
        .map(|x| *x as u8)
        .take_while(|x| *x != 0)
        .collect();
    ensure!(!bytes.is_empty(), "Unix address unavailable");
    Ok(bytes)
}
