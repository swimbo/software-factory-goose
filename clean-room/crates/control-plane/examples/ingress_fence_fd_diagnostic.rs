//! Synthetic Tokio pre-bind descriptor inventory; emits only classes and counts.
#[cfg(all(target_os = "linux", feature = "restate"))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use anyhow::{Context as _, ensure};
    use std::{collections::BTreeMap, os::unix::ffi::OsStrExt};
    ensure!(
        unsafe { libc::geteuid() } == 2000 && unsafe { libc::getegid() } == 2000,
        "fixture identity unavailable"
    );
    let status = std::fs::read_to_string("/proc/self/status")?;
    for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        let line = status
            .lines()
            .find(|v| v.starts_with(&format!("{key}:")))
            .context("capabilities unavailable")?;
        ensure!(
            line.split_whitespace().nth(1) == Some("0000000000000000"),
            "capabilities unavailable"
        );
    }
    ensure!(
        status
            .lines()
            .any(|v| v.split_whitespace().collect::<Vec<_>>() == ["NoNewPrivs:", "1"]),
        "NNP unavailable"
    );
    let paths: Vec<_> = std::fs::read_dir("/proc/self/fd")?
        .map(|v| v.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    let mut counts = BTreeMap::<&str, u32>::new();
    for path in paths {
        let fd: i32 = path
            .file_name()
            .context("fd unavailable")?
            .to_string_lossy()
            .parse()?;
        if fd <= 2 {
            continue;
        }
        let target = match std::fs::read_link(&path) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        let bytes = target.as_os_str().as_bytes();
        let class = if bytes == b"anon_inode:[eventpoll]" {
            "eventpoll"
        } else if bytes == b"anon_inode:[eventfd]" {
            "eventfd"
        } else if bytes.starts_with(b"socket:[") {
            let mut domain: libc::c_int = 0;
            let mut len = std::mem::size_of_val(&domain) as libc::socklen_t;
            ensure!(
                unsafe {
                    libc::getsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_DOMAIN,
                        (&mut domain as *mut libc::c_int).cast(),
                        &mut len,
                    )
                } == 0,
                "socket type unavailable"
            );
            match domain {
                libc::AF_UNIX => "socket_unix",
                libc::AF_INET => "socket_ipv4",
                libc::AF_INET6 => "socket_ipv6",
                _ => "socket_other",
            }
        } else {
            "other"
        };
        *counts.entry(class).or_default() += 1;
    }
    println!("{}", serde_json::to_string(&counts)?);
    Ok(())
}
#[cfg(not(all(target_os = "linux", feature = "restate")))]
fn main() {
    eprintln!("Linux synthetic fixture only");
    std::process::exit(1);
}
