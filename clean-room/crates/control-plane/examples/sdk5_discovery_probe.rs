//! Fixed, non-dumpable Linux SDK5 discovery probe.
#[cfg(target_os = "linux")]
mod linux {
    use anyhow::{Context, Result, ensure};
    use http_body_util::{BodyExt, Empty, Limited};
    use hyper::{Request, body::Bytes, client::conn::http2};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use std::time::Duration;
    use tokio::{net::TcpStream, time::timeout};
    fn verify_bootstrap() -> anyhow::Result<()> {
        ensure!(
            unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
            "dump protection unavailable"
        );
        ensure!(
            unsafe { libc::getuid() } == 2000
                && unsafe { libc::geteuid() } == 2000
                && unsafe { libc::getgid() } == 2000
                && unsafe { libc::getegid() } == 2000,
            "fixture UID/GID unavailable"
        );
        let status = std::fs::read_to_string("/proc/self/status")?;
        for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
            let line = status
                .lines()
                .find(|s| s.starts_with(&format!("{key}:")))
                .context("capabilities unavailable")?;
            ensure!(
                line.split_whitespace().nth(1) == Some("0000000000000000"),
                "capabilities not empty"
            );
        }
        ensure!(
            status
                .lines()
                .any(|s| s.split_whitespace().collect::<Vec<_>>() == ["NoNewPrivs:", "1"]),
            "no-new-privileges required"
        );
        for key in ["Uid", "Gid"] {
            let line = status
                .lines()
                .find(|line| line.starts_with(&format!("{key}:")))
                .context("identity fields unavailable")?;
            ensure!(
                line.split_whitespace().skip(1).collect::<Vec<_>>()
                    == ["2000", "2000", "2000", "2000"],
                "identity fields invalid"
            );
        }
        verify_descriptor_inventory()?;
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let stdin = std::fs::metadata("/proc/self/fd/0")?;
        let null = std::fs::metadata("/dev/null")?;
        ensure!(
            stdin.file_type().is_char_device()
                && (stdin.dev(), stdin.ino()) == (null.dev(), null.ino()),
            "stdin unavailable"
        );
        for fd in [1, 2] {
            let meta = std::fs::metadata(format!("/proc/self/fd/{fd}"))?;
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            ensure!(
                meta.file_type().is_fifo()
                    && meta.uid() == 0
                    && flags >= 0
                    && flags & libc::O_ACCMODE == libc::O_WRONLY,
                "supervisor pipe unavailable"
            );
        }
        Ok(())
    }

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
                    (0..=2).contains(&number) || number == fd,
                    "unexpected inherited descriptor"
                );
            }
            Ok(())
        })();
        let closed = unsafe { libc::closedir(dir) };
        ensure!(closed == 0, "descriptor inventory close failed");
        result
    }

    async fn run() -> Result<()> {
        let stream =
            timeout(Duration::from_secs(5), TcpStream::connect("127.0.0.1:9085")).await??;
        let (mut sender, connection) = timeout(
            Duration::from_secs(5),
            http2::handshake(TokioExecutor::new(), TokioIo::new(stream)),
        )
        .await??;
        let task = tokio::spawn(connection);
        let request = Request::get("http://127.0.0.1:9085/discover")
            .header("accept", "application/vnd.restate.endpointmanifest.v4+json")
            .body(Empty::<Bytes>::new())?;
        let reply = timeout(Duration::from_secs(5), sender.send_request(request)).await??;
        ensure!(reply.status() == 200, "discovery unavailable");
        let body = timeout(
            Duration::from_secs(5),
            Limited::new(reply.into_body(), 65536).collect(),
        )
        .await?
        .map_err(|_| anyhow::anyhow!("discovery body unavailable"))?;
        #[derive(serde::Deserialize)]
        struct Manifest {
            services: Vec<Service>,
        }
        #[derive(serde::Deserialize)]
        struct Service {
            name: String,
        }
        let manifest: Manifest = serde_json::from_slice(&body.to_bytes())?;
        let mut names: Vec<&str> = manifest
            .services
            .iter()
            .map(|item| item.name.as_str())
            .collect();
        names.sort_unstable();
        ensure!(
            names
                == [
                    "ClaimLeaseJournal",
                    "IntakeJournal",
                    "RuntimeIntakeJournal",
                    "WorkerQueueJournal"
                ],
            "service scope unavailable"
        );
        drop(sender);
        task.abort();
        println!("sdk5-discovery-verified");
        Ok(())
    }
    pub fn main() -> Result<()> {
        verify_bootstrap()?;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(run())
    }
}
#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    linux::main()
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("Linux required");
    std::process::exit(1);
}
