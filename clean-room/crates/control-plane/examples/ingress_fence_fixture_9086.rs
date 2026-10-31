//! Synthetic ingress-fence canary. Never use with a real Restate data directory.
#[cfg(feature = "restate")]
mod fixture {
    use anyhow::{Context as _, ensure};
    use restate_sdk::prelude::*;
    use serde::Serialize;
    use std::{net::SocketAddr, time::Duration};

    #[derive(Serialize)]
    struct StateView {
        version: &'static str,
        count: u64,
    }
    struct FenceFixture {
        version: &'static str,
    }
    #[restate_sdk::object]
    impl FenceFixture {
        #[handler]
        async fn increment(&self, ctx: ObjectContext<'_>) -> HandlerResult<Json<StateView>> {
            let count = ctx.get::<Json<u64>>("count").await?.map_or(0, |v| v.0);
            let next = count
                .checked_add(1)
                .ok_or_else(|| TerminalError::new_with_code(409, "counter overflow"))?;
            ctx.set("count", Json(next));
            Ok(Json(StateView {
                version: self.version,
                count: next,
            }))
        }
        #[handler]
        async fn hold(&self, ctx: ObjectContext<'_>) -> HandlerResult<Json<StateView>> {
            ctx.sleep(Duration::from_secs(3600)).await?;
            let count = ctx.get::<Json<u64>>("count").await?.map_or(0, |v| v.0);
            let next = count
                .checked_add(1)
                .ok_or_else(|| TerminalError::new_with_code(409, "counter overflow"))?;
            ctx.set("count", Json(next));
            Ok(Json(StateView {
                version: self.version,
                count: next,
            }))
        }
        #[handler]
        async fn schedule(&self, ctx: ObjectContext<'_>) -> HandlerResult<Json<bool>> {
            ctx.object_client::<FenceFixtureClient>("delayed")
                .increment()
                .send_after(Duration::from_secs(3600))
                .await?;
            Ok(Json(true))
        }
        #[handler]
        async fn inspect(&self, ctx: SharedObjectContext<'_>) -> HandlerResult<Json<StateView>> {
            let count = ctx.get::<Json<u64>>("count").await?.map_or(0, |v| v.0);
            Ok(Json(StateView {
                version: self.version,
                count,
            }))
        }
    }
    pub fn verify_bootstrap() -> anyhow::Result<()> {
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
        // Run before constructing Tokio: no inherited descriptor beyond stdio is allowed.
        let paths: Vec<_> = std::fs::read_dir("/proc/self/fd")?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<_, _>>()?;
        for path in paths {
            let fd: u32 = path
                .file_name()
                .context("fd name unavailable")?
                .to_string_lossy()
                .parse()?;
            if fd <= 2 {
                let metadata = std::fs::metadata(&path)?;
                use std::os::unix::fs::FileTypeExt;
                ensure!(
                    !metadata.file_type().is_socket(),
                    "socket on stdio forbidden"
                );
                continue;
            }
            match std::fs::read_link(&path) {
                Ok(_) => anyhow::bail!("unexpected inherited descriptor"),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
    pub async fn run() -> anyhow::Result<()> {
        let args: Vec<_> = std::env::args().collect();
        let (version, port) = match args.as_slice() {
            [_, mode] if mode == "new" => ("new", 9086),
            _ => anyhow::bail!("fixed fixture mode required"),
        };
        let address: SocketAddr = ([127, 0, 0, 1], port).into();
        let endpoint = Endpoint::builder().bind(FenceFixture { version }).build();
        HttpServer::new(endpoint).listen_and_serve(address).await;
        Ok(())
    }
}
#[cfg(feature = "restate")]
fn main() -> anyhow::Result<()> {
    fixture::verify_bootstrap()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(fixture::run())
}
#[cfg(not(feature = "restate"))]
fn main() {
    eprintln!("synthetic fixture requires restate feature");
    std::process::exit(1);
}
