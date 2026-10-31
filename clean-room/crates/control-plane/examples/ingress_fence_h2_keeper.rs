//! Fixed synthetic discovery connection. One HTTP/2 connection, never reconnected.
use anyhow::{Context, Result, ensure};
use http_body_util::{BodyExt, Empty, Limited};
use hyper::{Request, body::Bytes, client::conn::http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::time::Duration;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::TcpStream,
    time::timeout,
};

async fn discovery(sender: &mut http2::SendRequest<Empty<Bytes>>) -> Result<()> {
    let request = Request::get("http://127.0.0.1:9081/discover")
        .header("accept", "application/vnd.restate.endpointmanifest.v4+json")
        .body(Empty::new())?;
    let reply = timeout(Duration::from_secs(5), sender.send_request(request)).await??;
    ensure!(reply.status() == 200, "discovery status");
    let body = timeout(
        Duration::from_secs(5),
        Limited::new(reply.into_body(), 16384).collect(),
    )
    .await?
    .map_err(|_| anyhow::anyhow!("discovery body unavailable"))?;
    let v: serde_json::Value = serde_json::from_slice(&body.to_bytes())?;
    ensure!(
        v.get("services")
            .and_then(|s| s.as_array())
            .is_some_and(|s| s
                .iter()
                .any(|x| x.get("name").and_then(|n| n.as_str()) == Some("FenceFixture"))),
        "manifest unavailable"
    );
    Ok(())
}
async fn run() -> Result<()> {
    ensure!(std::env::args().count() == 1, "arguments forbidden");
    let stream = timeout(Duration::from_secs(5), TcpStream::connect("127.0.0.1:9081")).await??;
    let (mut sender, connection) =
        http2::handshake(TokioExecutor::new(), TokioIo::new(stream)).await?;
    let task = tokio::spawn(connection);
    discovery(&mut sender).await?;
    println!("initial-ok");
    let mut input = BufReader::new(tokio::io::stdin()).lines();
    ensure!(
        input.next_line().await?.as_deref() == Some("reuse"),
        "protocol"
    );
    discovery(&mut sender).await?;
    println!("reuse-ok");
    ensure!(
        input.next_line().await?.as_deref() == Some("retired"),
        "protocol"
    );
    let request = Request::get("http://127.0.0.1:9081/discover")
        .header("accept", "application/vnd.restate.endpointmanifest.v4+json")
        .body(Empty::new())?;
    let result = timeout(Duration::from_secs(5), sender.send_request(request))
        .await
        .context("retired connection outcome unknown")?;
    ensure!(result.is_err(), "retired connection still serves");
    let end = timeout(Duration::from_secs(5), task)
        .await
        .context("connection still alive")?;
    let _ = end;
    println!("retired-denied");
    Ok(())
}

fn verify_bootstrap() -> anyhow::Result<()> {
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

fn main() -> Result<()> {
    verify_bootstrap()?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run())
}
