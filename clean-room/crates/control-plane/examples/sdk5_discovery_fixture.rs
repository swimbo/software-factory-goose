//! Disposable fixed HTTP/2 discovery endpoint; no journal or production data.
#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    use http_body_util::Full;
    use hyper::{body::Bytes, server::conn::http2, service::service_fn, Response};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use std::convert::Infallible;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:9085").await?;
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let service = service_fn(|request: hyper::Request<hyper::body::Incoming>| async move {
                let (status, body) = if request.method() == hyper::Method::GET && request.uri().path() == "/discover" {
                    (200, r#"{"services":[{"name":"ClaimLeaseJournal"},{"name":"IntakeJournal"},{"name":"RuntimeIntakeJournal"},{"name":"WorkerQueueJournal"}]}"#)
                } else { (404, "") };
                Ok::<_, Infallible>(Response::builder().status(status).body(Full::new(Bytes::from_static(body.as_bytes()))).unwrap())
            });
            let _ = http2::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(stream), service).await;
        });
    }
}
#[cfg(not(target_os = "linux"))]
fn main() { eprintln!("Linux required"); }
