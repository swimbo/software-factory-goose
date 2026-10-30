//! Root stop-only authority, started exclusively by its fixed systemd socket.
#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use anyhow::{Result, ensure};
    use std::{
        io::{Read, Write},
        net::Shutdown,
        os::unix::net::UnixStream,
        time::Duration,
    };
    use watchdog::{
        activated_unix::{activated_listener, peer_uid},
        root_cgroup::{StopBackend, linux::KernelStop, stop_kernel},
        stop_wire::{RootOperation, RootStopReply, RootStopRequest},
    };
    const PATH: &str = "/run/software-factory-goose/root-stop.sock";
    // SAFETY: geteuid only reads process credentials.
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let listener = activated_listener(PATH, 2003)?;
    fn process(mut stream: UnixStream) -> Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        ensure!(peer_uid(&stream)? == 2003, "unauthorized peer");
        let mut body = Vec::new();
        (&mut stream).take(1025).read_to_end(&mut body)?;
        ensure!(body.len() <= 1024, "request too large");
        let request: RootStopRequest = serde_json::from_slice(&body)?;
        let reply = match request.operation {
            RootOperation::Stop => match KernelStop::open(&request.target) {
                Ok(target) => match (|| {
                    target.close_admission()?;
                    target.record_observation(None)?;
                    let result = stop_kernel(&target)?;
                    target.record_observation(Some(result))?;
                    Ok::<_, anyhow::Error>(result)
                })() {
                    Ok(containment) => RootStopReply {
                        outcome: "kernel_stopped".into(),
                        containment: Some(containment),
                        observation: None,
                    },
                    Err(_) => RootStopReply {
                        outcome: "unresolved".into(),
                        containment: None,
                        observation: None,
                    },
                },
                Err(_) => RootStopReply {
                    outcome: "unavailable".into(),
                    containment: None,
                    observation: None,
                },
            },
            RootOperation::Status => {
                match KernelStop::open(&request.target).and_then(|target| target.status()) {
                    Ok(observation) => RootStopReply {
                        outcome: "status".into(),
                        containment: None,
                        observation: Some(observation),
                    },
                    Err(_) => RootStopReply {
                        outcome: "unavailable".into(),
                        containment: None,
                        observation: None,
                    },
                }
            }
        };
        serde_json::to_writer(&mut stream, &reply)?;
        stream.flush()?;
        let _ = stream.shutdown(Shutdown::Both);
        Ok(())
    }
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let _ = process(stream);
            }
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("Linux required")
}
