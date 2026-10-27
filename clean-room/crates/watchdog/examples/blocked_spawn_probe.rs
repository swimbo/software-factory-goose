//! Disposable falsification probe: a stalled child setup can block the family stop lock.
//! No arbitrary PID or external process is targeted. This is not a production launcher.
use std::{
    io::{Read, Write},
    os::{fd::AsRawFd, unix::net::UnixStream, unix::process::CommandExt},
    process::Command,
    sync::{Arc, mpsc},
    time::Duration,
};

fn main() -> anyhow::Result<()> {
    let registry = Arc::new(watchdog::Registry::new()?);
    let target = registry.create_family()?;
    let (mut parent, child) = UnixStream::pair()?;
    parent.set_read_timeout(Some(Duration::from_secs(5)))?;
    parent.set_write_timeout(Some(Duration::from_secs(5)))?;
    let fd = child.as_raw_fd();
    let parent_fd = parent.as_raw_fd();
    let launcher_registry = registry.clone();
    let launch_target = target.clone();
    let launcher = std::thread::spawn(move || {
        // Keep the descriptor alive until spawn returns. The child executes only async-signal-
        // safe libc calls after fork. Closing the parent's socket also unblocks the read.
        let _child_socket = child;
        let mut command = Command::new("/bin/sleep");
        command.arg("30");
        unsafe {
            command.pre_exec(move || {
                libc::close(parent_fd);
                let byte = [1_u8];
                if libc::write(fd, byte.as_ptr().cast(), 1) != 1 {
                    return Err(std::io::Error::last_os_error());
                }
                let mut release = [0_u8];
                if libc::read(fd, release.as_mut_ptr().cast(), 1) != 1 {
                    return Err(std::io::Error::other("probe released without a byte"));
                }
                Ok(())
            });
        }
        launcher_registry.spawn_in_family(&launch_target, &mut command)
    });
    let mut ready = [0_u8];
    parent.read_exact(&mut ready)?;
    anyhow::ensure!(ready == [1], "child setup did not become blocked");
    let (tx, rx) = mpsc::channel();
    let (started_tx, started_rx) = mpsc::sync_channel(0);
    let stopper = std::thread::spawn(move || {
        let _ = started_tx.send(());
        let result = registry.stop(&target);
        let _ = tx.send(result);
    });
    started_rx.recv_timeout(Duration::from_secs(5))?;
    let blocked = matches!(
        rx.recv_timeout(Duration::from_millis(300)),
        Err(mpsc::RecvTimeoutError::Timeout)
    );
    // Release before asserting, so the owned child cannot remain stalled on a test failure.
    parent.write_all(&[1])?;
    let launch = launcher
        .join()
        .map_err(|_| anyhow::anyhow!("launcher panicked"))?;
    let stop = rx.recv_timeout(Duration::from_secs(10))??;
    stopper
        .join()
        .map_err(|_| anyhow::anyhow!("stopper panicked"))?;
    launch?;
    anyhow::ensure!(blocked, "stop unexpectedly returned during blocked spawn");
    anyhow::ensure!(
        stop.leader_reaped && stop.group_absent,
        "owned group cleanup incomplete"
    );
    println!(
        "PASS: stop was blocked during child setup; after release the owned group was stopped and reaped"
    );
    Ok(())
}
