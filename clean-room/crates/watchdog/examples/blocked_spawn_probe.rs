//! Disposable probe: a stalled child setup leaves stop responsive but unresolved.
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
    let other = registry.spawn_owned(Command::new("/bin/sleep").arg("30"))?;
    let mut existing = Command::new("/bin/sleep");
    existing.arg("30");
    let existing_member = registry.spawn_in_family(&target, &mut existing)?;
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
    let stop_registry = registry.clone();
    let stop_target = target.clone();
    let stopper = std::thread::spawn(move || {
        let _ = started_tx.send(());
        let result = stop_registry.stop(&stop_target);
        let _ = tx.send(result);
    });
    started_rx.recv_timeout(Duration::from_secs(5))?;
    let interim = rx.recv_timeout(Duration::from_secs(2));
    let rejected = if interim.is_ok() {
        registry
            .spawn_in_family(&target, &mut Command::new("/bin/true"))
            .is_err()
    } else {
        false
    };
    let other_stopped = if interim.is_ok() {
        registry
            .stop(&other)
            .is_ok_and(|result| result.leader_reaped && result.group_absent)
    } else {
        false
    };
    // Release before asserting, so the owned child cannot remain stalled on a test failure.
    parent.write_all(&[1])?;
    let launch = launcher
        .join()
        .map_err(|_| anyhow::anyhow!("launcher panicked"))?;
    let stop = interim??;
    stopper
        .join()
        .map_err(|_| anyhow::anyhow!("stopper panicked"))?;
    anyhow::ensure!(launch.is_err(), "late launch must be rejected");
    anyhow::ensure!(rejected, "family accepted a launch after stop");
    anyhow::ensure!(other_stopped, "unrelated family could not be stopped");
    anyhow::ensure!(
        stop.pending_launches == 1
            && !stop.group_absent
            && !stop.leader_reaped
            && !stop.signal_sent,
        "pending launch was reported as stopped"
    );
    anyhow::ensure!(
        stop.groups.len() == 1
            && stop.groups[0].member == existing_member
            && stop.groups[0].leader_reaped
            && stop.groups[0].group_absent,
        "previously registered group was not stopped"
    );
    let stop = registry.stop(&target)?;
    anyhow::ensure!(
        stop.leader_reaped && stop.group_absent,
        "owned group cleanup incomplete"
    );
    println!(
        "PASS: stop reported a pending launch; after release the late owned group was stopped and reaped"
    );
    Ok(())
}
