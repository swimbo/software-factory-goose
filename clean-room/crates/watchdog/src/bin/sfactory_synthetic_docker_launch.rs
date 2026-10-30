//! Review-only synthetic launcher. No socket, worker ingress, journal, or provider.
#[cfg(target_os = "linux")]
#[path = "../root_launch.rs"]
mod root_launch;
#[cfg(target_os = "linux")]
#[path = "../root_launch_docker.rs"]
mod root_launch_docker;

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, Result, ensure};
    use root_launch::{LaunchAuthority, RootLaunchState};
    use root_launch_docker::{BoundedCli, Runner};
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use std::{
        fs::OpenOptions,
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::Path,
        time::Duration,
    };
    const ROOT: &str = "/etc/software-factory-goose";
    const STATE: &str = "/var/lib/software-factory-goose/stop";
    const RECIPE: &str = "synthetic-network-none-python311-shell-setsid-sleep60-v1";
    fn read_file(path: &Path) -> Result<Vec<u8>> {
        let mut f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?;
        let m = f.metadata()?;
        ensure!(
            m.is_file()
                && m.uid() == 0
                && m.gid() == 0
                && m.nlink() == 1
                && m.mode() & 0o7777 == 0o600
                && m.len() <= 16384,
            "untrusted fixture record"
        );
        let mut b = Vec::new();
        Read::by_ref(&mut f).take(16385).read_to_end(&mut b)?;
        ensure!(b.len() as u64 == m.len(), "fixture record changed");
        Ok(b)
    }
    fn hex(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }
    fn mono_ns() -> Result<u64> {
        let mut t = std::mem::MaybeUninit::<libc::timespec>::uninit();
        // SAFETY: clock_gettime writes the valid timespec pointer on success.
        ensure!(
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, t.as_mut_ptr()) } == 0,
            "monotonic clock failed"
        );
        // SAFETY: successful clock_gettime initializes the timespec.
        let t = unsafe { t.assume_init() };
        u64::try_from(t.tv_sec)?
            .checked_mul(1_000_000_000)
            .and_then(|v| v.checked_add(t.tv_nsec as u64))
            .context("monotonic overflow")
    }
    type FixtureData = (Value, Value, Value, Vec<u8>, Vec<u8>);
    struct Authority {
        target: String,
        cli: BoundedCli,
    }
    impl Authority {
        fn data(&self) -> Result<FixtureData> {
            let g = &self.target;
            let cat = read_file(&Path::new(ROOT).join("tasks").join(format!("{g}.json")))?;
            let grant = read_file(
                &Path::new(ROOT)
                    .join("deadline-grants")
                    .join(format!("{g}.json")),
            )?;
            let armed = read_file(&Path::new(STATE).join(format!("{g}.deadline-armed.json")))?;
            Ok((
                serde_json::from_slice(&cat)?,
                serde_json::from_slice(&grant)?,
                serde_json::from_slice(&armed)?,
                cat,
                grant,
            ))
        }
        fn guard(&self) -> Result<()> {
            let info = self
                .cli
                .run(&["info".into(), "--format".into(), "{{.ID}}".into()])?;
            let version = self.cli.run(&[
                "version".into(),
                "--format".into(),
                "{{.Server.GitCommit}}".into(),
            ])?;
            let release = self.cli.run(&[
                "version".into(),
                "--format".into(),
                "{{.Server.Version}}".into(),
            ])?;
            let pid = self.cli.run_program(
                "/usr/bin/systemctl",
                &[
                    "show".into(),
                    "docker.service".into(),
                    "-p".into(),
                    "MainPID".into(),
                    "--value".into(),
                ],
                Duration::from_secs(8),
            )?;
            ensure!(
                info.trim() == "56d25a60-5f64-4212-b904-e750067ac6a5"
                    && version.trim() == "3ce5872"
                    && pid.trim() == "2145"
                    && release.trim() == "29.8.0",
                "daemon identity changed"
            );
            let raw = self.cli.run(&[
                "inspect".into(),
                "04f7717345b35b6cb6b3c5a2bfdf234c64346e90cc7c3b3c16d6b71eb0e10062".into(),
            ])?;
            let v: Value = serde_json::from_str(&raw)?;
            let a = v.as_array().context("bad original guard")?;
            ensure!(a.len() == 1, "ambiguous original");
            let o = &a[0];
            ensure!(
                o["Id"] == "04f7717345b35b6cb6b3c5a2bfdf234c64346e90cc7c3b3c16d6b71eb0e10062"
                    && o["Name"] == "/sf-owner-224a71d2db764249aa6cade3c1b39c80"
                    && o["State"]["Status"] == "created"
                    && o["State"]["Pid"] == 0
                    && o["Config"]["Labels"]["org.software-factory.escape-spike"]
                        == "224a71d2db764249aa6cade3c1b39c80",
                "original guard changed"
            );
            Ok(())
        }
    }
    impl LaunchAuthority for Authority {
        fn verify_bound_reservation(&self, g: &str) -> Result<String> {
            ensure!(g == self.target, "target mismatch");
            self.guard()?;
            // Reuse the root stop verifier's cgroup2 and protected catalogue checks.
            let _ = watchdog::root_cgroup::linux::KernelStop::open(g)?;
            let (cat, grant, armed, cb, gb) = self.data()?;
            let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
            let boot = boot.trim();
            ensure!(
                cat["schema"] == 1
                    && cat["target_id"] == g
                    && cat["generation"] == g
                    && cat["boot_id"] == boot
                    && grant["schema"] == 1
                    && grant["target_id"] == g
                    && grant["boot_id"] == boot
                    && grant["purpose"] == "synthetic-canary-only"
                    && grant["catalog_sha256"] == hex(&cb)
                    && armed["target"] == g
                    && armed["boot_id"] == boot
                    && armed["grant_sha256"] == hex(&gb)
                    && armed["engine_effects"] == false,
                "fixture binding mismatch"
            );
            let cg =
                Path::new("/sys/fs/cgroup").join(format!("sfactory{}.slice", g.to_lowercase()));
            let m = std::fs::symlink_metadata(cg)?;
            ensure!(
                m.is_dir() && cat["cgroup_dev"] == m.dev() && cat["cgroup_ino"] == m.ino(),
                "cgroup mismatch"
            );
            let mut h = Sha256::new();
            h.update(b"sfactory-synthetic-launch-v1\0");
            h.update(hex(&cb));
            h.update(hex(&gb));
            h.update(RECIPE);
            Ok(format!("{:x}", h.finalize()))
        }
        fn arm_independent_deadline(&self, g: &str) -> Result<()> {
            self.verify_deadline_and_reservation(g)
        }
        fn verify_deadline_and_reservation(&self, g: &str) -> Result<()> {
            ensure!(g == self.target, "target mismatch");
            let (_, grant, armed, _, _) = self.data()?;
            let wake = armed["wake_monotonic_ns"]
                .as_u64()
                .context("missing wake")?;
            ensure!(mono_ns()? < wake, "deadline elapsed");
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos();
            ensure!(
                now < grant["expires_unix_ns"]
                    .as_u64()
                    .context("missing expiry")? as u128,
                "grant expired"
            );
            let timer = format!("sfactorydeadline{}.timer", g.to_lowercase());
            let active = self.cli.run_program(
                "/usr/bin/systemctl",
                &[
                    "show".into(),
                    timer.clone(),
                    "-p".into(),
                    "ActiveState".into(),
                    "--value".into(),
                ],
                Duration::from_secs(8),
            )?;
            ensure!(active.trim() == "active", "deadline timer unavailable");
            let object = format!(
                "/org/freedesktop/systemd1/unit/{}_2etimer",
                timer.trim_end_matches(".timer")
            );
            let actual = self.cli.run_program(
                "/usr/bin/busctl",
                &[
                    "get-property".into(),
                    "org.freedesktop.systemd1".into(),
                    object,
                    "org.freedesktop.systemd1.Timer".into(),
                    "NextElapseUSecMonotonic".into(),
                ],
                Duration::from_secs(8),
            )?;
            ensure!(
                actual.trim() == format!("t {}", wake / 1000),
                "deadline wake changed"
            );
            Ok(())
        }
        fn create_stopped(&self, g: &str) -> Result<String> {
            root_launch_docker::create_stopped(&self.cli, g)
        }
        fn verify_owned_stopped(&self, g: &str, id: &str) -> Result<()> {
            root_launch_docker::verify_stopped(&self.cli, g, id)
        }
        fn start(&self, _: &str, id: &str) -> Result<()> {
            root_launch_docker::start(&self.cli, id)
        }
    }
    // SAFETY: geteuid only reads current credentials.
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let mut args = std::env::args();
    let _ = args.next();
    let target = args.next().context("target required")?;
    ensure!(args.next().is_none(), "unexpected arguments");
    let state = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(STATE)?;
    let authority = Authority {
        target: target.clone(),
        cli: BoundedCli,
    };
    let id = RootLaunchState::from_root_owned_directory(state)?.launch_once(&authority, &target)?;
    println!("{{\"target\":\"{target}\",\"id\":\"{id}\"}}");
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("Linux required")
}
