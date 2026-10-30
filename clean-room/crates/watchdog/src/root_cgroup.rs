//! Stop-only authority primitives. Kernel emptiness is never engine reconciliation.
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopResult {
    pub closed: bool,
    pub frozen: bool,
    pub empty: bool,
    pub engine_reconciled: bool,
}

/// Durable last stop observation; false fields mean not established, not necessarily absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopObservation {
    pub target_id: String,
    pub boot_id: String,
    pub cgroup_dev: u64,
    pub cgroup_ino: u64,
    pub observed: bool,
    pub observed_at_unix: Option<u64>,
    pub closed: bool,
    pub frozen: bool,
    pub empty: bool,
    pub engine_reconciled: bool,
}

/// A trusted implementation binds a fixed generation before these methods are called.
pub trait StopBackend {
    fn close_admission(&self) -> Result<()>;
    fn freeze(&self) -> Result<()>;
    fn kill_and_observe_empty(&self) -> Result<()>;
}

/// Completion of the kernel operation intentionally leaves engine state unresolved.
pub fn stop_kernel(backend: &impl StopBackend) -> Result<StopResult> {
    backend.close_admission()?;
    backend.freeze()?;
    backend.kill_and_observe_empty()?;
    Ok(StopResult {
        closed: true,
        frozen: true,
        empty: true,
        engine_reconciled: false,
    })
}

#[cfg(target_os = "linux")]
pub mod linux {
    use super::{StopBackend, StopObservation, StopResult};
    use anyhow::{Context, Result, bail, ensure};
    use serde::Deserialize;
    use std::{
        ffi::CString,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::{MetadataExt, OpenOptionsExt},
        },
        path::Path,
        sync::Mutex,
        time::{Duration, Instant},
    };

    const CATALOG: &str = "/etc/software-factory-goose/tasks";
    const STATE: &str = "/var/lib/software-factory-goose/stop";
    const CGROUP: &str = "/sys/fs/cgroup";
    const CGROUP2_MAGIC: libc::c_long = 0x6367_7270;
    const WAIT: Duration = Duration::from_secs(2);

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Catalog {
        schema: u32,
        target_id: String,
        task_id: String,
        generation: String,
        boot_id: String,
        cgroup_dev: u64,
        cgroup_ino: u64,
    }

    fn protected_directory(path: &Path) -> Result<File> {
        for ancestor in path.ancestors() {
            let m = fs::symlink_metadata(ancestor)?;
            ensure!(
                m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
                "unprotected directory"
            );
        }
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let m = f.metadata()?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "unprotected directory"
        );
        Ok(f)
    }
    fn openat(dir: &File, name: &str, flags: libc::c_int, mode: libc::mode_t) -> Result<File> {
        ensure!(
            !name.is_empty() && !name.contains('/') && name != "." && name != "..",
            "invalid component"
        );
        let n = CString::new(name)?;
        // SAFETY: the directory descriptor and NUL-terminated component remain valid.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                n.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                mode,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: a successful openat returns a newly owned file descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn trusted_regular(f: &File, exact_mode: Option<u32>) -> Result<()> {
        let m = f.metadata()?;
        ensure!(
            m.is_file()
                && m.uid() == 0
                && m.nlink() == 1
                && m.mode() & 0o022 == 0
                && exact_mode.is_none_or(|x| m.mode() & 0o777 == x),
            "unprotected file"
        );
        Ok(())
    }
    fn bounded_read(mut f: &File, max: u64) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        std::io::Read::by_ref(&mut f)
            .take(max + 1)
            .read_to_end(&mut out)?;
        ensure!(out.len() as u64 <= max, "record too large");
        Ok(out)
    }
    fn cgroup2(f: &File) -> Result<()> {
        let mut s = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: f is an open descriptor and statfs writes to initialized storage on success.
        ensure!(
            unsafe { libc::fstatfs(f.as_raw_fd(), s.as_mut_ptr()) } == 0,
            "cgroup filesystem unavailable"
        );
        // SAFETY: fstatfs returned success.
        ensure!(
            unsafe { s.assume_init() }.f_type as libc::c_long == CGROUP2_MAGIC,
            "wrong filesystem"
        );
        Ok(())
    }
    pub fn canonical_task(task: &str) -> Result<()> {
        ensure!(
            ulid::Ulid::from_string(task).is_ok_and(|u| u.to_string() == task),
            "invalid task identity"
        );
        Ok(())
    }
    fn stop_lock_name(task: &str) -> String {
        format!("{task}.stop.lock")
    }
    fn validate_catalog(c: &Catalog, target: &str, boot: &str) -> Result<()> {
        canonical_task(target)?;
        canonical_task(&c.task_id)?;
        ensure!(
            c.schema == 1
                && c.target_id == target
                && c.generation == target
                && c.cgroup_ino != 0
                && c.boot_id == boot.trim()
                && c.boot_id.len() == 36,
            "catalog identity or boot mismatch"
        );
        Ok(())
    }
    pub struct KernelStop {
        task: String,
        state: File,
        group: Mutex<Option<(File, File)>>,
        name: String,
        boot: String,
        dev: u64,
        ino: u64,
        lock: Mutex<Option<File>>,
    }
    impl KernelStop {
        /// Only fixed protected deployment roots are accepted; caller supplies an opaque ULID.
        pub fn open(task: &str) -> Result<Self> {
            canonical_task(task)?;
            // SAFETY: geteuid reads process state only.
            ensure!(unsafe { libc::geteuid() } == 0, "root authority required");
            let catalog = protected_directory(Path::new(CATALOG))?;
            let state = protected_directory(Path::new(STATE))?;
            ensure!(
                state.metadata()?.mode() & 0o777 == 0o700,
                "stop state must be private"
            );
            let cf = openat(&catalog, &format!("{task}.json"), libc::O_RDONLY, 0)?;
            trusted_regular(&cf, None)?;
            let c: Catalog = serde_json::from_slice(&bounded_read(&cf, 1024)?)?;
            let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
            validate_catalog(&c, task, &boot)?;
            let name = format!("sfactory{}.slice", task.to_ascii_lowercase());
            Ok(Self {
                task: task.into(),
                state,
                group: Mutex::new(None),
                name,
                boot: c.boot_id,
                dev: c.cgroup_dev,
                ino: c.cgroup_ino,
                lock: Mutex::new(None),
            })
        }
        fn current(&self, root: &File, group: &File) -> Result<()> {
            let fresh = openat(root, &self.name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            cgroup2(&fresh)?;
            for f in [&fresh, group] {
                let m = f.metadata()?;
                ensure!(
                    m.uid() == 0
                        && m.mode() & 0o022 == 0
                        && m.dev() == self.dev
                        && m.ino() == self.ino,
                    "cgroup changed"
                );
            }
            Ok(())
        }
        fn closed(&self) -> Result<bool> {
            match openat(
                &self.state,
                &format!("{}.closed", self.task),
                libc::O_RDONLY,
                0,
            ) {
                Ok(f) => {
                    trusted_regular(&f, Some(0o600))?;
                    ensure!(
                        bounded_read(&f, 128)? == format!("{}\n", self.task).as_bytes(),
                        "closure mismatch"
                    );
                    Ok(true)
                }
                Err(e)
                    if e.downcast_ref::<std::io::Error>()
                        .is_some_and(|x| x.kind() == std::io::ErrorKind::NotFound) =>
                {
                    Ok(false)
                }
                Err(e) => Err(e),
            }
        }
        fn observation(&self, result: Option<StopResult>) -> StopObservation {
            StopObservation {
                target_id: self.task.clone(),
                boot_id: self.boot.clone(),
                cgroup_dev: self.dev,
                cgroup_ino: self.ino,
                observed: result.is_some(),
                observed_at_unix: result.map(|_| {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |x| x.as_secs())
                }),
                closed: true,
                frozen: result.is_some_and(|x| x.frozen),
                empty: result.is_some_and(|x| x.empty),
                engine_reconciled: false,
            }
        }
        /// Replace only this generation's protected last-observation record.
        pub fn record_observation(&self, result: Option<StopResult>) -> Result<()> {
            ensure!(self.closed()?, "closure unavailable");
            if let Some(r) = result {
                ensure!(
                    r.closed && r.frozen && r.empty && !r.engine_reconciled,
                    "invalid kernel result"
                );
            }
            let temp = format!("{}.{}.tmp", self.task, ulid::Ulid::new());
            let mut f = openat(
                &self.state,
                &temp,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )?;
            serde_json::to_writer(&mut f, &self.observation(result))?;
            f.sync_all()?;
            let from = CString::new(temp.as_str())?;
            let to = CString::new(format!("{}.observation", self.task))?;
            // SAFETY: both names are fixed single components in the protected directory.
            ensure!(
                unsafe {
                    libc::renameat(
                        self.state.as_raw_fd(),
                        from.as_ptr(),
                        self.state.as_raw_fd(),
                        to.as_ptr(),
                    )
                } == 0,
                "observation rename failed"
            );
            self.state.sync_all()?;
            Ok(())
        }
        /// Read the last protected observation only; never changes cgroups or closure.
        pub fn status(&self) -> Result<StopObservation> {
            let closed = self.closed()?;
            match openat(
                &self.state,
                &format!("{}.observation", self.task),
                libc::O_RDONLY,
                0,
            ) {
                Ok(f) => {
                    trusted_regular(&f, Some(0o600))?;
                    let o: StopObservation = serde_json::from_slice(&bounded_read(&f, 2048)?)?;
                    ensure!(
                        closed
                            && o.closed
                            && o.target_id == self.task
                            && o.boot_id == self.boot
                            && o.cgroup_dev == self.dev
                            && o.cgroup_ino == self.ino
                            && !o.engine_reconciled
                            && ((o.observed
                                && o.frozen
                                && o.empty
                                && o.observed_at_unix.is_some())
                                || (!o.observed
                                    && !o.frozen
                                    && !o.empty
                                    && o.observed_at_unix.is_none())),
                        "invalid observation"
                    );
                    Ok(o)
                }
                Err(e)
                    if e.downcast_ref::<std::io::Error>()
                        .is_some_and(|x| x.kind() == std::io::ErrorKind::NotFound) =>
                {
                    let mut o = self.observation(None);
                    o.closed = closed;
                    Ok(o)
                }
                Err(e) => Err(e),
            }
        }
        fn set(&self, name: &str, value: &[u8]) -> Result<()> {
            let guard = self
                .group
                .lock()
                .map_err(|_| anyhow::anyhow!("group lock poisoned"))?;
            let (root, group) = guard.as_ref().context("cgroup unavailable")?;
            self.current(root, group)?;
            let mut f = openat(group, name, libc::O_WRONLY, 0)?;
            f.write_all(value)?;
            self.current(root, group)
        }
        fn event(&self, key: &str, expected: &str) -> Result<bool> {
            let guard = self
                .group
                .lock()
                .map_err(|_| anyhow::anyhow!("group lock poisoned"))?;
            let (root, group) = guard.as_ref().context("cgroup unavailable")?;
            self.current(root, group)?;
            let f = openat(group, "cgroup.events", libc::O_RDONLY, 0)?;
            let bytes = bounded_read(&f, 4096)?;
            let text = std::str::from_utf8(&bytes)?;
            let mut found = None;
            for line in text.lines() {
                let mut words = line.split_whitespace();
                if words.next() == Some(key) {
                    ensure!(found.is_none(), "duplicate event");
                    found = words.next();
                    ensure!(words.next().is_none(), "invalid event");
                }
            }
            self.current(root, group)?;
            Ok(found == Some(expected))
        }
        fn wait(&self, key: &str, value: &str) -> Result<()> {
            let until = Instant::now() + WAIT;
            loop {
                if self.event(key, value)? {
                    return Ok(());
                }
                if Instant::now() >= until {
                    bail!("cgroup observation unresolved");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
    impl StopBackend for KernelStop {
        fn close_admission(&self) -> Result<()> {
            let name = format!("{}.closed", self.task);
            let bytes = format!("{}\n", self.task);
            match openat(
                &self.state,
                &name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                0o600,
            ) {
                Ok(mut f) => {
                    f.write_all(bytes.as_bytes())?;
                    f.sync_all()?;
                    self.state.sync_all()?;
                }
                Err(e) => {
                    if e.downcast_ref::<std::io::Error>()
                        .is_none_or(|x| x.kind() != std::io::ErrorKind::AlreadyExists)
                    {
                        return Err(e);
                    }
                    let f = openat(&self.state, &name, libc::O_RDONLY, 0)?;
                    trusted_regular(&f, Some(0o600))?;
                    ensure!(
                        bounded_read(&f, 128)? == bytes.as_bytes(),
                        "closure mismatch"
                    );
                }
            }
            Ok(())
        }
        fn freeze(&self) -> Result<()> {
            let f = openat(
                &self.state,
                &stop_lock_name(&self.task),
                libc::O_RDWR | libc::O_CREAT,
                0o600,
            )?;
            trusted_regular(&f, Some(0o600))?;
            // SAFETY: flock operates on an owned file descriptor. Nonblocking keeps stop bounded.
            ensure!(
                unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
                "task operation pending"
            );
            *self
                .lock
                .lock()
                .map_err(|_| anyhow::anyhow!("lock poisoned"))? = Some(f);
            let root = protected_directory(Path::new(CGROUP))?;
            cgroup2(&root)?;
            let group = openat(&root, &self.name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            cgroup2(&group)?;
            self.current(&root, &group)?;
            *self
                .group
                .lock()
                .map_err(|_| anyhow::anyhow!("group lock poisoned"))? = Some((root, group));
            self.set("cgroup.freeze", b"1")?;
            self.wait("frozen", "1")
        }
        fn kill_and_observe_empty(&self) -> Result<()> {
            self.set("cgroup.kill", b"1")?;
            self.wait("populated", "0")?;
            self.wait("frozen", "1")
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn held_launch_lock_does_not_block_stop_lock() {
            let dir =
                std::env::temp_dir().join(format!("sfactory-lock-test-{}", ulid::Ulid::new()));
            fs::create_dir(&dir).unwrap();
            let launch = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(dir.join("target.lock"))
                .unwrap();
            // SAFETY: descriptors are owned by this test and flock is nonblocking.
            assert_eq!(
                unsafe { libc::flock(launch.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
                0
            );
            let stop = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(dir.join(stop_lock_name("target")))
                .unwrap();
            // SAFETY: descriptors are owned by this test and flock is nonblocking.
            let result = unsafe { libc::flock(stop.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            drop(stop);
            drop(launch);
            fs::remove_dir_all(dir).unwrap();
            assert_eq!(result, 0);
        }
        #[test]
        fn catalogue_refuses_wrong_boot_generation_and_identity() {
            let id = ulid::Ulid::new().to_string();
            let boot = "9a4a2acf-067c-4d65-9a76-4dce451f8e70";
            let mut c = Catalog {
                schema: 1,
                target_id: id.clone(),
                task_id: ulid::Ulid::new().to_string(),
                generation: id.clone(),
                boot_id: boot.into(),
                cgroup_dev: 1,
                cgroup_ino: 2,
            };
            assert!(validate_catalog(&c, &id, boot).is_ok());
            assert!(validate_catalog(&c, &id, "00000000-0000-0000-0000-000000000000").is_err());
            c.generation = ulid::Ulid::new().to_string();
            assert!(validate_catalog(&c, &id, boot).is_err());
            c.generation = id.clone();
            c.task_id = "not-a-task".into();
            assert!(validate_catalog(&c, &id, boot).is_err());
            c.task_id = ulid::Ulid::new().to_string();
            c.cgroup_ino = 0;
            assert!(validate_catalog(&c, &id, boot).is_err());
            assert!(canonical_task(&id.to_lowercase()).is_err());
        }
    }
}
