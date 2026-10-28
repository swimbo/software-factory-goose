//! Single-use latch-bound admission for disposable guarded-release fixtures only.
use crate::guarded_release::FixtureGroup;
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    ffi::{OsStr, OsString},
    fs::{File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};
const MAX_PROGRAM_BYTES: u64 = 128 * 1024 * 1024;
#[derive(PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    len: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
impl FileIdentity {
    fn of(file: &File) -> Result<Self> {
        let m = file.metadata()?;
        Ok(Self {
            dev: m.dev(),
            ino: m.ino(),
            len: m.len(),
            mode: m.mode(),
            uid: m.uid(),
            gid: m.gid(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_ns: m.ctime_nsec(),
        })
    }
}
#[derive(PartialEq, Eq)]
struct ProgramSnapshot {
    identity: FileIdentity,
    sha256: [u8; 32],
}
fn snapshot_program(path: &Path) -> Result<ProgramSnapshot> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let before = FileIdentity::of(&file)?;
    ensure!(
        file.metadata()?.is_file() && before.len <= MAX_PROGRAM_BYTES,
        "invalid or oversized fixture executable"
    );
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 8192];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        ensure!(
            total <= MAX_PROGRAM_BYTES,
            "fixture executable exceeds bound"
        );
        hash.update(&buffer[..n]);
    }
    ensure!(
        before == FileIdentity::of(&file)? && total == before.len,
        "fixture executable changed during inspection"
    );
    Ok(ProgramSnapshot {
        identity: before,
        sha256: hash.finalize().into(),
    })
}
#[derive(PartialEq, Eq)]
struct DirectoryIdentity {
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
}
fn snapshot_directory(path: &Path) -> Result<DirectoryIdentity> {
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = dir.metadata()?;
    ensure!(m.is_dir(), "fixture working directory unavailable");
    Ok(DirectoryIdentity {
        dev: m.dev(),
        ino: m.ino(),
        mode: m.mode(),
        uid: m.uid(),
        gid: m.gid(),
    })
}

/// Immutable trusted local fixture configuration. This is not a remote request type.
pub struct FixtureSpec {
    program: PathBuf,
    arguments: Vec<OsString>,
    cwd: PathBuf,
    executable: ProgramSnapshot,
    directory: DirectoryIdentity,
}
impl FixtureSpec {
    pub fn new<I, S>(program: impl AsRef<Path>, arguments: I, cwd: impl AsRef<Path>) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let program = program.as_ref().canonicalize()?;
        let cwd = cwd.as_ref().canonicalize()?;
        ensure!(
            program.is_file() && cwd.is_dir(),
            "invalid trusted fixture paths"
        );
        let executable = snapshot_program(&program)?;
        let directory = snapshot_directory(&cwd)?;
        let arguments: Vec<_> = arguments
            .into_iter()
            .map(|value| value.as_ref().to_os_string())
            .collect();
        ensure!(
            arguments.len() <= 32 && arguments.iter().all(|value| value.len() <= 4096),
            "fixture argument bounds exceeded"
        );
        Ok(Self {
            program,
            arguments,
            cwd,
            executable,
            directory,
        })
    }
}
/// One launcher reserves one private root durably before any child is spawned.
/// It never clears the latch or reuses a failed/consumed launch.
pub struct FixtureLauncher {
    spec: Option<FixtureSpec>,
}
impl FixtureLauncher {
    pub fn new(root: &Path, spec: FixtureSpec) -> Result<Self> {
        crate::recovery_latch::arm(root)?;
        Ok(Self { spec: Some(spec) })
    }
    pub fn launch(&mut self) -> Result<FixtureGroup> {
        let spec = self
            .spec
            .take()
            .context("fixture launch already consumed")?;
        ensure!(
            snapshot_program(&spec.program)? == spec.executable,
            "fixture executable changed since admission"
        );
        ensure!(
            snapshot_directory(&spec.cwd)? == spec.directory,
            "fixture working directory changed since admission"
        );
        let mut command = Command::new(spec.program);
        command
            .args(spec.arguments)
            .current_dir(spec.cwd)
            .env_clear()
            .env("PATH", "/usr/bin:/bin");
        FixtureGroup::launch(&mut command)
    }
}
