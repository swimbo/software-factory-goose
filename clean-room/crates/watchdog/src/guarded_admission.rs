//! Single-use latch-bound admission for disposable guarded-release fixtures only.
use crate::guarded_release::FixtureGroup;
use anyhow::{Context, Result, ensure};
use std::{
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    process::Command,
};

/// Immutable trusted local fixture configuration. This is not a remote request type.
pub struct FixtureSpec {
    program: PathBuf,
    arguments: Vec<OsString>,
    cwd: PathBuf,
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
        let mut command = Command::new(spec.program);
        command
            .args(spec.arguments)
            .current_dir(spec.cwd)
            .env_clear()
            .env("PATH", "/usr/bin:/bin");
        FixtureGroup::launch(&mut command)
    }
}
