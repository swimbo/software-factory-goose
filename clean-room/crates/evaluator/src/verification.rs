//! Local verification is a restricted Seatbelt process, not proof of the separate-UID
//! production boundary. Builds run from a fresh committed snapshot, offline, with no
//! inherited credentials. The operator must provision UID/holdout isolation separately.
use crate::{DeterministicVerdict, contains_secret};
use anyhow::{Context, Result, bail, ensure};
use shared::Receipt;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[derive(Debug, Clone)]
pub struct VerificationEvidence {
    pub sha: String,
    pub verdict: DeterministicVerdict,
    pub isolation: &'static str,
}

fn git(repo: &Path, args: &[&str]) -> Result<Vec<u8>> {
    git_input(repo, args, None)
}
fn git_input(repo: &Path, args: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>> {
    // Config, hooks, external diff and pager execution cannot become a code runner.
    let mut child = Command::new("/usr/bin/git")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args([
            "--no-replace-objects",
            "-c",
            "protocol.allow=never",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.pager=cat",
            "-C",
        ])
        .arg(repo)
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(bytes) = input {
        use std::io::Write;
        child
            .stdin
            .take()
            .context("missing Git input pipe")?
            .write_all(bytes)?;
    }
    let result = child.wait_with_output()?;
    ensure!(result.status.success(), "Git verification operation failed");
    Ok(result.stdout)
}
fn git_text(repo: &Path, args: &[&str]) -> Result<String> {
    Ok(String::from_utf8(git(repo, args)?)?.trim().to_owned())
}
fn exact_sha(sha: &str) -> Result<()> {
    ensure!(
        (sha.len() == 40 || sha.len() == 64) && sha.bytes().all(|b| b.is_ascii_hexdigit()),
        "full commit SHA required"
    );
    Ok(())
}
fn safe_local_config(repo: &Path) -> Result<()> {
    // `status` can otherwise invoke a clean filter configured by an untrusted checkout.
    // Reading config names does not execute filters/hooks; includes are never expanded.
    let names = git_text(
        repo,
        &[
            "config",
            "--local",
            "--no-includes",
            "--name-only",
            "--list",
        ],
    )?;
    for name in names.lines() {
        let allowed = [
            "core.repositoryformatversion",
            "core.filemode",
            "core.bare",
            "core.logallrefupdates",
            "core.ignorecase",
            "core.precomposeunicode",
            "user.name",
            "user.email",
            "extensions.objectformat",
        ];
        ensure!(
            allowed.contains(&name)
                || (name.starts_with("remote.")
                    && (name.ends_with(".url") || name.ends_with(".fetch")))
                || (name.starts_with("branch.")
                    && (name.ends_with(".remote") || name.ends_with(".merge"))),
            "unsupported local Git configuration"
        );
    }
    Ok(())
}
pub(crate) fn clean_at(repo: &Path, sha: &str) -> Result<()> {
    safe_local_config(repo)?;
    exact_sha(sha)?;
    ensure!(repo.is_dir(), "checkout does not exist");
    let canonical = repo.canonicalize()?;
    let root = PathBuf::from(git_text(repo, &["rev-parse", "--show-toplevel"])?).canonicalize()?;
    ensure!(canonical == root, "checkout must be the Git root");
    ensure!(
        git_text(repo, &["rev-parse", "HEAD"])? == sha,
        "checkout revision changed"
    );
    // Never run `git status`: even a config preflight can race an attacker adding
    // a clean-filter command. Index-only diff cannot execute text conversions.
    git(
        repo,
        &[
            "diff-index",
            "--cached",
            "--quiet",
            "--no-ext-diff",
            "--no-textconv",
            sha,
            "--",
        ],
    )
    .context("staged content differs from committed revision")?;
    let listing = git(repo, &["ls-tree", "-r", "-z", sha])?;
    let mut expected = std::collections::BTreeSet::new();
    for entry in listing.split(|b| *b == 0).filter(|e| !e.is_empty()) {
        let (header, name) = entry.split_at(
            entry
                .iter()
                .position(|b| *b == b'\t')
                .context("invalid tree entry")?,
        );
        let fields: Vec<_> = std::str::from_utf8(header)?.split_whitespace().collect();
        ensure!(
            fields.len() == 3 && fields[1] == "blob" && ["100644", "100755"].contains(&fields[0]),
            "unsupported tracked file type"
        );
        let relative = PathBuf::from(std::str::from_utf8(&name[1..])?);
        ensure!(
            relative
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(part) if part != ".git")),
            "invalid tracked path"
        );
        let path = repo.join(&relative);
        let metadata = fs::symlink_metadata(&path).context("tracked file missing")?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "tracked file type changed"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                (metadata.permissions().mode() & 0o111 != 0) == (fields[0] == "100755"),
                "tracked executable mode changed"
            );
        }
        ensure!(
            fs::read(&path)? == git(repo, &["cat-file", "blob", fields[2]])?,
            "tracked content changed"
        );
        expected.insert(relative);
    }
    fn walk(
        root: &Path,
        directory: &Path,
        expected: &std::collections::BTreeSet<PathBuf>,
    ) -> Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let relative = path.strip_prefix(root)?;
            if relative == Path::new(".git") {
                continue;
            }
            let kind = entry.file_type()?;
            if kind.is_dir() {
                walk(root, &path, expected)?;
            } else {
                ensure!(
                    kind.is_file() && expected.contains(relative),
                    "untracked or unsupported file in checkout"
                );
            }
        }
        Ok(())
    }
    walk(repo, repo, &expected)?;
    Ok(())
}

pub(crate) struct Scratch(pub(crate) PathBuf);
impl Scratch {
    pub(crate) fn new() -> Result<Self> {
        let dir = std::env::temp_dir().join(format!("factory-wall-{}", shared::new_id()));
        fs::create_dir(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self(dir.canonicalize()?))
    }
}

/// Export exact blobs without archive attributes, worktree filters or symlinks. The local
/// fixture runner caps snapshot bytes/files; Git preparation is not a hostile-input quota.
pub(crate) fn export_fixture_snapshot(repo: &Path, sha: &str, destination: &Path) -> Result<()> {
    clean_at(repo, sha)?;
    fs::create_dir(destination)?;
    let listing = git(repo, &["ls-tree", "-r", "-z", sha])?;
    ensure!(listing.len() <= 1_048_576, "snapshot listing too large");
    let mut total = 0_u64;
    for (index, entry) in listing
        .split(|b| *b == 0)
        .filter(|e| !e.is_empty())
        .enumerate()
    {
        ensure!(index < 10_000, "snapshot file limit exceeded");
        let split = entry
            .iter()
            .position(|b| *b == b'\t')
            .context("invalid tree")?;
        let fields: Vec<_> = std::str::from_utf8(&entry[..split])?
            .split_whitespace()
            .collect();
        ensure!(fields.len() == 3 && fields[1] == "blob", "invalid blob");
        let size: u64 = git_text(repo, &["cat-file", "-s", fields[2]])?.parse()?;
        total = total.checked_add(size).context("snapshot size overflow")?;
        ensure!(
            size <= 8_388_608 && total <= 33_554_432,
            "snapshot size limit exceeded"
        );
        let relative = PathBuf::from(std::str::from_utf8(&entry[split + 1..])?);
        ensure!(
            relative
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(p) if p != ".git")),
            "invalid snapshot path"
        );
        let path = destination.join(relative);
        fs::create_dir_all(path.parent().context("invalid parent")?)?;
        let blob = git(repo, &["cat-file", "blob", fields[2]])?;
        ensure!(blob.len() as u64 == size, "blob size mismatch");
        fs::write(&path, blob)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                path,
                fs::Permissions::from_mode(if fields[0] == "100755" { 0o700 } else { 0o600 }),
            )?;
        }
    }
    Ok(())
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Only a clean full-SHA checkout with a tracked Cargo manifest and lockfile can be
/// verified. Receipt.diff is untrusted and is never used as the scan input.
pub fn verify_worktree_evidence(
    worktree: &Path,
    receipt: &Receipt,
) -> Result<VerificationEvidence> {
    let sha = match receipt {
        Receipt::Completed {
            sha, exit_code: 0, ..
        } => sha,
        _ => bail!("successful completion receipt required"),
    };
    clean_at(worktree, sha)?;
    ensure!(
        cfg!(target_os = "macos") && Path::new("/usr/bin/sandbox-exec").is_file(),
        "Seatbelt isolation unavailable"
    );
    git(worktree, &["cat-file", "-e", &format!("{sha}:Cargo.toml")])
        .context("tracked Cargo.toml required")?;
    git(worktree, &["cat-file", "-e", &format!("{sha}:Cargo.lock")])
        .context("tracked Cargo.lock required")?;
    // Scan all tracked blobs, including content the worker omitted from its claimed diff.
    let listing = git(worktree, &["ls-tree", "-r", "-z", sha])?;
    let mut secret_scan_clean = true;
    for entry in listing.split(|b| *b == 0).filter(|e| !e.is_empty()) {
        let header = entry
            .split(|b| *b == b'\t')
            .next()
            .context("invalid tree")?;
        let header = std::str::from_utf8(header)?;
        let fields: Vec<_> = header.split_whitespace().collect();
        ensure!(
            fields.len() == 3 && fields[1] == "blob",
            "submodules are unsupported"
        );
        // Reject symlinks: build input must not escape the exported tree via a host path.
        ensure!(
            fields[0] != "120000",
            "symlinks in build input are unsupported"
        );
        let blob = git(worktree, &["cat-file", "blob", fields[2]])?;
        if contains_secret(&String::from_utf8_lossy(&blob)) {
            secret_scan_clean = false;
        }
    }
    if !secret_scan_clean {
        return Ok(VerificationEvidence {
            sha: sha.clone(),
            verdict: DeterministicVerdict {
                typecheck: false,
                tests_pass: false,
                secret_scan_clean: false,
            },
            isolation: "not_run_secret_scan_failed",
        });
    }
    let scratch = Scratch::new()?;
    let source = scratch.0.join("source");
    fs::create_dir(&source)?;
    let archive = scratch.0.join("source.tar");
    fs::write(&archive, git(worktree, &["archive", "--format=tar", sha])?)?;
    ensure!(
        Command::new("/usr/bin/tar")
            .args(["-xf"])
            .arg(&archive)
            .arg("-C")
            .arg(&source)
            .status()?
            .success(),
        "snapshot export failed"
    );
    let runner = RestrictedRunner::new(&scratch.0)?;
    // Host denial canaries must pass before even cargo metadata/build scripts execute.
    runner.canary()?;
    let typecheck = runner.cargo(
        &source,
        &["check", "--frozen", "--offline", "--all-targets"],
    )?;
    let tests_pass =
        typecheck && runner.cargo(&source, &["test", "--frozen", "--offline", "--all-targets"])?;
    clean_at(worktree, sha)?;
    Ok(VerificationEvidence {
        sha: sha.clone(),
        verdict: DeterministicVerdict {
            typecheck,
            tests_pass,
            secret_scan_clean,
        },
        isolation: "seatbelt_offline_ephemeral_snapshot",
    })
}

pub(crate) struct RestrictedRunner {
    root: PathBuf,
    profile: PathBuf,
    cargo: PathBuf,
    toolchain: PathBuf,
}
impl RestrictedRunner {
    pub(crate) fn new(root: &Path) -> Result<Self> {
        let home = PathBuf::from(std::env::var_os("HOME").context("operator home unavailable")?);
        let rustup = home.join(".cargo/bin/rustup");
        let result = Command::new(rustup)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .args(["which", "cargo"])
            .output()
            .context("trusted Rust toolchain unavailable")?;
        ensure!(
            result.status.success(),
            "trusted Rust toolchain unavailable"
        );
        let cargo = PathBuf::from(String::from_utf8(result.stdout)?.trim()).canonicalize()?;
        let toolchain = cargo
            .parent()
            .and_then(Path::parent)
            .context("invalid toolchain")?
            .to_path_buf();
        let profile = root.join("seatbelt.sb");
        let quote = |p: &Path| -> Result<String> {
            let s = p.to_str().context("non-UTF8 sandbox path")?;
            ensure!(
                !s.contains(['"', '\\', '\n', '\r']),
                "unsupported sandbox path"
            );
            Ok(format!("\"{s}\""))
        };
        let profile_text = format!(
            r#"(version 1)
(deny default)
(import "dyld-support.sb")
(allow process-fork process-exec)
(allow file-map-executable)
(allow sysctl-read)
(allow file-read-metadata)
(allow file-read* (subpath "/System") (subpath "/private/preboot/Cryptexes/OS") (subpath "/System/Volumes/Preboot/Cryptexes/OS") (subpath "/usr") (subpath "/bin") (subpath "/Library/Developer") (subpath {toolchain}) (subpath {root}) (literal "/dev/null") (literal "/private/etc/ssl/openssl.cnf") (literal "/dev/urandom") (literal "/dev/random"))
(allow file-write* (subpath {root}) (literal "/dev/null"))
(deny network*)
"#,
            toolchain = quote(&toolchain)?,
            root = quote(root)?
        );
        fs::write(&profile, profile_text)?;
        for dir in ["home", "tmp", "cargo-home", "target"] {
            fs::create_dir(root.join(dir))?;
        }
        Ok(Self {
            root: root.to_owned(),
            profile,
            cargo,
            toolchain,
        })
    }
    pub(crate) fn command(&self, cwd: &Path, executable: &Path, args: &[&str]) -> Command {
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command
            .args(["-f"])
            .arg(&self.profile)
            .arg(executable)
            .args(args)
            .current_dir(cwd)
            .env_clear()
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.toolchain.join("bin").display()),
            )
            .env("HOME", self.root.join("home"))
            .env("TMPDIR", self.root.join("tmp"))
            .env("CARGO_HOME", self.root.join("cargo-home"))
            .env("CARGO_TARGET_DIR", self.root.join("target"))
            .env("DEVELOPER_DIR", "/Library/Developer/CommandLineTools")
            .env(
                "SDKROOT",
                "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk",
            )
            .env("OPENSSL_CONF", "/dev/null")
            .env("CARGO_NET_OFFLINE", "true")
            .env("RUST_BACKTRACE", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        command
    }
    fn run(&self, cwd: &Path, executable: &Path, args: &[&str]) -> Result<bool> {
        let mut child = self.command(cwd, executable, args).spawn()?;
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait()? {
                // Descendants cannot survive a check that exits before its children.
                let _ = Command::new("/bin/kill")
                    .args(["-KILL", &format!("-{}", child.id())])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                return Ok(status.success());
            }
            if start.elapsed() > Duration::from_secs(120) {
                let _ = Command::new("/bin/kill")
                    .args(["-KILL", &format!("-{}", child.id())])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                let _ = child.kill();
                let _ = child.wait();
                bail!("isolated check exceeded timeout");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    pub(crate) fn canary(&self) -> Result<()> {
        let outside = Scratch::new()?;
        let secret = outside.0.join("host-secret");
        fs::write(&secret, "canary")?;
        let script = format!(
            "cat '{}' >/dev/null 2>&1 && exit 12; touch '{}' 2>/dev/null && exit 13; exit 0",
            secret.display(),
            outside.0.join("escape").display()
        );
        ensure!(
            self.run(&self.root, Path::new("/bin/sh"), &["-c", &script])?,
            "sandbox host-access canary failed"
        );
        ensure!(
            !outside.0.join("escape").exists(),
            "sandbox permitted host mutation"
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port().to_string();
        ensure!(
            Command::new("/usr/bin/nc")
                .args(["-z", "-w", "1", "127.0.0.1", &port])
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?
                .success(),
            "network canary positive control failed"
        );
        ensure!(
            !self.run(
                &self.root,
                Path::new("/usr/bin/nc"),
                &["-z", "-w", "1", "127.0.0.1", &port]
            )?,
            "sandbox permitted loopback network access"
        );
        Ok(())
    }
    fn cargo(&self, cwd: &Path, args: &[&str]) -> Result<bool> {
        self.run(cwd, &self.cargo, args)
    }
}

/// Atomically advance an operator-configured *bare* repository's current branch.
/// Compatibility wrapper only: an action-bound adapter must call
/// `promote_verified_commit_to_ref` with the approved explicit target reference.
/// Callers must authenticate human approval and match durable passing evidence first.
/// This helper never trusts a receipt as approval and never updates a working checkout.
pub fn promote_verified_commit(
    operator_repo: &Path,
    candidate_repo: &Path,
    expected_base: &str,
    approved_sha: &str,
) -> Result<()> {
    safe_local_config(operator_repo)?;
    let branch = git_text(operator_repo, &["symbolic-ref", "HEAD"])?;
    promote_verified_commit_to_ref(
        operator_repo,
        candidate_repo,
        &branch,
        expected_base,
        approved_sha,
    )
}

/// Advance exactly the approved branch, regardless of the bare repository's current HEAD.
/// This performs Git checks/CAS only: callers must first authenticate and durably consume
/// exact-action approval, and reconcile crash/retry outcomes. It does not supply authority.
pub fn promote_verified_commit_to_ref(
    operator_repo: &Path,
    candidate_repo: &Path,
    target_ref: &str,
    expected_base: &str,
    approved_sha: &str,
) -> Result<()> {
    exact_sha(expected_base)?;
    exact_sha(approved_sha)?;
    safe_local_config(operator_repo)?;
    ensure!(
        target_ref.starts_with("refs/heads/"),
        "promotion target must be a branch"
    );
    git(operator_repo, &["check-ref-format", target_ref])?;
    ensure!(
        git(operator_repo, &["symbolic-ref", "-q", target_ref]).is_err(),
        "promotion target must not be symbolic"
    );
    clean_at(candidate_repo, approved_sha)?;
    ensure!(
        git_text(operator_repo, &["rev-parse", "--is-bare-repository"])? == "true",
        "promotion target must be an operator-owned bare repository"
    );
    ensure!(
        git_text(operator_repo, &["rev-parse", target_ref])? == expected_base,
        "operator base changed"
    );
    ensure!(
        git(
            candidate_repo,
            &["merge-base", "--is-ancestor", expected_base, approved_sha]
        )
        .is_ok(),
        "candidate is not a fast-forward"
    );
    // Import raw objects, avoiding fetch/upload-pack and all repository transport hooks.
    let objects = git_text(
        candidate_repo,
        &[
            "rev-list",
            "--objects",
            "--no-object-names",
            approved_sha,
            &format!("^{expected_base}"),
        ],
    )?;
    ensure!(
        objects.lines().count() <= 10_000,
        "promotion object limit exceeded"
    );
    for object in objects.lines() {
        exact_sha(object)?;
        let kind = git_text(candidate_repo, &["cat-file", "-t", object])?;
        ensure!(
            ["commit", "tree", "blob", "tag"].contains(&kind.as_str()),
            "invalid Git object kind"
        );
        let bytes = git(candidate_repo, &["cat-file", &kind, object])?;
        let imported = git_input(
            operator_repo,
            &["hash-object", "-w", "-t", &kind, "--stdin"],
            Some(&bytes),
        )?;
        ensure!(
            String::from_utf8(imported)?.trim() == object,
            "imported object hash mismatch"
        );
    }
    clean_at(candidate_repo, approved_sha)?;
    git(
        operator_repo,
        &[
            "update-ref",
            "--no-deref",
            target_ref,
            approved_sha,
            expected_base,
        ],
    )?;
    ensure!(
        git_text(operator_repo, &["rev-parse", target_ref])? == approved_sha,
        "promotion read-back mismatch"
    );
    Ok(())
}
