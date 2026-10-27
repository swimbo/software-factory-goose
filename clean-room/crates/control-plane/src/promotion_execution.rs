//! Unregistered, trusted-owner Git executor. No caller-supplied filesystem paths are accepted.
//!
//! The same-object decision journal supplies authority. This adapter is not a transaction
//! with Git: a durable create-once per-branch fence makes ambiguous retries read-only. A crash
//! after marker creation but before CAS sacrifices availability. A target already at the
//! candidate proves only state, never attribution. The service owner and root are trusted;
//! these checks do not protect against concurrent same-UID mutation or hostile Git resource
//! exhaustion. Production ingress, authoritative task ownership and independent stop remain
//! separate activation gates. ACL validation is implemented only on the locked macOS host.

use crate::{
    approval::{ApprovalAction, Operation},
    promotion_decision::PromotionDecision,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Debug, thiserror::Error)]
#[error("promotion execution refused or outcome unknown; inspect the exact target before recovery")]
pub struct ExecutionError;
type Result<T> = std::result::Result<T, ExecutionError>;
fn checked<T>(value: std::result::Result<T, impl std::fmt::Debug>) -> Result<T> {
    value.map_err(|_| ExecutionError)
}

/// Operator-provisioned configuration only. Never deserialize these paths from an ingress.
pub struct RepositoryBinding {
    pub repository: String,
    pub target_ref: String,
    pub bare_target: PathBuf,
    pub candidate_snapshot: PathBuf,
    pub owner_uid: u32,
}
struct PinnedBinding {
    config: RepositoryBinding,
    target_identity: (u64, u64),
    candidate_identity: (u64, u64),
    fingerprint: String,
}
pub struct TrustedPromotionRepositories {
    bindings: BTreeMap<String, PinnedBinding>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionIntent {
    task_id: String,
    generation: u64,
    nonce: String,
    action: ApprovalAction,
    mapping_fingerprint: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionDisposition {
    Advanced,
    ReconciledAlreadyAtCandidate,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReceipt {
    pub disposition: ExecutionDisposition,
    pub attribution_unknown: bool,
    pub task_id: String,
    pub generation: u64,
    pub nonce: String,
    pub repository: String,
    pub target_ref: String,
    pub base_sha: String,
    pub candidate_sha: String,
    pub evidence_digest: String,
}
impl ExecutionReceipt {
    fn new(intent: &ExecutionIntent, advanced: bool) -> Self {
        Self {
            disposition: if advanced {
                ExecutionDisposition::Advanced
            } else {
                ExecutionDisposition::ReconciledAlreadyAtCandidate
            },
            attribution_unknown: !advanced,
            task_id: intent.task_id.clone(),
            generation: intent.generation,
            nonce: intent.nonce.clone(),
            repository: intent.action.repository.clone(),
            target_ref: intent.action.target_ref.clone(),
            base_sha: intent.action.base_sha.clone(),
            candidate_sha: intent.action.candidate_sha.clone(),
            evidence_digest: intent.action.evidence_digest.clone(),
        }
    }
}
impl TrustedPromotionRepositories {
    pub fn new(configs: Vec<RepositoryBinding>) -> Result<Self> {
        if configs.is_empty() || configs.len() > 64 {
            return Err(ExecutionError);
        }
        let mut bindings = BTreeMap::new();
        for config in configs {
            if config.owner_uid == 0
                || config.owner_uid != unsafe { libc::geteuid() }
                || !config.target_ref.is_ascii()
                || config.repository.is_empty()
                || config.repository.len() > 256
                || config.repository.trim() != config.repository
                || config.repository.chars().any(char::is_control)
                || bindings.contains_key(&config.repository)
            {
                return Err(ExecutionError);
            }
            let target_identity = protected_root(&config.bare_target, config.owner_uid)?;
            let candidate_identity = protected_root(&config.candidate_snapshot, config.owner_uid)?;
            if config.bare_target.starts_with(&config.candidate_snapshot)
                || config.candidate_snapshot.starts_with(&config.bare_target)
            {
                return Err(ExecutionError);
            }
            protected_tree(&config.bare_target, config.owner_uid)?;
            protected_tree(&config.candidate_snapshot, config.owner_uid)?;
            protected_git_layout(&config)?;
            checked(evaluator::promotion_target_revision(
                &config.bare_target,
                &config.target_ref,
            ))?;
            let fingerprint = hash(&(
                &config.repository,
                &config.target_ref,
                &config.bare_target,
                &config.candidate_snapshot,
                config.owner_uid,
                target_identity,
                candidate_identity,
            ))?;
            bindings.insert(
                config.repository.clone(),
                PinnedBinding {
                    config,
                    target_identity,
                    candidate_identity,
                    fingerprint,
                },
            );
        }
        Ok(Self { bindings })
    }
    /// The caller must resolve this decision from the consumed authoritative object state.
    /// A decoded PromotionDecision alone is not permission to call execute_once.
    pub(crate) fn prepare(&self, decision: &PromotionDecision) -> Result<ExecutionIntent> {
        checked(decision.action.validate())?;
        if decision.generation == 0
            || decision.task_id != decision.action.task_id
            || decision.action.operation != Operation::Promote
            || decision.action.base_sha == decision.action.candidate_sha
            || !ulid::Ulid::from_string(&decision.nonce)
                .is_ok_and(|id| id.to_string() == decision.nonce)
        {
            return Err(ExecutionError);
        }
        let binding = self
            .bindings
            .get(&decision.action.repository)
            .ok_or(ExecutionError)?;
        if binding.config.target_ref != decision.action.target_ref {
            return Err(ExecutionError);
        }
        validate_binding(binding)?;
        Ok(ExecutionIntent {
            task_id: decision.task_id.clone(),
            generation: decision.generation,
            nonce: decision.nonce.clone(),
            action: decision.action.clone(),
            mapping_fingerprint: binding.fingerprint.clone(),
        })
    }
    pub(crate) fn matches_decision(
        &self,
        intent: &ExecutionIntent,
        decision: &PromotionDecision,
    ) -> Result<()> {
        if self.prepare(decision)? != *intent {
            return Err(ExecutionError);
        }
        Ok(())
    }
    fn binding(&self, intent: &ExecutionIntent) -> Result<&PinnedBinding> {
        let binding = self
            .bindings
            .get(&intent.action.repository)
            .ok_or(ExecutionError)?;
        if binding.fingerprint != intent.mapping_fingerprint
            || binding.config.target_ref != intent.action.target_ref
            || intent.task_id != intent.action.task_id
            || intent.generation == 0
            || intent.action.operation != Operation::Promote
            || intent.action.base_sha == intent.action.candidate_sha
            || !ulid::Ulid::from_string(&intent.nonce)
                .is_ok_and(|id| id.to_string() == intent.nonce)
        {
            return Err(ExecutionError);
        }
        checked(intent.action.validate())?;
        validate_binding(binding)?;
        Ok(binding)
    }
    /// At most one fresh CAS per configured repository branch, across tasks and restarted
    /// processes. A retained fence is never automatically cleared, even after known success.
    /// Same-intent attempts only reconcile; different intents require future verified recovery.
    pub(crate) fn execute_once(&self, intent: &ExecutionIntent) -> Result<ExecutionReceipt> {
        let binding = self.binding(intent)?;
        let current = checked(evaluator::promotion_target_revision(
            &binding.config.bare_target,
            &intent.action.target_ref,
        ))?;
        if current == intent.action.candidate_sha {
            return self.reconcile(intent);
        }
        if current != intent.action.base_sha {
            return Err(ExecutionError);
        }
        if !claim_attempt(binding, intent)? {
            return self.reconcile(intent);
        }
        validate_binding(binding)?;
        let result = evaluator::promote_verified_commit_to_ref(
            &binding.config.bare_target,
            &binding.config.candidate_snapshot,
            &intent.action.target_ref,
            &intent.action.base_sha,
            &intent.action.candidate_sha,
        );
        let observed = self.reconcile(intent)?;
        if result.is_ok() {
            Ok(ExecutionReceipt::new(intent, true))
        } else {
            Ok(observed)
        }
    }
    /// Read-only recovery. Already-at-candidate never establishes which actor changed Git.
    pub(crate) fn reconcile(&self, intent: &ExecutionIntent) -> Result<ExecutionReceipt> {
        let binding = self.binding(intent)?;
        if !checked(evaluator::promotion_target_matches(
            &binding.config.bare_target,
            &intent.action.target_ref,
            &intent.action.base_sha,
            &intent.action.candidate_sha,
        ))? {
            return Err(ExecutionError);
        }
        validate_binding(binding)?;
        Ok(ExecutionReceipt::new(intent, false))
    }
}
fn hash(value: &impl Serialize) -> Result<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(checked(serde_json::to_vec(value))?)
    ))
}
fn identity(meta: &fs::Metadata) -> (u64, u64) {
    (meta.dev(), meta.ino())
}
fn open_checked(path: &Path) -> Result<File> {
    checked(
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path),
    )
}
#[cfg(target_os = "macos")]
fn no_acl(file: &File) -> Result<()> {
    use std::os::fd::AsRawFd;
    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut libc::c_void;
        fn acl_free(value: *mut libc::c_void) -> libc::c_int;
    }
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), 0x100) };
    if !acl.is_null() {
        unsafe {
            acl_free(acl);
        };
        return Err(ExecutionError);
    }
    if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
        return Err(ExecutionError);
    }
    Ok(())
}
#[cfg(not(target_os = "macos"))]
fn no_acl(_file: &File) -> Result<()> {
    Err(ExecutionError)
}
fn protected_root(path: &Path, uid: u32) -> Result<(u64, u64)> {
    if !path.is_absolute() || checked(path.canonicalize())? != path {
        return Err(ExecutionError);
    }
    for ancestor in path.ancestors() {
        let file = open_checked(ancestor)?;
        let meta = checked(file.metadata())?;
        if !meta.is_dir() || (meta.uid() != 0 && meta.uid() != uid) || meta.mode() & 0o022 != 0 {
            return Err(ExecutionError);
        }
        no_acl(&file)?;
    }
    let meta = checked(fs::symlink_metadata(path))?;
    if meta.uid() != uid || meta.mode() & 0o7777 != 0o700 {
        return Err(ExecutionError);
    }
    Ok(identity(&meta))
}
fn protected_tree(root: &Path, uid: u32) -> Result<()> {
    let mut pending = vec![root.to_path_buf()];
    let mut entries = 0u64;
    let mut total = 0u64;
    while let Some(path) = pending.pop() {
        entries += 1;
        if entries > 20_000 {
            return Err(ExecutionError);
        }
        let file = open_checked(&path)?;
        let meta = checked(file.metadata())?;
        if meta.uid() != uid || meta.mode() & 0o022 != 0 || meta.mode() & 0o6000 != 0 {
            return Err(ExecutionError);
        }
        no_acl(&file)?;
        if meta.is_dir() {
            for entry in checked(fs::read_dir(&path))? {
                if entries + pending.len() as u64 >= 20_000 {
                    return Err(ExecutionError);
                }
                pending.push(checked(entry)?.path());
            }
        } else if meta.is_file() {
            total = total.checked_add(meta.len()).ok_or(ExecutionError)?;
            if meta.nlink() != 1 || meta.len() > 8 * 1024 * 1024 || total > 64 * 1024 * 1024 {
                return Err(ExecutionError);
            }
        } else {
            return Err(ExecutionError);
        }
    }
    Ok(())
}
fn protected_git_layout(config: &RepositoryBinding) -> Result<()> {
    // Git indirection files can escape a safe directory without filesystem symlinks.
    // Shared object stores and linked worktrees are deliberately unsupported here.
    for git_dir in [&config.bare_target, &config.candidate_snapshot.join(".git")] {
        if !checked(fs::symlink_metadata(git_dir))?.is_dir() {
            return Err(ExecutionError);
        }
        for name in [
            "commondir",
            "gitdir",
            "objects/info/alternates",
            "objects/info/http-alternates",
            "info/grafts",
            "shallow",
            "worktrees",
        ] {
            match fs::symlink_metadata(git_dir.join(name)) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(ExecutionError),
            }
        }
    }
    Ok(())
}
fn validate_binding(binding: &PinnedBinding) -> Result<()> {
    let config = &binding.config;
    if unsafe { libc::geteuid() } != config.owner_uid
        || protected_root(&config.bare_target, config.owner_uid)? != binding.target_identity
        || protected_root(&config.candidate_snapshot, config.owner_uid)?
            != binding.candidate_identity
    {
        return Err(ExecutionError);
    }
    protected_tree(&config.bare_target, config.owner_uid)?;
    protected_tree(&config.candidate_snapshot, config.owner_uid)?;
    protected_git_layout(config)
}
fn claim_attempt(binding: &PinnedBinding, intent: &ExecutionIntent) -> Result<bool> {
    let dir = binding
        .config
        .bare_target
        .join(".sfactory-promotion-intents");
    match fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {
            checked(File::open(&binding.config.bare_target))?
                .sync_all()
                .map_err(|_| ExecutionError)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(ExecutionError),
    }
    protected_root(&dir, binding.config.owner_uid)?;
    // Never treat old per-nonce records or unknown directory contents as an empty
    // repository-wide fence namespace during an upgrade.
    for entry in checked(fs::read_dir(&dir))? {
        let name = checked(entry)?.file_name();
        let name = name.to_str().ok_or(ExecutionError)?;
        let key = name
            .strip_prefix("ref-")
            .and_then(|name| name.strip_suffix(".json"))
            .ok_or(ExecutionError)?;
        if key.len() != 64
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ExecutionError);
        }
    }
    // A branch fence spans every task object/nonce sharing this physical repository.
    // ASCII case-folding conservatively aliases case-only refs on macOS filesystems;
    // non-ASCII configured refs are refused to avoid normalization alias ambiguity.
    let ref_key = hash(&binding.config.target_ref.to_ascii_lowercase())?;
    let path = dir.join(format!("ref-{ref_key}.json"));
    let encoded = checked(serde_json::to_vec(intent))?;
    if encoded.len() > 16 * 1024 {
        return Err(ExecutionError);
    }
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(mut file) => {
            checked(file.write_all(&encoded))?;
            checked(file.sync_all())?;
            checked(File::open(dir))?
                .sync_all()
                .map_err(|_| ExecutionError)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let file = open_checked(&path)?;
            let meta = checked(file.metadata())?;
            if !meta.is_file()
                || meta.uid() != binding.config.owner_uid
                || meta.mode() & 0o7777 != 0o600
                || meta.nlink() != 1
                || meta.len() == 0
                || meta.len() > 16 * 1024
            {
                return Err(ExecutionError);
            }
            no_acl(&file)?;
            let mut recorded = Vec::new();
            checked(file.take(16 * 1024 + 1).read_to_end(&mut recorded))?;
            if checked(serde_json::from_slice::<ExecutionIntent>(&recorded))? != *intent {
                return Err(ExecutionError);
            }
            Ok(false)
        }
        Err(_) => Err(ExecutionError),
    }
}
use std::os::unix::fs::DirBuilderExt;
#[cfg(test)]
#[path = "promotion_execution_tests.rs"]
mod tests;
