//! Private Linux runtime bootstrap. Root-owned configuration is authority, never request JSON.
use crate::{intake::IntakeRequest, qualifier::IntentFeatures, runtime_intake::Catalog};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateRuntimeConfig {
    pub service_uid: u32,
    pub operator_uid: u32,
    pub evaluator_uid: u32,
    pub worker_uid: u32,
    pub brake_uid: u32,
    pub journal_uid: u32,
    pub operator_socket_gid: u32,
    pub worker_socket_gid: u32,
    pub boot_id: String,
    pub namespace_dev: u64,
    pub namespace_ino: u64,
    /// Captured and checked by the root-owned installer in the host network namespace.
    pub host_namespace_dev: u64,
    pub host_namespace_ino: u64,
    pub sdk_port: u16,
    pub restate_ingress_port: u16,
    pub postgres_port: u16,
    pub principal: String,
    pub worker_id: String,
    pub queue_id: String,
    pub intent_id: String,
    pub task_id: String,
    pub request: IntakeRequest,
    pub facts: TrustedFacts,
    pub evidence_sha256: String,
    /// Root-provisioned fixed generation; absent means launch grants are disabled.
    #[serde(default)]
    pub launch_scope: Option<crate::launch_reservation::LaunchScope>,
}
#[derive(Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedFacts {
    pub spec_clarity: f64,
    pub blast_radius: f64,
    pub novelty: f64,
    pub reversibility: f64,
    pub has_codified_knowledge: bool,
    pub fatal: bool,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipeEvidence {
    principal: String,
    request: IntakeRequest,
    facts: TrustedFacts,
}

impl PrivateRuntimeConfig {
    /// Bind every preserved scope to the same process, operator and private journal.
    pub fn registry_compatible(&self, other: &Self) -> bool {
        self.boot_id == other.boot_id
            && self.service_uid == other.service_uid
            && self.operator_uid == other.operator_uid
            && self.worker_uid == other.worker_uid
            && self.evaluator_uid == other.evaluator_uid
            && self.journal_uid == other.journal_uid
            && self.brake_uid == other.brake_uid
            && self.operator_socket_gid == other.operator_socket_gid
            && self.worker_socket_gid == other.worker_socket_gid
            && self.namespace_dev == other.namespace_dev
            && self.namespace_ino == other.namespace_ino
            && self.host_namespace_dev == other.host_namespace_dev
            && self.host_namespace_ino == other.host_namespace_ino
            && self.principal == other.principal
            && self.postgres_port == other.postgres_port
            && self.restate_ingress_port == other.restate_ingress_port
    }
    pub fn validate(
        &self,
        service_uid: u32,
        netns: (u64, u64),
        evidence_sha256: &str,
    ) -> anyhow::Result<()> {
        let mut ids = std::collections::BTreeSet::new();
        for uid in [
            self.service_uid,
            self.operator_uid,
            self.evaluator_uid,
            self.worker_uid,
            self.brake_uid,
            self.journal_uid,
        ] {
            anyhow::ensure!(uid > 0 && ids.insert(uid), "invalid identity separation");
        }
        anyhow::ensure!(
            service_uid == self.service_uid
                && self.operator_socket_gid > 0
                && self.worker_socket_gid > 0
                && self.operator_socket_gid != self.worker_socket_gid,
            "runtime identity mismatch"
        );
        anyhow::ensure!(
            netns == (self.namespace_dev, self.namespace_ino)
                && netns != (self.host_namespace_dev, self.host_namespace_ino)
                && self.namespace_ino != 0
                && self.host_namespace_ino != 0,
            "network namespace mismatch"
        );
        anyhow::ensure!(
            self.boot_id.len() == 36
                && self
                    .boot_id
                    .bytes()
                    .enumerate()
                    .all(|(i, b)| if [8, 13, 18, 23].contains(&i) {
                        b == b'-'
                    } else {
                        b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                    }),
            "invalid boot identity"
        );
        let mut ports = std::collections::BTreeSet::new();
        for port in [self.sdk_port, self.restate_ingress_port, self.postgres_port] {
            anyhow::ensure!(
                port >= 1024 && ports.insert(port),
                "invalid private port scope"
            );
        }
        anyhow::ensure!(
            !self.worker_id.is_empty()
                && self.worker_id.len() <= 256
                && self
                    .worker_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
            "invalid worker scope"
        );
        anyhow::ensure!(
            self.evidence_sha256 == evidence_sha256,
            "catalog evidence mismatch"
        );
        self.catalog()?;
        if let Some(scope) = &self.launch_scope {
            scope.validate()?;
            anyhow::ensure!(
                scope.task_id == self.task_id
                    && scope.intent_id == self.intent_id
                    && scope.queue_id == self.queue_id
                    && scope.worker_id == self.worker_id
                    && scope.spec.repository == self.request.repository
                    && scope.spec.base_revision == self.request.base_revision
                    && scope.catalog_sha256 == self.catalog()?.fingerprint()?
                    && ulid::Ulid::from_string(&scope.generation)
                        .is_ok_and(|u| u.to_string() == scope.generation),
                "root launch scope mismatch"
            );
        }
        Ok(())
    }
    /// Root-protected evidence must assert the exact recipe and factors, not only a digest.
    pub fn verify_evidence(&self, bytes: &[u8]) -> anyhow::Result<()> {
        let evidence: RecipeEvidence = serde_json::from_slice(bytes)?;
        anyhow::ensure!(
            evidence.principal == self.principal
                && evidence.request == self.request
                && evidence.facts == self.facts,
            "recipe evidence binding mismatch"
        );
        Ok(())
    }
    pub fn catalog(&self) -> anyhow::Result<Catalog> {
        Catalog::new(
            self.principal.clone(),
            self.queue_id.clone(),
            self.intent_id.clone(),
            self.task_id.clone(),
            self.request.clone(),
            IntentFeatures {
                spec_clarity: self.facts.spec_clarity,
                blast_radius: self.facts.blast_radius,
                novelty: self.facts.novelty,
                reversibility: self.facts.reversibility,
                has_codified_knowledge: self.facts.has_codified_knowledge,
                fatal: self.facts.fatal,
            },
            self.evidence_sha256.clone(),
        )
    }
}
/// Read only from fixed root-owned descriptors. Every ACL or uncertain ACL read is refused.
#[cfg(target_os = "linux")]
pub fn load_root_catalog() -> anyhow::Result<(PrivateRuntimeConfig, String)> {
    load_catalog_named("runtime.json", "evidence.json", None)
}

/// Fixed separate catalog for the opt-in sidecar; no request selects filesystem paths.
#[cfg(all(target_os = "linux", feature = "grant-sidecar"))]
pub fn load_grant_sidecar_catalog() -> anyhow::Result<(PrivateRuntimeConfig, String)> {
    load_catalog_named("grant-runtime.json", "grant-evidence.json", None)
}

/// The sidecar preserves the original canary catalog and requires its exact reviewed bytes.
#[cfg(all(target_os = "linux", feature = "grant-sidecar"))]
pub fn load_preserved_canary_catalog() -> anyhow::Result<(PrivateRuntimeConfig, String)> {
    load_catalog_named(
        "runtime.json",
        "evidence.json",
        Some("53082a93e3405f49f70ca5ea5681565a88cc3e1ca6d23397c803f4f5bfe152f6"),
    )
}

#[cfg(all(target_os = "linux", feature = "real-sidecar"))]
pub fn load_real_catalog() -> anyhow::Result<(PrivateRuntimeConfig, String)> {
    load_catalog_named("real-runtime.json", "real-evidence.json", None)
}
#[cfg(all(target_os = "linux", feature = "real-sidecar"))]
pub fn load_preserved_grant_catalog() -> anyhow::Result<(PrivateRuntimeConfig, String)> {
    load_catalog_named(
        "grant-runtime.json",
        "grant-evidence.json",
        Some("70c14a65b8229304e04eb7e693eb7dc2ef20c7c947349e2e09e0b08dae84547f"),
    )
}

/// Load the fixed root-owned registry and each pinned catalog. No caller provides paths.
#[cfg(all(target_os = "linux", feature = "registry-sidecar"))]
pub fn load_catalog_registry() -> anyhow::Result<(
    crate::catalog_registry::Registry,
    Vec<(PrivateRuntimeConfig, String)>,
)> {
    use std::{
        ffi::CString,
        fs::File,
        io::Read,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::MetadataExt,
        },
    };
    fn open(parent: i32, name: &str, flags: i32) -> anyhow::Result<File> {
        let name = CString::new(name)?;
        // SAFETY: terminated name and newly returned owned descriptor.
        let fd = unsafe {
            libc::openat(
                parent,
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        anyhow::ensure!(fd >= 0, "registry path unavailable");
        // SAFETY: fd was acquired above and has not been transferred.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn directory(f: &File) -> anyhow::Result<()> {
        let m = f.metadata()?;
        anyhow::ensure!(
            m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
            "registry ancestor unsafe"
        );
        let path = CString::new(format!("/proc/self/fd/{}", f.as_raw_fd()))?;
        for name in ["system.posix_acl_access", "system.posix_acl_default"] {
            let name = CString::new(name)?;
            // SAFETY: C strings are valid and null buffer requests size only.
            let result =
                unsafe { libc::getxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
            anyhow::ensure!(
                result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA),
                "registry ancestor ACL unavailable"
            );
        }
        Ok(())
    }
    let root = open(libc::AT_FDCWD, "/", libc::O_PATH | libc::O_DIRECTORY)?;
    directory(&root)?;
    let etc = open(root.as_raw_fd(), "etc", libc::O_PATH | libc::O_DIRECTORY)?;
    directory(&etc)?;
    let dir = open(
        etc.as_raw_fd(),
        "software-factory-goose",
        libc::O_PATH | libc::O_DIRECTORY,
    )?;
    directory(&dir)?;
    let mut f = open(
        dir.as_raw_fd(),
        "catalog-registry.json",
        libc::O_RDONLY | libc::O_NONBLOCK,
    )?;
    let m = f.metadata()?;
    anyhow::ensure!(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o644
            && m.len() <= 65536,
        "registry manifest unsafe"
    );
    let attr = CString::new("system.posix_acl_access")?;
    // SAFETY: fd and C string are valid; null buffer requests size only.
    let result = unsafe { libc::fgetxattr(f.as_raw_fd(), attr.as_ptr(), std::ptr::null_mut(), 0) };
    anyhow::ensure!(
        result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA),
        "registry ACL unavailable"
    );
    let mut bytes = Vec::new();
    f.by_ref().take(65537).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() as u64 == m.len(), "registry changed");
    let registry: crate::catalog_registry::Registry = serde_json::from_slice(&bytes)?;
    registry.validate()?;
    let mut catalogs = Vec::new();
    for entry in &registry.entries {
        let (cfg, evidence) =
            load_catalog_named(&entry.config, &entry.evidence, Some(&entry.config_sha256))?;
        anyhow::ensure!(
            evidence == entry.evidence_sha256
                && cfg.catalog()?.fingerprint()? == entry.catalog_sha256,
            "registry catalog digest mismatch"
        );
        catalogs.push((cfg, evidence));
    }
    Ok((registry, catalogs))
}

#[cfg(target_os = "linux")]
fn load_catalog_named(
    config_name: &str,
    evidence_name: &str,
    expected_config_sha256: Option<&str>,
) -> anyhow::Result<(PrivateRuntimeConfig, String)> {
    use sha2::{Digest, Sha256};
    use std::{
        ffi::CString,
        fs::File,
        io::Read,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::MetadataExt,
        },
    };
    fn open_at(parent: i32, name: &str, flags: i32) -> anyhow::Result<File> {
        let name = CString::new(name)?;
        // SAFETY: name is NUL terminated and the acquired descriptor is uniquely owned.
        let fd = unsafe {
            libc::openat(
                parent,
                name.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: fd is newly acquired and has not been transferred elsewhere.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn protected(file: &File, directory: bool) -> anyhow::Result<()> {
        let m = file.metadata()?;
        anyhow::ensure!(
            m.uid() == 0
                && m.mode() & 0o022 == 0
                && if directory {
                    m.is_dir()
                } else {
                    m.is_file() && m.nlink() == 1 && m.mode() & 0o111 == 0
                },
            "unprotected bootstrap object"
        );
        let names: &[&str] = if directory {
            &["system.posix_acl_access", "system.posix_acl_default"]
        } else {
            &["system.posix_acl_access"]
        };
        for name in names {
            let name = CString::new(*name)?;
            // O_PATH directory descriptors cannot be passed to fgetxattr. The
            // kernel-owned proc fd link resolves the already-pinned descriptor,
            // without re-resolving any caller-controlled ancestor.
            let size = if directory {
                let pinned = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
                // SAFETY: both strings are NUL terminated and this is a size query.
                unsafe { libc::getxattr(pinned.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) }
            } else {
                // SAFETY: the regular-file descriptor and attribute are valid.
                unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) }
            };
            if size >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENODATA) {
                anyhow::bail!("bootstrap ACL unavailable or present");
            }
        }
        Ok(())
    }
    let root = open_at(libc::AT_FDCWD, "/", libc::O_PATH | libc::O_DIRECTORY)?;
    protected(&root, true)?;
    let etc = open_at(root.as_raw_fd(), "etc", libc::O_PATH | libc::O_DIRECTORY)?;
    protected(&etc, true)?;
    let directory = open_at(
        etc.as_raw_fd(),
        "software-factory-goose",
        libc::O_PATH | libc::O_DIRECTORY,
    )?;
    protected(&directory, true)?;
    let mut config = open_at(
        directory.as_raw_fd(),
        config_name,
        libc::O_RDONLY | libc::O_NONBLOCK,
    )?;
    protected(&config, false)?;
    let mut evidence = open_at(
        directory.as_raw_fd(),
        evidence_name,
        libc::O_RDONLY | libc::O_NONBLOCK,
    )?;
    protected(&evidence, false)?;
    let mut config_bytes = Vec::new();
    config.by_ref().take(65537).read_to_end(&mut config_bytes)?;
    anyhow::ensure!(config_bytes.len() <= 65536, "config too large");
    let mut evidence_bytes = Vec::new();
    evidence
        .by_ref()
        .take(65537)
        .read_to_end(&mut evidence_bytes)?;
    anyhow::ensure!(
        !evidence_bytes.is_empty() && evidence_bytes.len() <= 65536,
        "evidence unavailable"
    );
    if let Some(expected) = expected_config_sha256 {
        anyhow::ensure!(
            format!("{:x}", Sha256::digest(&config_bytes)) == expected,
            "preserved catalog bytes changed"
        );
    }
    let parsed = serde_json::from_slice::<PrivateRuntimeConfig>(&config_bytes)?;
    parsed.verify_evidence(&evidence_bytes)?;
    Ok((parsed, format!("{:x}", Sha256::digest(evidence_bytes))))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> PrivateRuntimeConfig {
        serde_json::from_value(serde_json::json!({"service_uid":1001,"operator_uid":1000,"evaluator_uid":1002,"worker_uid":1003,"brake_uid":1004,"journal_uid":1005,"operator_socket_gid":1234,"worker_socket_gid":1235,"boot_id":"12345678-1234-1234-1234-123456789abc","namespace_dev":4,"namespace_ino":5,"host_namespace_dev":4,"host_namespace_ino":7,"sdk_port":9080,"restate_ingress_port":8080,"postgres_port":5432,"principal":"operator","worker_id":"worker","queue_id":"queue","intent_id":"01J00000000000000000000000","task_id":"01J00000000000000000000001","request":{"schema_version":1,"repository":"r","target_ref":"refs/heads/main","base_revision":"a".repeat(40),"intent":"build","acceptance_criteria":["test"]},"facts":{"spec_clarity":1.0,"blast_radius":0.0,"novelty":0.0,"reversibility":0.0,"has_codified_knowledge":true,"fatal":false},"evidence_sha256":"a".repeat(64)})).unwrap()
    }
    #[test]
    fn registry_rejects_changed_roles_namespace_and_journal() {
        let a = config();
        let mut b = config();
        assert!(a.registry_compatible(&b));
        b.worker_uid += 1;
        assert!(!a.registry_compatible(&b));
        b = config();
        b.namespace_ino += 1;
        assert!(!a.registry_compatible(&b));
        b = config();
        b.host_namespace_ino += 1;
        assert!(!a.registry_compatible(&b));
        b = config();
        b.postgres_port += 1;
        assert!(!a.registry_compatible(&b));
        b = config();
        b.principal = "other".into();
        assert!(!a.registry_compatible(&b));
    }
    #[test]
    fn refuses_mismatched_identity_namespace_and_evidence() {
        let mut c = config();
        assert!(c.validate(1001, (4, 5), &"a".repeat(64)).is_ok());
        assert!(c.validate(1000, (4, 5), &"a".repeat(64)).is_err());
        c.host_namespace_ino = 5;
        assert!(c.validate(1001, (4, 5), &"a".repeat(64)).is_err());
        c.host_namespace_ino = 7;
        assert!(c.validate(1001, (4, 6), &"a".repeat(64)).is_err());
        assert!(c.validate(1001, (4, 5), &"b".repeat(64)).is_err());
        c.worker_uid = 1000;
        assert!(c.validate(1001, (4, 5), &"a".repeat(64)).is_err());
    }
    #[test]
    fn evidence_cannot_substitute_recipe_or_factors() {
        let config = config();
        let mut evidence = serde_json::json!({"principal":"operator","request":{"schema_version":1,"repository":"r","target_ref":"refs/heads/main","base_revision":"a".repeat(40),"intent":"build","acceptance_criteria":["test"]},"facts":{"spec_clarity":1.0,"blast_radius":0.0,"novelty":0.0,"reversibility":0.0,"has_codified_knowledge":true,"fatal":false}});
        assert!(
            config
                .verify_evidence(&serde_json::to_vec(&evidence).unwrap())
                .is_ok()
        );
        evidence["request"]["intent"] = serde_json::json!("other");
        assert!(
            config
                .verify_evidence(&serde_json::to_vec(&evidence).unwrap())
                .is_err()
        );
    }
    #[test]
    fn launch_scope_is_root_catalog_bound() {
        let mut c = config();
        c.launch_scope = Some(crate::launch_reservation::LaunchScope {
            task_id: c.task_id.clone(),
            intent_id: c.intent_id.clone(),
            queue_id: c.queue_id.clone(),
            generation: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            spec: crate::workflow::LeaseSpec {
                repository: c.request.repository.clone(),
                base_revision: c.request.base_revision.clone(),
            },
            worker_id: c.worker_id.clone(),
            catalog_sha256: c.catalog().unwrap().fingerprint().unwrap(),
        });
        assert!(c.validate(1001, (4, 5), &"a".repeat(64)).is_ok());
        c.launch_scope.as_mut().unwrap().catalog_sha256 = "b".repeat(64);
        assert!(c.validate(1001, (4, 5), &"a".repeat(64)).is_err());
        c.launch_scope.as_mut().unwrap().catalog_sha256 =
            c.catalog().unwrap().fingerprint().unwrap();
        c.launch_scope.as_mut().unwrap().generation = "caller-label".into();
        assert!(c.validate(1001, (4, 5), &"a".repeat(64)).is_err());
        c.launch_scope.as_mut().unwrap().generation = "01ARZ3NDEKTSV4RRFFQ69G5FAV".into();
        c.launch_scope.as_mut().unwrap().intent_id = "other".into();
        assert!(c.validate(1001, (4, 5), &"a".repeat(64)).is_err());
        c.launch_scope.as_mut().unwrap().intent_id = c.intent_id.clone();
        c.launch_scope.as_mut().unwrap().queue_id = "other".into();
        assert!(c.validate(1001, (4, 5), &"a".repeat(64)).is_err());
    }
    #[test]
    fn duplicate_ports_and_untrusted_fields_are_rejected() {
        let mut c = config();
        c.sdk_port = c.postgres_port;
        assert!(c.validate(1001, (4, 5), &"a".repeat(64)).is_err());
        let mut value = serde_json::to_value(serde_json::json!({"unknown":1})).unwrap();
        value["caller_approval"] = serde_json::json!(true);
        assert!(serde_json::from_value::<PrivateRuntimeConfig>(value).is_err());
    }
}
