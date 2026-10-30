use clap::{Subcommand, ValueEnum};

#[cfg(any(target_os = "linux", test))]
fn finalization_summary(
    value: &serde_json::Value,
    generation: &str,
) -> anyhow::Result<serde_json::Value> {
    use anyhow::{Context, ensure};
    ensure!(
        value.get("generation").and_then(|v| v.as_str()) == Some(generation)
            && value
                .get("approval_not_established_by_finalization")
                .and_then(|v| v.as_bool())
                == Some(true),
        "status scope or approval mismatch"
    );
    let claim = value
        .get("legacy_claim")
        .context("historical status missing")?;
    let historical = if claim.is_null() {
        serde_json::Value::Null
    } else {
        let fields = claim.as_object().context("invalid historical status")?;
        ensure!(
            fields.len() == 3
                && fields.contains_key("version")
                && fields.contains_key("stage")
                && fields.contains_key("attempts")
                && fields["version"].is_u64()
                && fields["attempts"].is_u64()
                && matches!(
                    fields["stage"].as_str(),
                    Some("Queued" | "Leased" | "CoolingDown" | "Evaluating" | "Failed")
                ),
            "unsafe historical status"
        );
        claim.clone()
    };
    let finalization = value.get("finalization").context("finalization missing")?;
    let (outcome, projection) = if finalization.is_null() {
        ("unfinalized", "unavailable")
    } else {
        let outcome = finalization
            .pointer("/record/evidence/kind")
            .and_then(|v| v.as_str())
            .context("outcome missing")?;
        let projection = finalization
            .get("export")
            .and_then(|v| v.as_str())
            .context("projection missing")?;
        ensure!(
            matches!(outcome, "evaluated_pass" | "evaluated_fail" | "unknown")
                && matches!(projection, "pending" | "current" | "quarantined")
                && finalization
                    .pointer("/record/reservation/generation")
                    .and_then(|v| v.as_str())
                    == Some(generation),
            "invalid finalization summary"
        );
        (outcome, projection)
    };
    Ok(
        serde_json::json!({"generation":generation,"outcome":outcome,"projection":projection,"actual_spend":"unknown","promotion":"not established","legacy_claim":historical,"legacy_claim_is_historical":value.get("legacy_claim_is_historical").and_then(|v|v.as_bool()).context("historical flag missing")?}),
    )
}

#[cfg(any(target_os = "linux", test))]
fn finalization_socket(generation: &str) -> anyhow::Result<std::path::PathBuf> {
    anyhow::ensure!(
        ulid::Ulid::from_string(generation).is_ok_and(|id| id.to_string() == generation),
        "invalid canonical generation"
    );
    Ok(format!("/run/software-factory-goose/root-finalization/{generation}.sock").into())
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum IntakeProfile {
    Fixture,
    Real,
    Registry,
}
impl IntakeProfile {
    #[cfg(any(target_os = "linux", test))]
    fn socket(self) -> &'static str {
        match self {
            Self::Fixture => "/run/software-factory-goose/intake.sock",
            Self::Real => "/run/software-factory-goose/real-intake.sock",
            Self::Registry => "/run/software-factory-goose/registry-intake.sock",
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum PrivateCommand {
    Submit {
        #[arg(long)]
        id: String,
        #[arg(long)]
        request: std::path::PathBuf,
        #[arg(long, value_enum, default_value = "fixture")]
        profile: IntakeProfile,
    },
    Inspect {
        id: String,
        #[arg(long, value_enum, default_value = "fixture")]
        profile: IntakeProfile,
    },
    /// Read the authoritative additive outcome; this does not approve promotion.
    Finalization { generation: String },
    Stop {
        target: String,
        #[arg(long)]
        brake_key_file: std::path::PathBuf,
    },
    Status {
        target: String,
        #[arg(long)]
        brake_key_file: std::path::PathBuf,
    },
}

#[cfg(any(target_os = "linux", test))]
fn operator_identity(uid: u32, euid: u32) -> bool {
    uid == 1000 && euid == 1000
}
#[cfg(any(target_os = "linux", test))]
fn safe_root_parent(uid: u32, mode: u32, acl: bool) -> bool {
    uid == 0 && mode & 0o022 == 0 && !acl
}
#[cfg(any(target_os = "linux", test))]
fn safe_key_file(uid: u32, mode: u32, links: u64, acl: bool) -> bool {
    uid == 1000 && mode & 0o7777 == 0o600 && links == 1 && !acl
}
#[cfg(any(target_os = "linux", test))]
fn safe_socket(uid: u32, gid: u32, mode: u32, acl: bool) -> bool {
    uid == 0 && gid == 1000 && mode & 0o7777 == 0o660 && !acl
}

#[cfg(not(target_os = "linux"))]
pub async fn run(_: PrivateCommand, _: bool) -> anyhow::Result<()> {
    anyhow::bail!("private mode requires the provisioned Linux host")
}

#[cfg(target_os = "linux")]
pub async fn run(command: PrivateCommand, json_output: bool) -> anyhow::Result<()> {
    linux::run(command, json_output).await
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{
        PrivateCommand, finalization_socket, finalization_summary, operator_identity,
        safe_key_file, safe_root_parent, safe_socket,
    };
    use anyhow::{Context, ensure};
    use reqwest::header::HeaderValue;
    use serde::Deserialize;
    use sha2::{Digest, Sha256};
    use std::{
        ffi::CString,
        fs::{self, File, OpenOptions},
        io::Read,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{
                ffi::OsStrExt,
                fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
            },
        },
        path::{Component, Path, PathBuf},
        time::Duration,
    };

    const BRAKE: &str = "/run/software-factory-goose/brake.sock";
    const INPUT_LIMIT: usize = 60 * 1024;
    const OUTPUT_LIMIT: usize = 1024 * 1024;

    fn canonical_id(s: &str) -> anyhow::Result<()> {
        ensure!(
            ulid::Ulid::from_string(s).is_ok_and(|id| id.to_string() == s),
            "invalid canonical identifier"
        );
        Ok(())
    }
    #[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FinalizationAttestation {
        schema: u32,
        generation: String,
        boot_id: String,
        service_unit: String,
        socket_unit: String,
        main_pid: u32,
        invocation_id: String,
        exec_start: String,
        binary_sha256: String,
        service_unit_sha256: String,
        socket_unit_sha256: String,
        fragment_path: String,
        drop_in_paths: Vec<String>,
        private_namespace_dev: u64,
        private_namespace_ino: u64,
        anchor_unit: String,
        anchor_main_pid: u32,
        anchor_invocation_id: String,
        socket_dev: u64,
        socket_ino: u64,
        bootstrap_sha256: String,
    }
    fn protected_public(path: &Path, mode: u32, limit: usize) -> anyhow::Result<Vec<u8>> {
        let dir = open_directory_path(path.parent().context("protected parent missing")?, false)?;
        let mut file = open_child(
            &dir,
            path.file_name().context("protected filename missing")?,
            false,
        )?;
        let before = file.metadata()?;
        ensure!(
            before.is_file()
                && before.uid() == 0
                && before.gid() == 0
                && before.nlink() == 1
                && before.mode() & 0o7777 == mode
                && !has_acl(file.as_raw_fd())?
                && before.len() <= limit as u64,
            "unsafe protected file"
        );
        let mut bytes = Vec::new();
        (&mut file).take(limit as u64 + 1).read_to_end(&mut bytes)?;
        let after = file.metadata()?;
        ensure!(
            bytes.len() <= limit
                && bytes.len() as u64 == before.len()
                && (
                    before.dev(),
                    before.ino(),
                    before.len(),
                    before.mtime(),
                    before.mtime_nsec(),
                    before.ctime(),
                    before.ctime_nsec()
                ) == (
                    after.dev(),
                    after.ino(),
                    after.len(),
                    after.mtime(),
                    after.mtime_nsec(),
                    after.ctime(),
                    after.ctime_nsec()
                ),
            "protected file changed"
        );
        Ok(bytes)
    }
    fn verify_hash(path: &Path, mode: u32, expected: &str, limit: usize) -> anyhow::Result<()> {
        ensure!(
            expected.len() == 64
                && expected
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid attestation digest"
        );
        ensure!(
            format!("{:x}", Sha256::digest(protected_public(path, mode, limit)?)) == expected,
            "attested file changed"
        );
        Ok(())
    }
    async fn manager_properties(
        unit: &str,
    ) -> anyhow::Result<std::collections::BTreeMap<String, String>> {
        let binary = Path::new("/usr/bin/systemctl");
        let _ = protected_public(binary, 0o755, 32 * 1024 * 1024)?;
        let mut command = tokio::process::Command::new(binary);
        command.env_clear().env("PATH","/usr/bin:/bin").env("HOME","/nonexistent").env("LC_ALL","C").kill_on_drop(true).args(["show",unit,"--property=LoadState,ActiveState,MainPID,InvocationID,Names,FragmentPath,DropInPaths,ExecStart,User,Group,NoNewPrivileges,CapabilityBoundingSet,PrivateNetwork,BindsTo,JoinsNamespaceOf","--all","--no-pager"]);
        let output = tokio::time::timeout(Duration::from_secs(5), command.output()).await??;
        ensure!(
            output.status.success() && output.stdout.len() <= 32768 && output.stderr.len() <= 4096,
            "manager unavailable"
        );
        let mut props = std::collections::BTreeMap::new();
        for line in std::str::from_utf8(&output.stdout)?.lines() {
            let (k, v) = line.split_once('=').context("invalid manager property")?;
            ensure!(
                props.insert(k.to_string(), v.to_string()).is_none(),
                "duplicate manager property"
            );
        }
        Ok(props)
    }
    async fn finalization_attestation(
        generation: &str,
        socket: &Path,
    ) -> anyhow::Result<FinalizationAttestation> {
        canonical_id(generation)?;
        let manifest = PathBuf::from(format!(
            "/etc/software-factory-goose/finalization/{generation}.process.json"
        ));
        let value: FinalizationAttestation =
            serde_json::from_slice(&protected_public(&manifest, 0o444, 16384)?)?;
        let service = format!("software-factory-goose-root-finalization@{generation}.service");
        let socket_unit = format!("software-factory-goose-root-finalization@{generation}.socket");
        let fragment = "/etc/systemd/system/software-factory-goose-root-finalization@.service";
        let binary = "/usr/local/libexec/software-factory-goose/root_finalization_runtime";
        let anchor = "software-factory-goose-private-net.service";
        ensure!(
            value.schema == 1
                && value.generation == generation
                && value.service_unit == service
                && value.socket_unit == socket_unit
                && value.fragment_path == fragment
                && value.drop_in_paths.is_empty()
                && value.anchor_unit == anchor
                && value.main_pid > 0
                && value.anchor_main_pid > 0
                && value.private_namespace_dev > 0
                && value.private_namespace_ino > 0,
            "attestation scope mismatch"
        );
        ensure!(
            value.bootstrap_sha256.len() == 64
                && value
                    .bootstrap_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid bootstrap digest"
        );
        for id in [&value.invocation_id, &value.anchor_invocation_id] {
            ensure!(
                id.len() == 32
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "invalid invocation identity"
            );
        }
        ensure!(
            fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() == value.boot_id,
            "attestation boot changed"
        );
        verify_hash(Path::new(binary), 0o755, &value.binary_sha256, 100_000_000)?;
        verify_hash(
            Path::new(fragment),
            0o644,
            &value.service_unit_sha256,
            65536,
        )?;
        verify_hash(
            Path::new("/etc/systemd/system/software-factory-goose-root-finalization@.socket"),
            0o644,
            &value.socket_unit_sha256,
            65536,
        )?;
        let m = fs::symlink_metadata(socket)?;
        ensure!(
            m.file_type().is_socket()
                && safe_socket(m.uid(), m.gid(), m.mode(), socket_has_acl(socket)?)
                && m.nlink() == 1
                && (m.dev(), m.ino()) == (value.socket_dev, value.socket_ino),
            "attested socket changed"
        );
        let p = manager_properties(&service).await?;
        let a = manager_properties(anchor).await?;
        let s = manager_properties(&socket_unit).await?;
        let pid = value.main_pid.to_string();
        let anchor_pid = value.anchor_main_pid.to_string();
        for (k, v) in [
            ("LoadState", "loaded"),
            ("ActiveState", "active"),
            ("Names", service.as_str()),
            ("FragmentPath", fragment),
            ("DropInPaths", ""),
            ("User", "root"),
            ("Group", "root"),
            ("NoNewPrivileges", "yes"),
            ("CapabilityBoundingSet", ""),
            ("PrivateNetwork", "yes"),
            ("BindsTo", anchor),
            ("JoinsNamespaceOf", anchor),
            ("MainPID", pid.as_str()),
            ("InvocationID", value.invocation_id.as_str()),
            ("ExecStart", value.exec_start.as_str()),
        ] {
            ensure!(
                p.get(k).map(String::as_str) == Some(v),
                "service attestation changed: {k}"
            );
        }
        ensure!(
            value.exec_start.starts_with(&format!(
                "{{ path={binary} ; argv[]={binary} {generation} ; ignore_errors=no ;"
            )) && value.exec_start.matches("{ path=").count() == 1,
            "attested command mismatch"
        );
        for (k, v) in [
            ("LoadState", "loaded"),
            ("ActiveState", "active"),
            ("Names", anchor),
            ("MainPID", anchor_pid.as_str()),
            ("InvocationID", value.anchor_invocation_id.as_str()),
        ] {
            ensure!(
                a.get(k).map(String::as_str) == Some(v),
                "anchor identity changed: {k}"
            );
        }
        for (k, v) in [
            ("LoadState", "loaded"),
            ("ActiveState", "active"),
            ("Names", socket_unit.as_str()),
            (
                "FragmentPath",
                "/etc/systemd/system/software-factory-goose-root-finalization@.socket",
            ),
            ("DropInPaths", ""),
        ] {
            ensure!(
                s.get(k).map(String::as_str) == Some(v),
                "socket unit identity changed: {k}"
            );
        }
        Ok(value)
    }
    fn has_acl(fd: i32) -> anyhow::Result<bool> {
        has_acl_named(fd, c"system.posix_acl_access")
    }
    fn has_acl_named(fd: i32, name: &std::ffi::CStr) -> anyhow::Result<bool> {
        // O_PATH permits traversal of root-owned 0711 parents without read
        // permission; /proc/self/fd resolves this already pinned descriptor.
        let path = CString::new(format!("/proc/self/fd/{fd}"))?;
        let result =
            unsafe { libc::getxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
        if result >= 0 {
            return Ok(true);
        }
        let e = std::io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::ENODATA) => Ok(false),
            _ => Err(anyhow::anyhow!("cannot verify file ACL")),
        }
    }
    fn socket_has_acl(path: &Path) -> anyhow::Result<bool> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let result = unsafe {
            libc::lgetxattr(
                path.as_ptr(),
                c"system.posix_acl_access".as_ptr(),
                std::ptr::null_mut(),
                0,
            )
        };
        if result >= 0 {
            return Ok(true);
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ENODATA) => Ok(false),
            _ => Err(anyhow::anyhow!("cannot verify socket ACL")),
        }
    }
    fn open_child(dir: &File, name: &std::ffi::OsStr, directory: bool) -> anyhow::Result<File> {
        let name = CString::new(name.as_bytes())?;
        let flags = libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | if directory {
                libc::O_PATH | libc::O_DIRECTORY
            } else {
                libc::O_RDONLY | libc::O_NONBLOCK
            };
        let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
        ensure!(fd >= 0, "cannot open protected path");
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn open_directory_path(path: &Path, owner_key: bool) -> anyhow::Result<File> {
        ensure!(path.is_absolute(), "protected path must be absolute");
        let mut dir = File::open("/")?;
        let root = dir.metadata()?;
        ensure!(
            safe_root_parent(root.uid(), root.mode(), has_acl(dir.as_raw_fd())?)
                && !has_acl_named(dir.as_raw_fd(), c"system.posix_acl_default")?,
            "unsafe root directory"
        );
        for part in path.components() {
            match part {
                Component::RootDir => (),
                Component::Normal(name) => {
                    dir = open_child(&dir, name, true)?;
                    let meta = dir.metadata()?;
                    let valid = if owner_key {
                        (meta.uid() == 0 || meta.uid() == 1000)
                            && meta.mode() & 0o022 == 0
                            && !has_acl(dir.as_raw_fd())?
                    } else {
                        safe_root_parent(meta.uid(), meta.mode(), has_acl(dir.as_raw_fd())?)
                    };
                    ensure!(
                        meta.is_dir()
                            && valid
                            && !has_acl_named(dir.as_raw_fd(), c"system.posix_acl_default")?,
                        "unsafe protected parent directory"
                    );
                }
                _ => anyhow::bail!("invalid protected path"),
            }
        }
        Ok(dir)
    }
    fn read_key(path: &Path) -> anyhow::Result<[u8; 32]> {
        let parent = path.parent().context("key parent missing")?;
        let dir = open_directory_path(parent, true)?;
        let mut file = open_child(
            &dir,
            path.file_name().context("key filename missing")?,
            false,
        )?;
        let meta = file.metadata()?;
        ensure!(
            meta.is_file()
                && safe_key_file(
                    meta.uid(),
                    meta.mode(),
                    meta.nlink(),
                    has_acl(file.as_raw_fd())?
                ),
            "unsafe brake key file"
        );
        let mut bytes = [0u8; 33];
        let mut used = 0;
        while used < bytes.len() {
            let n = file.read(&mut bytes[used..])?;
            if n == 0 {
                break;
            }
            used += n;
        }
        ensure!(
            used == 32 && bytes[..32].iter().any(|b| *b != 0),
            "invalid brake key"
        );
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes[..32]);
        bytes.fill(0);
        Ok(key)
    }
    fn bounded_read(path: &Path) -> anyhow::Result<Vec<u8>> {
        let mut f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .context("cannot open request file")?;
        ensure!(f.metadata()?.is_file(), "request must be a regular file");
        let mut bytes = Vec::new();
        f.by_ref()
            .take((INPUT_LIMIT + 1) as u64)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= INPUT_LIMIT, "request exceeds limit");
        Ok(bytes)
    }
    async fn preflight(socket: &Path) -> anyhow::Result<()> {
        ensure!(
            operator_identity(unsafe { libc::getuid() }, unsafe { libc::geteuid() }),
            "private mode requires operator UID 1000"
        );
        let _parent =
            open_directory_path(socket.parent().context("socket parent missing")?, false)?;
        let before = fs::symlink_metadata(socket).context("private socket unavailable")?;
        ensure!(
            before.file_type().is_socket()
                && safe_socket(
                    before.uid(),
                    before.gid(),
                    before.mode(),
                    socket_has_acl(socket)?
                ),
            "unsafe private socket"
        );
        let stream = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::UnixStream::connect(socket),
        )
        .await??;
        ensure!(
            stream.peer_cred()?.uid() == 0,
            "private socket peer is not the root-created listener"
        );
        let after = fs::symlink_metadata(socket)?;
        ensure!(
            (
                before.dev(),
                before.ino(),
                before.uid(),
                before.gid(),
                before.mode()
            ) == (
                after.dev(),
                after.ino(),
                after.uid(),
                after.gid(),
                after.mode()
            ),
            "private socket changed during preflight"
        );
        Ok(())
    }
    pub async fn run(command: PrivateCommand, json_output: bool) -> anyhow::Result<()> {
        ensure!(
            operator_identity(unsafe { libc::getuid() }, unsafe { libc::geteuid() }),
            "private mode requires operator UID 1000"
        );
        let finalization_generation = match &command {
            PrivateCommand::Finalization { generation } => Some(generation.clone()),
            _ => None,
        };
        let (socket, route, body, key): (PathBuf, &str, serde_json::Value, Option<[u8; 32]>) =
            match command {
                PrivateCommand::Submit {
                    id,
                    request,
                    profile,
                } => {
                    canonical_id(&id)?;
                    let input = bounded_read(&request)?;
                    let request: serde_json::Value =
                        serde_json::from_slice(&input).context("invalid request JSON")?;
                    (
                        profile.socket().into(),
                        "/submit",
                        serde_json::json!({"key":id,"request":request}),
                        None,
                    )
                }
                PrivateCommand::Inspect { id, profile } => {
                    canonical_id(&id)?;
                    (
                        profile.socket().into(),
                        "/inspect",
                        serde_json::json!({"key":id}),
                        None,
                    )
                }
                PrivateCommand::Finalization { generation } => (
                    finalization_socket(&generation)?,
                    "/status",
                    serde_json::json!({}),
                    None,
                ),
                PrivateCommand::Stop {
                    target,
                    brake_key_file,
                } => {
                    canonical_id(&target)?;
                    (
                        BRAKE.into(),
                        "/stop",
                        serde_json::json!({"target":target}),
                        Some(read_key(&brake_key_file)?),
                    )
                }
                PrivateCommand::Status {
                    target,
                    brake_key_file,
                } => {
                    canonical_id(&target)?;
                    (
                        BRAKE.into(),
                        "/status",
                        serde_json::json!({"target":target}),
                        Some(read_key(&brake_key_file)?),
                    )
                }
            };
        ensure!(
            serde_json::to_vec(&body)?.len() <= 64 * 1024,
            "request exceeds protocol limit"
        );
        let attestation = if let Some(generation) = &finalization_generation {
            Some(finalization_attestation(generation, &socket).await?)
        } else {
            None
        };
        preflight(&socket).await?;
        // Reqwest opens a second connection. This relies on the checked root-owned,
        // non-writable socket directory remaining immutable to non-root principals.
        let client = reqwest::Client::builder()
            .unix_socket(socket.clone())
            .timeout(Duration::from_secs(8))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()?;
        let mut req = if finalization_generation.is_some() {
            client.get(format!("http://localhost{route}"))
        } else {
            client.post(format!("http://localhost{route}")).json(&body)
        };
        if let Some(mut key) = key {
            let mut encoded = String::with_capacity(64);
            for b in key {
                use std::fmt::Write;
                write!(&mut encoded, "{b:02x}")?;
            }
            key.fill(0);
            let mut value = HeaderValue::from_str(&encoded)?;
            value.set_sensitive(true);
            unsafe { encoded.as_bytes_mut().fill(0) };
            req = req.header("x-brake-key", value);
        }
        let mut response = req
            .send()
            .await
            .context("private request failed; outcome may be unknown")?;
        let status = response.status();
        ensure!(
            response
                .content_length()
                .is_none_or(|n| n <= OUTPUT_LIMIT as u64),
            "private response exceeds limit"
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                chunk.len() <= OUTPUT_LIMIT - bytes.len(),
                "private response exceeds limit"
            );
            bytes.extend_from_slice(&chunk);
        }
        ensure!(
            status.is_success(),
            "private request failed with status {status}; outcome may be unknown"
        );
        let mut value: serde_json::Value =
            serde_json::from_slice(&bytes).context("invalid private response")?;
        if let Some(generation) = finalization_generation {
            ensure!(
                Some(finalization_attestation(&generation, &socket).await?) == attestation,
                "finalization process changed during request"
            );
            value = finalization_summary(&value, &generation)?;
        }
        ensure!(
            value.get("error").is_none(),
            "private service reported an operation error"
        );
        if json_output {
            println!("{}", serde_json::to_string(&value)?);
        } else if value.get("outcome").is_some() {
            println!(
                "{}; projection {}; actual spend unknown; promotion not established",
                value["outcome"].as_str().unwrap_or("unavailable"),
                value["projection"].as_str().unwrap_or("unavailable")
            );
        } else {
            println!("[{status}] {}", serde_json::to_string(&value)?);
        }
        ensure!(
            status != reqwest::StatusCode::ACCEPTED,
            "stop remains pending; inspect status"
        );
        Ok(())
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::PermissionsExt;
        #[test]
        fn identifiers_and_request_size_are_bounded() {
            assert!(canonical_id("01ARZ3NDEKTSV4RRFFQ69G5FAV").is_ok());
            assert!(canonical_id("01arz3ndektsv4rrffq69g5fav").is_err());
            assert!(canonical_id("../../not-an-id").is_err());
            let dir =
                std::env::temp_dir().join(format!("sfctl-private-test-{}", ulid::Ulid::new()));
            fs::create_dir(&dir).unwrap();
            let file = dir.join("request");
            fs::write(&file, vec![b'x'; INPUT_LIMIT + 1]).unwrap();
            assert!(bounded_read(&file).is_err());
            fs::write(&file, b"{}").unwrap();
            assert_eq!(bounded_read(&file).unwrap(), b"{}");
            let fifo = dir.join("fifo");
            let name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            assert!(bounded_read(&fifo).is_err());
            fs::remove_dir_all(dir).unwrap();
        }
        #[test]
        fn execute_only_directory_supports_pinned_acl_inspection() {
            let dir = std::env::temp_dir().join(format!("sfctl-path-test-{}", ulid::Ulid::new()));
            fs::create_dir(&dir).unwrap();
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o111)).unwrap();
            let parent = File::open(dir.parent().unwrap()).unwrap();
            let pinned = open_child(&parent, dir.file_name().unwrap(), true).unwrap();
            assert!(!has_acl(pinned.as_raw_fd()).unwrap());
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
            fs::remove_dir(dir).unwrap();
        }
        #[test]
        fn tmp_key_is_rejected_even_if_private() {
            let dir = std::env::temp_dir().join(format!("sfctl-key-test-{}", ulid::Ulid::new()));
            fs::create_dir(&dir).unwrap();
            let file = dir.join("key");
            fs::write(&file, [7u8; 32]).unwrap();
            fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(read_key(&file).is_err());
            fs::remove_dir_all(dir).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[test]
    fn cli_private_shapes_are_explicit() {
        assert!(
            crate::Cli::try_parse_from([
                "sfctl",
                "private",
                "submit",
                "--id",
                "01ARZ3NDEKTSV4RRFFQ69G5FAV",
                "--request",
                "intent.json"
            ])
            .is_ok()
        );
        assert!(
            crate::Cli::try_parse_from([
                "sfctl",
                "private",
                "stop",
                "01ARZ3NDEKTSV4RRFFQ69G5FAV",
                "--brake-key-file",
                "key"
            ])
            .is_ok()
        );
        assert!(
            crate::Cli::try_parse_from(["sfctl", "private", "stop", "id", "--key", "secret"])
                .is_err()
        );
    }
    #[test]
    fn secure_metadata_rejects_wrong_owner_mode_and_unsafe_parent() {
        assert!(operator_identity(1000, 1000));
        assert!(!operator_identity(0, 1000));
        assert!(!operator_identity(1000, 0));
        assert!(safe_root_parent(0, 0o755, false));
        assert!(!safe_root_parent(1000, 0o755, false));
        assert!(!safe_root_parent(0, 0o777, false));
        assert!(!safe_root_parent(0, 0o755, true));
        assert!(safe_key_file(1000, 0o600, 1, false));
        assert!(!safe_key_file(0, 0o600, 1, false));
        assert!(!safe_key_file(1000, 0o644, 1, false));
        assert!(!safe_key_file(1000, 0o600, 2, false));
        assert!(!safe_key_file(1000, 0o600, 1, true));
        assert!(safe_socket(0, 1000, 0o660, false));
        assert!(!safe_socket(1000, 1000, 0o660, false));
        assert!(!safe_socket(0, 1000, 0o666, false));
        assert!(!safe_socket(0, 1000, 0o660, true));
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;
    use clap::Parser;
    #[derive(Parser)]
    struct Args {
        #[command(subcommand)]
        command: PrivateCommand,
    }
    #[test]
    fn finalization_output_is_scoped_and_excludes_raw_payloads() {
        let g = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
        let status = serde_json::json!({"generation":g,"task_id":"task","legacy_claim":{"version":1,"stage":"Leased","attempts":1},"legacy_claim_is_historical":true,"approval_not_established_by_finalization":true,"finalization":{"export":"pending","record":{"reservation":{"generation":g,"token":"SECRET"},"evidence":{"kind":"unknown","raw":"SECRET"}}}});
        let summary = finalization_summary(&status, g).unwrap();
        assert_eq!(summary["outcome"], "unknown");
        assert_eq!(summary["promotion"], "not established");
        assert!(!summary.to_string().contains("SECRET"));
        assert!(finalization_summary(&status, "01ARZ3NDEKTSV4RRFFQ69G5FAW").is_err());
        let mut forged = status.clone();
        forged["legacy_claim"]["token"] = serde_json::json!("SECRET");
        assert!(finalization_summary(&forged, g).is_err());
    }
    #[test]
    fn finalization_socket_path_is_generation_scoped() {
        let g = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
        assert_eq!(
            finalization_socket(g).unwrap(),
            std::path::PathBuf::from(format!(
                "/run/software-factory-goose/root-finalization/{g}.sock"
            ))
        );
        for invalid in ["../escape", "01arz3ndekt sv4rrffq69g5fav", ""] {
            assert!(finalization_socket(invalid).is_err());
        }
    }
    #[test]
    fn real_profile_selects_only_the_fixed_private_endpoint() {
        let args = Args::try_parse_from([
            "sfctl",
            "inspect",
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "--profile",
            "real",
        ])
        .unwrap();
        let PrivateCommand::Inspect { profile, .. } = args.command else {
            panic!("wrong command")
        };
        assert_eq!(
            profile.socket(),
            "/run/software-factory-goose/real-intake.sock"
        );
        assert!(
            Args::try_parse_from([
                "sfctl",
                "inspect",
                "01ARZ3NDEKTSV4RRFFQ69G5FAV",
                "--profile",
                "/tmp/evil.sock"
            ])
            .is_err()
        );
    }
}
