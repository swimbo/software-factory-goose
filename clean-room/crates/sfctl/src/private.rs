use clap::{Subcommand, ValueEnum};

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
    use super::{PrivateCommand, operator_identity, safe_key_file, safe_root_parent, safe_socket};
    use anyhow::{Context, ensure};
    use reqwest::header::HeaderValue;
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
    fn has_acl(fd: i32) -> anyhow::Result<bool> {
        // O_PATH permits traversal of root-owned 0711 parents without read
        // permission; /proc/self/fd resolves this already pinned descriptor.
        let path = CString::new(format!("/proc/self/fd/{fd}"))?;
        let result = unsafe {
            libc::getxattr(
                path.as_ptr(),
                c"system.posix_acl_access".as_ptr(),
                std::ptr::null_mut(),
                0,
            )
        };
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
            safe_root_parent(root.uid(), root.mode(), has_acl(dir.as_raw_fd())?),
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
                    ensure!(meta.is_dir() && valid, "unsafe protected parent directory");
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
        preflight(&socket).await?;
        // Reqwest opens a second connection. This relies on the checked root-owned,
        // non-writable socket directory remaining immutable to non-root principals.
        let client = reqwest::Client::builder()
            .unix_socket(socket)
            .timeout(Duration::from_secs(8))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()?;
        let mut req = client.post(format!("http://localhost{route}")).json(&body);
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
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).context("invalid private response")?;
        ensure!(
            value.get("error").is_none(),
            "private service reported an operation error"
        );
        if json_output {
            println!("{}", serde_json::to_string(&value)?);
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
