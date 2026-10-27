//! Inert Unix-socket verification. No factory router, database, worker or privileged action.
//! Run: cargo run --locked -p control-plane --example verify_operator_socket
//! Same-UID compromise, atomic pathname-race resistance, deployed cross-UID isolation,
//! request-connection server credentials, human approval and the independent brake are unproven.

#[cfg(unix)]
mod unix {
    use anyhow::{Context, ensure};
    use axum::{
        Json, Router,
        extract::{ConnectInfo, DefaultBodyLimit, State, connect_info::Connected},
        http::StatusCode,
        routing::post,
        serve::IncomingStream,
    };
    use serde_json::{Value, json};
    use std::{
        fs::{self, DirBuilder, Metadata, Permissions},
        os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt, symlink},
        path::{Path, PathBuf},
        time::Duration,
    };
    use tokio::net::{UnixListener, UnixStream};

    #[derive(Clone, Copy, Debug, PartialEq)]
    struct Identity {
        device: u64,
        inode: u64,
        uid: u32,
    }
    impl Identity {
        fn from(m: &Metadata) -> Self {
            Self {
                device: m.dev(),
                inode: m.ino(),
                uid: m.uid(),
            }
        }
    }

    struct PrivateDirectory {
        path: PathBuf,
        identity: Identity,
    }
    impl PrivateDirectory {
        fn create(uid: u32) -> anyhow::Result<Self> {
            let path = std::env::temp_dir().join(format!("sf-{}", shared::new_id()));
            DirBuilder::new().mode(0o700).create(&path)?;
            let metadata = fs::symlink_metadata(&path)?;
            let dir = Self {
                path,
                identity: Identity::from(&metadata),
            };
            verify_parent(&dir.path, uid)?;
            Ok(dir)
        }
    }
    impl Drop for PrivateDirectory {
        fn drop(&mut self) {
            if let Ok(m) = fs::symlink_metadata(&self.path)
                && m.file_type().is_dir()
                && Identity::from(&m) == self.identity
            {
                // Never recursively remove a directory containing an unknown replacement.
                let _ = fs::remove_dir(&self.path);
            }
        }
    }

    fn verify_parent(path: &Path, uid: u32) -> anyhow::Result<()> {
        let m = fs::symlink_metadata(path)?;
        ensure!(
            m.file_type().is_dir() && m.uid() == uid && m.mode() & 0o777 == 0o700,
            "private directory owner/mode/type mismatch"
        );
        Ok(())
    }

    #[derive(Debug, PartialEq)]
    enum Cleanup {
        Removed,
        Absent,
        Changed,
    }
    struct SocketGuard {
        path: PathBuf,
        identity: Identity,
        parent_identity: Identity,
    }
    impl SocketGuard {
        fn bind(path: &Path, uid: u32) -> anyhow::Result<(UnixListener, Self)> {
            let parent = path.parent().context("socket parent required")?;
            verify_parent(parent, uid)?;
            let parent_identity = Identity::from(&fs::symlink_metadata(parent)?);
            match fs::symlink_metadata(path) {
                Ok(_) => anyhow::bail!("socket path already exists; nothing removed"),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(e.into()),
            }
            let listener = UnixListener::bind(path)?;
            let metadata = fs::symlink_metadata(path)?;
            ensure!(
                metadata.file_type().is_socket() && metadata.uid() == uid,
                "unexpected socket identity"
            );
            let guard = Self {
                path: path.to_path_buf(),
                identity: Identity::from(&metadata),
                parent_identity,
            };
            fs::set_permissions(path, Permissions::from_mode(0o600))?;
            ensure!(
                fs::symlink_metadata(path)?.mode() & 0o777 == 0o600,
                "socket is not owner-only"
            );
            Ok((listener, guard))
        }

        fn cleanup(&self) -> anyhow::Result<Cleanup> {
            let parent = self.path.parent().context("socket parent required")?;
            let parent_metadata = fs::symlink_metadata(parent)?;
            if !parent_metadata.file_type().is_dir()
                || Identity::from(&parent_metadata) != self.parent_identity
                || parent_metadata.mode() & 0o777 != 0o700
            {
                return Ok(Cleanup::Changed);
            }
            let metadata = match fs::symlink_metadata(&self.path) {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Cleanup::Absent),
                Err(e) => return Err(e.into()),
            };
            if !metadata.file_type().is_socket() || Identity::from(&metadata) != self.identity {
                return Ok(Cleanup::Changed);
            }
            // Deliberately not claimed atomic against a hostile same-UID rename after this check.
            fs::remove_file(&self.path)?;
            Ok(Cleanup::Removed)
        }
    }
    impl Drop for SocketGuard {
        fn drop(&mut self) {
            let _ = self.cleanup();
        }
    }

    #[derive(Clone)]
    struct Peer {
        uid: Option<u32>,
    }
    impl Connected<IncomingStream<'_, UnixListener>> for Peer {
        fn connect_info(stream: IncomingStream<'_, UnixListener>) -> Self {
            Self {
                uid: stream.io().peer_cred().ok().map(|cred| cred.uid()),
            }
        }
    }
    #[derive(Clone)]
    struct Policy {
        expected_uid: u32,
        synthetic_credential_failure: bool,
    }
    fn allowed(peer: &Peer, policy: &Policy) -> bool {
        !policy.synthetic_credential_failure && peer.uid == Some(policy.expected_uid)
    }
    async fn diagnostic(
        State(policy): State<Policy>,
        ConnectInfo(peer): ConnectInfo<Peer>,
        Json(_body): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        if !allowed(&peer, &policy) {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error":"peer identity unavailable or mismatched"})),
            );
        }
        (
            StatusCode::OK,
            Json(
                json!({"diagnostic":true,"peer_uid":peer.uid,"privileged_operations":"unavailable"}),
            ),
        )
    }
    async fn unavailable(Json(_body): Json<Value>) -> (StatusCode, Json<Value>) {
        (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({"error":"unavailable in diagnostic spike"})),
        )
    }

    struct Server {
        task: tokio::task::JoinHandle<()>,
        socket: SocketGuard,
    }
    impl Server {
        fn start(path: &Path, actual_uid: u32, policy: Policy) -> anyhow::Result<Self> {
            let (listener, socket) = SocketGuard::bind(path, actual_uid)?;
            let app = Router::new()
                .route("/diagnostic", post(diagnostic))
                .route("/privileged", post(unavailable))
                .layer(DefaultBodyLimit::max(1024))
                .with_state(policy)
                .into_make_service_with_connect_info::<Peer>();
            let task = tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });
            Ok(Self { task, socket })
        }
        fn client(&self) -> anyhow::Result<reqwest::Client> {
            // No separate peer-credential probe is mistaken for authenticating this connection.
            let parent = self.socket.path.parent().context("missing parent")?;
            verify_parent(parent, self.socket.identity.uid)?;
            let m = fs::symlink_metadata(&self.socket.path)?;
            ensure!(
                m.file_type().is_socket()
                    && Identity::from(&m) == self.socket.identity
                    && m.mode() & 0o777 == 0o600,
                "client socket ownership check failed"
            );
            Ok(reqwest::Client::builder()
                .unix_socket(self.socket.path.as_path())
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(2))
                .pool_max_idle_per_host(0)
                .build()?)
        }
        async fn stop(self) -> anyhow::Result<()> {
            self.task.abort();
            // abort is bounded; no active requests remain in these sequential fixtures.
            ensure!(
                self.socket.cleanup()? == Cleanup::Removed,
                "normal cleanup failed"
            );
            ensure!(
                self.socket.cleanup()? == Cleanup::Absent,
                "repeated cleanup failed"
            );
            Ok(())
        }
    }
    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    pub async fn verify() -> anyhow::Result<()> {
        let (stream, peer) = UnixStream::pair()?;
        let uid = stream.peer_cred()?.uid();
        drop((stream, peer));
        let dir = PrivateDirectory::create(uid)?;
        let mut checks = Vec::new();
        let server = Server::start(
            &dir.path.join("s"),
            uid,
            Policy {
                expected_uid: uid,
                synthetic_credential_failure: false,
            },
        )?;
        let client = server.client()?;
        let response = client
            .post("http://localhost/diagnostic")
            .json(&json!({}))
            .send()
            .await?;
        ensure!(
            response.status() == StatusCode::OK,
            "expected peer rejected"
        );
        let body: Value = response.json().await?;
        ensure!(
            body["peer_uid"] == uid && body["diagnostic"] == true,
            "wrong diagnostic identity"
        );
        checks.push("actual_server_peer_credentials");
        let response = client
            .post("http://localhost/diagnostic")
            .json(&json!({"uid":uid.wrapping_add(1),"approved":true}))
            .send()
            .await?;
        let body: Value = response.error_for_status()?.json().await?;
        ensure!(
            body["peer_uid"] == uid && body["privileged_operations"] == "unavailable",
            "body altered authority"
        );
        let response = client
            .post("http://localhost/privileged")
            .json(&json!({"uid":uid,"approved":true}))
            .send()
            .await?;
        ensure!(
            response.status() == StatusCode::NOT_IMPLEMENTED,
            "privileged action was enabled"
        );
        checks.push("forged_body_cannot_enable_privilege");
        let response = client
            .post("http://localhost/diagnostic")
            .json(&json!({"body":"x".repeat(2048)}))
            .send()
            .await?;
        ensure!(
            response.status() == StatusCode::PAYLOAD_TOO_LARGE,
            "oversized body accepted"
        );
        checks.push("request_body_1kib_limit");
        ensure!(
            SocketGuard::bind(&dir.path.join("s"), uid).is_err(),
            "duplicate listener accepted"
        );
        checks.push("existing_live_socket_refused");
        drop(client);
        server.stop().await?;
        checks.push("normal_and_repeated_cleanup");

        for (name, policy) in [
            (
                "synthetic_uid_mismatch",
                Policy {
                    expected_uid: uid.wrapping_add(1),
                    synthetic_credential_failure: false,
                },
            ),
            (
                "synthetic_credential_read_failure",
                Policy {
                    expected_uid: uid,
                    synthetic_credential_failure: true,
                },
            ),
        ] {
            let claimed_uid = policy.expected_uid;
            let server = Server::start(&dir.path.join("s"), uid, policy)?;
            let client = server.client()?;
            let response = client
                .post("http://localhost/diagnostic")
                .json(&json!({"uid":claimed_uid,"approved":true}))
                .send()
                .await?;
            ensure!(
                response.status() == StatusCode::FORBIDDEN,
                "synthetic denial bypassed by body"
            );
            checks.push(name);
            drop(client);
            server.stop().await?;
        }

        let path = dir.path.join("s");
        fs::write(&path, b"fixture")?;
        ensure!(
            SocketGuard::bind(&path, uid).is_err() && fs::read(&path)? == b"fixture",
            "existing file changed"
        );
        fs::remove_file(&path)?;
        checks.push("existing_regular_file_refused");
        symlink("missing-target", &path)?;
        ensure!(
            SocketGuard::bind(&path, uid).is_err()
                && fs::symlink_metadata(&path)?.file_type().is_symlink(),
            "existing symlink changed"
        );
        fs::remove_file(&path)?;
        checks.push("existing_symlink_refused");
        let stale = UnixListener::bind(&path)?;
        drop(stale);
        ensure!(
            SocketGuard::bind(&path, uid).is_err()
                && fs::symlink_metadata(&path)?.file_type().is_socket(),
            "stale socket changed"
        );
        fs::remove_file(&path)?;
        checks.push("existing_stale_socket_refused");

        let unsafe_dir = dir.path.join("unsafe");
        DirBuilder::new().mode(0o700).create(&unsafe_dir)?;
        fs::set_permissions(&unsafe_dir, Permissions::from_mode(0o755))?;
        ensure!(
            SocketGuard::bind(&unsafe_dir.join("s"), uid).is_err(),
            "unsafe parent accepted"
        );
        fs::remove_dir(&unsafe_dir)?;
        ensure!(
            SocketGuard::bind(&path, uid.wrapping_add(1)).is_err(),
            "unexpected owner accepted"
        );
        checks.push("unsafe_parent_and_wrong_owner_refused");

        for replacement in ["socket", "file", "symlink"] {
            let (original_listener, original) = SocketGuard::bind(&path, uid)?;
            let moved = dir.path.join("old");
            fs::rename(&path, &moved)?;
            let replacement_listener = match replacement {
                "socket" => Some(UnixListener::bind(&path)?),
                "file" => {
                    fs::write(&path, b"replacement")?;
                    None
                }
                _ => {
                    symlink("missing-target", &path)?;
                    None
                }
            };
            ensure!(
                original.cleanup()? == Cleanup::Changed,
                "replacement removed during cleanup"
            );
            match replacement {
                "socket" => {
                    let connection = UnixStream::connect(&path).await?;
                    let (accepted, _) = replacement_listener.as_ref().unwrap().accept().await?;
                    drop((connection, accepted));
                }
                "file" => ensure!(
                    fs::read(&path)? == b"replacement",
                    "replacement content changed"
                ),
                _ => ensure!(
                    fs::symlink_metadata(&path)?.file_type().is_symlink(),
                    "replacement symlink changed"
                ),
            }
            drop(original); // Repeated cleanup must still preserve the replacement.
            ensure!(
                fs::symlink_metadata(&path).is_ok(),
                "drop removed replacement"
            );
            drop((original_listener, replacement_listener));
            fs::remove_file(&path)?;
            fs::remove_file(&moved)?;
        }
        checks.push("controlled_socket_file_symlink_replacements_preserved");
        ensure!(
            fs::read_dir(&dir.path)?.next().is_none(),
            "fixture cleanup left artifacts"
        );
        let dir_path = dir.path.clone();
        drop(dir);
        ensure!(!dir_path.exists(), "private directory cleanup failed");
        checks.push("private_directory_removed");
        println!("Local socket transport checks passed.");
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "transport_spike":"passed", "platform":std::env::consts::OS,
                "architecture":std::env::consts::ARCH,"actual_peer_uid":uid,
                "checks_passed":checks, "peer_mismatch":"synthetic", "peer_read_error":"synthetic",
                "client_assurance":"directory_and_socket_ownership_only",
                "client_request_connection_peer_credentials":"not_run",
                "deployed_cross_uid_denial":"not_run", "human_approval":"not_run",
                "independent_brake":"not_run", "privileged_operations":"unavailable",
                "limits":{"overall_seconds":30,"request_seconds":2,"body_bytes":1024,"fixture_concurrency":1},
                "cleanup_claim":"controlled replacement preserved under private-directory assumption; not atomic race freedom"
            }))?
        );
        Ok(())
    }
}

#[cfg(unix)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(30), unix::verify()).await??;
    Ok(())
}

#[cfg(not(unix))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("Unix-socket verification requires a Unix host")
}
