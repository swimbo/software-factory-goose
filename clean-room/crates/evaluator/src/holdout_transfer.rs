//! Unregistered store-to-evaluator protocol on an already-connected Unix stream.
//!
//! Both sides authenticate the actual connection's kernel peer UID before any protocol
//! bytes. Production constructors require three distinct nonroot principals and the actual
//! process role. No identity assertion in a body/header is accepted. One immutable manifest
//! selected by trusted configuration is served; the evaluator pins its independently resolved
//! digest. This module never binds sockets, provisions accounts, or exposes generator routes.
//! Deployment must protect the listener and descriptors and limit concurrent connections.
//! Trust is local OS principal authority, not human presence or MFA. Tests using same-account
//! streams prove the protocol only, not deployed UID separation or protection from root.

use crate::{
    holdout_runner::{FixtureManifest, MAX_MANIFEST_BYTES},
    holdout_store::ProtectedHoldoutStore,
};
use serde::{Deserialize, Serialize};
use std::{fmt, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

const MAX_REQUEST_BYTES: usize = 256;

/// Loaded from trusted service configuration, never a caller's request.
#[derive(Clone, Copy)]
pub struct TransferIdentities {
    pub store_uid: u32,
    pub evaluator_uid: u32,
    pub generator_uid: u32,
}
impl TransferIdentities {
    fn validate(self, role: u32) -> Result<(), TransferError> {
        let ids = [self.store_uid, self.evaluator_uid, self.generator_uid];
        // SAFETY: geteuid has no arguments or memory access obligations.
        let current = unsafe { libc::geteuid() };
        if ids.contains(&0)
            || ids[0] == ids[1]
            || ids[0] == ids[2]
            || ids[1] == ids[2]
            || current != role
        {
            return Err(TransferError);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TransferError;
impl fmt::Display for TransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("holdout transfer unavailable")
    }
}
impl std::error::Error for TransferError {}

fn valid_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn validate_limits(digest: &str, deadline: Duration) -> Result<(), TransferError> {
    if !valid_digest(digest)
        || !(Duration::from_millis(10)..=Duration::from_secs(5)).contains(&deadline)
    {
        return Err(TransferError);
    }
    Ok(())
}

/// Store-owner component. Synchronous protected loading happens once during construction,
/// outside the network deadline. An opened instance serves the immutable selected snapshot;
/// revocation/reconfiguration requires dropping it and closing its service externally.
pub struct ManifestServer {
    identities: TransferIdentities,
    manifest: FixtureManifest,
    deadline: Duration,
}
impl ManifestServer {
    pub fn new(
        store: &ProtectedHoldoutStore,
        expected_digest: &str,
        deadline: Duration,
    ) -> Result<Self, TransferError> {
        let config = store.config();
        let identities = TransferIdentities {
            store_uid: config.store_uid,
            evaluator_uid: config.evaluator_uid,
            generator_uid: config.generator_uid,
        };
        identities.validate(identities.store_uid)?;
        validate_limits(expected_digest, deadline)?;
        let manifest = store
            .load_digest(expected_digest)
            .map_err(|_| TransferError)?;
        Ok(Self {
            identities,
            manifest,
            deadline,
        })
    }
    /// Takes ownership so cancellation/refusal drops and closes the stream. No retry on it.
    pub async fn serve(&self, stream: UnixStream) -> Result<(), TransferError> {
        self.identities.validate(self.identities.store_uid)?;
        send_manifest(
            stream,
            self.identities.evaluator_uid,
            &self.manifest,
            self.deadline,
        )
        .await
    }
}

/// Evaluator component: has no store path or filesystem capability. The expected digest is
/// resolved by trusted task/manifest selection, not by a generator-supplied receipt.
pub struct ManifestClient {
    identities: TransferIdentities,
    digest: String,
    deadline: Duration,
}
impl ManifestClient {
    pub fn new(
        identities: TransferIdentities,
        expected_digest: &str,
        deadline: Duration,
    ) -> Result<Self, TransferError> {
        identities.validate(identities.evaluator_uid)?;
        validate_limits(expected_digest, deadline)?;
        Ok(Self {
            identities,
            digest: expected_digest.into(),
            deadline,
        })
    }
    pub async fn fetch(&self, stream: UnixStream) -> Result<FixtureManifest, TransferError> {
        self.identities.validate(self.identities.evaluator_uid)?;
        receive_manifest(
            stream,
            self.identities.store_uid,
            &self.digest,
            self.deadline,
        )
        .await
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u32,
    digest: String,
}

fn authenticate_peer(stream: &UnixStream, expected: u32) -> Result<(), TransferError> {
    if expected == 0 || stream.peer_cred().map_err(|_| TransferError)?.uid() != expected {
        return Err(TransferError);
    }
    Ok(())
}
async fn read_frame(stream: &mut UnixStream, max: usize) -> Result<Vec<u8>, TransferError> {
    let length = stream.read_u32().await.map_err(|_| TransferError)? as usize;
    if length == 0 || length > max {
        return Err(TransferError);
    }
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| TransferError)?;
    Ok(bytes)
}
async fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> Result<(), TransferError> {
    let length = u32::try_from(bytes.len()).map_err(|_| TransferError)?;
    stream.write_u32(length).await.map_err(|_| TransferError)?;
    stream.write_all(bytes).await.map_err(|_| TransferError)
}
async fn send_manifest(
    mut stream: UnixStream,
    expected_peer: u32,
    manifest: &FixtureManifest,
    deadline: Duration,
) -> Result<(), TransferError> {
    authenticate_peer(&stream, expected_peer)?;
    tokio::time::timeout(deadline, async {
        let raw = read_frame(&mut stream, MAX_REQUEST_BYTES).await?;
        let request: Request = serde_json::from_slice(&raw).map_err(|_| TransferError)?;
        if request.version != 1 || request.digest != manifest.digest() {
            return Err(TransferError);
        }
        // Require end-of-request before releasing secret bytes; timeout covers peers
        // that send a valid frame but keep the write half open.
        let mut trailing = [0u8; 1];
        if stream
            .read(&mut trailing)
            .await
            .map_err(|_| TransferError)?
            != 0
        {
            return Err(TransferError);
        }
        write_frame(&mut stream, manifest.source_bytes()).await?;
        stream.shutdown().await.map_err(|_| TransferError)
    })
    .await
    .map_err(|_| TransferError)?
}
async fn receive_manifest(
    mut stream: UnixStream,
    expected_peer: u32,
    digest: &str,
    deadline: Duration,
) -> Result<FixtureManifest, TransferError> {
    authenticate_peer(&stream, expected_peer)?;
    tokio::time::timeout(deadline, async {
        let request = serde_json::to_vec(&Request {
            version: 1,
            digest: digest.into(),
        })
        .map_err(|_| TransferError)?;
        write_frame(&mut stream, &request).await?;
        // Half-close the request direction without closing the response direction.
        stream.shutdown().await.map_err(|_| TransferError)?;
        let raw = read_frame(&mut stream, MAX_MANIFEST_BYTES).await?;
        let manifest = FixtureManifest::parse_trusted(&raw).map_err(|_| TransferError)?;
        if manifest.digest() != digest {
            return Err(TransferError);
        }
        // Exact one-response protocol: refuse trailing data and peers that never close.
        let mut trailing = [0u8; 1];
        if stream
            .read(&mut trailing)
            .await
            .map_err(|_| TransferError)?
            != 0
        {
            return Err(TransferError);
        }
        Ok(manifest)
    })
    .await
    .map_err(|_| TransferError)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    const BODY: &[u8] = br#"{"version":1,"scenarios":[{"script":"SECRET_SCENARIO_BODY"}]}"#;
    const WAIT: Duration = Duration::from_millis(100);
    fn uid() -> u32 {
        unsafe { libc::geteuid() }
    }
    fn manifest() -> FixtureManifest {
        FixtureManifest::parse_trusted(BODY).unwrap()
    }

    // Same-account transport fixtures deliberately exercise private protocol functions.
    // Public constructors must refuse this topology; these tests prove no deployed UID split.
    #[tokio::test]
    async fn real_kernel_peer_roundtrip_preserves_exact_manifest_digest() {
        let (a, b) = UnixStream::pair().unwrap();
        let m = manifest();
        let (sent, got) = tokio::join!(
            send_manifest(a, uid(), &m, WAIT),
            receive_manifest(b, uid(), m.digest(), WAIT)
        );
        sent.unwrap();
        assert_eq!(got.unwrap().digest(), m.digest());
    }

    #[tokio::test]
    async fn wrong_evaluator_peer_receives_no_manifest() {
        let (a, mut b) = UnixStream::pair().unwrap();
        assert!(
            send_manifest(a, uid() + 1, &manifest(), WAIT)
                .await
                .is_err()
        );
        let mut bytes = Vec::new();
        b.read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.is_empty());
    }

    #[tokio::test]
    async fn wrong_store_peer_receives_no_request() {
        let (mut a, b) = UnixStream::pair().unwrap();
        assert!(
            receive_manifest(b, uid() + 1, manifest().digest(), WAIT)
                .await
                .is_err()
        );
        let mut bytes = Vec::new();
        a.read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.is_empty());
    }

    #[tokio::test]
    async fn forged_identity_wrong_digest_and_malformed_request_are_refused_without_body() {
        for request in [
            format!(
                r#"{{"version":1,"digest":"{}","uid":{}}}"#,
                manifest().digest(),
                uid()
            ),
            format!(r#"{{"version":1,"digest":"{}"}}"#, "a".repeat(64)),
            "SECRET_BAD_JSON".into(),
        ] {
            let (a, mut b) = UnixStream::pair().unwrap();
            let m = manifest();
            let (result, received) = tokio::join!(send_manifest(a, uid(), &m, WAIT), async {
                write_frame(&mut b, request.as_bytes()).await.unwrap();
                let mut bytes = Vec::new();
                b.read_to_end(&mut bytes).await.unwrap();
                bytes
            });
            assert_eq!(
                result.unwrap_err().to_string(),
                "holdout transfer unavailable"
            );
            assert!(received.is_empty());
        }
    }

    #[tokio::test]
    async fn trailing_request_bytes_are_refused_without_manifest() {
        let (a, mut b) = UnixStream::pair().unwrap();
        let m = manifest();
        let request = serde_json::to_vec(&Request {
            version: 1,
            digest: m.digest().into(),
        })
        .unwrap();
        let (result, received) = tokio::join!(send_manifest(a, uid(), &m, WAIT), async {
            write_frame(&mut b, &request).await.unwrap();
            b.write_all(b"unexpected trailing bytes").await.unwrap();
            b.shutdown().await.unwrap();
            let mut bytes = Vec::new();
            b.read_to_end(&mut bytes).await.unwrap();
            bytes
        });
        assert!(result.is_err());
        assert!(
            received.is_empty(),
            "manifest released after trailing request data"
        );
    }

    #[tokio::test]
    async fn valid_request_without_eof_times_out_without_manifest() {
        let (a, mut b) = UnixStream::pair().unwrap();
        let m = manifest();
        let request = serde_json::to_vec(&Request {
            version: 1,
            digest: m.digest().into(),
        })
        .unwrap();
        write_frame(&mut b, &request).await.unwrap();
        assert!(send_manifest(a, uid(), &m, WAIT).await.is_err());
        let mut bytes = Vec::new();
        b.read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.is_empty());
    }

    #[tokio::test]
    async fn oversized_and_truncated_requests_are_bounded() {
        for length in [MAX_REQUEST_BYTES as u32 + 1, u32::MAX, 30] {
            let (a, mut b) = UnixStream::pair().unwrap();
            b.write_u32(length).await.unwrap();
            b.write_all(b"short").await.unwrap();
            b.shutdown().await.unwrap();
            assert!(send_manifest(a, uid(), &manifest(), WAIT).await.is_err());
        }
    }

    #[tokio::test]
    async fn response_size_digest_and_schema_fail_closed() {
        for variant in 0..4 {
            let (mut a, b) = UnixStream::pair().unwrap();
            let m = manifest();
            let raw = br#"{"version":1,"scenarios":[],"secret":"SECRET_RESPONSE"}"#;
            let expected = if variant == 3 {
                format!("{:x}", sha2::Sha256::digest(raw))
            } else {
                m.digest().into()
            };
            let (_, result) = tokio::join!(
                async {
                    read_frame(&mut a, MAX_REQUEST_BYTES).await.unwrap();
                    if variant == 0 {
                        a.write_u32(u32::MAX).await.unwrap();
                    } else if variant == 1 {
                        a.write_u32(30).await.unwrap();
                        a.write_all(b"short").await.unwrap();
                    } else {
                        write_frame(&mut a, raw).await.unwrap();
                    }
                    a.shutdown().await.unwrap();
                },
                receive_manifest(b, uid(), &expected, WAIT)
            );
            assert_eq!(
                result.err().unwrap().to_string(),
                "holdout transfer unavailable"
            );
        }
    }

    #[tokio::test]
    async fn trailing_response_or_missing_end_of_stream_is_refused() {
        for trailing in [true, false] {
            let (mut a, b) = UnixStream::pair().unwrap();
            let m = manifest();
            let (_, result) = tokio::join!(
                async {
                    read_frame(&mut a, MAX_REQUEST_BYTES).await.unwrap();
                    write_frame(&mut a, BODY).await.unwrap();
                    if trailing {
                        a.write_all(b"SECRET_TRAILING").await.unwrap();
                        a.shutdown().await.unwrap();
                    } else {
                        tokio::time::sleep(WAIT * 2).await;
                    }
                },
                receive_manifest(b, uid(), m.digest(), WAIT)
            );
            assert!(result.is_err());
        }
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn public_store_server_refuses_same_owner_connected_to_real_listener() {
        use crate::holdout_store::StoreConfig;
        use std::{fs, os::unix::fs::PermissionsExt};
        struct Temporary(std::path::PathBuf);
        impl Drop for Temporary {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let temp = Temporary(
            std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("transfer-{}", shared::new_id())),
        );
        fs::create_dir(&temp.0).unwrap();
        fs::set_permissions(&temp.0, fs::Permissions::from_mode(0o700)).unwrap();
        let m = manifest();
        let path = temp.0.join(format!("{}.json", m.digest()));
        fs::write(&path, BODY).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let store = ProtectedHoldoutStore::open(&StoreConfig {
            root: temp.0.clone(),
            store_uid: uid(),
            evaluator_uid: uid() + 1,
            generator_uid: uid() + 2,
        })
        .unwrap();
        let server = ManifestServer::new(&store, m.digest(), WAIT).unwrap();
        assert!(ManifestServer::new(&store, &"b".repeat(64), WAIT).is_err());
        let listener = tokio::net::UnixListener::bind(temp.0.join("socket")).unwrap();
        let mut client = UnixStream::connect(temp.0.join("socket")).await.unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        assert!(server.serve(accepted).await.is_err());
        let mut data = Vec::new();
        client.read_to_end(&mut data).await.unwrap();
        assert!(data.is_empty());
    }

    #[tokio::test]
    async fn stalled_headers_and_bodies_time_out() {
        for body_started in [false, true] {
            let (a, mut b) = UnixStream::pair().unwrap();
            if body_started {
                b.write_u32(20).await.unwrap();
                b.write_all(b"short").await.unwrap();
            }
            let start = std::time::Instant::now();
            assert!(send_manifest(a, uid(), &manifest(), WAIT).await.is_err());
            assert!(start.elapsed() < Duration::from_secs(2));
            let (mut a, b) = UnixStream::pair().unwrap();
            if body_started {
                a.write_u32(20).await.unwrap();
                a.write_all(b"short").await.unwrap();
            }
            assert!(
                receive_manifest(b, uid(), manifest().digest(), WAIT)
                    .await
                    .is_err()
            );
        }
    }

    #[test]
    fn public_client_refuses_wrong_role_duplicate_root_and_bad_limits() {
        let identities = TransferIdentities {
            store_uid: uid() + 1,
            evaluator_uid: uid(),
            generator_uid: uid() + 2,
        };
        assert!(ManifestClient::new(identities, manifest().digest(), WAIT).is_ok());
        for ids in [
            TransferIdentities {
                store_uid: uid(),
                ..identities
            },
            TransferIdentities {
                generator_uid: uid(),
                ..identities
            },
            TransferIdentities {
                store_uid: 0,
                ..identities
            },
            TransferIdentities {
                evaluator_uid: uid() + 3,
                ..identities
            },
        ] {
            assert!(ManifestClient::new(ids, manifest().digest(), WAIT).is_err());
        }
        for timeout in [Duration::ZERO, Duration::from_secs(6)] {
            assert!(ManifestClient::new(identities, manifest().digest(), timeout).is_err());
        }
        assert!(ManifestClient::new(identities, "../private", WAIT).is_err());
    }
}
