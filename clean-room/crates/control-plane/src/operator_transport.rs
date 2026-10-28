//! Group-access Unix transport for a separately provisioned local operator.
//! Kernel UID is OS-principal authentication, not human-presence or MFA evidence.
//! Provision users/groups/directories externally; this module never changes them.
use anyhow::{Context, Result, bail, ensure};
use axum::{
    extract::{ConnectInfo, Request, State, connect_info::Connected},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    serve::IncomingStream,
};
use std::{
    collections::BTreeSet,
    fs::{self, Metadata, Permissions},
    io::Read,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use tokio::net::{UnixListener, UnixStream};

#[derive(Debug, Clone)]
pub struct OperatorSocketConfig {
    pub path: PathBuf,
    pub operator_uid: u32,
    pub generator_uid: u32,
    pub evaluator_uid: u32,
    pub access_gid: u32,
}

/// Created only from an accepted socket's kernel credentials. Never deserialize it.
#[derive(Debug, Clone)]
pub struct OperatorPeer {
    uid: Option<u32>,
}
impl Connected<IncomingStream<'_, UnixListener>> for OperatorPeer {
    fn connect_info(stream: IncomingStream<'_, UnixListener>) -> Self {
        Self {
            uid: stream.io().peer_cred().ok().map(|c| c.uid()),
        }
    }
}

/// Inserted by require_operator only after connection identity passes policy.
#[derive(Debug, Clone, Copy)]
pub struct AuthenticatedOperator {
    uid: u32,
}
impl AuthenticatedOperator {
    pub fn uid(&self) -> u32 {
        self.uid
    }
}

#[derive(Debug, Clone)]
pub struct OperatorPolicy {
    expected_uid: u32,
}

/// Internal same-account transport fixtures only; public policy still comes from safe bind.
#[cfg(test)]
pub(crate) fn fixture_policy(expected_uid: u32) -> OperatorPolicy {
    OperatorPolicy { expected_uid }
}

/// Apply via from_fn_with_state(policy, require_operator), and serve with
/// into_make_service_with_connect_info::<OperatorPeer>(). No request body/header
/// participates in authentication; missing ConnectInfo fails closed.
pub async fn require_operator(
    State(policy): State<OperatorPolicy>,
    mut request: Request,
    next: Next,
) -> Response {
    let uid = request
        .extensions()
        .get::<ConnectInfo<OperatorPeer>>()
        .and_then(|peer| peer.0.uid);
    match uid {
        Some(uid) if uid == policy.expected_uid => {
            request
                .extensions_mut()
                .insert(AuthenticatedOperator { uid });
            next.run(request).await
        }
        _ => (
            StatusCode::FORBIDDEN,
            "OS peer identity unavailable or mismatched",
        )
            .into_response(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
}
impl Identity {
    fn of(m: &Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            uid: m.uid(),
            gid: m.gid(),
        }
    }
}

/// Keep alive while serving. Cleanup checks the captured parent/socket identity.
/// This is not atomic against an attacker already controlling the service UID.
#[derive(Debug)]
pub struct OperatorSocketGuard {
    path: PathBuf,
    identity: Identity,
    parent: Identity,
}
impl OperatorSocketGuard {
    pub fn cleanup(&self) -> Result<bool> {
        let parent = self.path.parent().context("socket parent missing")?;
        let pm = fs::symlink_metadata(parent)?;
        if !pm.is_dir()
            || pm.file_type().is_symlink()
            || Identity::of(&pm) != self.parent
            || pm.mode() & 0o7777 != 0o2710
        {
            return Ok(false);
        }
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        if !metadata.file_type().is_socket() || Identity::of(&metadata) != self.identity {
            return Ok(false);
        }
        fs::remove_file(&self.path)?;
        Ok(true)
    }
}
impl Drop for OperatorSocketGuard {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// Production entry: no same-UID bypass or automatic provisioning exists.
/// Expected parent mode is 02710, owned by service UID/access GID. That group
/// must contain only service and operator; generator/evaluator must be excluded.
pub fn bind_operator_socket(
    config: &OperatorSocketConfig,
) -> Result<(UnixListener, OperatorPolicy, OperatorSocketGuard)> {
    ensure!(
        cfg!(target_os = "macos"),
        "local account/group validation currently requires macOS"
    );
    let (a, b) = UnixStream::pair()?;
    let service_uid = a.peer_cred()?.uid();
    drop((a, b));
    validate_distinct(service_uid, config)?;
    let operator_groups = validate_accounts_and_group(service_uid, config)?;
    validate_ancestor_access(
        &config.path,
        service_uid,
        config.operator_uid,
        &operator_groups,
    )?;
    let (listener, guard) = bind_checked(&config.path, service_uid, config.access_gid)?;
    Ok((
        listener,
        OperatorPolicy {
            expected_uid: config.operator_uid,
        },
        guard,
    ))
}

fn validate_distinct(service_uid: u32, config: &OperatorSocketConfig) -> Result<()> {
    let uids = [
        service_uid,
        config.operator_uid,
        config.generator_uid,
        config.evaluator_uid,
    ];
    ensure!(
        uids.iter().all(|u| *u > 0) && uids.into_iter().collect::<BTreeSet<_>>().len() == 4,
        "service, operator, generator and evaluator must have distinct non-root UIDs"
    );
    ensure!(
        config.access_gid > 0,
        "a non-root dedicated access group is required"
    );
    Ok(())
}

// Commands only inspect fixed OS identity tools. Both output and runtime are bounded;
// no user-supplied executable, shell command, environment, or argument option is used.
fn identity_command(binary: &str, arguments: &[&str]) -> Result<String> {
    // A reaped/reused numeric PID must never be targeted by cleanup. Refuse inherited
    // auto-reaping before launch; changing SIGCHLD concurrently remains unsupported.
    let mut action = std::mem::MaybeUninit::<libc::sigaction>::uninit();
    // SAFETY: read-only query writes a complete sigaction on success.
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), action.as_mut_ptr()) } != 0 {
        bail!("cannot inspect child-reaping policy");
    }
    let action = unsafe { action.assume_init() };
    ensure!(
        action.sa_sigaction == libc::SIG_DFL && action.sa_flags & libc::SA_NOCLDWAIT == 0,
        "unsupported child-reaping policy"
    );
    let mut child = Command::new(binary)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .context("identity output pipe missing")?;
    use std::os::fd::AsRawFd;
    // SAFETY: the pipe is owned and remains live until the end of this function.
    let flags = unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        let _ = child.kill();
        let _ = child.wait();
        bail!("identity output setup failed");
    }
    let start = Instant::now();
    let mut bytes = Vec::new();
    let mut status = None;
    let mut eof = false;
    let result = loop {
        if start.elapsed() >= Duration::from_secs(3) {
            break Err(anyhow::anyhow!("local identity lookup timed out"));
        }
        let mut block = [0u8; 4096];
        match stdout.read(&mut block) {
            Ok(0) => eof = true,
            Ok(n) => {
                if n > 16_384usize.saturating_sub(bytes.len()) {
                    break Err(anyhow::anyhow!("identity output limit exceeded"));
                }
                bytes.extend_from_slice(&block[..n]);
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) => {}
            Err(_) => break Err(anyhow::anyhow!("identity output unavailable")),
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(s) => status = s,
                Err(_) => break Err(anyhow::anyhow!("identity lookup wait failed")),
            }
        }
        if eof && let Some(exit) = status {
            if !exit.success() {
                break Err(anyhow::anyhow!("local identity lookup failed"));
            }
            break String::from_utf8(bytes)
                .map(|s| s.trim().to_owned())
                .map_err(|_| anyhow::anyhow!("invalid identity output"));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    if status.is_none() {
        // Only the still-owned direct child is killed; an already reaped child is never signaled.
        if matches!(child.try_wait(), Ok(None)) {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
    result
}
fn groups(uid: Option<u32>) -> Result<BTreeSet<u32>> {
    let text = if let Some(uid) = uid {
        identity_command("/usr/bin/id", &["-G", &uid.to_string()])?
    } else {
        identity_command("/usr/bin/id", &["-G"])?
    };
    text.split_whitespace()
        .map(|v| v.parse().context("invalid group ID"))
        .collect()
}
fn username(uid: u32) -> Result<String> {
    ensure!(
        identity_command("/usr/bin/id", &["-u", &uid.to_string()])?.parse::<u32>()? == uid,
        "UID lookup mismatch"
    );
    let name = identity_command("/usr/bin/id", &["-un", &uid.to_string()])?;
    ensure!(valid_name(&name), "unsupported local account name");
    Ok(name)
}
fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        && !s.starts_with('-')
}
fn search_records(text: &str) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for line in text
        .lines()
        .filter(|l| !l.starts_with(char::is_whitespace) && !l.trim().is_empty() && *l != ")")
    {
        let name = line
            .split_whitespace()
            .next()
            .context("invalid directory record")?;
        ensure!(valid_name(name), "invalid directory record name");
        names.push(name.to_owned());
    }
    Ok(names)
}
fn validate_accounts_and_group(
    service_uid: u32,
    config: &OperatorSocketConfig,
) -> Result<BTreeSet<u32>> {
    let service = username(service_uid)?;
    let operator = username(config.operator_uid)?;
    let _ = username(config.generator_uid)?;
    let _ = username(config.evaluator_uid)?;
    let operator_groups = groups(Some(config.operator_uid))?;
    ensure!(
        groups(None)?.contains(&config.access_gid) && operator_groups.contains(&config.access_gid),
        "service process and operator must belong to access group"
    );
    for uid in [config.generator_uid, config.evaluator_uid] {
        ensure!(
            !groups(Some(uid))?.contains(&config.access_gid),
            "worker identity belongs to operator access group"
        );
    }
    let gid = config.access_gid.to_string();
    let group_names = search_records(&identity_command(
        "/usr/bin/dscl",
        &[".", "-search", "/Groups", "PrimaryGroupID", &gid],
    )?)?;
    ensure!(
        group_names.len() == 1,
        "access group must resolve to exactly one local group"
    );
    let record = format!("/Groups/{}", group_names[0]);
    let attributes = identity_command(
        "/usr/bin/dscl",
        &[
            ".",
            "-read",
            &record,
            "GroupMembership",
            "GroupMembers",
            "NestedGroups",
        ],
    )?;
    let mut names = Vec::new();
    let mut guids = Vec::new();
    let mut active = "";
    for line in attributes.lines() {
        let values = if let Some((key, value)) = line.split_once(':') {
            active = key;
            value
        } else {
            line
        };
        match active {
            "GroupMembership" => names.extend(values.split_whitespace().map(str::to_owned)),
            "GroupMembers" => guids.extend(values.split_whitespace().map(str::to_owned)),
            "NestedGroups" => ensure!(
                values.trim().is_empty(),
                "nested access groups are unsupported"
            ),
            "No such key" => (),
            _ => bail!("unrecognized group membership record"),
        }
    }
    for guid in guids {
        ensure!(
            guid.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'),
            "invalid group member identifier"
        );
        let resolved = search_records(&identity_command(
            "/usr/bin/dscl",
            &[".", "-search", "/Users", "GeneratedUID", &guid],
        )?)?;
        ensure!(
            resolved.len() == 1,
            "group member must resolve to one local account"
        );
        names.extend(resolved);
    }
    names.extend(search_records(&identity_command(
        "/usr/bin/dscl",
        &[".", "-search", "/Users", "PrimaryGroupID", &gid],
    )?)?);
    let actual_members: BTreeSet<_> = names.into_iter().collect();
    let expected_members: BTreeSet<_> = [operator, service].into_iter().collect();
    ensure!(
        actual_members == expected_members,
        "access group must contain exactly the service and operator accounts"
    );
    Ok(operator_groups)
}

fn validate_ancestor_access(
    socket: &Path,
    service_uid: u32,
    operator_uid: u32,
    groups: &BTreeSet<u32>,
) -> Result<()> {
    let parent = socket.parent().context("socket parent required")?;
    ensure!(
        socket.is_absolute() && parent.canonicalize()? == parent,
        "socket requires an absolute canonical parent without symlinks"
    );
    for ancestor in parent.ancestors() {
        let m = fs::symlink_metadata(ancestor)?;
        ensure!(
            m.is_dir() && !m.file_type().is_symlink(),
            "socket ancestor is not a real directory"
        );
        ensure!(
            [0, service_uid].contains(&m.uid()) && m.mode() & 0o022 == 0,
            "socket ancestor must be root/service-owned and not group/world-writable"
        );
        let execute = if m.uid() == operator_uid {
            0o100
        } else if groups.contains(&m.gid()) {
            0o010
        } else {
            0o001
        };
        ensure!(
            m.mode() & execute != 0,
            "operator cannot traverse socket ancestor"
        );
        // POSIX mode checks alone do not exclude ACL write grants on macOS.
        let listing = identity_command(
            "/bin/ls",
            &[
                "-lde",
                ancestor.to_str().context("non-UTF8 socket ancestor")?,
            ],
        )?;
        ensure!(
            listing.lines().count() == 1,
            "socket ancestors with ACLs require explicit review and are unsupported"
        );
    }
    Ok(())
}
fn bind_checked(
    path: &Path,
    service_uid: u32,
    access_gid: u32,
) -> Result<(UnixListener, OperatorSocketGuard)> {
    let parent = path.parent().context("socket parent required")?;
    let pm = fs::symlink_metadata(parent)?;
    ensure!(
        pm.is_dir()
            && !pm.file_type().is_symlink()
            && pm.uid() == service_uid
            && pm.gid() == access_gid
            && pm.mode() & 0o7777 == 0o2710,
        "socket parent requires service ownership, access group and mode 02710"
    );
    match fs::symlink_metadata(path) {
        Ok(_) => bail!("socket path already exists; nothing removed"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    let listener = UnixListener::bind(path)?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_socket()
            && metadata.uid() == service_uid
            && metadata.gid() == access_gid,
        "unexpected bound socket identity"
    );
    let guard = OperatorSocketGuard {
        path: path.to_owned(),
        identity: Identity::of(&metadata),
        parent: Identity::of(&pm),
    };
    fs::set_permissions(path, Permissions::from_mode(0o660))?;
    let after = fs::symlink_metadata(path)?;
    ensure!(
        Identity::of(&after) == guard.identity && after.mode() & 0o7777 == 0o660,
        "socket mode or identity mismatch"
    );
    Ok((listener, guard))
}

#[cfg(test)]
mod tests {
    #[test]
    fn identity_lookup_refuses_inherited_auto_reaping_before_spawn() {
        const MARKER: &str = "SFACTORY_TEST_IDENTITY_AUTO_REAP";
        if std::env::var_os(MARKER).is_some() {
            // This is an isolated test process; the parent test runner's SIGCHLD stays intact.
            unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) };
            assert!(super::identity_command("/usr/bin/true", &[]).is_err());
            return;
        }
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "operator_transport::tests::identity_lookup_refuses_inherited_auto_reaping_before_spawn"])
            .env(MARKER, "1").output().unwrap();
        assert!(child.status.success());
    }

    #[test]
    fn identity_lookup_times_out_when_exited_child_leaves_pipe_open() {
        let started = std::time::Instant::now();
        let result = super::identity_command("/bin/sh", &["-c", "/bin/sleep 5 & printf fixture"]);
        assert!(
            result.is_err(),
            "lookup returned success despite retained output pipe"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(4));
    }
    use super::*;
    use axum::{Extension, Json, Router, middleware, routing::post};
    use serde_json::{Value, json};
    use std::os::unix::fs::{DirBuilderExt, symlink};
    use tower::ServiceExt;

    struct Fixture {
        path: PathBuf,
        uid: u32,
        gid: u32,
    }
    impl Fixture {
        fn new() -> Self {
            let (a, _b) = UnixStream::pair().unwrap();
            let creds = a.peer_cred().unwrap();
            let path = std::env::temp_dir().join(format!("ot-{}", shared::new_id()));
            fs::DirBuilder::new().mode(0o2710).create(&path).unwrap();
            fs::set_permissions(&path, Permissions::from_mode(0o2710)).unwrap();
            Self {
                path: path.canonicalize().unwrap(),
                uid: creds.uid(),
                gid: creds.gid(),
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
    fn router(expected_uid: u32) -> Router {
        Router::new()
            .route(
                "/diagnostic",
                post(
                    |Extension(peer): Extension<AuthenticatedOperator>| async move {
                        Json(json!({"kernel_uid": peer.uid(), "mutations": "unavailable"}))
                    },
                ),
            )
            .layer(middleware::from_fn_with_state(
                OperatorPolicy { expected_uid },
                require_operator,
            ))
    }
    #[tokio::test]
    async fn real_connection_identity_wins_over_body_and_synthetic_mismatch_denies() {
        let fixture = Fixture::new();
        for expected_uid in [fixture.uid, fixture.uid.wrapping_add(1)] {
            let path = fixture.path.join("s");
            // Test-only same-account binding; public production entry has no bypass.
            let (listener, guard) = bind_checked(&path, fixture.uid, fixture.gid).unwrap();
            let app = router(expected_uid);
            let server = tokio::spawn(async move {
                axum::serve(
                    listener,
                    app.into_make_service_with_connect_info::<OperatorPeer>(),
                )
                .await
                .unwrap();
            });
            let client = reqwest::Client::builder()
                .unix_socket(path.clone())
                .build()
                .unwrap();
            let response = client
                .post("http://localhost/diagnostic")
                .json(&json!({"uid":expected_uid, "operator_uid": expected_uid, "approved":true}))
                .send()
                .await
                .unwrap();
            if expected_uid == fixture.uid {
                assert_eq!(response.status(), StatusCode::OK);
                let body: Value = response.json().await.unwrap();
                assert_eq!(body["kernel_uid"], fixture.uid);
                assert_eq!(body["mutations"], "unavailable");
            } else {
                assert_eq!(response.status(), StatusCode::FORBIDDEN);
            }
            server.abort();
            let _ = server.await;
            assert!(guard.cleanup().unwrap());
        }
    }
    #[tokio::test]
    async fn missing_and_failed_peer_lookup_deny_before_handler() {
        for peer in [None, Some(OperatorPeer { uid: None })] {
            let mut request = Request::builder()
                .method("POST")
                .uri("/diagnostic")
                .body(axum::body::Body::from(r#"{"uid":501,"approved":true}"#))
                .unwrap();
            if let Some(peer) = peer {
                request.extensions_mut().insert(ConnectInfo(peer));
            }
            assert_eq!(
                router(501).oneshot(request).await.unwrap().status(),
                StatusCode::FORBIDDEN
            );
        }
    }
    #[tokio::test]
    async fn public_entry_rejects_same_uid_without_provisioning() {
        let f = Fixture::new();
        let config = OperatorSocketConfig {
            path: f.path.join("s"),
            operator_uid: f.uid,
            generator_uid: f.uid + 1,
            evaluator_uid: f.uid + 2,
            access_gid: f.gid,
        };
        assert!(bind_operator_socket(&config).is_err());
        assert!(!config.path.exists());
    }
    #[tokio::test]
    async fn existing_entries_and_symlink_parent_are_never_removed() {
        let f = Fixture::new();
        let path = f.path.join("s");
        fs::write(&path, "preserved").unwrap();
        assert!(bind_checked(&path, f.uid, f.gid).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "preserved");
        fs::remove_file(&path).unwrap();
        symlink(f.path.join("absent"), &path).unwrap();
        assert!(bind_checked(&path, f.uid, f.gid).is_err());
        assert!(
            fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        fs::remove_file(&path).unwrap();
        let stale = UnixListener::bind(&path).unwrap();
        drop(stale);
        assert!(bind_checked(&path, f.uid, f.gid).is_err());
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
        let alias = f.path.join("alias");
        symlink(&f.path, &alias).unwrap();
        assert!(bind_checked(&alias.join("new"), f.uid, f.gid).is_err());
    }
    #[tokio::test]
    async fn insecure_parent_and_replaced_endpoint_fail_closed() {
        let f = Fixture::new();
        let path = f.path.join("s");
        fs::set_permissions(&f.path, Permissions::from_mode(0o2770)).unwrap();
        assert!(bind_checked(&path, f.uid, f.gid).is_err());
        fs::set_permissions(&f.path, Permissions::from_mode(0o2710)).unwrap();
        let (listener, guard) = bind_checked(&path, f.uid, f.gid).unwrap();
        drop(listener);
        fs::remove_file(&path).unwrap();
        fs::write(&path, "replacement").unwrap();
        assert!(!guard.cleanup().unwrap());
        assert_eq!(fs::read_to_string(&path).unwrap(), "replacement");
    }
    #[test]
    fn account_and_group_parser_is_strict() {
        assert_eq!(
            search_records("access\t\tPrimaryGroupID = (\n    555\n)").unwrap(),
            vec!["access"]
        );
        assert!(search_records("-malicious\tPrimaryGroupID = (\n555\n)").is_err());
        let config = OperatorSocketConfig {
            path: PathBuf::from("/unprovisioned/s"),
            operator_uid: 1001,
            generator_uid: 1002,
            evaluator_uid: 1003,
            access_gid: 1004,
        };
        assert!(validate_distinct(1000, &config).is_ok());
        assert!(validate_distinct(1001, &config).is_err());
        assert!(validate_distinct(0, &config).is_err());
    }
}
