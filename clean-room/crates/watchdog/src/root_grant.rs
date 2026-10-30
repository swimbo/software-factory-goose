//! Root grant client and verifier. No launch endpoint or production wiring.
//! Socket activation identifies the listener creator, not necessarily the
//! serving process; an independently verified service attestation is required.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
            net::UnixStream,
        },
    },
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const SOCKET: &str = "/run/software-factory-goose/real-launch-grant.sock";
#[cfg(target_os = "linux")]
fn no_acl(f: &File) -> Result<()> {
    no_attr(f, "system.posix_acl_access")
}
#[cfg(target_os = "linux")]
fn no_attr(f: &File, attr: &str) -> Result<()> {
    let name = std::ffi::CString::new(attr)?;
    // SAFETY: live file descriptor and terminated attribute name; null buffer queries size.
    let rc = unsafe { libc::fgetxattr(f.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
    ensure!(
        rc < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA),
        "ACL present or unavailable"
    );
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn no_acl(_f: &File) -> Result<()> {
    bail!("Linux ACL validation required")
}
pub struct ReservationIntent {
    generation: String,
    catalog_sha256: String,
    state: File,
}
pub struct ReceivedReservation {
    generation: String,
    catalog_sha256: String,
    reservation: Reservation,
}
pub struct VerifiedGrant {
    binding_sha256: String,
    expires_at_ms: u64,
    hard_deadline_ms: u64,
}
pub struct VerifiedCatalog {
    catalog: LaunchCatalog,
    recipe: LaunchRecipe,
}
impl VerifiedCatalog {
    pub fn recipe(&self) -> &LaunchRecipe {
        &self.recipe
    }
}
impl VerifiedGrant {
    pub fn binding_sha256(&self) -> &str {
        &self.binding_sha256
    }
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
    pub fn hard_deadline_ms(&self) -> u64 {
        self.hard_deadline_ms
    }
}
/// Permanently fences a single request before it can reach the journal.
pub fn begin_reservation(dir: &File, verified: &VerifiedCatalog) -> Result<ReservationIntent> {
    let g = verified.catalog.scope.generation.as_str();
    let catalog_sha256 = verified.catalog.scope.catalog_sha256.as_str();
    validate_root_state(dir)?;
    ensure_open_generation(dir, g)?;
    ensure!(
        canonical_id(g) && digest_ok(catalog_sha256),
        "invalid reservation identity"
    );
    let name = std::ffi::CString::new(format!("{g}.grant-request"))?;
    // SAFETY: trusted directory and fixed single-component name; exclusive create.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: openat returned an owned descriptor.
    let mut f = unsafe { File::from_raw_fd(fd) };
    no_acl(&f)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.gid() == 0 && m.nlink() == 1 && m.mode() & 0o7777 == 0o600,
        "invalid intent metadata"
    );
    write!(f, "{g}\n{catalog_sha256}\n")?;
    f.sync_all()?;
    dir.sync_all()?;
    ensure_open_generation(dir, g)?;
    Ok(ReservationIntent {
        generation: g.to_owned(),
        catalog_sha256: catalog_sha256.to_owned(),
        state: dir.try_clone()?,
    })
}
fn ensure_open_generation(dir: &File, g: &str) -> Result<()> {
    let name = std::ffi::CString::new(format!("{g}.closed"))?;
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fixed name, live directory descriptor, valid output pointer.
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == 0 {
        bail!("generation closed")
    }
    ensure!(
        std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT),
        "closure state unavailable"
    );
    Ok(())
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseSpec {
    pub repository: String,
    pub base_revision: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub task_id: String,
    pub intent_id: String,
    pub queue_id: String,
    pub generation: String,
    pub spec: LeaseSpec,
    pub worker_id: String,
    pub catalog_sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reservation {
    pub scope: Scope,
    pub generation: String,
    pub attempt: u32,
    pub token_sha256: String,
    pub expires_at_ms: u64,
    pub hard_deadline_ms: u64,
}
/// This fixed root-owned catalogue is distinct from the stop-only catalogue.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchCatalog {
    pub schema: u32,
    pub scope: Scope,
    pub boot_id: String,
    pub cgroup_dev: u64,
    pub cgroup_ino: u64,
    pub recipe_sha256: String,
    pub max_expiry_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchRecipe {
    pub schema: u32,
    pub purpose: String,
    pub generation: String,
    pub task_id: String,
    pub worker_uid: u32,
    pub goose_binary_sha256: String,
    pub worker_image_id: String,
    pub worker_program_sha256: String,
    pub writer_image_id: String,
    pub writer_program_sha256: String,
    pub profile_sha256: String,
    pub prompt_sha256: String,
    pub relay_scope_template_sha256: String,
    pub provider_binding_sha256: String,
    pub fixed_parent: String,
}
fn validate_recipe(r: &LaunchRecipe, c: &LaunchCatalog) -> Result<()> {
    ensure!(
        r.schema == 1
            && r.purpose == "nuc-goose-write-files-v1"
            && r.generation == c.scope.generation
            && r.task_id == c.scope.task_id
            && r.worker_uid == 2001
            && r.goose_binary_sha256
                == "802d1478e6a53ef7c68a56ccfed3aec59eab0afd68aa411ec0c1b516dc5334db"
            && r.worker_image_id
                == "sha256:509d7c54cfdbf6afd9e1c80ff924d367bdaf0979e6ef63b1f7d1134ce3a9710a"
            && r.writer_image_id
                == "sha256:2efe778192492f6934540be9771bc1057b4724fe20bed6f71a362a4b91636b48"
            && r.worker_program_sha256
                == "c0f51ee7767c6448c1fa3908e137c280753de302af9e7196751bb67fbc601df1"
            && r.writer_program_sha256
                == "4ade60e556a391795b8f2b13a5e6d52efb68a04d6d806f5e0bf76e3cdc0d3d8c"
            && [
                &r.worker_program_sha256,
                &r.writer_program_sha256,
                &r.profile_sha256,
                &r.prompt_sha256,
                &r.relay_scope_template_sha256,
                &r.provider_binding_sha256
            ]
            .iter()
            .all(|s| digest_ok(s))
            && r.fixed_parent == format!("sfactory{}.slice", r.generation.to_lowercase()),
        "invalid root recipe"
    );
    Ok(())
}
/// Load only the fixed root-owned per-generation launch catalogue. The existing
/// stop catalogue remains the separate authority for cgroup2 and boot identity.
#[cfg(target_os = "linux")]
pub fn load_root_catalog(g: &str) -> Result<VerifiedCatalog> {
    ensure!(canonical_id(g), "invalid generation");
    let root = Path::new("/etc/software-factory-goose/launch-catalog");
    for p in root.ancestors() {
        let m = std::fs::symlink_metadata(p)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
            "untrusted catalogue directory"
        );
        let dir = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(p)?;
        no_acl(&dir)?;
        no_attr(&dir, "system.posix_acl_default")?;
    }
    let dm = std::fs::symlink_metadata(root)?;
    ensure!(dm.mode() & 0o7777 == 0o700, "catalogue directory mode");
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(root.join(format!("{g}.json")))?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o600
            && m.len() <= 16384,
        "untrusted launch catalogue"
    );
    let mut raw = Vec::new();
    no_acl(&f)?;
    Read::by_ref(&mut f).take(16385).read_to_end(&mut raw)?;
    ensure!(raw.len() as u64 == m.len(), "launch catalogue changed");
    let c: LaunchCatalog = serde_json::from_slice(&raw)?;
    let mut rf = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(root.join(format!("{g}.recipe.json")))?;
    let rm = rf.metadata()?;
    ensure!(
        rm.is_file()
            && rm.uid() == 0
            && rm.gid() == 0
            && rm.nlink() == 1
            && rm.mode() & 0o7777 == 0o600
            && rm.len() <= 16384,
        "untrusted launch recipe"
    );
    let mut recipe_raw = Vec::new();
    no_acl(&rf)?;
    Read::by_ref(&mut rf)
        .take(16385)
        .read_to_end(&mut recipe_raw)?;
    ensure!(recipe_raw.len() as u64 == rm.len(), "launch recipe changed");
    let recipe: LaunchRecipe = serde_json::from_slice(&recipe_raw)?;
    ensure!(
        json_bytes(&recipe)? == recipe_raw
            && format!("{:x}", Sha256::digest(&recipe_raw)) == c.recipe_sha256,
        "recipe digest or canonical encoding mismatch"
    );
    validate_recipe(&recipe, &c)?;
    ensure!(c.scope.generation == g, "catalogue generation mismatch");
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    validate_catalog(&c, boot.trim())?;
    ensure!(c.max_expiry_ms > now_ms()?, "catalogue expired");
    let _ = crate::root_cgroup::linux::KernelStop::open(g)?;
    let path = Path::new("/sys/fs/cgroup").join(format!("sfactory{}.slice", g.to_lowercase()));
    let cg = std::fs::symlink_metadata(path)?;
    ensure!(
        cg.is_dir() && cg.dev() == c.cgroup_dev && cg.ino() == c.cgroup_ino,
        "catalogue cgroup mismatch"
    );
    Ok(VerifiedCatalog { catalog: c, recipe })
}
fn json_bytes<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(v)?;
    fn sort(v: serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(m) => {
                let b: BTreeMap<_, _> = m.into_iter().map(|(k, v)| (k, sort(v))).collect();
                serde_json::to_value(b).expect("JSON value serialization")
            }
            serde_json::Value::Array(a) => {
                serde_json::Value::Array(a.into_iter().map(sort).collect())
            }
            v => v,
        }
    }
    Ok(serde_json::to_vec(&sort(value))?)
}

fn digest_ok(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn canonical_id(s: &str) -> bool {
    ulid::Ulid::from_string(s).is_ok_and(|u| u.to_string() == s)
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
}
fn validate_catalog(c: &LaunchCatalog, boot: &str) -> Result<()> {
    ensure!(
        c.schema == 1
            && c.boot_id == boot
            && c.cgroup_dev > 0
            && c.cgroup_ino > 0
            && canonical_id(&c.scope.generation)
            && digest_ok(&c.recipe_sha256)
            && digest_ok(&c.scope.catalog_sha256),
        "invalid catalog"
    );
    ensure!(
        [
            &c.scope.task_id,
            &c.scope.intent_id,
            &c.scope.queue_id,
            &c.scope.worker_id
        ]
        .iter()
        .all(|s| identifier(s))
            && !c.scope.spec.repository.is_empty()
            && c.scope.spec.repository.len() <= 256
            && c.scope.spec.repository.trim() == c.scope.spec.repository
            && !c.scope.spec.repository.chars().any(char::is_control)
            && [40, 64].contains(&c.scope.spec.base_revision.len())
            && c.scope
                .spec
                .base_revision
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid catalog scope"
    );
    Ok(())
}
/// Domain-separated digest of complete typed grant plus the exact root launch
/// catalogue and recipe. The caller must separately prove catalogue provenance,
/// cgroup/boot identity and the independent deadline before engine effects.
pub fn validate_and_bind(
    c: &LaunchCatalog,
    g: &Reservation,
    boot: &str,
    now_ms: u64,
) -> Result<String> {
    validate_catalog(c, boot)?;
    ensure!(
        g.scope == c.scope
            && g.generation == c.scope.generation
            && g.attempt > 0
            && digest_ok(&g.token_sha256)
            && now_ms < g.expires_at_ms
            && g.expires_at_ms <= g.hard_deadline_ms
            && g.hard_deadline_ms <= c.max_expiry_ms,
        "grant mismatch or expired"
    );
    // BTreeMap makes byte ordering independent of serde_json's map feature set.
    let grant = json_bytes(g)?;
    let cat = json_bytes(c)?;
    let mut h = Sha256::new();
    h.update(b"sfactory-root-grant-v1\0");
    h.update((grant.len() as u64).to_be_bytes());
    h.update(grant);
    h.update((cat.len() as u64).to_be_bytes());
    h.update(cat);
    Ok(format!("{:x}", h.finalize()))
}
/// Persist the complete verified reservation and its binding before engine use.
/// A future root catalogue loader must establish catalogue provenance separately.
pub fn persist_verified(
    dir: &File,
    received: ReceivedReservation,
    verified: &VerifiedCatalog,
    boot: &str,
    now: u64,
) -> Result<VerifiedGrant> {
    validate_root_state(dir)?;
    let catalog = &verified.catalog;
    ensure_open_generation(dir, &catalog.scope.generation)?;
    ensure!(
        received.generation == catalog.scope.generation
            && received.catalog_sha256 == catalog.scope.catalog_sha256,
        "grant target mismatch"
    );
    let binding = validate_and_bind(catalog, &received.reservation, boot, now)?;
    let expiry = received.reservation.expires_at_ms;
    let hard = received.reservation.hard_deadline_ms;
    let record = serde_json::to_vec(
        &serde_json::json!({"schema":1,"generation":received.generation,"binding_sha256":binding,"reservation":received.reservation}),
    )?;
    let name = std::ffi::CString::new(format!("{}.grant-verified", catalog.scope.generation))?;
    // SAFETY: protected root directory and one fixed name; exclusive create.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: openat returned a fresh, owned descriptor.
    let mut f = unsafe { File::from_raw_fd(fd) };
    no_acl(&f)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.gid() == 0 && m.nlink() == 1 && m.mode() & 0o7777 == 0o600,
        "bad grant record metadata"
    );
    f.write_all(&record)?;
    f.sync_all()?;
    dir.sync_all()?;
    Ok(VerifiedGrant {
        binding_sha256: binding,
        expires_at_ms: expiry,
        hard_deadline_ms: hard,
    })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifiedRecord {
    schema: u32,
    generation: String,
    binding_sha256: String,
    reservation: Reservation,
}
fn read_state(dir: &File, name: &str) -> Result<Vec<u8>> {
    let n = std::ffi::CString::new(name)?;
    // SAFETY: name is one derived component and dir is a validated owned descriptor.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            n.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: openat returned a fresh descriptor.
    let mut f = unsafe { File::from_raw_fd(fd) };
    no_acl(&f)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o600
            && m.len() <= 16384,
        "bad grant state"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut f).take(16385).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 == m.len(), "grant state changed");
    Ok(bytes)
}
/// Revalidate the persisted full grant without asking the journal again.
pub fn load_verified(
    dir: &File,
    verified: &VerifiedCatalog,
    boot: &str,
    now: u64,
) -> Result<VerifiedGrant> {
    validate_root_state(dir)?;
    let catalog = &verified.catalog;
    let g = &catalog.scope.generation;
    ensure_open_generation(dir, g)?;
    let expected = format!("{g}\n{}\n", catalog.scope.catalog_sha256);
    ensure!(
        read_state(dir, &format!("{g}.grant-request"))? == expected.as_bytes(),
        "grant intent mismatch"
    );
    let record: VerifiedRecord =
        serde_json::from_slice(&read_state(dir, &format!("{g}.grant-verified"))?)?;
    ensure!(
        record.schema == 1 && record.generation == *g,
        "grant record target mismatch"
    );
    let binding = validate_and_bind(catalog, &record.reservation, boot, now)?;
    ensure!(record.binding_sha256 == binding, "grant binding changed");
    ensure_open_generation(dir, g)?;
    Ok(VerifiedGrant {
        binding_sha256: binding,
        expires_at_ms: record.reservation.expires_at_ms,
        hard_deadline_ms: record.reservation.hard_deadline_ms,
    })
}

/// Must establish the fixed protected systemd service identity and executable
/// before and after the request. Peer UID 0 alone cannot establish the server.
pub trait ServiceAttestation {
    fn verify(&self) -> Result<()>;
}
fn trusted_socket() -> Result<()> {
    let p = Path::new(SOCKET);
    let m = std::fs::symlink_metadata(p)?;
    ensure!(
        m.file_type().is_socket() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o600,
        "untrusted grant socket"
    );
    for parent in p.parent().into_iter().flat_map(Path::ancestors) {
        let m = std::fs::symlink_metadata(parent)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
            "untrusted socket parent"
        );
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn peer_root(s: &UnixStream) -> Result<()> {
    let mut u = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: kernel fills a correctly sized ucred for this live socket.
    ensure!(
        unsafe {
            libc::getsockopt(
                s.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                u.as_mut_ptr().cast(),
                &mut len,
            )
        } == 0
            && len as usize == std::mem::size_of::<libc::ucred>(),
        "peer unavailable"
    );
    // SAFETY: getsockopt succeeded with the full structure.
    ensure!(
        unsafe { u.assume_init() }.uid == 0,
        "unexpected socket peer"
    );
    Ok(())
}
fn parse_http(bytes: &[u8]) -> Result<Reservation> {
    let split = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("missing HTTP headers")?;
    ensure!(split <= 4096, "HTTP headers too large");
    let header = std::str::from_utf8(&bytes[..split])?;
    let mut lines = header.split("\r\n");
    ensure!(lines.next() == Some("HTTP/1.1 200 OK"), "grant unavailable");
    let mut length = None;
    for line in lines {
        let (k, v) = line.split_once(':').context("invalid header")?;
        if k.eq_ignore_ascii_case("transfer-encoding") {
            bail!("unsupported transfer encoding")
        }
        if k.eq_ignore_ascii_case("content-length") {
            ensure!(length.is_none(), "duplicate content length");
            length = Some(v.trim().parse::<usize>()?);
        }
    }
    let body = &bytes[split + 4..];
    ensure!(
        length == Some(body.len()) && body.len() <= 16384,
        "invalid HTTP body length"
    );
    Ok(serde_json::from_slice(body)?)
}
fn read_response(stream: &mut UnixStream, timeout: Duration) -> Result<Vec<u8>> {
    let end = Instant::now() + timeout;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let remaining = end
            .checked_duration_since(Instant::now())
            .context("grant response deadline")?;
        ensure!(!remaining.is_zero(), "grant response deadline");
        stream.set_read_timeout(Some(remaining))?;
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        ensure!(
            bytes.len().saturating_add(n) <= 20480,
            "grant response too large"
        );
        bytes.extend_from_slice(&chunk[..n]);
    }
    Ok(bytes)
}
/// A caller must fsync a create-only root reservation-request intent before
/// invoking this method. Timeout, malformed reply or disconnect is unknown and
/// must never trigger a fresh claim or automatic retry.
#[cfg(target_os = "linux")]
pub fn request_reserved(
    intent: ReservationIntent,
    attestor: &impl ServiceAttestation,
) -> Result<ReceivedReservation> {
    let g = &intent.generation;
    ensure_open_generation(&intent.state, g)?;
    trusted_socket()?;
    attestor.verify()?;
    // SAFETY: socket creates a new descriptor, transferred to UnixStream below.
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    ensure!(fd >= 0, "socket unavailable");
    // SAFETY: fd is freshly allocated and now exclusively owned by stream.
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    // SAFETY: zero initializes sockaddr_un, including its NUL-terminated path.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let path = SOCKET.as_bytes();
    ensure!(path.len() < addr.sun_path.len(), "socket path too long");
    for (dst, src) in addr.sun_path.iter_mut().zip(path) {
        *dst = *src as libc::c_char;
    }
    // SAFETY: addr points to a fully initialized local sockaddr_un.
    let rc = unsafe {
        libc::connect(
            fd,
            (&addr as *const libc::sockaddr_un).cast(),
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        ensure!(
            err.raw_os_error() == Some(libc::EINPROGRESS),
            "connect unavailable"
        );
        let mut p = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: poll receives one valid pollfd and a bounded timeout.
        ensure!(
            unsafe { libc::poll(&mut p, 1, 3000) } == 1 && p.revents & libc::POLLOUT != 0,
            "connect timeout"
        );
        let mut code: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: getsockopt writes one integer into the supplied storage.
        ensure!(
            unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut code as *mut libc::c_int).cast(),
                    &mut len,
                )
            } == 0
                && code == 0,
            "connect failed"
        );
    }
    // SAFETY: fcntl operates on the live stream descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    ensure!(
        flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) } == 0,
        "socket mode unavailable"
    );
    trusted_socket()?;
    let reservation = request_on_connected(stream, g, attestor)?;
    ensure_open_generation(&intent.state, g)?;
    ensure!(reservation.generation == *g, "grant target mismatch");
    Ok(ReceivedReservation {
        generation: g.clone(),
        catalog_sha256: intent.catalog_sha256,
        reservation,
    })
}
/// Verify an already-connected stream in a bounded fixture; never authorizes an
/// engine operation or implies the remote reservation was not committed on error.
#[cfg(target_os = "linux")]
fn request_on_connected(
    mut stream: UnixStream,
    g: &str,
    attestor: &impl ServiceAttestation,
) -> Result<Reservation> {
    ensure!(canonical_id(g), "invalid generation");
    attestor.verify()?;
    peer_root(&stream)?;
    stream.set_read_timeout(Some(Duration::from_secs(12)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    let body = serde_json::to_vec(&serde_json::json!({"generation":g}))?;
    write!(
        stream,
        "POST /reserve HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    stream.flush()?;
    let bytes = read_response(&mut stream, Duration::from_secs(12))?;
    let grant = parse_http(&bytes)?;
    attestor.verify()?;
    Ok(grant)
}
/// Wall-clock read for callers; expiry alone does not replace independent timer.
pub fn now_ms() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}
// Avoid accepting a directory descriptor merely because it is open.
pub fn validate_root_state(dir: &File) -> Result<()> {
    let m = dir.metadata()?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "untrusted root state"
    );
    no_acl(dir)?;
    #[cfg(target_os = "linux")]
    no_attr(dir, "system.posix_acl_default")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (LaunchCatalog, Reservation) {
        let g = "01M65N5TM28WPH7BKQ153SPNJR".to_owned();
        let scope = Scope {
            task_id: "task".into(),
            intent_id: "intent".into(),
            queue_id: "queue".into(),
            generation: g.clone(),
            worker_id: "worker".into(),
            catalog_sha256: "a".repeat(64),
            spec: LeaseSpec {
                repository: "repo".into(),
                base_revision: "b".repeat(40),
            },
        };
        let grant = Reservation {
            scope: scope.clone(),
            generation: g,
            attempt: 1,
            token_sha256: "c".repeat(64),
            expires_at_ms: 200,
            hard_deadline_ms: 300,
        };
        (
            LaunchCatalog {
                schema: 1,
                scope,
                boot_id: "boot".into(),
                cgroup_dev: 29,
                cgroup_ino: 42,
                recipe_sha256: "d".repeat(64),
                max_expiry_ms: 300,
            },
            grant,
        )
    }
    #[test]
    fn exact_grant_binds_recipe_and_deadlines() {
        let (c, g) = fixture();
        let v = validate_and_bind(&c, &g, "boot", 100).unwrap();
        assert_eq!(v.len(), 64);
        assert_eq!(
            v,
            "c414f3b8434a6a95ab5aaed7ce414acfbde118400bebb5e4f0f933f01abe3d43"
        );
        let mut changed = c.clone();
        changed.recipe_sha256 = "e".repeat(64);
        assert_ne!(v, validate_and_bind(&changed, &g, "boot", 100).unwrap());
        let mut changed_grant = g.clone();
        changed_grant.attempt = 2;
        assert_ne!(
            v,
            validate_and_bind(&c, &changed_grant, "boot", 100).unwrap()
        );
        assert!(validate_and_bind(&c, &g, "other-boot", 100).is_err());
        assert!(validate_and_bind(&c, &g, "boot", 200).is_err());
        changed_grant = g.clone();
        changed_grant.scope.worker_id = "other".into();
        assert!(validate_and_bind(&c, &changed_grant, "boot", 100).is_err());
        changed_grant = g.clone();
        changed_grant.hard_deadline_ms = 301;
        assert!(validate_and_bind(&c, &changed_grant, "boot", 100).is_err());
    }
    #[test]
    fn http_rejects_duplicate_or_ambiguous_framing() {
        let (_, g) = fixture();
        let body = serde_json::to_vec(&g).unwrap();
        let request = |headers: &str| {
            let mut b = format!("HTTP/1.1 200 OK\r\n{headers}\r\n\r\n").into_bytes();
            b.extend_from_slice(&body);
            b
        };
        assert_eq!(
            parse_http(&request(&format!("Content-Length: {}", body.len()))).unwrap(),
            g
        );
        assert!(
            parse_http(&request(&format!(
                "Content-Length: {}\r\nContent-Length: {}",
                body.len(),
                body.len()
            )))
            .is_err()
        );
        assert!(
            parse_http(&request(&format!(
                "Content-Length: {}\r\nTransfer-Encoding: chunked",
                body.len()
            )))
            .is_err()
        );
        assert!(parse_http(&request("Content-Length: 0")).is_err());
    }
    #[test]
    fn duplicate_grant_fields_denied() {
        let (_, g) = fixture();
        let raw = serde_json::to_string(&g).unwrap();
        let raw = raw.replacen("{", "{\"attempt\":5,", 1);
        let b = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            raw.len(),
            raw
        );
        assert!(parse_http(b.as_bytes()).is_err());
    }
    #[test]
    fn slow_drip_cannot_extend_total_response_deadline() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            for _ in 0..20 {
                if writer.write_all(b"x").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(15));
            }
        });
        let start = Instant::now();
        assert!(read_response(&mut reader, Duration::from_millis(60)).is_err());
        assert!(start.elapsed() < Duration::from_millis(250));
        drop(reader);
        worker.join().unwrap();
    }
    #[test]
    fn closure_file_or_broken_symlink_closes_reservation() {
        use std::os::unix::fs::symlink;
        let g = ulid::Ulid::new().to_string();
        let path = std::env::temp_dir().join(format!("sfactory-grant-closure-{g}"));
        std::fs::create_dir(&path).unwrap();
        let dir = File::open(&path).unwrap();
        assert!(ensure_open_generation(&dir, &g).is_ok());
        symlink("missing", path.join(format!("{g}.closed"))).unwrap();
        assert!(ensure_open_generation(&dir, &g).is_err());
        std::fs::remove_dir_all(path).unwrap();
    }
}
