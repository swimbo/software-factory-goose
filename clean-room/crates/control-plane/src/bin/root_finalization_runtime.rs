//! Unactivated fixed-generation root finalization service. Requires separately reviewed
//! root-owned bootstrap, socket activation, namespace isolation and process attestation.
#[cfg(all(target_os = "linux", feature = "restate"))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    use control_plane::{
        launch_reservation::LaunchScope,
        root_finalization_evidence::read_root_config,
        root_finalization_ingress::{
            self, FixedEvidence, FixedJournalBackend, UnknownCleanupVerifier,
        },
    };
    use serde::Deserialize;
    use std::{
        ffi::CString,
        fs::OpenOptions,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
        },
        path::{Path, PathBuf},
        sync::Arc,
    };

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Config {
        schema: u32,
        generation: String,
        scope: LaunchScope,
        boot_id: String,
        namespace_dev: u64,
        namespace_ino: u64,
        host_namespace_dev: u64,
        host_namespace_ino: u64,
        request_sha256: String,
        grant_sha256: String,
        catalog_sha256: String,
        recipe_sha256: String,
        observation_sha256: String,
    }
    let args: Vec<_> = std::env::args().collect();
    anyhow::ensure!(
        args.len() == 2
            && ulid::Ulid::from_string(&args[1]).is_ok_and(|v| v.to_string() == args[1]),
        "canonical generation required"
    );
    let generation = &args[1];
    anyhow::ensure!(
        unsafe { libc::geteuid() } == 0 && unsafe { libc::getegid() } == 0,
        "root identity required"
    );
    let status = std::fs::read_to_string("/proc/self/status")?;
    for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        let line = status
            .lines()
            .find(|s| s.starts_with(&format!("{key}:")))
            .ok_or_else(|| anyhow::anyhow!("capability status unavailable"))?;
        anyhow::ensure!(
            line.split_whitespace().nth(1) == Some("0000000000000000"),
            "capabilities not empty"
        );
    }
    anyhow::ensure!(
        status
            .lines()
            .any(|s| s.split_whitespace().collect::<Vec<_>>() == ["NoNewPrivs:", "1"]),
        "no-new-privileges required"
    );
    let config_path = PathBuf::from(format!(
        "/etc/software-factory-goose/finalization/{generation}.runtime.json"
    ));
    let config: Config = serde_json::from_slice(&read_root_config(&config_path)?)?;
    config.scope.validate()?;
    anyhow::ensure!(
        config.schema == 1
            && config.generation == *generation
            && config.scope.generation == *generation
            && std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() == config.boot_id,
        "generation or boot mismatch"
    );
    let ns = std::fs::metadata("/proc/self/ns/net")?;
    anyhow::ensure!(
        ns.dev() == config.namespace_dev
            && ns.ino() == config.namespace_ino
            && config.namespace_dev != 0
            && config.namespace_ino != 0,
        "private namespace mismatch"
    );
    anyhow::ensure!(
        config.host_namespace_dev != 0
            && config.host_namespace_ino != 0
            && (config.host_namespace_dev, config.host_namespace_ino) != (ns.dev(), ns.ino()),
        "host network namespace refused"
    );
    // Root bootstrap must pin host-anchor self-observation under the same boot ID;
    // this process cannot inspect another UID's namespace without extra privilege.
    let devices = std::fs::read_to_string("/proc/self/net/dev")?;
    anyhow::ensure!(devices.len() <= 65536, "interface inventory too large");
    let names: Vec<_> = devices
        .lines()
        .skip(2)
        .filter_map(|line| line.split_once(':').map(|(name, _)| name.trim()))
        .collect();
    anyhow::ensure!(
        names == ["lo"],
        "private namespace has unexpected interfaces"
    );
    let dir = Path::new("/run/software-factory-goose/root-finalization");
    for parent in [
        Path::new("/"),
        Path::new("/run"),
        Path::new("/run/software-factory-goose"),
        dir,
    ] {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent)?;
        let m = file.metadata()?;
        anyhow::ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "socket ancestor unsafe"
        );
        if parent == dir {
            anyhow::ensure!(
                m.gid() == 1000 && m.mode() & 0o7777 == 0o710,
                "socket parent mismatch"
            );
        }
        for name in [c"system.posix_acl_access", c"system.posix_acl_default"] {
            let n = unsafe {
                libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0)
            };
            anyhow::ensure!(
                n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA),
                "socket parent ACL unverified"
            );
        }
    }
    let socket_path = dir.join(format!("{generation}.sock"));
    let meta = std::fs::symlink_metadata(&socket_path)?;
    anyhow::ensure!(
        meta.file_type().is_socket()
            && meta.uid() == 0
            && meta.gid() == 1000
            && meta.nlink() == 1
            && meta.mode() & 0o7777 == 0o660,
        "socket metadata mismatch"
    );
    use std::os::unix::ffi::OsStrExt;
    let path_c = CString::new(socket_path.as_os_str().as_bytes())?;
    let acl = unsafe {
        libc::lgetxattr(
            path_c.as_ptr(),
            c"system.posix_acl_access".as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    anyhow::ensure!(
        acl < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA),
        "socket ACL unverified"
    );
    anyhow::ensure!(
        std::env::var("LISTEN_PID")?.parse::<u32>()? == std::process::id()
            && std::env::var("LISTEN_FDS")? == "1"
            && std::env::var("LISTEN_FDNAMES")? == "root-finalization",
        "socket activation mismatch"
    );
    let mut accepting: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    anyhow::ensure!(
        unsafe {
            libc::getsockopt(
                3,
                libc::SOL_SOCKET,
                libc::SO_ACCEPTCONN,
                (&mut accepting as *mut libc::c_int).cast(),
                &mut len,
            )
        } == 0
            && accepting == 1,
        "listener unavailable"
    );
    let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(3) };
    anyhow::ensure!(
        listener.local_addr()?.as_pathname() == Some(socket_path.as_path()),
        "listener name mismatch"
    );
    listener.set_nonblocking(true)?;
    let listener = tokio::net::UnixListener::from_std(listener)?;
    let fixed = |dir: &str, suffix: &str| PathBuf::from(format!("{dir}/{generation}{suffix}"));
    let verifier = UnknownCleanupVerifier {
        grant: (
            fixed("/var/lib/software-factory-goose/stop", ".grant-verified"),
            config.grant_sha256,
        ),
        catalog: (
            fixed("/etc/software-factory-goose/launch-catalog", ".json"),
            config.catalog_sha256,
        ),
        recipe: (
            fixed("/etc/software-factory-goose/launch-catalog", ".recipe.json"),
            config.recipe_sha256,
        ),
        observation: (
            fixed("/var/lib/software-factory-goose/stop", ".observation"),
            config.observation_sha256,
        ),
    };
    let evidence = FixedEvidence::new(
        config.scope.clone(),
        fixed(
            "/var/lib/software-factory-goose/stop",
            ".root-finalization-request.json",
        ),
        config.request_sha256,
        verifier,
    )?;
    let backend = Arc::new(FixedJournalBackend::new(8080, &config.scope)?);
    let app = root_finalization_ingress::router(evidence, backend)?;
    root_finalization_ingress::serve(listener, app).await?;
    Ok(())
}
#[cfg(not(all(target_os = "linux", feature = "restate")))]
fn main() {
    eprintln!("Linux with restate feature required");
    std::process::exit(1);
}
