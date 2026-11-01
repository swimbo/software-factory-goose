//! Root-provisioned, socket-activated runtime entrypoint. Never use on a shared network namespace.
#[cfg(all(target_os = "linux", feature = "restate"))]
fn activated_socket_fds(names: &str) -> anyhow::Result<(i32, i32)> {
    let names: Vec<_> = names.split(':').collect();
    anyhow::ensure!(names.len() == 2, "socket activation scope mismatch");
    match names.as_slice() {
        ["intake", "worker"] => Ok((3, 4)),
        ["worker", "intake"] => Ok((4, 3)),
        _ => anyhow::bail!("socket activation names mismatch"),
    }
}

#[cfg(all(target_os = "linux", feature = "restate"))]
fn activated_socket_fds_with_grant(names: &str) -> anyhow::Result<(i32, i32, i32)> {
    let names: Vec<_> = names.split(':').collect();
    anyhow::ensure!(names.len() == 3, "socket activation scope mismatch");
    let locate = |expected: &str| -> anyhow::Result<i32> {
        let positions: Vec<_> = names
            .iter()
            .enumerate()
            .filter_map(|(i, name)| (*name == expected).then_some(i))
            .collect();
        anyhow::ensure!(positions.len() == 1, "socket activation names mismatch");
        Ok(3 + positions[0] as i32)
    };
    Ok((
        locate("intake")?,
        locate("worker")?,
        locate("launch-grant")?,
    ))
}

#[cfg(all(target_os = "linux", feature = "restate"))]
fn bootstrap_ready() -> anyhow::Result<bool> {
    #[cfg(not(feature = "grant-sidecar"))]
    let path = "/etc/software-factory-goose/private-bootstrap-complete";
    #[cfg(all(feature = "grant-sidecar", not(feature = "real-sidecar")))]
    let path = "/etc/software-factory-goose/grant-bootstrap-complete";
    #[cfg(all(feature = "real-sidecar", not(feature = "registry-sidecar")))]
    let path = "/etc/software-factory-goose/real-bootstrap-complete";
    #[cfg(all(feature = "registry-sidecar", not(feature = "registry-v5")))]
    let path = "/etc/software-factory-goose/registry-bootstrap-complete";
    #[cfg(feature = "registry-v5")]
    let path = "/etc/software-factory-goose/registry-v5-bootstrap-complete";
    receipt_ready(std::path::Path::new(path), 0)
}

#[cfg(all(target_os = "linux", feature = "restate"))]
fn receipt_ready(path: &std::path::Path, owner: u32) -> anyhow::Result<bool> {
    use std::{
        io::Read,
        os::{
            fd::AsRawFd,
            unix::fs::{MetadataExt, OpenOptionsExt},
        },
    };
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let m = file.metadata()?;
    anyhow::ensure!(
        m.is_file()
            && m.uid() == owner
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o644
            && m.len() <= 128,
        "unsafe bootstrap completion receipt"
    );
    let attribute = c"system.posix_acl_access";
    // SAFETY: descriptor and NUL-terminated attribute are valid; this is a size query.
    let size = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            attribute.as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    anyhow::ensure!(
        size < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA),
        "bootstrap receipt ACL unverified"
    );
    let mut bytes = Vec::new();
    file.by_ref().take(129).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes == b"private canary bootstrap completed; acceptance tests required\n",
        "bootstrap completion receipt mismatch"
    );
    Ok(true)
}

#[cfg(all(test, target_os = "linux", feature = "restate"))]
#[test]
fn completion_receipt_requires_expected_owner_mode_and_exact_bytes() {
    use std::os::unix::fs::PermissionsExt;
    let base = std::env::temp_dir().join(format!("sfactory-receipt-test-{}", std::process::id()));
    std::fs::create_dir(&base).unwrap();
    let path = base.join("receipt");
    let uid = unsafe { libc::geteuid() };
    assert!(!receipt_ready(&path, uid).unwrap());
    std::fs::write(
        &path,
        b"private canary bootstrap completed; acceptance tests required\n",
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(receipt_ready(&path, uid).unwrap());
    assert!(receipt_ready(&path, uid + 1).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(receipt_ready(&path, uid).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::write(&path, b"incorrect").unwrap();
    assert!(receipt_ready(&path, uid).is_err());
    std::fs::remove_dir_all(base).unwrap();
}

#[cfg(all(test, target_os = "linux", feature = "restate"))]
#[test]
fn activated_names_require_exact_unique_pair_in_either_order() {
    assert_eq!(activated_socket_fds("intake:worker").unwrap(), (3, 4));
    assert_eq!(activated_socket_fds("worker:intake").unwrap(), (4, 3));
    for invalid in [
        "worker:worker",
        "intake",
        "intake:worker:extra",
        "other:intake",
    ] {
        assert!(activated_socket_fds(invalid).is_err());
    }
}

#[cfg(all(test, target_os = "linux", feature = "restate"))]
#[test]
fn activated_grant_requires_exact_unique_names_in_any_order() {
    assert_eq!(
        activated_socket_fds_with_grant("launch-grant:worker:intake").unwrap(),
        (5, 4, 3)
    );
    for invalid in [
        "intake:worker:worker",
        "intake:worker",
        "intake:worker:other",
        "intake:worker:launch-grant:extra",
    ] {
        assert!(activated_socket_fds_with_grant(invalid).is_err());
    }
}

#[cfg(all(target_os = "linux", feature = "restate"))]
async fn run() -> anyhow::Result<()> {
    use control_plane::{
        intake_adapter::{IntakePeer, IntakePolicy, intake_router},
        intake_workflow::IntakeJournal,
        root_launch_grant::{self, FixedJournalBackend, Peer as GrantPeer},
        runtime_intake::RuntimeIntakeJournal,
        runtime_loopback_backend::RuntimeLoopbackBackend,
        worker_adapter::{WorkerBinding, WorkerPeer, WorkerPolicy, worker_router},
        worker_queue::WorkerQueueJournal,
        workflow::{ClaimLeaseJournal, LeaseSpec},
    };
    use restate_sdk::prelude::*;
    use std::{
        collections::BTreeSet,
        ffi::{CStr, CString},
        fs::{File, OpenOptions},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{
                fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
                net::UnixListener as StdUnixListener,
            },
        },
        path::Path,
        sync::Arc,
    };
    use tokio::net::UnixListener;

    fn private_lo_only() -> anyhow::Result<()> {
        // SAFETY: if_nameindex allocates a terminated list released exactly once below.
        let ptr = unsafe { libc::if_nameindex() };
        anyhow::ensure!(!ptr.is_null(), "network interface inventory unavailable");
        let mut names = BTreeSet::new();
        let mut i = 0usize;
        loop {
            // SAFETY: list is terminated by the documented zero/null entry.
            let item = unsafe { &*ptr.add(i) };
            if item.if_index == 0 && item.if_name.is_null() {
                break;
            }
            if item.if_name.is_null() || i > 256 {
                unsafe { libc::if_freenameindex(ptr) };
                anyhow::bail!("invalid interface inventory");
            }
            // SAFETY: non-null interface names are NUL terminated by libc.
            names.insert(unsafe { CStr::from_ptr(item.if_name) }.to_bytes().to_vec());
            i += 1;
        }
        // SAFETY: the allocation has not yet been freed.
        unsafe { libc::if_freenameindex(ptr) };
        anyhow::ensure!(
            names == BTreeSet::from([b"lo".to_vec()]),
            "private namespace contains network interfaces"
        );
        Ok(())
    }
    fn no_acl(file: &File, directory: bool) -> anyhow::Result<()> {
        let names: &[&str] = if directory {
            &["system.posix_acl_access", "system.posix_acl_default"]
        } else {
            &["system.posix_acl_access"]
        };
        for name in names {
            let name = CString::new(*name)?;
            // SAFETY: fd and name remain valid for the size-only xattr call.
            let size = unsafe {
                libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0)
            };
            anyhow::ensure!(
                size < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA),
                "socket ACL unavailable or present"
            );
        }
        Ok(())
    }
    fn socket(fd: i32, path: &str, gid: u32, mode: u32) -> anyhow::Result<UnixListener> {
        for parent in ["/", "/run", "/run/software-factory-goose"] {
            let dir = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(parent)?;
            let m = dir.metadata()?;
            anyhow::ensure!(
                m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
                "unprotected socket ancestor"
            );
            no_acl(&dir, true)?;
        }
        let meta = std::fs::symlink_metadata(path)?;
        anyhow::ensure!(
            meta.file_type().is_socket()
                && meta.uid() == 0
                && meta.gid() == gid
                && meta.mode() & 0o777 == mode,
            "socket path binding mismatch"
        );
        let path_c = CString::new(path)?;
        let acl_c = CString::new("system.posix_acl_access")?;
        // SAFETY: path and ACL names are NUL terminated; no value buffer is supplied.
        let acl =
            unsafe { libc::lgetxattr(path_c.as_ptr(), acl_c.as_ptr(), std::ptr::null_mut(), 0) };
        anyhow::ensure!(
            acl < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA),
            "socket ACL unavailable or present"
        );
        // SAFETY: fcntl checks validity before ownership is transferred to Rust.
        anyhow::ensure!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0,
            "activated descriptor unavailable"
        );
        let mut accepting: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: output pointers reference initialized storage of the declared length.
        anyhow::ensure!(
            unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_ACCEPTCONN,
                    (&mut accepting as *mut libc::c_int).cast(),
                    &mut len,
                )
            } == 0
                && accepting == 1,
            "activated socket is not listening"
        );
        // SAFETY: systemd socket activation supplies exactly these owned descriptors; validation follows.
        let std_listener = unsafe { StdUnixListener::from_raw_fd(fd) };
        anyhow::ensure!(
            std_listener.local_addr()?.as_pathname() == Some(Path::new(path)),
            "activated socket name mismatch"
        );
        std_listener.set_nonblocking(true)?;
        Ok(UnixListener::from_std(std_listener)?)
    }
    anyhow::ensure!(
        std::env::args_os().count() == 1,
        "arguments are not accepted"
    );
    #[cfg(not(feature = "grant-sidecar"))]
    let (config, evidence) = control_plane::private_runtime::load_root_catalog()?;
    #[cfg(all(feature = "grant-sidecar", not(feature = "real-sidecar")))]
    let (config, evidence) = control_plane::private_runtime::load_grant_sidecar_catalog()?;
    #[cfg(all(feature = "real-sidecar", not(feature = "registry-sidecar")))]
    let (config, evidence) = control_plane::private_runtime::load_real_catalog()?;
    #[cfg(feature = "registry-sidecar")]
    let (config, evidence, registry_prior) = {
        let (registry, mut catalogs) = control_plane::private_runtime::load_catalog_registry()?;
        let position = catalogs
            .iter()
            .position(|(c, _)| c.intent_id == registry.active_intent)
            .ok_or_else(|| anyhow::anyhow!("active registry catalog missing"))?;
        anyhow::ensure!(
            !matches!(
                registry.entries[position].config.as_str(),
                "runtime.json" | "grant-runtime.json" | "real-runtime.json"
            ),
            "historical catalog cannot become active"
        );
        let (cfg, evidence) = catalogs.remove(position);
        (cfg, evidence, catalogs)
    };
    anyhow::ensure!(
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() == config.boot_id,
        "boot identity mismatch"
    );
    let current = std::fs::metadata("/proc/self/ns/net")?;
    // SAFETY: reading effective UID has no side effect.
    let uid = unsafe { libc::geteuid() };
    config.validate(uid, (current.dev(), current.ino()), &evidence)?;
    #[cfg(all(feature = "grant-sidecar", not(feature = "registry-sidecar")))]
    let preserved = {
        let (old, old_evidence) = control_plane::private_runtime::load_preserved_canary_catalog()?;
        old.validate(uid, (current.dev(), current.ino()), &old_evidence)?;
        anyhow::ensure!(
            old.boot_id == config.boot_id
                && old.service_uid == config.service_uid
                && old.operator_uid == config.operator_uid
                && old.worker_uid == config.worker_uid
                && old.evaluator_uid == config.evaluator_uid
                && old.journal_uid == config.journal_uid
                && old.brake_uid == config.brake_uid
                && old.operator_socket_gid == config.operator_socket_gid
                && old.worker_socket_gid == config.worker_socket_gid
                && old.host_namespace_dev == config.host_namespace_dev
                && old.host_namespace_ino == config.host_namespace_ino
                && old.principal == config.principal
                && old.postgres_port == config.postgres_port
                && old.restate_ingress_port == config.restate_ingress_port
                && old.sdk_port != config.sdk_port
                && old.launch_scope.is_none(),
            "preserved runtime binding mismatch"
        );
        old
    };
    private_lo_only()?;
    anyhow::ensure!(
        std::env::var("LISTEN_PID")?.parse::<u32>()? == std::process::id()
            && std::env::var("LISTEN_FDS")?
                == if config.launch_scope.is_some() {
                    "3"
                } else {
                    "2"
                },
        "socket activation scope mismatch"
    );
    let names = std::env::var("LISTEN_FDNAMES")?;
    let (intake_fd, worker_fd, grant_fd) = if config.launch_scope.is_some() {
        let (a, b, c) = activated_socket_fds_with_grant(&names)?;
        (a, b, Some(c))
    } else {
        let (a, b) = activated_socket_fds(&names)?;
        (a, b, None)
    };
    #[cfg(not(feature = "grant-sidecar"))]
    let (intake_path, worker_path) = (
        "/run/software-factory-goose/intake.sock",
        "/run/software-factory-goose/worker.sock",
    );
    #[cfg(all(feature = "grant-sidecar", not(feature = "real-sidecar")))]
    let (intake_path, worker_path) = (
        "/run/software-factory-goose/grant-intake.sock",
        "/run/software-factory-goose/grant-worker.sock",
    );
    #[cfg(all(feature = "real-sidecar", not(feature = "registry-sidecar")))]
    let (intake_path, worker_path) = (
        "/run/software-factory-goose/real-intake.sock",
        "/run/software-factory-goose/real-worker.sock",
    );
    #[cfg(all(feature = "registry-sidecar", not(feature = "registry-v5")))]
    let (intake_path, worker_path) = (
        "/run/software-factory-goose/registry-intake.sock",
        "/run/software-factory-goose/registry-worker.sock",
    );
    #[cfg(feature = "registry-v5")]
    let (intake_path, worker_path) = (
        "/run/software-factory-goose/registry-v5-intake.sock",
        "/run/software-factory-goose/registry-v5-worker.sock",
    );
    #[cfg(feature = "grant-sidecar")]
    anyhow::ensure!(
        config.launch_scope.is_some(),
        "sidecar launch scope required"
    );
    let intake = socket(intake_fd, intake_path, config.operator_socket_gid, 0o660)?;
    let worker = socket(worker_fd, worker_path, config.worker_socket_gid, 0o660)?;
    let grant = grant_fd
        .map(|fd| {
            socket(
                fd,
                if cfg!(feature = "registry-v5") {
                    "/run/software-factory-goose/registry-v5-launch-grant.sock"
                } else if cfg!(feature = "registry-sidecar") {
                    "/run/software-factory-goose/registry-launch-grant.sock"
                } else if cfg!(feature = "real-sidecar") {
                    "/run/software-factory-goose/real-launch-grant.sock"
                } else {
                    "/run/software-factory-goose/launch-grant.sock"
                },
                0,
                0o600,
            )
        })
        .transpose()?;
    let grant_router = if let Some(scope) = &config.launch_scope {
        Some(root_launch_grant::router(
            scope.clone(),
            Arc::new(FixedJournalBackend::new(
                config.restate_ingress_port,
                scope,
            )?),
        )?)
    } else {
        None
    };
    let backend = Arc::new(RuntimeLoopbackBackend::new(
        config.restate_ingress_port,
        config.principal.clone(),
        config.intent_id.clone(),
        config.task_id.clone(),
        config.queue_id.clone(),
        LeaseSpec {
            repository: config.request.repository.clone(),
            base_revision: config.request.base_revision.clone(),
        },
    )?);
    let intake_router = intake_router(
        IntakePolicy::new(
            config.service_uid,
            config.operator_uid,
            config.principal.clone(),
        )?,
        backend.clone(),
    )?;
    let worker_router = worker_router(
        WorkerPolicy::new(
            config.service_uid,
            config.operator_uid,
            config.evaluator_uid,
            vec![WorkerBinding {
                uid: config.worker_uid,
                worker_id: config.worker_id.clone(),
                queue_id: config.queue_id.clone(),
            }],
        )?,
        backend,
    )?;
    // The database must already be provisioned in this private namespace. Never migrate or
    // create deployment/state automatically: old journal authority must be resolved separately.
    let db = format!(
        "postgres://sfactory@127.0.0.1:{}/sfactory",
        config.postgres_port
    );
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&db)
        .await?;
    let catalog = config.catalog()?;
    #[cfg(all(feature = "grant-sidecar", not(feature = "real-sidecar")))]
    let (claim_journal, queue_journal, intake_journal) = {
        let scope = config
            .launch_scope
            .clone()
            .ok_or_else(|| anyhow::anyhow!("sidecar scope missing"))?;
        (
            ClaimLeaseJournal::new_with_preserved_launch_scope(
                config.worker_id.clone(),
                pool,
                scope,
                preserved.task_id.clone(),
                preserved.worker_id.clone(),
            )?,
            WorkerQueueJournal::new_with_preserved_queue(
                config.worker_id.clone(),
                config.queue_id.clone(),
                preserved.worker_id.clone(),
                preserved.queue_id.clone(),
            )?,
            RuntimeIntakeJournal::new_with_preserved_catalog(preserved.catalog()?, catalog)?,
        )
    };
    #[cfg(all(feature = "real-sidecar", not(feature = "registry-sidecar")))]
    let (claim_journal, queue_journal, intake_journal) = {
        let (prior, prior_evidence) =
            control_plane::private_runtime::load_preserved_grant_catalog()?;
        prior.validate(uid, (current.dev(), current.ino()), &prior_evidence)?;
        anyhow::ensure!(
            prior.boot_id == config.boot_id
                && prior.service_uid == config.service_uid
                && prior.operator_uid == config.operator_uid
                && prior.worker_uid == config.worker_uid
                && prior.evaluator_uid == config.evaluator_uid
                && prior.journal_uid == config.journal_uid
                && prior.brake_uid == config.brake_uid
                && prior.operator_socket_gid == config.operator_socket_gid
                && prior.worker_socket_gid == config.worker_socket_gid
                && prior.host_namespace_dev == config.host_namespace_dev
                && prior.host_namespace_ino == config.host_namespace_ino
                && config.sdk_port == 9083
                && prior.principal == config.principal
                && prior.postgres_port == config.postgres_port
                && prior.restate_ingress_port == config.restate_ingress_port
                && prior.sdk_port != config.sdk_port
                && prior.sdk_port != preserved.sdk_port,
            "preserved grant binding mismatch"
        );
        let prior_scope = prior
            .launch_scope
            .clone()
            .ok_or_else(|| anyhow::anyhow!("preserved grant scope missing"))?;
        let scope = config
            .launch_scope
            .clone()
            .ok_or_else(|| anyhow::anyhow!("real scope missing"))?;
        (
            ClaimLeaseJournal::new_with_catalog_scopes(
                pool,
                vec![
                    (preserved.task_id.clone(), preserved.worker_id.clone()),
                    (prior.task_id.clone(), prior.worker_id.clone()),
                    (config.task_id.clone(), config.worker_id.clone()),
                ],
                vec![prior_scope, scope],
            )?,
            WorkerQueueJournal::new_with_queue_scopes(vec![
                (preserved.queue_id.clone(), preserved.worker_id.clone()),
                (prior.queue_id.clone(), prior.worker_id.clone()),
                (config.queue_id.clone(), config.worker_id.clone()),
            ])?,
            RuntimeIntakeJournal::new_with_catalogs(vec![
                preserved.catalog()?,
                prior.catalog()?,
                catalog,
            ])?,
        )
    };
    #[cfg(feature = "registry-sidecar")]
    let (claim_journal, queue_journal, intake_journal) = {
        anyhow::ensure!(
            config.sdk_port
                == if cfg!(feature = "registry-v5") {
                    9085
                } else {
                    9084
                }
                && config.launch_scope.is_some(),
            "registry front scope invalid"
        );
        let mut cats = Vec::new();
        let mut workers = Vec::new();
        let mut queues = Vec::new();
        let mut scopes = Vec::new();
        for (prior, prior_evidence) in registry_prior {
            prior.validate(uid, (current.dev(), current.ino()), &prior_evidence)?;
            anyhow::ensure!(
                config.registry_compatible(&prior),
                "registry common binding mismatch"
            );
            workers.push((prior.task_id.clone(), prior.worker_id.clone()));
            queues.push((prior.queue_id.clone(), prior.worker_id.clone()));
            if let Some(scope) = prior.launch_scope.clone() {
                scopes.push(scope);
            }
            cats.push(prior.catalog()?);
        }
        workers.push((config.task_id.clone(), config.worker_id.clone()));
        queues.push((config.queue_id.clone(), config.worker_id.clone()));
        scopes.push(
            config
                .launch_scope
                .clone()
                .ok_or_else(|| anyhow::anyhow!("active root scope missing"))?,
        );
        cats.push(catalog);
        (
            ClaimLeaseJournal::new_with_catalog_scopes(pool, workers, scopes)?,
            WorkerQueueJournal::new_with_queue_scopes(queues)?,
            RuntimeIntakeJournal::new_with_catalogs(cats)?,
        )
    };
    #[cfg(not(feature = "grant-sidecar"))]
    let (claim_journal, queue_journal, intake_journal) = {
        let claim = if let Some(scope) = &config.launch_scope {
            ClaimLeaseJournal::new_with_root_launch_scope(
                config.worker_id.clone(),
                pool,
                scope.clone(),
            )?
        } else {
            ClaimLeaseJournal::new_for_private_ingress(config.worker_id.clone(), pool)?
        };
        (
            claim,
            WorkerQueueJournal::new_for_private_ingress(config.worker_id.clone())?,
            RuntimeIntakeJournal::new_for_protected_bootstrap(catalog),
        )
    };
    let endpoint = Endpoint::builder()
        .bind(IntakeJournal::new_for_private_ingress(
            config.principal.clone(),
        )?)
        .bind(claim_journal)
        .bind(queue_journal)
        .bind(intake_journal);
    let endpoint =
        control_plane::harness_owner::bind_owner(endpoint, config.harness_owner.as_ref())?.build();
    let address: std::net::SocketAddr = format!("127.0.0.1:{}", config.sdk_port).parse()?;
    let sdk = tokio::spawn(async move {
        HttpServer::new(endpoint).listen_and_serve(address).await;
    });
    // The SDK must run for one-shot registration, but neither external Unix
    // listener serves requests until root publishes the completed bootstrap receipt.
    let mut sdk = sdk;
    let gate = async {
        loop {
            match bootstrap_ready()? {
                true => return Ok::<(), anyhow::Error>(()),
                false => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
            }
        }
    };
    tokio::select! {
        result = gate => result?,
        result = &mut sdk => { result?; anyhow::bail!("SDK exited before bootstrap completion") }
    }
    let a = async move {
        axum::serve(
            intake,
            intake_router.into_make_service_with_connect_info::<IntakePeer>(),
        )
        .await
    };
    let b = async move {
        axum::serve(
            worker,
            worker_router.into_make_service_with_connect_info::<WorkerPeer>(),
        )
        .await
    };
    let c = async move {
        match (grant, grant_router) {
            (Some(listener), Some(router)) => {
                axum::serve(
                    listener,
                    router.into_make_service_with_connect_info::<GrantPeer>(),
                )
                .await
            }
            (None, None) => std::future::pending().await,
            _ => unreachable!("validated launch scope and listener"),
        }
    };
    tokio::select! {result=a=>{result?;anyhow::bail!("intake listener exited")},result=b=>{result?;anyhow::bail!("worker listener exited")},result=sdk=>{result?;anyhow::bail!("SDK listener exited")},result=c=>{result?;anyhow::bail!("grant listener exited")}}
}
#[cfg(all(target_os = "linux", feature = "restate"))]
fn main() -> anyhow::Result<()> {
    #[cfg(feature = "registry-v5")]
    control_plane::sdk5_startup_guard::verify()?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run())
}
#[cfg(not(all(target_os = "linux", feature = "restate")))]
fn main() {
    eprintln!("private runtime requires provisioned Linux and Restate feature");
    std::process::exit(1);
}
