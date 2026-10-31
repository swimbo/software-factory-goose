//! Root-provisioned, service-created Unix spending frontend. No registration, inventory,
//! lease, allowance or launch grant is synthesized by starting this binary.
#[cfg(all(target_os = "linux", feature = "registry-sidecar"))]
async fn run() -> anyhow::Result<()> {
    use control_plane::{
        harness_owner::{HarnessJournalBackend, active_owner_catalog},
        harness_spending_ingress, private_runtime,
    };
    use std::{
        ffi::CString,
        os::{
            fd::AsRawFd,
            unix::{
                ffi::OsStrExt,
                fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            },
        },
        sync::Arc,
    };
    let args: Vec<_> = std::env::args().collect();
    anyhow::ensure!(
        args.len() == 2
            && !args[1].is_empty()
            && args[1].len() <= 128
            && args[1]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
        "fixed root owner required"
    );
    let (registry, catalogs) = private_runtime::load_catalog_registry()?;
    let (config, evidence) = active_owner_catalog(&registry.active_intent, &catalogs)?;
    let binding = config
        .harness_owner
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("harness owner not configured"))?;
    anyhow::ensure!(binding.owner == args[1], "inconsistent owner catalogs");
    anyhow::ensure!(
        unsafe { libc::geteuid() } == config.journal_uid
            && unsafe { libc::getegid() } == config.journal_uid,
        "private journal identity required"
    );
    let namespace = std::fs::metadata("/proc/self/ns/net")?;
    config.validate(
        config.service_uid,
        (namespace.dev(), namespace.ino()),
        evidence,
    )?;
    anyhow::ensure!(
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() == config.boot_id,
        "boot changed"
    );
    let status = std::fs::read_to_string("/proc/self/status")?;
    for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        anyhow::ensure!(
            status
                .lines()
                .any(|l| l.split_whitespace().collect::<Vec<_>>()
                    == [format!("{key}:"), "0000000000000000".into()]),
            "capabilities must be empty"
        );
    }
    anyhow::ensure!(
        status
            .lines()
            .any(|l| l.split_whitespace().collect::<Vec<_>>() == ["NoNewPrivs:", "1"]),
        "no new privileges required"
    );
    let devices = std::fs::read_to_string("/proc/self/net/dev")?;
    anyhow::ensure!(
        devices.len() <= 65536
            && devices
                .lines()
                .skip(2)
                .filter_map(|l| l.split_once(':').map(|(n, _)| n.trim()))
                .collect::<Vec<_>>()
                == ["lo"],
        "private namespace required"
    );
    fn no_acl(fd: i32, dir: bool) -> anyhow::Result<()> {
        for name in if dir {
            &[c"system.posix_acl_access", c"system.posix_acl_default"][..]
        } else {
            &[c"system.posix_acl_access"][..]
        } {
            let n = unsafe { libc::fgetxattr(fd, name.as_ptr(), std::ptr::null_mut(), 0) };
            anyhow::ensure!(
                n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA),
                "socket ACL unverified"
            );
        }
        Ok(())
    }
    let path = binding.ingress_path();
    let parent_path = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("socket parent unavailable"))?;
    for parent in parent_path.ancestors() {
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent)?;
        let m = directory.metadata()?;
        if parent == parent_path {
            anyhow::ensure!(
                m.uid() == config.journal_uid
                    && m.gid() == binding.socket_gid
                    && m.mode() & 0o7777 == 0o750,
                "service-owned readable socket parent required"
            );
        } else {
            anyhow::ensure!(
                m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0 && m.mode() & 0o005 == 0o005,
                "readable root socket ancestry required"
            );
        }
        no_acl(directory.as_raw_fd(), true)?;
        let mut fs = std::mem::MaybeUninit::<libc::statfs>::uninit();
        anyhow::ensure!(
            unsafe { libc::fstatfs(directory.as_raw_fd(), fs.as_mut_ptr()) } == 0
                && unsafe { fs.assume_init() }.f_type == 0xef53,
            "ext4 socket ancestry required"
        );
    }
    let mut groups = vec![0 as libc::gid_t; 128];
    let count = unsafe { libc::getgroups(groups.len() as i32, groups.as_mut_ptr()) };
    anyhow::ensure!(
        count >= 0 && groups[..count as usize].contains(&binding.socket_gid),
        "socket traversal group required"
    );
    // Do not unlink an occupied path, even after a crash. Root must reconcile it.
    let listener = tokio::net::UnixListener::bind(&path)?;
    let name = CString::new(path.as_os_str().as_bytes())?;
    anyhow::ensure!(
        unsafe { libc::chown(name.as_ptr(), u32::MAX, binding.socket_gid) } == 0,
        "socket group unavailable"
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))?;
    let m = std::fs::symlink_metadata(&path)?;
    anyhow::ensure!(
        m.file_type().is_socket()
            && m.uid() == config.journal_uid
            && m.gid() == binding.socket_gid
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o660,
        "socket metadata mismatch"
    );
    let acl = unsafe {
        libc::lgetxattr(
            name.as_ptr(),
            c"system.posix_acl_access".as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    anyhow::ensure!(
        acl < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA),
        "socket ACL unverified"
    );
    let policy = binding.policy(config)?;
    let backend = Arc::new(HarnessJournalBackend::new(
        config.restate_ingress_port,
        binding.clone(),
    )?);
    let app = harness_spending_ingress::router(policy, backend)?;
    harness_spending_ingress::serve(listener, app).await?;
    Ok(())
}
#[cfg(all(target_os = "linux", feature = "registry-sidecar"))]
fn main() -> anyhow::Result<()> {
    anyhow::ensure!(
        std::env::var_os("LISTEN_PID").is_none()
            && std::env::var_os("LISTEN_FDS").is_none()
            && std::env::var_os("LISTEN_FDNAMES").is_none(),
        "root-created activated listener refused"
    );
    unsafe {
        libc::umask(0o077);
    }
    let expected = std::path::Path::new("/proc/self/fd");
    let mut fds = Vec::new();
    for entry in std::fs::read_dir(expected)? {
        let entry = entry?;
        if let Ok(fd) = entry.file_name().to_string_lossy().parse::<i32>() {
            fds.push(fd);
        }
    }
    // read_dir's own descriptor has closed; inspect only descriptors still open.
    for fd in fds {
        if fd > 2 {
            anyhow::ensure!(
                unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0,
                "unexpected inherited descriptor"
            );
        }
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run())
}
#[cfg(not(all(target_os = "linux", feature = "registry-sidecar")))]
fn main() {
    eprintln!("Linux production registry build required");
    std::process::exit(1);
}
