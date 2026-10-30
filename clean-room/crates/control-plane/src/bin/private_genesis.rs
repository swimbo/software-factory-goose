//! One-shot genesis for a separately provisioned, fresh private PostgreSQL cluster.
//! Not a migration or recovery mechanism for an existing database.
#[cfg(all(target_os = "linux", feature = "restate"))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use control_plane::{
        private_database_genesis::initialize_fresh, private_runtime::load_root_catalog,
    };
    use sqlx::postgres::PgConnectOptions;
    use std::{
        fs::OpenOptions,
        io::Write,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::Path,
    };
    anyhow::ensure!(std::env::args_os().count() == 1, "arguments forbidden");
    let (config, evidence) = load_root_catalog()?;
    anyhow::ensure!(
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() == config.boot_id,
        "boot identity mismatch"
    );
    let namespace = std::fs::metadata("/proc/self/ns/net")?;
    let uid = unsafe { libc::geteuid() };
    // The catalogue validates every identity, evidence and namespace; the invoking
    // journal account is checked separately because the SDK runs as control.
    config.validate(
        config.service_uid,
        (namespace.dev(), namespace.ino()),
        &evidence,
    )?;
    anyhow::ensure!(uid == config.journal_uid, "journal identity mismatch");
    let dir = Path::new("/var/lib/software-factory-goose/journal");
    let dir_meta = std::fs::symlink_metadata(dir)?;
    anyhow::ensure!(
        dir_meta.is_dir() && dir_meta.uid() == uid && dir_meta.mode() & 0o7777 == 0o700,
        "journal root mismatch"
    );
    let marker = dir.join("private-genesis-started");
    let mut receipt = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&marker)?;
    receipt.write_all(b"genesis started; never automatically replay\n")?;
    receipt.sync_all()?;
    std::fs::File::open(dir)?.sync_all()?;
    let opts = PgConnectOptions::new()
        .host("/var/lib/software-factory-goose/journal/socket")
        .port(config.postgres_port)
        .username("sfactory_admin")
        .database("sfactory");
    initialize_fresh(opts).await?;
    let mut done = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dir.join("private-genesis-complete"))?;
    done.write_all(b"fresh projection genesis completed\n")?;
    done.sync_all()?;
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}
#[cfg(not(all(target_os = "linux", feature = "restate")))]
fn main() {
    eprintln!("private genesis requires Linux and Restate feature");
    std::process::exit(1);
}
