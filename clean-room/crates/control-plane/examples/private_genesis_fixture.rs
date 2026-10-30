//! Disposable Unix-socket-only exercise of the exact genesis SQL; not deployment authority.
#[cfg(all(unix, feature = "restate"))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use sqlx::{Connection, PgConnection, postgres::PgConnectOptions};
    let root = std::env::var("SFACTORY_GENESIS_FIXTURE_DIR")?;
    anyhow::ensure!(
        root.starts_with("/tmp/sfactory-genesis-fixture-") && !root.contains(".."),
        "fixture path mismatch"
    );
    let port: u16 = std::env::var("SFACTORY_GENESIS_FIXTURE_PORT")?.parse()?;
    anyhow::ensure!(port >= 1024, "fixture port mismatch");
    let admin = PgConnectOptions::new()
        .host(&root)
        .port(port)
        .username("sfactory_admin")
        .database("sfactory");
    control_plane::private_database_genesis::initialize_fresh(admin.clone()).await?;
    anyhow::ensure!(
        control_plane::private_database_genesis::initialize_fresh(admin)
            .await
            .is_err(),
        "existing cluster accepted"
    );
    let app_host = if std::env::var_os("SFACTORY_GENESIS_FIXTURE_APP_TCP").is_some() {
        "127.0.0.1"
    } else {
        root.as_str()
    };
    let app = PgConnectOptions::new()
        .host(app_host)
        .port(port)
        .username("sfactory")
        .database("sfactory");
    let mut conn = PgConnection::connect_with(&app).await?;
    let flags: (bool,bool,bool,bool,bool) = sqlx::query_as("SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=current_user").fetch_one(&mut conn).await?;
    anyhow::ensure!(
        flags == (false, false, false, false, false),
        "application role overprivileged"
    );
    sqlx::query("INSERT INTO outbox(invocation_id,step_seq,step_kind,payload) VALUES ('fixture',1,'fixture','{}')").execute(&mut conn).await?;
    sqlx::query("INSERT INTO claim_lease_projection(work_package_id,version,snapshot) VALUES ('fixture',1,'{}')").execute(&mut conn).await?;
    sqlx::query("UPDATE claim_lease_projection SET version=2 WHERE work_package_id='fixture'")
        .execute(&mut conn)
        .await?;
    for sql in [
        "CREATE TABLE forbidden(id integer)",
        "SELECT * FROM audit_events",
        "DELETE FROM outbox",
        "COPY (SELECT 1) TO PROGRAM 'true'",
        "SET ROLE sfactory_admin",
    ] {
        anyhow::ensure!(
            sqlx::query(sql).execute(&mut conn).await.is_err(),
            "application unexpectedly authorized"
        );
    }
    println!("PASS: exact fresh genesis, bounded projection grants and admin privilege denials");
    Ok(())
}
#[cfg(not(all(unix, feature = "restate")))]
fn main() {
    eprintln!("fixture requires Unix and Restate feature");
    std::process::exit(1);
}
