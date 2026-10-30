//! Fresh-only projection genesis. Authority to select a cluster belongs to the protected caller.
use crate::projection;
use sqlx::{Connection, PgConnection, postgres::PgConnectOptions};

pub async fn initialize_fresh(opts: PgConnectOptions) -> anyhow::Result<()> {
    let mut conn = PgConnection::connect_with(&opts).await?;
    let identity: (String, String, bool) = sqlx::query_as("SELECT current_user, current_database(), usesuper FROM pg_user WHERE usename = current_user").fetch_one(&mut conn).await?;
    anyhow::ensure!(
        identity == ("sfactory_admin".to_owned(), "sfactory".to_owned(), true),
        "admin identity mismatch"
    );
    let occupied: bool = sqlx::query_scalar("SELECT EXISTS (SELECT FROM pg_namespace WHERE nspname NOT LIKE 'pg_%' AND nspname <> 'information_schema' AND nspname <> 'public') OR EXISTS (SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public') OR EXISTS (SELECT FROM pg_roles WHERE rolname='sfactory') OR EXISTS (SELECT FROM pg_extension WHERE extname <> 'plpgsql')").fetch_one(&mut conn).await?;
    anyhow::ensure!(!occupied, "database is not fresh; retain started receipt");
    drop(conn);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await?;
    projection::migrate(&pool).await?;
    let mut tx = pool.begin().await?;
    for statement in [
        "CREATE ROLE sfactory LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS",
        "REVOKE ALL ON DATABASE sfactory FROM PUBLIC",
        "GRANT CONNECT ON DATABASE sfactory TO sfactory",
        "REVOKE CREATE ON SCHEMA public FROM PUBLIC",
        "GRANT USAGE ON SCHEMA public TO sfactory",
        "GRANT SELECT, INSERT ON TABLE outbox TO sfactory",
        "GRANT SELECT, INSERT, UPDATE ON TABLE claim_lease_projection TO sfactory",
    ] {
        sqlx::query(statement).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    pool.close().await;
    Ok(())
}
