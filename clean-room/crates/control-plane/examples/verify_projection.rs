//! Disposable-Postgres integration verification; never point at a standing service.
//!
//! Run with SFACTORY_TEST_DATABASE_URL=postgres://postgres@127.0.0.1:PORT/sfactory_verification
//! cargo run -p control-plane --example verify_projection
//! The harness refuses remote hosts, URL overrides, other database names, and populated
//! target tables. It rebuilds only its synthetic claim projection. Supply a fresh disposable pgvector database.
//! This proves projection SQL and synthetic vector recall, NOT journal/outbox replay.

use anyhow::{Context, ensure};
use control_plane::{memory, projection};
use shared::{Actor, AuditEvent, Lane, QualifierDecision, Receipt};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{net::IpAddr, time::Duration};

fn verified_url(raw: &str) -> anyhow::Result<reqwest::Url> {
    let url = reqwest::Url::parse(raw).context("invalid test database URL")?;
    ensure!(
        matches!(url.scheme(), "postgres" | "postgresql"),
        "Postgres URL required"
    );
    ensure!(
        url.path() == "/sfactory_verification",
        "test database must be sfactory_verification"
    );
    ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "URL overrides are forbidden"
    );
    ensure!(
        url.username() == "postgres" && url.password().is_none(),
        "use synthetic trust-auth postgres only"
    );
    ensure!(
        url.port().is_some(),
        "explicit disposable database port required"
    );
    let host = url.host_str().unwrap_or_default().trim_matches(['[', ']']);
    ensure!(
        host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()),
        "numeric loopback host required"
    );
    Ok(url)
}

async fn count(pool: &PgPool, query: &str) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar(query).fetch_one(pool).await?)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let raw = std::env::var("SFACTORY_TEST_DATABASE_URL")
        .context("set SFACTORY_TEST_DATABASE_URL to a fresh disposable database")?;
    let url = verified_url(&raw)?;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(10))
        .connect(url.as_str())
        .await?;
    let db: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&pool)
        .await?;
    ensure!(db == "sfactory_verification", "connected to wrong database");
    projection::migrate(&pool).await?;
    projection::migrate(&pool).await?;
    let extension: String =
        sqlx::query_scalar("SELECT extversion FROM pg_extension WHERE extname = 'vector'")
            .fetch_one(&pool)
            .await?;
    for query in [
        "SELECT count(*) FROM receipts",
        "SELECT count(*) FROM qualifier_decisions",
        "SELECT count(*) FROM audit_events",
        "SELECT count(*) FROM work_packages",
        "SELECT count(*) FROM embeddings",
        "SELECT count(*) FROM outbox",
        "SELECT count(*) FROM claim_lease_projection",
    ] {
        ensure!(
            count(&pool, query).await? == 0,
            "fresh empty verification database required"
        );
    }
    println!("PASS: migrations applied twice; pgvector {extension}");

    let decision = QualifierDecision {
        intent_id: "verification-intent".into(),
        score: 0.95,
        lane: Lane::Dark,
        reason: "synthetic fixture".into(),
        fatal: false,
    };
    projection::project_qualifier_decision(&pool, &decision).await?;
    projection::project_qualifier_decision(&pool, &decision).await?;
    ensure!(
        count(&pool, "SELECT count(*) FROM qualifier_decisions").await? == 1,
        "qualifier redelivery duplicated"
    );
    let stored: (f64, String, bool) =
        sqlx::query_as("SELECT score, lane, fatal FROM qualifier_decisions")
            .fetch_one(&pool)
            .await?;
    ensure!(
        stored == (0.95, "dark".into(), false),
        "qualifier fields changed"
    );
    println!("PASS: qualifier redelivery = one intact row");

    let receipt = Receipt::Completed {
        sha: "a".repeat(40),
        diff: "synthetic diff".into(),
        turn_count: 2,
        exit_code: 0,
        wall_time_ms: 42,
        spend_usd: 0.01,
    };
    projection::project_receipt(
        &pool,
        &receipt,
        "verification-work",
        "verification-invocation",
        1,
    )
    .await?;
    projection::project_receipt(
        &pool,
        &receipt,
        "verification-work",
        "verification-invocation",
        1,
    )
    .await?;
    ensure!(
        count(&pool, "SELECT count(*) FROM receipts").await? == 1,
        "receipt redelivery duplicated"
    );
    projection::project_receipt(
        &pool,
        &receipt,
        "verification-work",
        "verification-invocation",
        2,
    )
    .await?;
    ensure!(
        count(&pool, "SELECT count(*) FROM receipts").await? == 2,
        "distinct step lost"
    );
    let stored: (String, i64, i32) =
        sqlx::query_as("SELECT git_revision, wall_time_ms, turn_count FROM receipts LIMIT 1")
            .fetch_one(&pool)
            .await?;
    ensure!(stored == ("a".repeat(40), 42, 2), "receipt fields changed");
    println!("PASS: receipt redelivery = one row; distinct step_seq = two rows");

    let event = AuditEvent {
        id: "verification-audit".into(),
        timestamp: chrono::Utc::now(),
        actor: Actor::System,
        action: "verification".into(),
        entity_id: "verification-work".into(),
        entity_type: "work_package".into(),
        metadata: serde_json::json!({"synthetic":true}),
    };
    projection::project_audit_event(&pool, &event).await?;
    projection::project_audit_event(&pool, &event).await?;
    ensure!(
        count(&pool, "SELECT count(*) FROM audit_events").await? == 1,
        "audit redelivery duplicated"
    );
    println!("PASS: audit redelivery = one row");

    projection::project_work_package(
        &pool,
        "verification-work",
        "verification-intent",
        "Building",
        1,
        0.01,
        None,
    )
    .await?;
    projection::project_work_package(
        &pool,
        "verification-work",
        "verification-intent",
        "Evaluating",
        1,
        0.01,
        Some(&"a".repeat(40)),
    )
    .await?;
    let stored: (String, i32) = sqlx::query_as("SELECT stage, attempts FROM work_packages")
        .fetch_one(&pool)
        .await?;
    ensure!(
        stored == ("Evaluating".into(), 1),
        "ordered work-package update failed"
    );
    println!("PASS: ordered work-package update = one current row");

    let mut first = vec![0.0_f32; 1536];
    first[0] = 1.0;
    let mut second = vec![0.0_f32; 1536];
    second[1] = 1.0;
    memory::store_embedding(&pool, "first axis", &first, "synthetic", "fixture-1536").await?;
    memory::store_embedding(&pool, "second axis", &second, "synthetic", "fixture-1536").await?;
    ensure!(
        memory::recall(&pool, &first, 1).await? == vec!["first axis"],
        "first vector recall failed"
    );
    ensure!(
        memory::recall(&pool, &second, 1).await? == vec!["second axis"],
        "second vector recall failed"
    );
    ensure!(
        count(&pool, "SELECT count(*) FROM outbox").await? == 0,
        "harness unexpectedly wrote outbox"
    );
    println!("PASS: 1536-dimension synthetic cosine recall in both directions");
    verify_claim_outbox(&pool).await?;
    println!(
        "BOUNDARY: SQL transaction/redelivery/rebuild proof only; no live Restate crash replay, full journal recovery, ANN recall-quality or live embeddings proof"
    );
    pool.close().await;
    Ok(())
}

async fn verify_claim_outbox(pool: &PgPool) -> anyhow::Result<()> {
    use projection::{
        ClaimProjectionError, ClaimTransitionEvent, deliver_claim_event, rebuild_claim_projection,
    };
    let event = |invocation: &str, task: &str, version: u64| ClaimTransitionEvent {
        invocation_id: invocation.into(),
        step_seq: 0,
        work_package_id: task.into(),
        version,
        snapshot: serde_json::json!({"work_package_id":task,"version":version,"stage":format!("v{version}")}),
    };
    let first = event("claim-invocation-1", "claim-task", 1);
    let (a, b) = tokio::join!(
        deliver_claim_event(pool, &first),
        deliver_claim_event(pool, &first)
    );
    a?;
    b?;
    ensure!(
        count(pool, "SELECT count(*) FROM outbox").await? == 1,
        "redelivery duplicated event"
    );
    let mut changed = first.clone();
    changed.snapshot["stage"] = serde_json::json!("forged");
    ensure!(
        matches!(
            deliver_claim_event(pool, &changed).await,
            Err(ClaimProjectionError::Conflict(_))
        ),
        "changed event accepted"
    );
    let conflicting = event("another-invocation", "claim-task", 1);
    ensure!(
        matches!(
            deliver_claim_event(pool, &conflicting).await,
            Err(ClaimProjectionError::Conflict(_))
        ),
        "conflicting aggregate version accepted"
    );
    deliver_claim_event(pool, &event("claim-invocation-3", "claim-task", 3)).await?;
    deliver_claim_event(pool, &event("claim-invocation-2", "claim-task", 2)).await?;
    let mut old_conflict = event("old-version-conflict", "claim-task", 1);
    old_conflict.snapshot["stage"] = serde_json::json!("contradictory-old-history");
    ensure!(
        matches!(
            deliver_claim_event(pool, &old_conflict).await,
            Err(ClaimProjectionError::Conflict(_))
        ),
        "old version conflict escaped after version3"
    );
    ensure!(
        count(
            pool,
            "SELECT count(*) FROM outbox WHERE invocation_id='old-version-conflict'"
        )
        .await?
            == 0,
        "conflicting old history committed"
    );

    let current: serde_json::Value = sqlx::query_scalar(
        "SELECT snapshot FROM claim_lease_projection WHERE work_package_id='claim-task'",
    )
    .fetch_one(pool)
    .await?;
    ensure!(
        current == event("unused", "claim-task", 3).snapshot,
        "late event rolled projection backwards"
    );
    // Deliberately fail projection after the event INSERT, proving both roll back together.
    sqlx::query("ALTER TABLE claim_lease_projection ADD CONSTRAINT verification_fail CHECK (work_package_id <> 'rollback-task')").execute(pool).await?;
    ensure!(
        matches!(
            deliver_claim_event(pool, &event("rollback-invocation", "rollback-task", 1)).await,
            Err(ClaimProjectionError::Conflict(_))
        ),
        "injected failure was not terminal"
    );
    ensure!(
        count(
            pool,
            "SELECT count(*) FROM outbox WHERE invocation_id='rollback-invocation'"
        )
        .await?
            == 0,
        "event escaped failed transaction"
    );
    sqlx::query("ALTER TABLE claim_lease_projection DROP CONSTRAINT verification_fail")
        .execute(pool)
        .await?;
    let mut distinct_step = event("claim-invocation-1", "other-task", 1);
    distinct_step.step_seq = 1;
    deliver_claim_event(pool, &distinct_step).await?;
    let before: Vec<(String, i64, serde_json::Value)> = sqlx::query_as("SELECT work_package_id, version, snapshot FROM claim_lease_projection ORDER BY work_package_id").fetch_all(pool).await?;
    sqlx::query("DELETE FROM claim_lease_projection")
        .execute(pool)
        .await?;
    rebuild_claim_projection(pool).await?;
    let after: Vec<(String, i64, serde_json::Value)> = sqlx::query_as("SELECT work_package_id, version, snapshot FROM claim_lease_projection ORDER BY work_package_id").fetch_all(pool).await?;
    ensure!(before == after, "rebuild changed claim snapshots");
    ensure!(
        count(pool, "SELECT count(*) FROM outbox").await? == 4,
        "rebuild changed retained events"
    );
    ensure!(
        count(pool, "SELECT count(*) FROM work_packages").await? == 1,
        "rebuild changed unrelated projection"
    );
    // Corrupt retained binding: rebuild must reject before replacing the existing snapshot.
    sqlx::query("UPDATE outbox SET payload=jsonb_set(payload,'{snapshot,version}','99') WHERE invocation_id='claim-invocation-3'").execute(pool).await?;
    ensure!(
        matches!(
            rebuild_claim_projection(pool).await,
            Err(ClaimProjectionError::Conflict(_))
        ),
        "corrupt retained binding accepted"
    );
    let unchanged: Vec<(String, i64, serde_json::Value)> = sqlx::query_as("SELECT work_package_id, version, snapshot FROM claim_lease_projection ORDER BY work_package_id").fetch_all(pool).await?;
    ensure!(unchanged == before, "failed rebuild changed projection");
    sqlx::query("UPDATE outbox SET payload=jsonb_set(payload,'{snapshot,version}','3') WHERE invocation_id='claim-invocation-3'").execute(pool).await?;
    // Simulate corrupted restored history missing its unique index. Rebuild must reject
    // version ties independently, rather than choose an arbitrary DISTINCT ON winner.
    sqlx::query("DROP INDEX outbox_claim_version")
        .execute(pool)
        .await?;
    sqlx::query("INSERT INTO outbox(invocation_id,step_seq,step_kind,payload) VALUES ('old-version-conflict',0,'claim_transition_v1',$1)").bind(serde_json::to_value(&old_conflict)?).execute(pool).await?;
    ensure!(
        matches!(
            rebuild_claim_projection(pool).await,
            Err(ClaimProjectionError::Conflict(_))
        ),
        "duplicate retained version accepted by rebuild"
    );
    let unchanged: Vec<(String, i64, serde_json::Value)> = sqlx::query_as("SELECT work_package_id, version, snapshot FROM claim_lease_projection ORDER BY work_package_id").fetch_all(pool).await?;
    ensure!(
        unchanged == before,
        "ambiguous history rebuild changed projection"
    );
    sqlx::query("DELETE FROM outbox WHERE invocation_id='old-version-conflict'")
        .execute(pool)
        .await?;
    sqlx::query("CREATE UNIQUE INDEX outbox_claim_version ON outbox ((payload->>'work_package_id'), ((payload->>'version')::bigint)) WHERE step_kind='claim_transition_v1'").execute(pool).await?;
    println!(
        "PASS: concurrent redelivery, distinct steps, current/old version conflicts, out-of-order delivery, atomic rollback, exact claim rebuild and corrupt/duplicate history rejection"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_explicit_disposable_loopback_database_is_accepted() {
        assert!(verified_url("postgres://postgres@127.0.0.1:65432/sfactory_verification").is_ok());
        for url in [
            "postgres://postgres@example.com:65432/sfactory_verification",
            "postgres://postgres@127.0.0.1:65432/production",
            "postgres://postgres@127.0.0.1:65432/sfactory_verification?host=example.com",
            "postgres://postgres@127.0.0.1/sfactory_verification",
            "postgres://postgres:password@127.0.0.1:65432/sfactory_verification",
        ] {
            assert!(verified_url(url).is_err());
        }
    }
}
