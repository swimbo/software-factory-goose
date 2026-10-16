//! Postgres read projection (consensus R3) — the queryable read model.
//!
//! Postgres is NOT the source of truth (the Restate journal is). These functions upsert the
//! projection idempotently; every primary key is the outbox key, so a redelivered event is a
//! no-op (`ON CONFLICT DO NOTHING`).

use sqlx::PgPool;

/// Run pending migrations (outbox + projection tables in `migrations/`).
pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

/// Idempotent upsert of a qualifier decision (`sfctl inspect` reads this).
pub async fn project_qualifier_decision(
    pool: &PgPool,
    d: &shared::QualifierDecision,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO qualifier_decisions (intent_id, score, lane, reason, fatal)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (intent_id) DO NOTHING
        "#,
    )
    .bind(&d.intent_id)
    .bind(d.score)
    .bind(d.lane.to_string())
    .bind(&d.reason)
    .bind(d.fatal)
    .execute(pool)
    .await?;
    Ok(())
}

/// Idempotent upsert of a work-package lifecycle row.
pub async fn project_work_package(
    pool: &PgPool,
    id: &str,
    intent_id: &str,
    stage: &str,
    attempts: u32,
    unit_spent_usd: f64,
    git_revision: Option<&str>,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO work_packages (id, intent_id, stage, attempts, unit_spent_usd, git_revision)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (id) DO UPDATE SET stage = EXCLUDED.stage, attempts = EXCLUDED.attempts,
            unit_spent_usd = EXCLUDED.unit_spent_usd, git_revision = EXCLUDED.git_revision
        "#,
    )
    .bind(id)
    .bind(intent_id)
    .bind(stage)
    .bind(attempts as i32)
    .bind(unit_spent_usd)
    .bind(git_revision)
    .execute(pool)
    .await?;
    Ok(())
}

/// Idempotent upsert of a receipt bound to an exact git revision (R6).
pub async fn project_receipt(
    pool: &PgPool,
    r: &shared::Receipt,
    work_package_id: &str,
) -> anyhow::Result<()> {
    let (status, sha, wall_time_ms, turn_count, exit_code, diff) = match r {
        shared::Receipt::Completed { sha, diff, turn_count, exit_code, wall_time_ms } => {
            ("completed", sha.as_str(), *wall_time_ms, *turn_count, *exit_code, diff.as_str())
        }
        shared::Receipt::TimedOut { sha, turn_count, wall_time_ms } => {
            ("timed_out", sha.as_str(), *wall_time_ms, *turn_count, -1, "")
        }
        shared::Receipt::Failed { exit_code, stderr_tail } => {
            ("failed", "", 0, 0, *exit_code, stderr_tail.as_str())
        }
        shared::Receipt::Crashed { signal, .. } => {
            ("crashed", "", 0, 0, *signal, "")
        }
    };
    sqlx::query(
        r#"
        INSERT INTO receipts (id, work_package_id, status, git_revision, wall_time_ms, turn_count, exit_code, diff)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(shared::new_id())
    .bind(work_package_id)
    .bind(status)
    .bind(sha)
    .bind(wall_time_ms as i64)
    .bind(turn_count as i32)
    .bind(exit_code)
    .bind(diff)
    .execute(pool)
    .await?;
    Ok(())
}

/// Append an audit event ("lights off, nothing unseen").
pub async fn project_audit_event(pool: &PgPool, e: &shared::AuditEvent) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO audit_events (id, timestamp, actor, action, entity_id, entity_type, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(&e.id)
    .bind(e.timestamp)
    .bind(match e.actor {
        shared::Actor::Human => "human",
        shared::Actor::Agent => "agent",
        shared::Actor::System => "system",
    })
    .bind(&e.action)
    .bind(&e.entity_id)
    .bind(&e.entity_type)
    .bind(&e.metadata)
    .execute(pool)
    .await?;
    Ok(())
}
