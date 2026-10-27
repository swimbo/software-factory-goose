//! Postgres read projection (consensus R3) — the queryable read model.
//!
//! Postgres is NOT the source of truth (the Restate journal is). These functions upsert the
//! projection. The caller must supply journal event identities for receipts and deliver
//! lifecycle updates in order. Claim transitions use journal-retried transactional outbox delivery; other helpers do not.

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
    .bind(i32::try_from(attempts)?)
    .bind(unit_spent_usd)
    .bind(git_revision)
    .execute(pool)
    .await?;
    Ok(())
}

/// Idempotent receipt projection (R6), keyed by the journal event, not a fresh random ID.
/// Callers must reuse `(invocation_id, step_seq)` for every redelivery.
pub async fn project_receipt(
    pool: &PgPool,
    r: &shared::Receipt,
    work_package_id: &str,
    invocation_id: &str,
    step_seq: u64,
) -> anyhow::Result<()> {
    anyhow::ensure!(!invocation_id.is_empty(), "missing receipt invocation ID");
    let receipt_id = receipt_event_id(invocation_id, step_seq);
    let (status, sha, wall_time_ms, turn_count, exit_code, diff) = match r {
        shared::Receipt::Completed {
            sha,
            diff,
            turn_count,
            exit_code,
            wall_time_ms,
            ..
        } => (
            "completed",
            sha.as_str(),
            *wall_time_ms,
            *turn_count,
            *exit_code,
            diff.as_str(),
        ),
        shared::Receipt::TimedOut {
            sha,
            turn_count,
            wall_time_ms,
        } => (
            "timed_out",
            sha.as_str(),
            *wall_time_ms,
            *turn_count,
            -1,
            "",
        ),
        shared::Receipt::Failed {
            exit_code,
            stderr_tail,
        } => ("failed", "", 0, 0, *exit_code, stderr_tail.as_str()),
        shared::Receipt::Crashed { signal, .. } => ("crashed", "", 0, 0, *signal, ""),
    };
    sqlx::query(
        r#"
        INSERT INTO receipts (id, work_package_id, status, git_revision, wall_time_ms, turn_count, exit_code, diff)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(receipt_id)
    .bind(work_package_id)
    .bind(status)
    .bind(sha)
    .bind(i64::try_from(wall_time_ms)?)
    .bind(i32::try_from(turn_count)?)
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

fn receipt_event_id(invocation_id: &str, step_seq: u64) -> String {
    // Length-prefix avoids collisions even if invocation IDs contain delimiters.
    format!("{}:{}:{}", invocation_id.len(), invocation_id, step_seq)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_redelivery_reuses_identity_but_attempts_do_not() {
        assert_eq!(
            receipt_event_id("invocation", 4),
            receipt_event_id("invocation", 4)
        );
        assert_ne!(
            receipt_event_id("invocation", 4),
            receipt_event_id("invocation", 5)
        );
        assert_ne!(
            receipt_event_id("invocation", 4),
            receipt_event_id("another", 4)
        );
        assert_ne!(receipt_event_id("a:1", 2), receipt_event_id("a", 12));
    }
}

/// Immutable full claim snapshot, produced once per mutation by the authoritative object.
/// `step_seq` identifies the producer's outbox step, not an aggregate version.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimTransitionEvent {
    pub invocation_id: String,
    pub step_seq: u64,
    pub work_package_id: String,
    pub version: u64,
    pub snapshot: serde_json::Value,
}

#[derive(Debug, thiserror::Error)]
pub enum ClaimProjectionError {
    #[error("claim projection integrity conflict: {0}")]
    Conflict(String),
    #[error("claim projection database failure: {0}")]
    Database(sqlx::Error),
}
impl From<sqlx::Error> for ClaimProjectionError {
    fn from(error: sqlx::Error) -> Self {
        if error
            .as_database_error()
            .and_then(|e| e.code())
            .is_some_and(|code| {
                ["22", "23", "42"]
                    .iter()
                    .any(|prefix| code.starts_with(prefix))
            })
        {
            // Invalid data, integrity violations and invalid SQL/schema are deterministic.
            Self::Conflict("database rejected delivery deterministically".into())
        } else {
            Self::Database(error)
        }
    }
}
impl ClaimTransitionEvent {
    fn validate(&self) -> Result<(), ClaimProjectionError> {
        if self.invocation_id.is_empty()
            || self.work_package_id.is_empty()
            || self.step_seq > i64::MAX as u64
            || self.version == 0
            || self.version > i64::MAX as u64
            || self
                .snapshot
                .get("work_package_id")
                .and_then(|v| v.as_str())
                != Some(self.work_package_id.as_str())
            || self.snapshot.get("version").and_then(|v| v.as_u64()) != Some(self.version)
        {
            return Err(ClaimProjectionError::Conflict(
                "invalid event identity or snapshot binding".into(),
            ));
        }
        Ok(())
    }
}

/// One SQL transaction retains the immutable event and advances the read snapshot. Repeated
/// delivery is safe after a commit whose acknowledgement was lost. Older events cannot roll
/// the snapshot backwards. Caller must retry transient database errors using its journal.
pub async fn deliver_claim_event(
    pool: &PgPool,
    event: &ClaimTransitionEvent,
) -> Result<(), ClaimProjectionError> {
    event.validate()?;
    let payload = serde_json::to_value(event)
        .map_err(|_| ClaimProjectionError::Conflict("event serialization failed".into()))?;
    let mut tx = pool.begin().await?;
    sqlx::query("INSERT INTO outbox (invocation_id,step_seq,step_kind,payload) VALUES ($1,$2,'claim_transition_v1',$3) ON CONFLICT (invocation_id,step_seq) DO NOTHING")
        .bind(&event.invocation_id).bind(event.step_seq as i64).bind(&payload).execute(&mut *tx).await?;
    let stored: (String, serde_json::Value) = sqlx::query_as(
        "SELECT step_kind,payload FROM outbox WHERE invocation_id=$1 AND step_seq=$2",
    )
    .bind(&event.invocation_id)
    .bind(event.step_seq as i64)
    .fetch_one(&mut *tx)
    .await?;
    if stored.0 != "claim_transition_v1" || stored.1 != payload {
        return Err(ClaimProjectionError::Conflict(
            "event key was reused with different content".into(),
        ));
    }
    sqlx::query("INSERT INTO claim_lease_projection (work_package_id,version,snapshot) VALUES ($1,$2,$3) ON CONFLICT (work_package_id) DO UPDATE SET version=EXCLUDED.version,snapshot=EXCLUDED.snapshot WHERE claim_lease_projection.version < EXCLUDED.version")
        .bind(&event.work_package_id).bind(event.version as i64).bind(&event.snapshot).execute(&mut *tx).await?;
    let projected: (i64, serde_json::Value) = sqlx::query_as(
        "SELECT version,snapshot FROM claim_lease_projection WHERE work_package_id=$1",
    )
    .bind(&event.work_package_id)
    .fetch_one(&mut *tx)
    .await?;
    if projected.0 == event.version as i64 && projected.1 != event.snapshot {
        return Err(ClaimProjectionError::Conflict(
            "projection version has different content".into(),
        ));
    }
    tx.commit().await?;
    Ok(())
}

/// Rebuild ONLY claim snapshots from retained SQL outbox events. This is not reconstruction
/// from the Restate journal. Losing Postgres/outbox requires a separate, still-unimplemented
/// journal-backed re-export; replaying completed `ctx.run` calls does not redo their effects.
pub async fn rebuild_claim_projection(pool: &PgPool) -> Result<(), ClaimProjectionError> {
    let mut tx = pool.begin().await?;
    // Same lock order as delivery (outbox then projection), excluding concurrent delivery.
    sqlx::query("LOCK TABLE outbox IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *tx)
        .await?;
    sqlx::query("LOCK TABLE claim_lease_projection IN EXCLUSIVE MODE")
        .execute(&mut *tx)
        .await?;
    let invalid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM outbox WHERE step_kind='claim_transition_v1' AND ((payload->>'invocation_id'=invocation_id AND payload->>'step_seq'=step_seq::text AND payload->>'work_package_id'<>'' AND (payload->>'version')::bigint>0 AND payload->'snapshot'->>'work_package_id'=payload->>'work_package_id' AND payload->'snapshot'->'version'=payload->'version') IS NOT TRUE))").fetch_one(&mut *tx).await?;
    // The migration prevents duplicate versions. Still reject corrupted/restored history
    // if that index was removed: DISTINCT ON must never select arbitrarily among ties.
    let duplicate: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM outbox WHERE step_kind='claim_transition_v1' GROUP BY payload->>'work_package_id',payload->>'version' HAVING count(*)>1)").fetch_one(&mut *tx).await?;
    if duplicate {
        return Err(ClaimProjectionError::Conflict(
            "retained history has duplicate aggregate versions".into(),
        ));
    }
    if invalid {
        return Err(ClaimProjectionError::Conflict(
            "retained event failed rebuild validation".into(),
        ));
    }
    sqlx::query("DELETE FROM claim_lease_projection")
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO claim_lease_projection(work_package_id,version,snapshot) SELECT DISTINCT ON (payload->>'work_package_id') payload->>'work_package_id',(payload->>'version')::bigint,payload->'snapshot' FROM outbox WHERE step_kind='claim_transition_v1' ORDER BY payload->>'work_package_id',(payload->>'version')::bigint DESC").execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
