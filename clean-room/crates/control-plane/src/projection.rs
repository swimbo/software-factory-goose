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
    // Raw diff/stderr are authoritative receipt content, never a safe read-model field.
    let (status, sha, wall_time_ms, turn_count, exit_code) = match r {
        shared::Receipt::Completed {
            sha,
            turn_count,
            exit_code,
            wall_time_ms,
            ..
        } => (
            "completed",
            Some(sha.as_str()).filter(|sha| canonical_revision(sha)),
            *wall_time_ms,
            *turn_count,
            *exit_code,
        ),
        shared::Receipt::TimedOut {
            sha,
            turn_count,
            wall_time_ms,
        } => (
            "timed_out",
            Some(sha.as_str()).filter(|sha| canonical_revision(sha)),
            *wall_time_ms,
            *turn_count,
            -1,
        ),
        shared::Receipt::Failed { exit_code, .. } => ("failed", None, 0, 0, *exit_code),
        shared::Receipt::Crashed { signal, .. } => ("crashed", None, 0, 0, *signal),
    };
    sqlx::query(
        r#"
        INSERT INTO receipts (id, work_package_id, status, git_revision, wall_time_ms, turn_count, exit_code, diff)
        VALUES ($1, $2, $3, $4, $5, $6, $7, NULL)
        ON CONFLICT (id) DO UPDATE SET diff=NULL
        "#,
    )
    .bind(receipt_id)
    .bind(work_package_id)
    .bind(status)
    .bind(sha)
    .bind(i64::try_from(wall_time_ms)?)
    .bind(i32::try_from(turn_count)?)
    .bind(exit_code)
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

fn canonical_revision(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
/// Allowlisted read model. No lease token, worker/repository free text, diff or stderr field.
/// Authoritative claim state retains those private values only in Restate.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimProjectionSnapshot {
    pub schema_version: u8,
    pub version: u64,
    pub work_package_id: String,
    pub base_revision: String,
    pub stage: ClaimProjectionStage,
    pub attempts: u32,
    pub cooldown_until_ms: u64,
    pub active: Option<LeaseProjectionSummary>,
    pub last_completion: Option<CompletionProjectionSummary>,
}
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ClaimProjectionStage {
    Queued,
    Leased,
    CoolingDown,
    Evaluating,
    Failed,
}
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseProjectionSummary {
    pub attempt: u32,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub hard_deadline_ms: u64,
}
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletionProjectionSummary {
    pub lease: LeaseProjectionSummary,
    pub receipt: ReceiptProjectionSummary,
}
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReceiptProjectionSummary {
    Completed {
        sha: Option<String>,
        turn_count: u32,
        exit_code: i32,
        wall_time_ms: u64,
        spend_usd: f64,
    },
    TimedOut {
        sha: Option<String>,
        turn_count: u32,
        wall_time_ms: u64,
    },
    Failed {
        exit_code: i32,
    },
    Crashed {
        signal: i32,
        core_dumped: bool,
    },
}
impl From<&shared::Receipt> for ReceiptProjectionSummary {
    fn from(receipt: &shared::Receipt) -> Self {
        let revision = |s: &String| canonical_revision(s).then(|| s.clone());
        match receipt {
            shared::Receipt::Completed {
                sha,
                turn_count,
                exit_code,
                wall_time_ms,
                spend_usd,
                ..
            } => Self::Completed {
                sha: revision(sha),
                turn_count: *turn_count,
                exit_code: *exit_code,
                wall_time_ms: *wall_time_ms,
                spend_usd: *spend_usd,
            },
            shared::Receipt::TimedOut {
                sha,
                turn_count,
                wall_time_ms,
            } => Self::TimedOut {
                sha: revision(sha),
                turn_count: *turn_count,
                wall_time_ms: *wall_time_ms,
            },
            shared::Receipt::Failed { exit_code, .. } => Self::Failed {
                exit_code: *exit_code,
            },
            shared::Receipt::Crashed {
                signal,
                core_dumped,
            } => Self::Crashed {
                signal: *signal,
                core_dumped: *core_dumped,
            },
        }
    }
}
impl ClaimProjectionSnapshot {
    fn validate(&self) -> Result<(), ClaimProjectionError> {
        let valid_receipt =
            self.last_completion
                .as_ref()
                .is_none_or(|completion| match &completion.receipt {
                    ReceiptProjectionSummary::Completed { sha, spend_usd, .. } => {
                        sha.as_ref().is_none_or(|s| canonical_revision(s))
                            && spend_usd.is_finite()
                            && *spend_usd >= 0.0
                    }
                    ReceiptProjectionSummary::TimedOut { sha, .. } => {
                        sha.as_ref().is_none_or(|s| canonical_revision(s))
                    }
                    _ => true,
                });
        // Evaluating means this claim's current attempt completed successfully. A syntactically
        // valid revision alone is not proof of repository provenance or an evaluator verdict.
        let evaluating_bound = self.stage != ClaimProjectionStage::Evaluating
            || (self.active.is_none()
                && self.attempts > 0
                && self.last_completion.as_ref().is_some_and(|completion| {
                    completion.lease.attempt == self.attempts
                        && matches!(
                            &completion.receipt,
                            ReceiptProjectionSummary::Completed {
                                sha: Some(sha),
                                exit_code: 0,
                                ..
                            } if canonical_revision(sha)
                        )
                }));
        if self.schema_version != 2
            || !canonical_revision(&self.base_revision)
            || !valid_receipt
            || !evaluating_bound
        {
            return Err(ClaimProjectionError::Conflict(
                "unsafe or unsupported claim projection schema".into(),
            ));
        }
        Ok(())
    }
}

/// Immutable allowlisted claim snapshot, produced once per mutation by the authoritative object.
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
    pub(crate) fn validate(&self) -> Result<(), ClaimProjectionError> {
        let snapshot: ClaimProjectionSnapshot = serde_json::from_value(self.snapshot.clone())
            .map_err(|_| {
                ClaimProjectionError::Conflict(
                    "claim snapshot contains unsupported or unsafe fields".into(),
                )
            })?;
        snapshot.validate()?;
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
    let mut tx = pool.begin().await?;
    lock_claim_aggregate(&mut tx, &event.work_package_id).await?;
    deliver_claim_event_tx(&mut tx, event).await?;
    tx.commit().await?;
    Ok(())
}
async fn lock_claim_aggregate(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    key: &str,
) -> Result<(), ClaimProjectionError> {
    // All claim writers share this transaction-scoped lock. Hash collisions only serialize
    // unrelated aggregates; they cannot weaken integrity. SQL rebuild uses table locks.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(key)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
async fn deliver_claim_event_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    event: &ClaimTransitionEvent,
) -> Result<(), ClaimProjectionError> {
    event.validate()?;
    let payload = serde_json::to_value(event)
        .map_err(|_| ClaimProjectionError::Conflict("event serialization failed".into()))?;
    sqlx::query("INSERT INTO outbox (invocation_id,step_seq,step_kind,payload) VALUES ($1,$2,'claim_transition_v1',$3) ON CONFLICT (invocation_id,step_seq) DO NOTHING")
        .bind(&event.invocation_id).bind(event.step_seq as i64).bind(&payload).execute(&mut **tx).await?;
    let stored: (String, serde_json::Value) = sqlx::query_as(
        "SELECT step_kind,payload FROM outbox WHERE invocation_id=$1 AND step_seq=$2",
    )
    .bind(&event.invocation_id)
    .bind(event.step_seq as i64)
    .fetch_one(&mut **tx)
    .await?;
    if stored.0 != "claim_transition_v1" || stored.1 != payload {
        return Err(ClaimProjectionError::Conflict(
            "event key was reused with different content".into(),
        ));
    }
    sqlx::query("INSERT INTO claim_lease_projection (work_package_id,version,snapshot) VALUES ($1,$2,$3) ON CONFLICT (work_package_id) DO UPDATE SET version=EXCLUDED.version,snapshot=EXCLUDED.snapshot WHERE claim_lease_projection.version < EXCLUDED.version")
        .bind(&event.work_package_id).bind(event.version as i64).bind(&event.snapshot).execute(&mut **tx).await?;
    let projected: (i64, serde_json::Value) = sqlx::query_as(
        "SELECT version,snapshot FROM claim_lease_projection WHERE work_package_id=$1",
    )
    .bind(&event.work_package_id)
    .fetch_one(&mut **tx)
    .await?;
    if projected.0 == event.version as i64 && projected.1 != event.snapshot {
        return Err(ClaimProjectionError::Conflict(
            "projection version has different content".into(),
        ));
    }
    Ok(())
}

/// Re-export one complete authoritative claim history in a single SQL transaction.
/// This is not journal reconstruction itself: only the object may supply the retained chain.
/// Existing content must exactly agree; unrelated aggregate histories are left untouched.
pub async fn reexport_claim_events(
    pool: &PgPool,
    events: &[ClaimTransitionEvent],
) -> Result<(), ClaimProjectionError> {
    let Some(last) = events.last() else {
        return Err(ClaimProjectionError::Conflict("empty history".into()));
    };
    let mut identities = std::collections::BTreeSet::new();
    for (index, event) in events.iter().enumerate() {
        event.validate()?;
        if event.version != index as u64 + 1
            || event.work_package_id != last.work_package_id
            || !identities.insert((&event.invocation_id, event.step_seq))
        {
            return Err(ClaimProjectionError::Conflict(
                "noncontiguous or conflicting re-export history".into(),
            ));
        }
    }
    let mut tx = pool.begin().await?;
    lock_claim_aggregate(&mut tx, &last.work_package_id).await?;
    for event in events {
        deliver_claim_event_tx(&mut tx, event).await?;
    }
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM outbox WHERE step_kind='claim_transition_v1' AND payload->>'work_package_id'=$1")
        .bind(&last.work_package_id).fetch_one(&mut *tx).await?;
    let projected: (i64, serde_json::Value) = sqlx::query_as(
        "SELECT version,snapshot FROM claim_lease_projection WHERE work_package_id=$1",
    )
    .bind(&last.work_package_id)
    .fetch_one(&mut *tx)
    .await?;
    if count != events.len() as i64 || projected != (last.version as i64, last.snapshot.clone()) {
        return Err(ClaimProjectionError::Conflict(
            "SQL history differs from authoritative re-export".into(),
        ));
    }
    tx.commit().await?;
    Ok(())
}

/// Rebuild ONLY claim snapshots from retained SQL outbox events. This is not reconstruction
/// from the Restate journal. After SQL loss, invoke each object's explicit retained-history
/// re-export first; replaying completed `ctx.run` calls does not redo their effects.
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
    // Never copy legacy raw-capability/free-text payloads into the read model. Keep this
    // manual helper bounded; larger stores need a separately reviewed paginated recovery.
    let payloads: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT payload FROM outbox WHERE step_kind='claim_transition_v1' LIMIT 10001",
    )
    .fetch_all(&mut *tx)
    .await?;
    if payloads.len() > 10000 {
        return Err(ClaimProjectionError::Conflict(
            "bounded claim rebuild limit exceeded".into(),
        ));
    }
    for payload in payloads {
        let event: ClaimTransitionEvent = serde_json::from_value(payload)
            .map_err(|_| ClaimProjectionError::Conflict("invalid retained event schema".into()))?;
        event.validate()?;
    }
    sqlx::query("DELETE FROM claim_lease_projection")
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO claim_lease_projection(work_package_id,version,snapshot) SELECT DISTINCT ON (payload->>'work_package_id') payload->>'work_package_id',(payload->>'version')::bigint,payload->'snapshot' FROM outbox WHERE step_kind='claim_transition_v1' ORDER BY payload->>'work_package_id',(payload->>'version')::bigint DESC").execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod safe_snapshot_tests {
    use super::*;
    fn event() -> ClaimTransitionEvent {
        ClaimTransitionEvent {
            invocation_id: "fixture".into(),
            step_seq: 0,
            work_package_id: "task".into(),
            version: 1,
            snapshot: serde_json::json!({"schema_version":2,"version":1,"work_package_id":"task","base_revision":"a".repeat(40),"stage":"Queued","attempts":0,"cooldown_until_ms":0,"active":null,"last_completion":null}),
        }
    }
    #[test]
    fn nested_capabilities_and_unscanned_text_are_not_valid_projection_fields() {
        let safe = event();
        safe.validate().unwrap();
        let lease = serde_json::json!({"attempt":1,"issued_at_ms":0,"expires_at_ms":10,"hard_deadline_ms":10});
        let mut token = safe.clone();
        token.snapshot["active"] = lease.clone();
        token.snapshot["active"]["token"] = "SYNTHETIC_CAPABILITY".into();
        assert!(token.validate().is_err());
        for receipt in [
            serde_json::json!({"status":"failed","exit_code":1,"stderr_tail":"SYNTHETIC_RAW_STDERR"}),
            serde_json::json!({"status":"completed","sha":"b".repeat(40),"turn_count":1,"exit_code":0,"wall_time_ms":1,"spend_usd":0.01,"diff":"SYNTHETIC_RAW_DIFF"}),
        ] {
            let mut event = safe.clone();
            event.snapshot["last_completion"] =
                serde_json::json!({"lease":lease,"receipt":receipt});
            assert!(event.validate().is_err());
        }
    }
    #[test]
    fn arbitrary_timeout_revision_is_withheld_from_receipt_summary() {
        let summary = ReceiptProjectionSummary::from(&shared::Receipt::TimedOut {
            sha: "SYNTHETIC_SECRET_NOT_A_REVISION".into(),
            turn_count: 1,
            wall_time_ms: 1,
        });
        assert_eq!(
            serde_json::to_value(summary).unwrap()["sha"],
            serde_json::Value::Null
        );
    }

    #[test]
    fn evaluating_snapshot_requires_the_current_attempts_successful_exact_revision() {
        let mut evaluated = event();
        evaluated.snapshot["stage"] = "Evaluating".into();
        evaluated.snapshot["attempts"] = 2.into();
        evaluated.snapshot["last_completion"] = serde_json::json!({
            "lease":{"attempt":2,"issued_at_ms":0,"expires_at_ms":10,"hard_deadline_ms":300000},
            "receipt":{"status":"completed","sha":"b".repeat(40),"turn_count":1,"exit_code":0,"wall_time_ms":1,"spend_usd":0.01}
        });
        evaluated.validate().unwrap();
        for field in 0..5 {
            let mut corrupt = evaluated.clone();
            match field {
                0 => corrupt.snapshot["last_completion"]["lease"]["attempt"] = 1.into(),
                1 => {
                    corrupt.snapshot["last_completion"]["receipt"]["sha"] = serde_json::Value::Null
                }
                2 => corrupt.snapshot["last_completion"]["receipt"]["exit_code"] = 1.into(),
                3 => corrupt.snapshot["last_completion"] = serde_json::Value::Null,
                _ => {
                    corrupt.snapshot["active"] =
                        corrupt.snapshot["last_completion"]["lease"].clone()
                }
            }
            assert!(corrupt.validate().is_err(), "accepted variant {field}");
        }
    }
}
