//! Idempotent derived SQL view. Never use SQL to authorize a generation or approval.
use crate::root_finalization::{Envelope, record_digest};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Delivery {
    Current,
    Pending,
    IntegrityConflict,
}

/// The immutable payload and event identity commit together in one SQL transaction.
/// A lost acknowledgement is safe to redeliver. A changed existing row is never replaced.
pub async fn export(pool: &PgPool, envelope: &Envelope) -> Delivery {
    let Ok(digest) = record_digest(&envelope.record) else {
        return Delivery::IntegrityConflict;
    };
    if envelope.event.version != 1 || envelope.event.payload_sha256 != digest {
        return Delivery::IntegrityConflict;
    }
    let task = &envelope.record.reservation.scope.task_id;
    let generation = &envelope.record.reservation.generation;
    let Ok(payload) = serde_json::to_value(&envelope.record) else {
        return Delivery::IntegrityConflict;
    };
    let Ok(mut tx) = pool.begin().await else {
        return Delivery::Pending;
    };
    let insert = sqlx::query(
        "INSERT INTO root_finalization_projection \
         (task_id,generation,event_version,payload_sha256,payload) \
         VALUES ($1,$2,1,$3,$4) ON CONFLICT DO NOTHING",
    )
    .bind(task)
    .bind(generation)
    .bind(&digest)
    .bind(&payload)
    .execute(&mut *tx)
    .await;
    if insert.is_err() {
        return Delivery::Pending;
    }
    let row = sqlx::query(
        "SELECT generation,event_version,payload_sha256,payload \
         FROM root_finalization_projection WHERE task_id=$1 FOR UPDATE",
    )
    .bind(task)
    .fetch_optional(&mut *tx)
    .await;
    let row = match row {
        Ok(Some(row)) => row,
        Ok(None) => return Delivery::IntegrityConflict,
        Err(_) => return Delivery::Pending,
    };
    let matches = row.try_get::<String, _>("generation").ok().as_ref() == Some(generation)
        && row.try_get::<i64, _>("event_version").ok() == Some(1)
        && row.try_get::<String, _>("payload_sha256").ok().as_ref() == Some(&digest)
        && row.try_get::<serde_json::Value, _>("payload").ok().as_ref() == Some(&payload);
    if !matches {
        return Delivery::IntegrityConflict;
    }
    if tx.commit().await.is_err() {
        return Delivery::Pending;
    }
    Delivery::Current
}
