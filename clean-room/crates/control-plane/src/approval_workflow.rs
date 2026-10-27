//! Feature-gated Restate approval ledger, deliberately NOT registered by the application.
//!
//! SECURITY BOUNDARY: constructor configuration is NOT per-request authentication. Bind this
//! object only behind ingress accessible exclusively to the independently verified local
//! operator adapter. That adapter must authenticate kernel peer identity on EACH request,
//! and resolve/check authoritative task, revision and evidence eligibility before issuance
//! and execution. Ordinary Restate ingress access must not confer this authority.
//!
//! Each object is keyed by a server-generated canonical ULID nonce. Exclusive handlers keep
//! immutable issuance and consumption in one object state. The consumed record is a durable
//! authorization decision, not proof an external Git/credential/budget mutation executed.
//! Real Restate crash/replay behavior and private ingress isolation remain unverified.

use crate::approval::{self, ApprovalAction, ApprovalError, ApprovalRecord, TrustedOperator};
use restate_sdk::{prelude::*, serde::Json};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueRequest {
    pub action: ApprovalAction,
    pub ttl_ms: u64,
}

/// UID is deliberately absent: submitted binding data is never an authenticated identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumeRequest {
    pub action: ApprovalAction,
    pub nonce: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

pub struct ApprovalJournal {
    operator: TrustedOperator,
    audience: String,
}
impl ApprovalJournal {
    /// Configuration only, NOT proof of authority for any future invocation. Do not bind
    /// this service before private ingress and the authenticating adapter are verified.
    pub fn new_for_private_ingress(
        operator: TrustedOperator,
        audience: String,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !audience.is_empty()
                && audience.len() <= 256
                && audience.trim() == audience
                && !audience.chars().any(char::is_control),
            "invalid approval audience"
        );
        Ok(Self { operator, audience })
    }
}

#[restate_sdk::object]
impl ApprovalJournal {
    #[handler]
    async fn issue(
        &self,
        ctx: ObjectContext<'_>,
        request: Json<IssueRequest>,
    ) -> HandlerResult<Json<ApprovalRecord>> {
        let existing = ctx
            .get::<Json<ApprovalRecord>>("record")
            .await?
            .map(|r| r.0);
        // A journaled clock result is stable on replay; never use naked wall time in a handler.
        let now_ms = ctx.run(clock_millis).await?;
        let record = issue_or_reuse(
            existing,
            request.0,
            ctx.key(),
            &self.operator,
            &self.audience,
            now_ms,
        )?;
        ctx.set("record", Json(record.clone()));
        Ok(Json(record))
    }

    #[handler]
    async fn consume(
        &self,
        ctx: ObjectContext<'_>,
        request: Json<ConsumeRequest>,
    ) -> HandlerResult<Json<ApprovalRecord>> {
        let mut record = ctx
            .get::<Json<ApprovalRecord>>("record")
            .await?
            .ok_or_else(|| TerminalError::new_with_code(404, "approval does not exist"))?
            .0;
        let now_ms = ctx.run(clock_millis).await?;
        consume_stored(
            &mut record,
            request.0,
            ctx.key(),
            &self.operator,
            &self.audience,
            now_ms,
        )?;
        // This same record includes both the immutable action and consumption decision.
        ctx.set("record", Json(record.clone()));
        Ok(Json(record))
    }

    /// Recovery/inspection only; callers must not treat a stored consumed decision as a
    /// fresh authorization for a different action or a different external execution.
    #[handler]
    async fn status(
        &self,
        ctx: SharedObjectContext<'_>,
    ) -> HandlerResult<Json<Option<ApprovalRecord>>> {
        Ok(Json(
            ctx.get::<Json<ApprovalRecord>>("record")
                .await?
                .map(|r| r.0),
        ))
    }
}

async fn clock_millis() -> HandlerResult<u64> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| TerminalError::new("system clock is before Unix epoch"))?;
    u64::try_from(duration.as_millis())
        .map_err(|_| TerminalError::new("system clock overflow").into())
}

fn terminal(error: ApprovalError) -> TerminalError {
    let code = match error {
        ApprovalError::AlreadyConsumed | ApprovalError::BindingMismatch => 409,
        ApprovalError::UnauthorizedOperator | ApprovalError::WrongAudience => 403,
        ApprovalError::OutsideValidityWindow => 410,
        _ => 400,
    };
    TerminalError::new_with_code(code, error.to_string())
}

fn issue_or_reuse(
    existing: Option<ApprovalRecord>,
    request: IssueRequest,
    key: &str,
    operator: &TrustedOperator,
    audience: &str,
    now_ms: u64,
) -> Result<ApprovalRecord, TerminalError> {
    if request.action.audience != audience {
        return Err(terminal(ApprovalError::WrongAudience));
    }
    if let Some(record) = existing {
        if record.nonce != key
            || record.action != request.action
            || record.operator_uid != operator.uid()
            || record.expires_at_ms.checked_sub(record.issued_at_ms) != Some(request.ttl_ms)
        {
            return Err(TerminalError::new_with_code(
                409,
                "nonce already binds a different approval",
            ));
        }
        // Never extend expiry or clear consumption, even for an exact repeated issue request.
        return Ok(record);
    }
    approval::issue_with_nonce(
        request.action,
        key.to_string(),
        operator,
        now_ms,
        request.ttl_ms,
    )
    .map_err(terminal)
}

fn consume_stored(
    record: &mut ApprovalRecord,
    request: ConsumeRequest,
    key: &str,
    operator: &TrustedOperator,
    audience: &str,
    now_ms: u64,
) -> Result<(), TerminalError> {
    if record.nonce != key || request.nonce != key {
        return Err(terminal(ApprovalError::BindingMismatch));
    }
    let presented = ApprovalRecord {
        action: request.action,
        nonce: request.nonce,
        issued_at_ms: request.issued_at_ms,
        expires_at_ms: request.expires_at_ms,
        operator_uid: record.operator_uid,
        consumed_at_ms: None,
    };
    approval::consume(record, &presented, operator, audience, now_ms).map_err(terminal)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn operator() -> TrustedOperator {
        approval::authenticate_operator(501, 501, &[502, 503]).unwrap()
    }
    fn request() -> IssueRequest {
        IssueRequest {
            action: ApprovalAction {
                operation: approval::Operation::Promote,
                task_id: "task".into(),
                repository: "repo".into(),
                target_ref: "refs/heads/main".into(),
                candidate_sha: "a".repeat(40),
                base_sha: "b".repeat(40),
                evidence_digest: "c".repeat(64),
                reason: "verified fixture".into(),
                audience: "local".into(),
            },
            ttl_ms: 1000,
        }
    }
    fn presentation(record: &ApprovalRecord) -> ConsumeRequest {
        ConsumeRequest {
            action: record.action.clone(),
            nonce: record.nonce.clone(),
            issued_at_ms: record.issued_at_ms,
            expires_at_ms: record.expires_at_ms,
        }
    }
    #[test]
    fn reissuance_cannot_reset_consumption_or_extend_expiry() {
        let nonce = shared::new_id();
        let record = issue_or_reuse(None, request(), &nonce, &operator(), "local", 1000).unwrap();
        assert_eq!(
            issue_or_reuse(
                Some(record.clone()),
                request(),
                &nonce,
                &operator(),
                "local",
                9999
            )
            .unwrap(),
            record
        );
        let mut consumed = record.clone();
        consume_stored(
            &mut consumed,
            presentation(&record),
            &nonce,
            &operator(),
            "local",
            1500,
        )
        .unwrap();
        let restored = issue_or_reuse(
            Some(consumed.clone()),
            request(),
            &nonce,
            &operator(),
            "local",
            9999,
        )
        .unwrap();
        assert_eq!(restored, consumed);
        let mut restored = restored;
        assert_eq!(
            consume_stored(
                &mut restored,
                presentation(&record),
                &nonce,
                &operator(),
                "local",
                1501
            )
            .unwrap_err()
            .code(),
            409
        );
    }
    #[test]
    fn same_nonce_cannot_change_action_lifetime_or_audience() {
        let nonce = shared::new_id();
        let record = issue_or_reuse(None, request(), &nonce, &operator(), "local", 1000).unwrap();
        let mut changed = request();
        changed.action.candidate_sha = "d".repeat(40);
        assert_eq!(
            issue_or_reuse(
                Some(record.clone()),
                changed,
                &nonce,
                &operator(),
                "local",
                1001
            )
            .unwrap_err()
            .code(),
            409
        );
        let mut changed = request();
        changed.ttl_ms += 1;
        assert_eq!(
            issue_or_reuse(
                Some(record.clone()),
                changed,
                &nonce,
                &operator(),
                "local",
                1001
            )
            .unwrap_err()
            .code(),
            409
        );
        assert_eq!(
            issue_or_reuse(None, request(), &nonce, &operator(), "other", 1000)
                .unwrap_err()
                .code(),
            403
        );
    }
    #[test]
    fn expiry_and_changed_presentation_fail_without_consuming() {
        let nonce = shared::new_id();
        let original = issue_or_reuse(None, request(), &nonce, &operator(), "local", 1000).unwrap();
        let mut record = original.clone();
        assert_eq!(
            consume_stored(
                &mut record,
                presentation(&original),
                &nonce,
                &operator(),
                "local",
                2000
            )
            .unwrap_err()
            .code(),
            410
        );
        let mut changed = presentation(&original);
        changed.action.reason = "changed".into();
        assert_eq!(
            consume_stored(&mut record, changed, &nonce, &operator(), "local", 1500)
                .unwrap_err()
                .code(),
            409
        );
        assert_eq!(record, original);
    }
    #[test]
    fn payloads_cannot_deserialize_identity_authority() {
        let mut issue_json = serde_json::to_value(request()).unwrap();
        issue_json["operator_uid"] = serde_json::json!(501);
        assert!(serde_json::from_value::<IssueRequest>(issue_json).is_err());
        let nonce = shared::new_id();
        let record = issue_or_reuse(None, request(), &nonce, &operator(), "local", 1000).unwrap();
        let mut consume_json = serde_json::to_value(presentation(&record)).unwrap();
        consume_json["peer_uid"] = serde_json::json!(501);
        assert!(serde_json::from_value::<ConsumeRequest>(consume_json).is_err());
    }
}
