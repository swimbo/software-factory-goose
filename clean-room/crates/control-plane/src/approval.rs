//! Action-bound local operator approvals. A verified, distinct OS principal is the authority;
//! this does not claim human presence or MFA. Only server-held records are authoritative.
//! Persistence adapters must serialize consumption and the durable mutation decision.

use serde::{Deserialize, Serialize};

/// Short-lived approval window. Selecting this bound does not establish human presence.
pub const MAX_APPROVAL_TTL_MS: u64 = 300_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Promote,
    RaiseBudget {
        new_cap_microusd: u64,
    },
    IssueCredential {
        kind: shared::CredentialKind,
        scope: String,
        ttl_secs: u64,
    },
}

/// Server-resolved immutable action. The issuer must obtain revisions/evidence from trusted
/// task state, not blindly issue an approval for caller claims. Canonical input is required;
/// whitespace/case normalization is never applied silently after presentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalAction {
    pub operation: Operation,
    pub task_id: String,
    pub repository: String,
    pub target_ref: String,
    pub candidate_sha: String,
    pub base_sha: String,
    pub evidence_digest: String,
    pub reason: String,
    pub audience: String,
}

/// A serializable challenge/ledger record, not a signed bearer authorization. Deserializing
/// this from a client never confers authority; `consume` requires a separate stored record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRecord {
    pub action: ApprovalAction,
    pub nonce: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub operator_uid: u32,
    pub consumed_at_ms: Option<u64>,
}

/// Construct only from kernel connection credentials and server configuration. This type
/// intentionally has no Deserialize implementation. A configured UID alone is not a peer
/// proof: adapters must authenticate each request before calling the pure contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedOperator {
    uid: u32,
}
impl TrustedOperator {
    pub fn uid(&self) -> u32 {
        self.uid
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApprovalError {
    #[error("operator identity is not separate from configured runtime identities")]
    InvalidIdentityConfiguration,
    #[error("request is not from the configured operator identity")]
    UnauthorizedOperator,
    #[error("invalid canonical action field: {0}")]
    InvalidField(&'static str),
    #[error("invalid approval lifetime")]
    InvalidLifetime,
    #[error("approval is expired or not yet valid")]
    OutsideValidityWindow,
    #[error("approval audience does not match this deployment")]
    WrongAudience,
    #[error("presented action does not match the stored approval")]
    BindingMismatch,
    #[error("approval was already consumed")]
    AlreadyConsumed,
}

pub fn authenticate_operator(
    peer_uid: u32,
    configured_operator_uid: u32,
    runtime_uids: &[u32],
) -> Result<TrustedOperator, ApprovalError> {
    if configured_operator_uid == 0
        || runtime_uids.is_empty()
        || runtime_uids.contains(&0)
        || runtime_uids.contains(&configured_operator_uid)
        || runtime_uids
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != runtime_uids.len()
    {
        return Err(ApprovalError::InvalidIdentityConfiguration);
    }
    if peer_uid != configured_operator_uid {
        return Err(ApprovalError::UnauthorizedOperator);
    }
    Ok(TrustedOperator { uid: peer_uid })
}

impl ApprovalAction {
    pub fn validate(&self) -> Result<(), ApprovalError> {
        for (name, value, limit) in [
            ("task_id", self.task_id.as_str(), 256),
            ("repository", self.repository.as_str(), 2048),
            ("reason", self.reason.as_str(), 4096),
            ("audience", self.audience.as_str(), 256),
        ] {
            canonical_text(name, value, limit)?;
        }
        if !valid_ref(&self.target_ref) {
            return Err(ApprovalError::InvalidField("target_ref"));
        }
        if !valid_hex(&self.candidate_sha, &[40, 64]) {
            return Err(ApprovalError::InvalidField("candidate_sha"));
        }
        if !valid_hex(&self.base_sha, &[self.candidate_sha.len()]) {
            return Err(ApprovalError::InvalidField("base_sha"));
        }
        if !valid_hex(&self.evidence_digest, &[64]) {
            return Err(ApprovalError::InvalidField("evidence_digest"));
        }
        match &self.operation {
            Operation::RaiseBudget {
                new_cap_microusd: 0,
            } => return Err(ApprovalError::InvalidField("new_cap_microusd")),
            Operation::IssueCredential {
                scope, ttl_secs, ..
            } => {
                canonical_text("credential_scope", scope, 1024)?;
                if *ttl_secs == 0 {
                    return Err(ApprovalError::InvalidField("credential_ttl"));
                }
            }
            _ => {}
        }
        Ok(())
    }
}

fn canonical_text(name: &'static str, value: &str, limit: usize) -> Result<(), ApprovalError> {
    if value.is_empty()
        || value.len() > limit
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ApprovalError::InvalidField(name));
    }
    Ok(())
}

fn valid_hex(value: &str, lengths: &[usize]) -> bool {
    lengths.contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_ref(value: &str) -> bool {
    value.starts_with("refs/heads/")
        && value.len() <= 1024
        && !value.ends_with('.')
        && !value.contains("..")
        && !value.contains("@{")
        && !value.chars().any(|c| {
            c.is_control()
                || c.is_whitespace()
                || matches!(c, '~' | '^' | ':' | '?' | '*' | '[' | '\\')
        })
        && value
            .split('/')
            .all(|part| !part.is_empty() && !part.starts_with('.') && !part.ends_with(".lock"))
}

/// Non-durable helper. Journaled adapters use `issue_with_nonce` with a server-generated
/// nonce that is persisted/journaled before calling this pure function.
pub fn issue(
    action: ApprovalAction,
    operator: &TrustedOperator,
    now_ms: u64,
    ttl_ms: u64,
) -> Result<ApprovalRecord, ApprovalError> {
    issue_with_nonce(action, shared::new_id(), operator, now_ms, ttl_ms)
}

/// The nonce must not overwrite another ledger entry, including a consumed/expired one.
pub fn issue_with_nonce(
    action: ApprovalAction,
    nonce: String,
    operator: &TrustedOperator,
    now_ms: u64,
    ttl_ms: u64,
) -> Result<ApprovalRecord, ApprovalError> {
    action.validate()?;
    if ulid::Ulid::from_string(&nonce)
        .map(|n| n.to_string() != nonce)
        .unwrap_or(true)
    {
        return Err(ApprovalError::InvalidField("nonce"));
    }
    if ttl_ms == 0 || ttl_ms > MAX_APPROVAL_TTL_MS {
        return Err(ApprovalError::InvalidLifetime);
    }
    let expires_at_ms = now_ms
        .checked_add(ttl_ms)
        .ok_or(ApprovalError::InvalidLifetime)?;
    Ok(ApprovalRecord {
        action,
        nonce,
        issued_at_ms: now_ms,
        expires_at_ms,
        operator_uid: operator.uid(),
        consumed_at_ms: None,
    })
}

/// Validate and consume the authoritative server-held record once. This mutable operation
/// must run under the ledger's exclusive transaction/virtual-object handler, coupled to a
/// durable execution decision. Cloning the record is not a ledger and does not prevent replay.
/// The execution adapter must also revalidate current task/revision/evidence state before
/// mutation; this contract only verifies exact agreement with the stored approval.
pub fn consume(
    record: &mut ApprovalRecord,
    presented: &ApprovalRecord,
    operator: &TrustedOperator,
    expected_audience: &str,
    now_ms: u64,
) -> Result<(), ApprovalError> {
    if record.consumed_at_ms.is_some() {
        return Err(ApprovalError::AlreadyConsumed);
    }
    if record.operator_uid != operator.uid() {
        return Err(ApprovalError::UnauthorizedOperator);
    }
    record.action.validate()?;
    let ttl = record
        .expires_at_ms
        .checked_sub(record.issued_at_ms)
        .ok_or(ApprovalError::InvalidLifetime)?;
    if ttl == 0 || ttl > MAX_APPROVAL_TTL_MS {
        return Err(ApprovalError::InvalidLifetime);
    }
    if record.action.audience != expected_audience {
        return Err(ApprovalError::WrongAudience);
    }
    if now_ms < record.issued_at_ms || now_ms >= record.expires_at_ms {
        return Err(ApprovalError::OutsideValidityWindow);
    }
    if record != presented {
        return Err(ApprovalError::BindingMismatch);
    }
    record.consumed_at_ms = Some(now_ms);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operator() -> TrustedOperator {
        authenticate_operator(501, 501, &[502, 503]).unwrap()
    }
    fn action() -> ApprovalAction {
        ApprovalAction {
            operation: Operation::Promote,
            task_id: "task-1".into(),
            repository: "repo-1".into(),
            target_ref: "refs/heads/main".into(),
            candidate_sha: "a".repeat(40),
            base_sha: "b".repeat(40),
            evidence_digest: "c".repeat(64),
            reason: "Acceptance evidence reviewed".into(),
            audience: "factory-local".into(),
        }
    }
    fn record() -> ApprovalRecord {
        issue_with_nonce(action(), shared::new_id(), &operator(), 1000, 1000).unwrap()
    }

    #[test]
    fn exact_action_can_be_consumed_only_once() {
        let mut stored = record();
        let presented = stored.clone();
        assert_eq!(
            consume(&mut stored, &presented, &operator(), "factory-local", 1500),
            Ok(())
        );
        assert_eq!(stored.consumed_at_ms, Some(1500));
        assert_eq!(
            consume(&mut stored, &presented, &operator(), "factory-local", 1501),
            Err(ApprovalError::AlreadyConsumed)
        );
    }

    #[test]
    fn every_significant_field_is_bound() {
        let original = record();
        let mut altered = Vec::new();
        macro_rules! change {
            ($field:ident, $value:expr) => {{
                let mut r = original.clone();
                r.action.$field = $value;
                altered.push(r);
            }};
        }
        change!(
            operation,
            Operation::RaiseBudget {
                new_cap_microusd: 1_000_000
            }
        );
        change!(task_id, "different-task".into());
        change!(repository, "different-repo".into());
        change!(target_ref, "refs/heads/other".into());
        change!(candidate_sha, "d".repeat(40));
        change!(base_sha, "e".repeat(40));
        change!(evidence_digest, "f".repeat(64));
        change!(reason, "different reason".into());
        change!(audience, "different-audience".into());
        let mut r = original.clone();
        r.nonce = shared::new_id();
        altered.push(r);
        let mut r = original.clone();
        r.expires_at_ms += 1;
        altered.push(r);
        let mut r = original.clone();
        r.issued_at_ms += 1;
        altered.push(r);
        let mut r = original.clone();
        r.operator_uid = 999;
        altered.push(r);
        let mut r = original.clone();
        r.consumed_at_ms = Some(1);
        altered.push(r);
        for presented in altered {
            let mut stored = original.clone();
            assert!(consume(&mut stored, &presented, &operator(), "factory-local", 1500).is_err());
            assert_eq!(stored, original);
        }
    }

    #[test]
    fn wrong_peer_audience_and_time_fail_closed() {
        assert!(authenticate_operator(0, 0, &[502, 503]).is_err());
        assert!(authenticate_operator(501, 501, &[0, 503]).is_err());
        assert!(authenticate_operator(501, 501, &[502, 502]).is_err());
        assert!(authenticate_operator(502, 501, &[502, 503]).is_err());
        assert!(authenticate_operator(501, 501, &[501, 503]).is_err());
        assert!(authenticate_operator(501, 501, &[]).is_err());
        let other = authenticate_operator(504, 504, &[502, 503]).unwrap();
        let original = record();
        for now in [999, 2000, 2001] {
            let mut stored = original.clone();
            assert!(consume(&mut stored, &original, &operator(), "factory-local", now).is_err());
            assert_eq!(stored, original);
        }
        let mut stored = original.clone();
        assert!(consume(&mut stored, &original, &other, "factory-local", 1500).is_err());
        assert!(consume(&mut stored, &original, &operator(), "other", 1500).is_err());
    }

    #[test]
    fn invalid_ttl_hash_and_reference_are_rejected() {
        for ttl in [0, MAX_APPROVAL_TTL_MS + 1, u64::MAX] {
            assert!(issue(action(), &operator(), 1000, ttl).is_err());
        }
        assert!(issue(action(), &operator(), u64::MAX, 1).is_err());
        for invalid in ["abc", &"z".repeat(40), &"A".repeat(40)] {
            let mut a = action();
            a.candidate_sha = invalid.into();
            assert!(issue(a, &operator(), 1000, 1000).is_err());
        }
        let mut a = action();
        a.target_ref = "main".into();
        assert!(issue(a, &operator(), 1000, 1000).is_err());
    }

    #[test]
    fn serialized_record_keeps_consumption_and_replay_rejection() {
        let mut stored = record();
        let presented = stored.clone();
        consume(&mut stored, &presented, &operator(), "factory-local", 1500).unwrap();
        let mut restored: ApprovalRecord =
            serde_json::from_str(&serde_json::to_string(&stored).unwrap()).unwrap();
        assert_eq!(
            consume(
                &mut restored,
                &presented,
                &operator(),
                "factory-local",
                1501
            ),
            Err(ApprovalError::AlreadyConsumed)
        );
    }

    #[test]
    fn serialized_racing_consumers_have_one_winner() {
        let original = record();
        let shared = std::sync::Arc::new(std::sync::Mutex::new(original.clone()));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let state = shared.clone();
                let presented = original.clone();
                std::thread::spawn(move || {
                    consume(
                        &mut state.lock().unwrap(),
                        &presented,
                        &operator(),
                        "factory-local",
                        1500,
                    )
                    .is_ok()
                })
            })
            .collect();
        assert_eq!(
            threads
                .into_iter()
                .map(|t| usize::from(t.join().unwrap()))
                .sum::<usize>(),
            1
        );
    }

    #[test]
    fn credential_and_budget_parameters_are_bound() {
        let mut request = action();
        request.operation = Operation::IssueCredential {
            kind: shared::CredentialKind::Privileged,
            scope: "git:push:agent/task-1".into(),
            ttl_secs: 60,
        };
        let original = issue(request, &operator(), 1000, 1000).unwrap();
        for replacement in [
            Operation::IssueCredential {
                kind: shared::CredentialKind::BrokerIssued,
                scope: "git:push:agent/task-1".into(),
                ttl_secs: 60,
            },
            Operation::IssueCredential {
                kind: shared::CredentialKind::Privileged,
                scope: "git:push:main".into(),
                ttl_secs: 60,
            },
            Operation::IssueCredential {
                kind: shared::CredentialKind::Privileged,
                scope: "git:push:agent/task-1".into(),
                ttl_secs: 3600,
            },
        ] {
            let mut stored = original.clone();
            let mut presented = original.clone();
            presented.action.operation = replacement;
            assert_eq!(
                consume(&mut stored, &presented, &operator(), "factory-local", 1500),
                Err(ApprovalError::BindingMismatch)
            );
        }
        let mut request = action();
        request.operation = Operation::RaiseBudget {
            new_cap_microusd: 750_000,
        };
        let mut stored = issue(request, &operator(), 1000, 1000).unwrap();
        let mut presented = stored.clone();
        presented.action.operation = Operation::RaiseBudget {
            new_cap_microusd: 75_000_000,
        };
        assert_eq!(
            consume(&mut stored, &presented, &operator(), "factory-local", 1500),
            Err(ApprovalError::BindingMismatch)
        );
    }

    #[test]
    fn submitted_authority_or_comparison_flags_are_not_part_of_the_contract() {
        for (field, value) in [
            ("role", serde_json::json!("operator")),
            ("verified", serde_json::json!(true)),
            ("matches_candidate", serde_json::json!(true)),
        ] {
            let mut submitted = serde_json::to_value(record()).unwrap();
            submitted[field] = value;
            assert!(serde_json::from_value::<ApprovalRecord>(submitted).is_err());
        }
        let first = issue(action(), &operator(), 1000, 1000).unwrap();
        let second = issue(action(), &operator(), 1000, 1000).unwrap();
        assert_ne!(first.nonce, second.nonce);
    }
}
