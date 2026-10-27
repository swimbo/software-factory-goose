//! Immutable intake contracts. Admission records intent; it never authorizes execution.

use serde::{Deserialize, Serialize};

pub const INTAKE_SCHEMA_VERSION: u32 = 1;
pub const MAX_INTENT_BYTES: usize = 16 * 1024;
pub const MAX_CRITERION_BYTES: usize = 2048;
pub const MAX_CRITERIA: usize = 32;
pub const MAX_REQUEST_TEXT_BYTES: usize = 32 * 1024;

/// Client intent only. Identity, qualification, budgets and approvals are not accepted.
/// Repository is a logical identifier to resolve through a future trusted repository registry;
/// accepting it here neither reads a caller-selected path nor verifies repository contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntakeRequest {
    pub schema_version: u32,
    pub repository: String,
    pub target_ref: String,
    pub base_revision: String,
    pub intent: String,
    pub acceptance_criteria: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntakeStatus {
    AwaitingQualification,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredIntake {
    pub schema_version: u32,
    pub idempotency_key: String,
    pub intent_id: String,
    pub submitted_by: String,
    pub created_at_ms: u64,
    pub request: IntakeRequest,
    pub status: IntakeStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IntakeError {
    #[error("idempotency key must be a canonical uppercase ULID")]
    InvalidKey,
    #[error("invalid configured submitter scope")]
    InvalidPrincipal,
    #[error("invalid intake request: {0}")]
    InvalidRequest(&'static str),
    #[error("idempotency key already binds a different request")]
    ConflictingReuse,
    #[error("intake belongs to a different submitter")]
    PrincipalMismatch,
    #[error("stored intake binding is invalid")]
    StoredBindingMismatch,
}

pub(crate) fn valid_principal(principal: &str) -> bool {
    !principal.is_empty()
        && principal.len() <= 256
        && principal.trim() == principal
        && !principal.chars().any(char::is_control)
}

fn valid_path_components(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}
fn valid_text(value: &str, limit: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= limit
        && !value
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
}
fn validate_request(request: &IntakeRequest) -> Result<(), IntakeError> {
    let invalid = IntakeError::InvalidRequest;
    if request.schema_version != INTAKE_SCHEMA_VERSION {
        return Err(invalid("unsupported schema version"));
    }
    if !valid_path_components(&request.repository) {
        return Err(invalid("repository must be a bounded logical identifier"));
    }
    let branch = request
        .target_ref
        .strip_prefix("refs/heads/")
        .unwrap_or_default();
    if !valid_path_components(&request.target_ref)
        || branch.is_empty()
        || request.target_ref.contains("..")
        || request
            .target_ref
            .split('/')
            .any(|part| part.starts_with('.') || part.ends_with('.') || part.ends_with(".lock"))
    {
        return Err(invalid("target ref must be a canonical branch reference"));
    }
    if !matches!(request.base_revision.len(), 40 | 64)
        || !request
            .base_revision
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid(
            "base revision must be a full lowercase hex object ID",
        ));
    }
    if !valid_text(&request.intent, MAX_INTENT_BYTES)
        || request.acceptance_criteria.is_empty()
        || request.acceptance_criteria.len() > MAX_CRITERIA
        || request
            .acceptance_criteria
            .iter()
            .any(|c| !valid_text(c, MAX_CRITERION_BYTES))
    {
        return Err(invalid(
            "intent or acceptance criteria are missing, oversized or contain control characters",
        ));
    }
    // Individual lengths and item count are already bounded, so this sum cannot overflow.
    let bytes = request.repository.len()
        + request.target_ref.len()
        + request.base_revision.len()
        + request.intent.len()
        + request
            .acceptance_criteria
            .iter()
            .map(String::len)
            .sum::<usize>();
    if bytes > MAX_REQUEST_TEXT_BYTES {
        return Err(invalid("combined request text exceeds limit"));
    }
    Ok(())
}

/// Deterministic first-write-wins admission. Compare full typed values (including whitespace
/// and criterion order); no normalization or truncation can silently merge distinct intent.
/// The owner must serialize competing submissions through one Restate object key. This pure
/// function alone is not a concurrency primitive. Records/keys have no automatic expiry.
pub fn submit_once(
    existing: Option<&StoredIntake>,
    key: &str,
    submitter: &str,
    request: IntakeRequest,
    now_ms: u64,
) -> Result<StoredIntake, IntakeError> {
    if ulid::Ulid::from_string(key).is_err()
        || ulid::Ulid::from_string(key).is_ok_and(|id| id.to_string() != key)
    {
        return Err(IntakeError::InvalidKey);
    }
    if !valid_principal(submitter) {
        return Err(IntakeError::InvalidPrincipal);
    }
    if let Some(stored) = existing {
        if stored.schema_version != INTAKE_SCHEMA_VERSION
            || stored.idempotency_key != key
            || stored.intent_id != key
            || !valid_principal(&stored.submitted_by)
            || validate_request(&stored.request).is_err()
        {
            return Err(IntakeError::StoredBindingMismatch);
        }
        if stored.submitted_by != submitter {
            return Err(IntakeError::PrincipalMismatch);
        }
        if stored.request != request {
            return Err(IntakeError::ConflictingReuse);
        }
        return Ok(stored.clone());
    }
    validate_request(&request)?;
    Ok(StoredIntake {
        schema_version: INTAKE_SCHEMA_VERSION,
        idempotency_key: key.into(),
        intent_id: key.into(),
        submitted_by: submitter.into(),
        created_at_ms: now_ms,
        request,
        status: IntakeStatus::AwaitingQualification,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: &str = "01J00000000000000000000000";
    fn request() -> IntakeRequest {
        IntakeRequest {
            schema_version: 1,
            repository: "org/repo".into(),
            target_ref: "refs/heads/main".into(),
            base_revision: "a".repeat(40),
            intent: "Add a deterministic parser".into(),
            acceptance_criteria: vec!["Reject malformed input".into()],
        }
    }
    #[test]
    fn identical_retry_returns_original_record_after_serialization_and_clock_change() {
        let original = submit_once(None, KEY, "operator-42", request(), 100).unwrap();
        let restored: StoredIntake =
            serde_json::from_str(&serde_json::to_string(&original).unwrap()).unwrap();
        for now in [0, 101, u64::MAX] {
            assert_eq!(
                submit_once(Some(&restored), KEY, "operator-42", request(), now).unwrap(),
                original
            );
        }
        assert_eq!(original.intent_id, KEY);
        assert_eq!(original.status, IntakeStatus::AwaitingQualification);
    }
    #[test]
    fn every_immutable_request_binding_rejects_key_reuse() {
        let stored = submit_once(None, KEY, "operator-42", request(), 100).unwrap();
        for field in 0..6 {
            let mut changed = request();
            match field {
                0 => changed.schema_version = 2,
                1 => changed.repository = "org/other".into(),
                2 => changed.target_ref = "refs/heads/other".into(),
                3 => changed.base_revision = "b".repeat(40),
                4 => changed.intent.push(' '),
                _ => changed.acceptance_criteria.push("Another assertion".into()),
            }
            assert_eq!(
                submit_once(Some(&stored), KEY, "operator-42", changed, 101),
                Err(IntakeError::ConflictingReuse)
            );
        }
    }
    #[test]
    fn distinct_keys_remain_distinct_and_principal_cannot_take_over_existing_intake() {
        let stored = submit_once(None, KEY, "operator-42", request(), 100).unwrap();
        let other_key = "01J00000000000000000000001";
        assert_ne!(
            submit_once(None, other_key, "operator-42", request(), 100)
                .unwrap()
                .intent_id,
            stored.intent_id
        );
        assert_eq!(
            submit_once(Some(&stored), KEY, "operator-43", request(), 101),
            Err(IntakeError::PrincipalMismatch)
        );
        assert_eq!(
            submit_once(Some(&stored), other_key, "operator-42", request(), 101),
            Err(IntakeError::StoredBindingMismatch)
        );
    }
    #[test]
    fn no_identity_risk_approval_or_budget_authority_can_enter_through_payload() {
        for name in [
            "submitted_by",
            "operator_uid",
            "status",
            "lane",
            "fatal",
            "has_codified_knowledge",
            "budget_usd",
            "approved",
        ] {
            let mut json = serde_json::to_value(request()).unwrap();
            json[name] = serde_json::json!(true);
            assert!(
                serde_json::from_value::<IntakeRequest>(json).is_err(),
                "accepted {name}"
            );
        }
    }
    #[test]
    fn invalid_key_schema_revision_ref_and_text_are_rejected() {
        for key in [
            "",
            "key",
            "01j00000000000000000000000",
            "81J00000000000000000000000",
        ] {
            assert!(submit_once(None, key, "operator-42", request(), 0).is_err());
        }
        for field in 0..7 {
            let mut invalid = request();
            match field {
                0 => invalid.schema_version = 2,
                1 => invalid.repository = " ../repo ".into(),
                2 => invalid.base_revision = "short".into(),
                3 => invalid.target_ref = "refs/heads/main.lock".into(),
                4 => invalid.intent = " \n ".into(),
                5 => invalid.acceptance_criteria.clear(),
                _ => invalid.acceptance_criteria[0] = "bad\0text".into(),
            }
            assert!(submit_once(None, KEY, "operator-42", invalid, 0).is_err());
        }
        assert!(submit_once(None, KEY, "", request(), 0).is_err());
    }
    #[test]
    fn stored_corruption_and_reordered_criteria_do_not_become_fresh_admission() {
        let mut submitted = request();
        submitted
            .acceptance_criteria
            .push("Preserve input order".into());
        let stored = submit_once(None, KEY, "operator-42", submitted.clone(), 100).unwrap();
        let mut reordered = submitted.clone();
        reordered.acceptance_criteria.reverse();
        assert_eq!(
            submit_once(Some(&stored), KEY, "operator-42", reordered, 101),
            Err(IntakeError::ConflictingReuse)
        );
        for field in 0..4 {
            let mut corrupt = stored.clone();
            match field {
                0 => corrupt.schema_version = 99,
                1 => corrupt.intent_id = "wrong".into(),
                2 => corrupt.idempotency_key = "wrong".into(),
                _ => corrupt.request.base_revision = "short".into(),
            }
            assert_eq!(
                submit_once(Some(&corrupt), KEY, "operator-42", submitted.clone(), 101),
                Err(IntakeError::StoredBindingMismatch)
            );
        }
    }
    #[test]
    fn accepted_ref_subset_is_deliberately_canonical() {
        for reference in [
            "refs/heads/main",
            "refs/heads/feature/parser_v2",
            "refs/heads/release-1.2",
        ] {
            let mut valid = request();
            valid.target_ref = reference.into();
            assert!(submit_once(None, KEY, "operator-42", valid, 0).is_ok());
        }
        for reference in [
            "main",
            "refs/tags/v1",
            "refs/heads/",
            "refs/heads/.hidden",
            "refs/heads/a..b",
            "refs/heads/a//b",
            "refs/heads/branch.",
            "refs/heads/a.lock/b",
            "refs/heads/a@{b",
            "refs/heads/a b",
        ] {
            let mut invalid = request();
            invalid.target_ref = reference.into();
            assert!(
                submit_once(None, KEY, "operator-42", invalid, 0).is_err(),
                "accepted {reference}"
            );
        }
    }
    #[test]
    fn explicit_size_limits_bound_durable_record() {
        let mut invalid = request();
        invalid.intent = "x".repeat(MAX_INTENT_BYTES + 1);
        assert!(submit_once(None, KEY, "operator-42", invalid, 0).is_err());
        let mut invalid = request();
        invalid.acceptance_criteria = vec!["x".into(); MAX_CRITERIA + 1];
        assert!(submit_once(None, KEY, "operator-42", invalid, 0).is_err());
        let mut invalid = request();
        invalid.acceptance_criteria = vec!["x".repeat(MAX_CRITERION_BYTES); MAX_CRITERIA];
        assert!(submit_once(None, KEY, "operator-42", invalid, 0).is_err());
    }
}
