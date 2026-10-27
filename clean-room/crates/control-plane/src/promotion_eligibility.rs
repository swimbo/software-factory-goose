//! Pure adapter from authoritative task/evidence snapshots to action-bound promotion.
//!
//! Inputs must come from trusted state/evaluator reads, never request JSON. This module
//! does not authenticate those sources, supply transaction isolation, or execute Git.
//! The snapshot generation must advance whenever eligibility or stored evidence changes.
//! A durable integration must read/revalidate/consume under exclusive state access and
//! journal the execution decision before any mutation, then reconcile ambiguous outcomes.
//! Local passing summaries do not prove the deployed separate-UID/holdout boundary.

use crate::{
    approval::{self, ApprovalAction, ApprovalError, ApprovalRecord, Operation, TrustedOperator},
    state::Stage,
};
use evaluator::{
    VerificationEvidence,
    holdout::{PrefilterReport, PrefilterStatus},
};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Server-resolved state; deliberately not deserializable as a caller authority assertion.
#[derive(Debug, Clone)]
pub struct PromotionSnapshot {
    pub task_id: String,
    /// Registered operator-owned repository identity, resolved to a protected path elsewhere.
    pub repository: String,
    pub target_ref: String,
    pub candidate_sha: String,
    pub base_sha: String,
    pub manifest_digest: String,
    /// Monotonic authoritative state/evidence generation, starting at one.
    pub generation: u64,
    pub stage: Stage,
    pub stopped: bool,
    pub active_claim: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum EligibilityError {
    #[error("task is not eligible for promotion")]
    IneligibleState,
    #[error("wall evidence is not a passing result for the current candidate")]
    InvalidWallEvidence,
    #[error(
        "holdout evidence is incomplete, rejected or does not match the current manifest and candidate"
    )]
    InvalidHoldoutEvidence,
    #[error("current state or evidence differs from the approved action")]
    StateChanged,
    #[error("cannot encode promotion evidence")]
    EvidenceEncoding,
    #[error(transparent)]
    Approval(#[from] ApprovalError),
}

/// Normalized summary digest, not a signature or a hash of raw execution transcripts.
/// Generation binds the authoritative evidence record version; the caller must maintain it.
#[derive(Serialize)]
struct EvidenceSummary<'a> {
    schema: &'static str,
    task_id: &'a str,
    repository: &'a str,
    target_ref: &'a str,
    candidate_sha: &'a str,
    base_sha: &'a str,
    manifest_digest: &'a str,
    generation: u64,
    typecheck: bool,
    tests_pass: bool,
    secret_scan_clean: bool,
    isolation: &'a str,
    prefilter: PrefilterStatus,
}

/// Construct the presented action from current trusted state, not caller-supplied revisions
/// or evidence digests. The reason is operator presentation metadata, not eligibility proof.
pub fn prepare_promotion(
    snapshot: &PromotionSnapshot,
    verification: &VerificationEvidence,
    holdout: &PrefilterReport,
    reason: &str,
    audience: &str,
) -> Result<ApprovalAction, EligibilityError> {
    if snapshot.stage != Stage::AwaitingPromotion
        || snapshot.stopped
        || snapshot.active_claim
        || snapshot.generation == 0
        || snapshot.base_sha == snapshot.candidate_sha
    {
        return Err(EligibilityError::IneligibleState);
    }
    if verification.sha != snapshot.candidate_sha
        || !verification.verdict.all_pass()
        || verification.isolation != "seatbelt_offline_ephemeral_snapshot"
    {
        return Err(EligibilityError::InvalidWallEvidence);
    }
    if holdout.candidate_sha() != snapshot.candidate_sha
        || holdout.manifest_digest() != snapshot.manifest_digest
        || holdout.feedback().status != PrefilterStatus::Passed
    {
        return Err(EligibilityError::InvalidHoldoutEvidence);
    }
    let summary = EvidenceSummary {
        schema: "sfactory-promotion-summary-v1",
        task_id: &snapshot.task_id,
        repository: &snapshot.repository,
        target_ref: &snapshot.target_ref,
        candidate_sha: &snapshot.candidate_sha,
        base_sha: &snapshot.base_sha,
        manifest_digest: &snapshot.manifest_digest,
        generation: snapshot.generation,
        typecheck: verification.verdict.typecheck,
        tests_pass: verification.verdict.tests_pass,
        secret_scan_clean: verification.verdict.secret_scan_clean,
        isolation: verification.isolation,
        prefilter: holdout.feedback().status,
    };
    let encoded = serde_json::to_vec(&summary).map_err(|_| EligibilityError::EvidenceEncoding)?;
    let action = ApprovalAction {
        operation: Operation::Promote,
        task_id: snapshot.task_id.clone(),
        repository: snapshot.repository.clone(),
        target_ref: snapshot.target_ref.clone(),
        candidate_sha: snapshot.candidate_sha.clone(),
        base_sha: snapshot.base_sha.clone(),
        evidence_digest: format!("{:x}", Sha256::digest(encoded)),
        reason: reason.to_owned(),
        audience: audience.to_owned(),
    };
    action.validate()?;
    Ok(action)
}

/// Exact bindings after in-memory revalidation and consumption. Not a durable authorization
/// token: do not serialize or treat possession as permission to bypass the journal.
pub struct RevalidatedPromotion {
    repository: String,
    target_ref: String,
    candidate_sha: String,
    base_sha: String,
}
impl RevalidatedPromotion {
    pub fn repository(&self) -> &str {
        &self.repository
    }
    pub fn target_ref(&self) -> &str {
        &self.target_ref
    }
    pub fn candidate_sha(&self) -> &str {
        &self.candidate_sha
    }
    pub fn base_sha(&self) -> &str {
        &self.base_sha
    }
}

/// Pure, in-memory transition only. All eligibility and presentation checks precede mutation
/// of `stored`. Callers must use exclusive authoritative state and persist the result; cloning
/// the ledger is not replay protection. No endpoint currently invokes this adapter.
#[allow(clippy::too_many_arguments)]
pub fn consume_eligible_promotion(
    stored: &mut ApprovalRecord,
    presented: &ApprovalRecord,
    snapshot: &PromotionSnapshot,
    verification: &VerificationEvidence,
    holdout: &PrefilterReport,
    operator: &TrustedOperator,
    audience: &str,
    now_ms: u64,
) -> Result<RevalidatedPromotion, EligibilityError> {
    let expected = prepare_promotion(
        snapshot,
        verification,
        holdout,
        &stored.action.reason,
        audience,
    )?;
    if stored.action != expected {
        return Err(EligibilityError::StateChanged);
    }
    approval::consume(stored, presented, operator, audience, now_ms)?;
    Ok(RevalidatedPromotion {
        repository: expected.repository,
        target_ref: expected.target_ref,
        candidate_sha: expected.candidate_sha,
        base_sha: expected.base_sha,
    })
}
