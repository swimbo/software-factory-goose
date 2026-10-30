//! Durable launch reservation contract for the authoritative claim object.
use crate::workflow::{ClaimLeaseState, LeaseProof, LeaseSpec, LeaseStage};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchScope {
    pub task_id: String,
    pub intent_id: String,
    pub queue_id: String,
    pub generation: String,
    pub spec: LeaseSpec,
    pub worker_id: String,
    /// Digest of root-protected exact task/evidence catalog; never supplied by a worker.
    pub catalog_sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchReservation {
    pub scope: LaunchScope,
    pub generation: String,
    pub attempt: u32,
    pub token_sha256: String,
    pub expires_at_ms: u64,
    pub hard_deadline_ms: u64,
}
fn canonical(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
fn hex_digest(s: &str, lengths: &[usize]) -> bool {
    lengths.contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl LaunchScope {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            canonical(&self.task_id)
                && canonical(&self.intent_id)
                && canonical(&self.queue_id)
                && canonical(&self.generation)
                && canonical(&self.worker_id)
                && !self.spec.repository.is_empty()
                && self.spec.repository.len() <= 256
                && self.spec.repository.trim() == self.spec.repository
                && !self.spec.repository.chars().any(char::is_control)
                && hex_digest(&self.spec.base_revision, &[40, 64])
                && hex_digest(&self.catalog_sha256, &[64]),
            "invalid root launch scope"
        );
        Ok(())
    }
}
pub fn reserve(
    scope: &LaunchScope,
    state: &ClaimLeaseState,
    proof: &LeaseProof,
    now: u64,
) -> anyhow::Result<LaunchReservation> {
    scope.validate()?;
    anyhow::ensure!(
        state.work_package_id == scope.task_id
            && state.spec == scope.spec
            && state.stage == LeaseStage::Leased
            && state.attempts == proof.attempt
            && proof.attempt > 0,
        "claim scope mismatch"
    );
    let lease = state
        .active
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no active claim"))?;
    anyhow::ensure!(
        lease.worker_id == scope.worker_id
            && lease.attempt == proof.attempt
            && lease.token == proof.token
            && ulid::Ulid::from_string(&lease.token).is_ok_and(|u| u.to_string() == lease.token)
            && lease.issued_at_ms < lease.expires_at_ms
            && lease.expires_at_ms <= lease.hard_deadline_ms
            && now >= lease.issued_at_ms
            && now < lease.expires_at_ms
            && now < lease.hard_deadline_ms,
        "stale, foreign, or expired lease"
    );
    Ok(LaunchReservation {
        scope: scope.clone(),
        generation: scope.generation.clone(),
        attempt: lease.attempt,
        token_sha256: format!("{:x}", Sha256::digest(lease.token.as_bytes())),
        expires_at_ms: lease.expires_at_ms,
        hard_deadline_ms: lease.hard_deadline_ms,
    })
}
pub fn allow_mutation(reservation: Option<&LaunchReservation>) -> anyhow::Result<()> {
    anyhow::ensure!(
        reservation.is_none(),
        "launch reserved; closure and reconciliation required"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::{ActiveLease, ClaimLeaseState, LeaseProof, LeaseSpec, LeaseStage};
    fn fixture() -> (LaunchScope, ClaimLeaseState, LeaseProof) {
        let spec = LeaseSpec {
            repository: "repo".into(),
            base_revision: "a".repeat(40),
        };
        let lease = ActiveLease {
            worker_id: "worker".into(),
            attempt: 1,
            token: "01ARZ3NDEKTSV4RRFFQ69G5FAX".into(),
            issued_at_ms: 100,
            expires_at_ms: 200,
            hard_deadline_ms: 300,
        };
        let proof = LeaseProof {
            attempt: 1,
            token: "01ARZ3NDEKTSV4RRFFQ69G5FAX".into(),
        };
        (
            LaunchScope {
                task_id: "task".into(),
                intent_id: "intent".into(),
                queue_id: "queue".into(),
                generation: "generation".into(),
                spec: spec.clone(),
                worker_id: "worker".into(),
                catalog_sha256: "b".repeat(64),
            },
            ClaimLeaseState {
                version: 1,
                work_package_id: "task".into(),
                spec,
                stage: LeaseStage::Leased,
                attempts: 1,
                cooldown_until_ms: 0,
                active: Some(lease),
                last_completion: None,
            },
            proof,
        )
    }
    #[test]
    fn grant_binds_scope_and_active_lease() {
        let (scope, state, proof) = fixture();
        let grant = reserve(&scope, &state, &proof, 150).unwrap();
        assert_eq!(grant.generation, "generation");
        assert_eq!(grant.attempt, 1);
        assert_ne!(grant.token_sha256, proof.token);
        let mut foreign = scope.clone();
        foreign.task_id = "other".into();
        assert!(reserve(&foreign, &state, &proof, 150).is_err());
        foreign = scope.clone();
        foreign.spec.base_revision = "b".repeat(40);
        assert!(reserve(&foreign, &state, &proof, 150).is_err());
        let mut wrong = proof.clone();
        wrong.token = "01ARZ3NDEKTSV4RRFFQ69G5FAW".into();
        assert!(reserve(&scope, &state, &wrong, 150).is_err());
        assert!(reserve(&scope, &state, &proof, 99).is_err());
        assert!(reserve(&scope, &state, &proof, 200).is_err());
        let mut corrupted = state.clone();
        corrupted.active.as_mut().unwrap().hard_deadline_ms = 199;
        assert!(reserve(&scope, &corrupted, &proof, 150).is_err());
        corrupted = state.clone();
        corrupted.attempts = 0;
        corrupted.active.as_mut().unwrap().attempt = 0;
        let mut zero = proof.clone();
        zero.attempt = 0;
        assert!(reserve(&scope, &corrupted, &zero, 150).is_err());
        corrupted = state.clone();
        corrupted.active.as_mut().unwrap().token = "not-a-ulid".into();
        let mut bad = proof.clone();
        bad.token = "not-a-ulid".into();
        assert!(reserve(&scope, &corrupted, &bad, 150).is_err());
    }
    #[test]
    fn reservation_blocks_any_claim_mutation_even_after_deadline() {
        let (scope, state, proof) = fixture();
        let grant = reserve(&scope, &state, &proof, 150).unwrap();
        assert!(allow_mutation(Some(&grant)).is_err());
        assert!(allow_mutation(None).is_ok());
        assert!(allow_mutation(Some(&grant)).is_err());
    }
}
