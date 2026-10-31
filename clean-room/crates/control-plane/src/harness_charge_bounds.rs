//! Compose reviewed physical bounds into the existing spending reservation.
//! Arithmetic is not provider attestation or launch authority.

use crate::{
    gateway::ReviewedModelContract,
    harness_spending::{ChargeBound, RouteBound},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedComponent {
    pub id: String,
    pub max_physical_attempts: u32,
    pub contract: ReviewedModelContract,
}

/// Protected configuration, never accepted from worker/model JSON. Expected
/// components come independently from the frozen route's complete path inventory.
/// Price maxima include cache surcharges, reasoning, routing and fixed fees, as
/// required by ReviewedModelContract; unknown maxima cannot become zero.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteReview {
    pub route_sha256: String,
    pub review_sha256: String,
    pub usage_tariff_sha256: Option<String>,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
    pub max_request_bytes: u64,
    pub max_output_tokens: u64,
    pub components: Vec<ReviewedComponent>,
}

fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
impl RouteReview {
    pub fn route_bound(
        &self,
        expected_components: &[&str],
        now_ms: u64,
    ) -> anyhow::Result<RouteBound> {
        anyhow::ensure!(
            digest(&self.route_sha256)
                && digest(&self.review_sha256)
                && self.usage_tariff_sha256.as_ref().is_none_or(|s| digest(s)),
            "invalid charge review binding"
        );
        anyhow::ensure!(
            self.valid_from_ms <= now_ms
                && now_ms < self.valid_until_ms
                && self.valid_until_ms <= 253_402_300_799_999,
            "charge review unavailable or expired"
        );
        anyhow::ensure!(
            (1..=65536).contains(&self.max_request_bytes)
                && (1..=16384).contains(&self.max_output_tokens),
            "invalid logical request limits"
        );
        let expected: BTreeSet<&str> = expected_components.iter().copied().collect();
        let actual: BTreeSet<&str> = self.components.iter().map(|c| c.id.as_str()).collect();
        anyhow::ensure!(
            !expected.is_empty()
                && expected.len() <= 32
                && expected.len() == expected_components.len()
                && actual.len() == self.components.len()
                && expected == actual
                && expected.iter().all(|s| name(s)),
            "incomplete physical path coverage"
        );
        let mut components = Vec::new();
        let mut total = 0_u64;
        let mut physical_attempts = 0_u32;
        for component in &self.components {
            component.contract.validate()?;
            anyhow::ensure!(
                component.contract.reviewed_at_ms <= self.valid_from_ms
                    && self.valid_until_ms <= component.contract.valid_until_ms,
                "component review does not cover route interval"
            );
            anyhow::ensure!(
                (1..=32).contains(&component.max_physical_attempts),
                "unknown physical attempt bound"
            );
            physical_attempts += component.max_physical_attempts;
            anyhow::ensure!(
                physical_attempts <= 32,
                "physical manifest capacity exceeded"
            );
            let maximum = component
                .contract
                .upper_bound_microusd()?
                .checked_mul(u64::from(component.max_physical_attempts))
                .ok_or_else(|| anyhow::anyhow!("component charge overflow"))?;
            total = total
                .checked_add(maximum)
                .ok_or_else(|| anyhow::anyhow!("route charge overflow"))?;
            components.push(ChargeBound {
                id: component.id.clone(),
                max_charge_microusd: maximum,
            });
        }
        anyhow::ensure!(total <= 750_000, "logical call exceeds permanent task cap");
        let binding = format!("{:x}", Sha256::digest(serde_json::to_vec(self)?));
        Ok(RouteBound {
            route_sha256: self.route_sha256.clone(),
            review_sha256: binding,
            usage_tariff_sha256: self.usage_tariff_sha256.clone(),
            valid_from_ms: self.valid_from_ms,
            valid_until_ms: self.valid_until_ms,
            max_request_bytes: self.max_request_bytes,
            max_output_tokens: self.max_output_tokens,
            components,
        })
    }
}

/// Affordability check only. Existing sole-owner reserve/begin remains the
/// authoritative check against opening task/day inventory and concurrent calls.
/// Rescheduling days never resets a permanent task or refunds its reservations.
pub fn minimum_permanent_reservation(
    bound: &RouteBound,
    attempts: u32,
    minimum_calls_per_attempt: u32,
) -> anyhow::Result<u64> {
    anyhow::ensure!(
        attempts > 0 && minimum_calls_per_attempt > 0 && !bound.components.is_empty(),
        "missing benchmark call inventory"
    );
    let mut one = 0_u64;
    for component in &bound.components {
        anyhow::ensure!(
            component.max_charge_microusd > 0,
            "unknown component charge"
        );
        one = one
            .checked_add(component.max_charge_microusd)
            .ok_or_else(|| anyhow::anyhow!("route charge overflow"))?;
    }
    let total = one
        .checked_mul(u64::from(attempts))
        .and_then(|v| v.checked_mul(u64::from(minimum_calls_per_attempt)))
        .ok_or_else(|| anyhow::anyhow!("benchmark charge overflow"))?;
    anyhow::ensure!(
        total <= 750_000,
        "minimum reservations exceed permanent task cap"
    );
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::{OutputLimitField, ReviewedModelContract};

    fn component(id: &str, attempts: u32) -> ReviewedComponent {
        ReviewedComponent {
            id: id.into(),
            max_physical_attempts: attempts,
            contract: ReviewedModelContract {
                model: "fixture/model".into(),
                review_digest: "a".repeat(64),
                reviewed_at_ms: 10,
                valid_until_ms: 100,
                input_microusd_per_million: 300_000,
                output_microusd_per_million: 1_200_000,
                max_billable_input_tokens: 1000,
                max_billable_output_tokens: 100,
                fixed_call_microusd: 1,
                max_request_bytes: 4096,
                output_limit_field: OutputLimitField::MaxTokens,
            },
        }
    }
    fn review() -> RouteReview {
        RouteReview {
            route_sha256: "b".repeat(64),
            review_sha256: "c".repeat(64),
            usage_tariff_sha256: Some("d".repeat(64)),
            valid_from_ms: 20,
            valid_until_ms: 90,
            max_request_bytes: 4096,
            max_output_tokens: 100,
            components: vec![component("answer", 2), component("fallback", 1)],
        }
    }
    #[test]
    fn reserves_all_attempts_and_alternatives_without_refunds() {
        let bound = review().route_bound(&["answer", "fallback"], 30).unwrap();
        assert_eq!(bound.components[0].max_charge_microusd, 842);
        assert_eq!(bound.components[1].max_charge_microusd, 421);
        assert_eq!(minimum_permanent_reservation(&bound, 6, 2).unwrap(), 15_156);
    }
    #[test]
    fn full_context_cannot_fit_existing_permanent_task_cap() {
        let mut r = review();
        r.components = vec![component("answer", 1)];
        r.components[0].contract.max_billable_input_tokens = 1_000_000;
        let bound = r.route_bound(&["answer"], 30).unwrap();
        assert!(minimum_permanent_reservation(&bound, 6, 1).is_err());
        r.components[0].contract.input_microusd_per_million = 1_320_000;
        assert!(r.route_bound(&["answer"], 30).is_err());
    }
    #[test]
    fn rejects_incomplete_duplicate_expired_unknown_and_overflow() {
        assert!(review().route_bound(&["answer"], 30).is_err());
        assert!(review().route_bound(&["answer", "answer"], 30).is_err());
        assert!(review().route_bound(&["answer", "fallback"], 100).is_err());
        let mut r = review();
        r.components[0].max_physical_attempts = 0;
        assert!(r.route_bound(&["answer", "fallback"], 30).is_err());
        r = review();
        r.components[0].contract.max_billable_input_tokens = 0;
        assert!(r.route_bound(&["answer", "fallback"], 30).is_err());
        r = review();
        r.components[0].contract.reviewed_at_ms = 25;
        assert!(r.route_bound(&["answer", "fallback"], 30).is_err());
        r = review();
        r.components[0].contract.max_billable_input_tokens = u64::MAX - 1;
        r.components[0].contract.input_microusd_per_million = u64::MAX;
        assert!(r.route_bound(&["answer", "fallback"], 30).is_err());
        r = review();
        r.components[0].max_physical_attempts = 32;
        assert!(r.route_bound(&["answer", "fallback"], 30).is_err());
    }
    #[test]
    fn rounds_components_up_and_requires_positive_inventory() {
        let mut r = review();
        r.components[0].contract.max_billable_input_tokens = 1;
        r.components[0].contract.max_billable_output_tokens = 1;
        r.components[0].contract.output_microusd_per_million = 1;
        r.max_output_tokens = 1;
        let b = r.route_bound(&["answer", "fallback"], 30).unwrap();
        assert_eq!(b.components[0].max_charge_microusd, 6);
        assert!(minimum_permanent_reservation(&b, 0, 1).is_err());
        assert!(minimum_permanent_reservation(&b, 6, 0).is_err());
        assert!(minimum_permanent_reservation(&b, u32::MAX, u32::MAX).is_err());
    }

    #[test]
    fn overflow_cannot_wrap_to_an_affordable_zero_and_component_expiry_is_bound() {
        let mut bound = review().route_bound(&["answer", "fallback"], 30).unwrap();
        bound.components = vec![ChargeBound {
            id: "answer".into(),
            max_charge_microusd: 65_536,
        }];
        assert_eq!(
            minimum_permanent_reservation(&bound, 16_777_216, 16_777_216)
                .unwrap_err()
                .to_string(),
            "benchmark charge overflow"
        );
        let mut r = review();
        r.components[0].contract.valid_until_ms = 80;
        assert_eq!(
            r.route_bound(&["answer", "fallback"], 30)
                .unwrap_err()
                .to_string(),
            "component review does not cover route interval"
        );
    }
}
