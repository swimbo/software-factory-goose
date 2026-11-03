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

/// The final-wire authorizer must match this API to the actual endpoint.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewedEmbeddingApi {
    Embeddings,
}

/// Input/fee maxima and an explicit review of absent output billing.
/// Digests reference independent provider evidence; they are not attestations.
/// This is distinct from the chat contract accepted by GatewayClient.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedEmbeddingContract {
    pub api: ReviewedEmbeddingApi,
    pub model: String,
    pub review_digest: String,
    pub no_output_review_digest: String,
    pub reviewed_at_ms: u64,
    pub valid_until_ms: u64,
    pub input_microusd_per_million: u64,
    pub max_billable_input_tokens: u64,
    pub fixed_call_microusd: u64,
    pub max_request_bytes: usize,
}

impl ReviewedEmbeddingContract {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.model.is_empty()
                && self.model.len() <= 256
                && self.model.bytes().all(|b| b.is_ascii_graphic())
                && digest(&self.review_digest)
                && digest(&self.no_output_review_digest)
                && self.reviewed_at_ms < self.valid_until_ms
                && (1..=1024 * 1024).contains(&self.max_request_bytes),
            "invalid reviewed embedding contract"
        );
        anyhow::ensure!(
            (1..=(1_u64 << 53)).contains(&self.upper_bound_microusd()?),
            "embedding reservation outside exact integer conversion range"
        );
        Ok(())
    }

    pub fn upper_bound_microusd(&self) -> anyhow::Result<u64> {
        anyhow::ensure!(
            self.input_microusd_per_million > 0
                && (1..u64::MAX).contains(&self.max_billable_input_tokens),
            "missing or unbounded embedding input charge"
        );
        let product = u128::from(self.max_billable_input_tokens)
            .checked_mul(u128::from(self.input_microusd_per_million))
            .ok_or_else(|| anyhow::anyhow!("embedding price multiplication overflow"))?;
        let input = product
            .checked_add(999_999)
            .ok_or_else(|| anyhow::anyhow!("embedding price rounding overflow"))?
            / 1_000_000;
        let total = input
            .checked_add(u128::from(self.fixed_call_microusd))
            .ok_or_else(|| anyhow::anyhow!("embedding price total overflow"))?;
        Ok(u64::try_from(total)?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedEmbeddingComponent {
    pub id: String,
    pub max_physical_attempts: u32,
    pub contract: ReviewedEmbeddingContract,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub embedding_components: Vec<ReviewedEmbeddingComponent>,
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
        let actual: BTreeSet<&str> = self
            .components
            .iter()
            .map(|c| c.id.as_str())
            .chain(self.embedding_components.iter().map(|c| c.id.as_str()))
            .collect();
        anyhow::ensure!(
            !expected.is_empty()
                && expected.len() <= 32
                && expected.len() == expected_components.len()
                && actual.len() == self.components.len() + self.embedding_components.len()
                && expected == actual
                && expected.iter().all(|s| name(s)),
            "incomplete physical path coverage"
        );
        let mut components = Vec::new();
        let mut total = 0_u64;
        let mut physical_attempts = 0_u32;
        let mut include = |id: &str,
                           attempts: u32,
                           reviewed_at: u64,
                           valid_until: u64,
                           per_call: u64|
         -> anyhow::Result<()> {
            anyhow::ensure!(
                reviewed_at <= self.valid_from_ms && self.valid_until_ms <= valid_until,
                "component review does not cover route interval"
            );
            anyhow::ensure!(
                (1..=32).contains(&attempts),
                "unknown physical attempt bound"
            );
            physical_attempts += attempts;
            anyhow::ensure!(
                physical_attempts <= 32,
                "physical manifest capacity exceeded"
            );
            let maximum = per_call
                .checked_mul(u64::from(attempts))
                .ok_or_else(|| anyhow::anyhow!("component charge overflow"))?;
            total = total
                .checked_add(maximum)
                .ok_or_else(|| anyhow::anyhow!("route charge overflow"))?;
            components.push(ChargeBound {
                id: id.to_owned(),
                max_charge_microusd: maximum,
            });
            Ok(())
        };
        for component in &self.components {
            component.contract.validate()?;
            include(
                &component.id,
                component.max_physical_attempts,
                component.contract.reviewed_at_ms,
                component.contract.valid_until_ms,
                component.contract.upper_bound_microusd()?,
            )?;
        }
        for component in &self.embedding_components {
            component.contract.validate()?;
            include(
                &component.id,
                component.max_physical_attempts,
                component.contract.reviewed_at_ms,
                component.contract.valid_until_ms,
                component.contract.upper_bound_microusd()?,
            )?;
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
            embedding_components: vec![],
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
    #[test]
    fn legacy_chat_review_bytes_and_wallet_binding_remain_stable() {
        let raw = include_str!("../tests/fixtures/legacy-chat-charge-review.json").trim();
        let old: RouteReview = serde_json::from_str(raw).unwrap();
        assert_eq!(serde_json::to_string(&old).unwrap(), raw);
        assert_eq!(
            old.route_bound(&["answer", "fallback"], 30)
                .unwrap()
                .review_sha256,
            "b030c01140f22738d889ecc4fe19a6991ed6084a2aac7a684689aa0c6d324b78"
        );
    }

    fn embedding_review_json() -> serde_json::Value {
        let mut value = serde_json::to_value(review()).unwrap();
        value["embedding_components"] = serde_json::json!([{
            "id": "semantic_embedding", "max_physical_attempts": 2,
            "contract": {
                "api": "embeddings", "model": "fixture/embedding",
                "review_digest": "e".repeat(64),
                "no_output_review_digest": "f".repeat(64),
                "reviewed_at_ms": 10, "valid_until_ms": 100,
                "input_microusd_per_million": 300_001,
                "max_billable_input_tokens": 3, "fixed_call_microusd": 2,
                "max_request_bytes": 4096
            }
        }]);
        value
    }

    #[test]
    fn embedding_input_and_fixed_fees_join_the_same_permanent_task_cap() {
        let r: RouteReview = serde_json::from_value(embedding_review_json()).unwrap();
        let b = r
            .route_bound(&["answer", "fallback", "semantic_embedding"], 30)
            .unwrap();
        assert_eq!(
            b.components
                .iter()
                .map(|c| c.max_charge_microusd)
                .collect::<Vec<_>>(),
            vec![842, 421, 6]
        );
        assert_eq!(minimum_permanent_reservation(&b, 6, 1).unwrap(), 7_614);
    }
    #[test]
    fn embedding_schema_cannot_be_used_as_a_chat_contract() {
        let value = embedding_review_json();
        let contract = value["embedding_components"][0]["contract"].clone();
        assert!(serde_json::from_value::<ReviewedModelContract>(contract.clone()).is_err());
        assert!(
            serde_json::from_value::<ReviewedEmbeddingContract>(
                serde_json::to_value(component("answer", 1).contract).unwrap()
            )
            .is_err()
        );
        for (field, replacement) in [
            ("api", serde_json::json!("chat_completions")),
            ("output_microusd_per_million", serde_json::json!(0)),
        ] {
            let mut invalid = contract.clone();
            invalid[field] = replacement;
            assert!(serde_json::from_value::<ReviewedEmbeddingContract>(invalid).is_err());
        }
        let mut missing = contract;
        missing
            .as_object_mut()
            .unwrap()
            .remove("no_output_review_digest");
        assert!(serde_json::from_value::<ReviewedEmbeddingContract>(missing).is_err());
    }

    #[test]
    fn embedding_rejects_unknown_bounds_and_invalid_evidence() {
        for (field, value) in [
            ("input_microusd_per_million", serde_json::json!(0)),
            ("max_billable_input_tokens", serde_json::json!(0)),
            ("max_billable_input_tokens", serde_json::json!(u64::MAX)),
            ("fixed_call_microusd", serde_json::json!(u64::MAX)),
            ("max_request_bytes", serde_json::json!(0)),
            ("no_output_review_digest", serde_json::json!("unknown")),
            ("reviewed_at_ms", serde_json::json!(100)),
        ] {
            let mut value_json = embedding_review_json();
            value_json["embedding_components"][0]["contract"][field] = value;
            let r: RouteReview = serde_json::from_value(value_json).unwrap();
            assert!(
                r.route_bound(&["answer", "fallback", "semantic_embedding"], 30)
                    .is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn embedding_inventory_attempts_interval_and_proof_are_bound() {
        let r: RouteReview = serde_json::from_value(embedding_review_json()).unwrap();
        let expected = ["answer", "fallback", "semantic_embedding"];
        assert!(r.route_bound(&["answer", "fallback"], 30).is_err());
        let original = r.route_bound(&expected, 30).unwrap();
        let mut changed = r.clone();
        changed.embedding_components[0]
            .contract
            .no_output_review_digest = "a".repeat(64);
        assert_ne!(
            original.review_sha256,
            changed.route_bound(&expected, 30).unwrap().review_sha256
        );
        for attempts in [0, 30] {
            changed = r.clone();
            changed.embedding_components[0].max_physical_attempts = attempts;
            assert!(changed.route_bound(&expected, 30).is_err());
        }
        changed = r.clone();
        changed.embedding_components[0].id = "answer".into();
        assert!(changed.route_bound(&expected, 30).is_err());
        changed = r.clone();
        changed.embedding_components[0].contract.valid_until_ms = 80;
        assert!(changed.route_bound(&expected, 30).is_err());
        changed = r;
        changed.embedding_components[0]
            .contract
            .input_microusd_per_million = 200_000_000_000;
        let expensive = changed.route_bound(&expected, 30).unwrap_err();
        assert_eq!(
            expensive.to_string(),
            "logical call exceeds permanent task cap"
        );
        changed.embedding_components[0].max_physical_attempts = 1;
        changed.embedding_components[0]
            .contract
            .input_microusd_per_million = 66_666_666_666;
        let bound = changed.route_bound(&expected, 30).unwrap();
        assert!(minimum_permanent_reservation(&bound, 6, 1).is_err());
    }
}
