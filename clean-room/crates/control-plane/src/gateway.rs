//! Gateway wiring — the LiteLLM/Bifrost credential broker + budget choke point (consensus R7).
//!
//! The gateway is the *only* route to inference, so gateway-denial = loop death. The critical
//! property is **default-deny**: if the budget cannot be read (Restate down / partition), the
//! call is refused — never fail-open. This module encodes that property; the budget itself is
//! the Restate `BudgetCounter` object, and `gates::Budget::can_spend` is the pure check.

use crate::gates::Budget;

/// The result of a budget check at the gateway boundary.
pub enum Gate {
    /// Proceed: within budget.
    Allow,
    /// Hard-denied: over budget. A terminal state for the unit, not a retryable error.
    Denied,
    /// Budget unreadable — **fail closed** (R7).
    Unavailable,
}

/// The default-deny gate the gateway applies before *every* inference call.
pub fn gate_call(budget: Option<&Budget>, estimate_usd: f64) -> Gate {
    match budget {
        None => Gate::Unavailable, // cannot read budget → deny
        Some(b) if b.can_spend(estimate_usd) => Gate::Allow,
        Some(_) => Gate::Denied,
    }
}

/// HTTP client for the Bifrost gateway (the credential broker + budget choke point).
///
/// Bifrost is OpenAI-compatible for inference but authenticates callers with the `x-bf-vk`
/// virtual-key header (not `Authorization: Bearer`), and exposes budgets through its governance
/// API. The pure `gate_call` above converts a budget read into the default-deny `Gate`.
pub struct GatewayClient {
    base_url: String,
    /// Sent as `x-bf-vk` on inference calls (`sk-bf-*`).
    virtual_key: String,
    /// Management bearer token for reading governance (budgets) — distinct from the VK.
    admin_key: String,
    http: reqwest::Client,
}

impl GatewayClient {
    pub fn new(
        base_url: impl Into<String>,
        virtual_key: impl Into<String>,
        admin_key: impl Into<String>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            virtual_key: virtual_key.into(),
            admin_key: admin_key.into(),
            http: reqwest::Client::new(),
        }
    }

    /// Forward a chat-completion call. Bifrost authenticates the caller with the `x-bf-vk`
    /// virtual-key header; the model may be provider-prefixed (`openrouter/z-ai/glm-5`).
    pub async fn chat(
        &self,
        model: &str,
        messages: &[serde_json::Value],
    ) -> anyhow::Result<serde_json::Value> {
        let body = serde_json::json!({ "model": model, "messages": messages });
        let resp = self
            .http
            .post(format!("{}/v1/chat/completions", self.base_url))
            .header("x-bf-vk", &self.virtual_key)
            .json(&body)
            .send()
            .await?;
        Ok(resp.json().await?)
    }

    /// Read the remaining budget for a virtual key via Bifrost's governance API.
    ///
    /// Remaining = the tightest headroom across the key's `budgets[]` (`max_limit − current_usage`).
    /// `None` = unreadable → `gate_call` fails closed (R7: a gateway that cannot read the budget
    /// spends nothing).
    pub async fn remaining_budget(&self, vk_id: &str) -> Option<f64> {
        let resp = self
            .http
            .get(format!("{}/api/governance/virtual-keys", self.base_url))
            .query(&[("id", vk_id)])
            .bearer_auth(&self.admin_key)
            .send()
            .await
            .ok()?;
        let json: serde_json::Value = resp.json().await.ok()?;
        // Accept either a `{ "virtual_keys": [ ... ] }` envelope or a bare array.
        let vks = json
            .get("virtual_keys")
            .and_then(|v| v.as_array())
            .or_else(|| json.as_array())?;
        let vk = vks
            .iter()
            .find(|v| v.get("id").and_then(|i| i.as_str()) == Some(vk_id))
            .or_else(|| vks.first())?;
        let budgets = vk.get("budgets")?.as_array()?;
        budgets
            .iter()
            .filter_map(|b| {
                let max = b.get("max_limit")?.as_f64()?;
                let used = b.get("current_usage").and_then(|u| u.as_f64()).unwrap_or(0.0);
                Some(max - used)
            })
            .fold(None, |acc: Option<f64>, r| Some(acc.map_or(r, |a| a.min(r))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget(cap: f64) -> Budget {
        Budget {
            per_unit_cap_usd: cap,
            per_day_cap_usd: cap * 100.0,
            spent_today_usd: 0.0,
            unit_spent_usd: 0.0,
        }
    }

    #[test]
    fn allows_within_budget() {
        assert!(matches!(gate_call(Some(&budget(0.75)), 0.10), Gate::Allow));
    }

    #[test]
    fn denies_over_budget() {
        assert!(matches!(gate_call(Some(&budget(0.75)), 10.0), Gate::Denied));
    }

    #[test]
    fn unreadable_budget_fails_closed() {
        // None = budget state cannot be read → the call must NOT proceed (R7).
        assert!(matches!(gate_call(None, 0.01), Gate::Unavailable));
    }
}
