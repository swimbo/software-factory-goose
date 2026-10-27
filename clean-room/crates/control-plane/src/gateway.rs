//! Gateway wiring — the LiteLLM/Bifrost credential broker + budget choke point (consensus R7).
//!
//! This client requires a Restate reservation before forwarding inference. Deployment must
//! additionally route every worker call through this boundary and enforce token/cost limits;
//! the standalone Goose worker is not wired through this client yet. Invalid or unavailable
//! budget state denies the call.

use crate::gates::Budget;
use std::time::Duration;

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
        Some(b)
            if [
                estimate_usd,
                b.per_unit_cap_usd,
                b.per_day_cap_usd,
                b.spent_today_usd,
                b.unit_spent_usd,
            ]
            .iter()
            .all(|v| v.is_finite() && *v >= 0.0)
                && b.can_spend(estimate_usd) =>
        {
            Gate::Allow
        }
        Some(_) => Gate::Denied,
    }
}

/// Per-call reservation coordinates. The estimate must upper-bound the requested call cost;
/// the gateway must enforce token/pricing limits separately. A reservation is retained on
/// downstream failure, conservatively charging an ambiguous outcome rather than refunding it.
pub struct InferenceBudget<'a> {
    pub restate_url: &'a str,
    pub budget_id: &'a str,
    pub virtual_key_id: &'a str,
    pub estimate_usd: f64,
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
            base_url: base_url.into().trim_end_matches('/').to_string(),
            virtual_key: virtual_key.into(),
            admin_key: admin_key.into(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("valid HTTP client configuration"),
        }
    }

    /// Forward a chat-completion call. Bifrost authenticates the caller with the `x-bf-vk`
    /// virtual-key header; the model may be provider-prefixed (`openrouter/z-ai/glm-5`).
    pub async fn chat(
        &self,
        model: &str,
        messages: &[serde_json::Value],
        budget: &InferenceBudget<'_>,
    ) -> anyhow::Result<serde_json::Value> {
        anyhow::ensure!(
            budget.estimate_usd.is_finite() && budget.estimate_usd > 0.0,
            "inference requires a finite positive cost reservation"
        );
        let remaining = self
            .remaining_budget(budget.virtual_key_id)
            .await
            .ok_or_else(|| anyhow::anyhow!("gateway budget unavailable"))?;
        anyhow::ensure!(budget.estimate_usd <= remaining, "gateway budget exhausted");
        // The virtual object's exclusive handler serializes concurrent reservations.
        let reservation_url = budget_reservation_url(budget.restate_url, budget.budget_id)?;
        let reserved: bool = self
            .http
            .post(reservation_url)
            .json(&budget.estimate_usd)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        anyhow::ensure!(reserved, "unit budget exhausted");
        let body = serde_json::json!({ "model": model, "messages": messages });
        let resp = self
            .http
            .post(format!("{}/v1/chat/completions", self.base_url))
            .header("x-bf-vk", &self.virtual_key)
            .json(&body)
            .send()
            .await?;
        Ok(resp.error_for_status()?.json().await?)
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
            .ok()?
            .error_for_status()
            .ok()?;
        let json: serde_json::Value = resp.json().await.ok()?;
        parse_remaining_budget(&json, vk_id)
    }
}

fn budget_reservation_url(base: &str, budget_id: &str) -> anyhow::Result<reqwest::Url> {
    anyhow::ensure!(!budget_id.is_empty(), "missing unit budget key");
    let mut url = reqwest::Url::parse(base)?;
    let mut segments = url
        .path_segments_mut()
        .map_err(|_| anyhow::anyhow!("invalid Restate base URL"))?;
    segments
        .pop_if_empty()
        .extend(["restate", "call", "BudgetCounter", budget_id, "try_spend"]);
    drop(segments);
    Ok(url)
}

fn parse_remaining_budget(json: &serde_json::Value, vk_id: &str) -> Option<f64> {
    if vk_id.is_empty() {
        return None;
    }
    let vks = json
        .get("virtual_keys")
        .and_then(|v| v.as_array())
        .or_else(|| json.as_array())?;
    let vk = vks
        .iter()
        .find(|v| v.get("id").and_then(|i| i.as_str()) == Some(vk_id))?;
    let budgets = vk.get("budgets")?.as_array()?;
    if budgets.is_empty() {
        return None;
    }
    let mut remaining = f64::INFINITY;
    for b in budgets {
        // Missing usage or a malformed budget cannot be silently ignored.
        let max = b.get("max_limit")?.as_f64()?;
        let used = b.get("current_usage")?.as_f64()?;
        if !max.is_finite() || !used.is_finite() || max < 0.0 || used < 0.0 {
            return None;
        }
        remaining = remaining.min((max - used).max(0.0));
    }
    Some(remaining)
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

    #[test]
    fn negative_or_nonfinite_estimates_are_denied() {
        for estimate in [-1.0, f64::NAN, f64::INFINITY] {
            assert!(matches!(
                gate_call(Some(&budget(0.75)), estimate),
                Gate::Denied
            ));
        }
    }

    #[test]
    fn governance_never_borrows_another_keys_budget_or_defaults_missing_usage() {
        let json = serde_json::json!({"virtual_keys": [{"id": "other", "budgets": [
            {"max_limit": 100, "current_usage": 0}
        ]}]});
        assert_eq!(parse_remaining_budget(&json, "requested"), None);
        for bad in [
            serde_json::json!([]),
            serde_json::json!([{"max_limit": 100}]),
            serde_json::json!([{"max_limit": 100, "current_usage": -1}]),
            serde_json::json!([{"max_limit": 100, "current_usage": 0}, {}]),
        ] {
            let json = serde_json::json!([{"id": "key", "budgets": bad}]);
            assert_eq!(parse_remaining_budget(&json, "key"), None);
        }
    }

    #[test]
    fn governance_uses_tightest_valid_budget() {
        let json = serde_json::json!([{"id": "key", "budgets": [
            {"max_limit": 100, "current_usage": 2},
            {"max_limit": 1, "current_usage": 0.75}
        ]}]);
        assert_eq!(parse_remaining_budget(&json, "key"), Some(0.25));
    }

    #[tokio::test]
    async fn inference_requires_successful_governance_and_atomic_reservation() {
        use axum::{
            Json, Router,
            http::StatusCode,
            routing::{get, post},
        };
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        // false reservation; invalid JSON; unreachable reservation; failed governance; success.
        for (governance_ok, reservation_status, reservation_body, expected_calls) in [
            (true, StatusCode::OK, serde_json::json!(false), 0),
            (
                true,
                StatusCode::OK,
                serde_json::json!({"error":"bad response"}),
                0,
            ),
            (
                true,
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!(true),
                0,
            ),
            (false, StatusCode::OK, serde_json::json!(true), 0),
            (true, StatusCode::OK, serde_json::json!(true), 1),
        ] {
            let inference_count = Arc::new(AtomicUsize::new(0));
            let count = inference_count.clone();
            let app = Router::new()
            .route("/api/governance/virtual-keys", get(move || async move {
                (if governance_ok { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE },
                 Json(serde_json::json!([{"id":"key", "budgets":[{"max_limit":1,"current_usage":0}]}])))
            }))
            .route("/restate/call/BudgetCounter/unit/try_spend", post(move || { let body = reservation_body.clone(); async move { (reservation_status, Json(body)) } }))
            .route("/v1/chat/completions", post(move || {
                let count = count.clone();
                async move { count.fetch_add(1, Ordering::SeqCst); Json(serde_json::json!({})) }
            }));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let client = GatewayClient::new(&base, "test-vk", "test-admin");
            let budget = InferenceBudget {
                restate_url: &base,
                budget_id: "unit",
                virtual_key_id: "key",
                estimate_usd: 0.1,
            };
            assert_eq!(
                client.chat("test", &[], &budget).await.is_ok(),
                expected_calls == 1
            );
            assert_eq!(inference_count.load(Ordering::SeqCst), expected_calls);
            server.abort();
        }
    }
}
