//! Gateway wiring — the LiteLLM/Bifrost credential broker + budget choke point (consensus R7).
//!
//! This client requires a Restate reservation before forwarding inference. Deployment must
//! additionally route every worker call through this boundary and verify that configured
//! price/token maxima and output-limit semantics are enforced by the upstream provider;
//! the standalone Goose worker is not wired through this client yet. Invalid or unavailable
//! budget state denies the call.

use crate::gates::Budget;
use std::{collections::HashMap, time::Duration};

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

/// Explicit price review supplied by trusted deployment configuration, never by an inference
/// request. This is an assertion requiring external provider review, not an attestation.
/// Prices must upper-bound the aggregate effective charge per input/output token (including
/// overlapping cache surcharges, reasoning and routing markups); fixed_call_microusd must cover
/// all non-token charges. These claims need provider/gateway evidence before live use.
/// Token limits describe hard maxima for ALL billable input/output, including provider-added
/// context. Unknown charges or unbounded accepted requests cannot use this contract.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedModelContract {
    pub model: String,
    pub review_digest: String,
    pub reviewed_at_ms: u64,
    pub valid_until_ms: u64,
    pub input_microusd_per_million: u64,
    pub output_microusd_per_million: u64,
    pub max_billable_input_tokens: u64,
    pub max_billable_output_tokens: u64,
    pub fixed_call_microusd: u64,
    pub max_request_bytes: usize,
    pub output_limit_field: OutputLimitField,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputLimitField {
    MaxCompletionTokens,
    MaxTokens,
}
impl OutputLimitField {
    fn name(self) -> &'static str {
        match self {
            Self::MaxCompletionTokens => "max_completion_tokens",
            Self::MaxTokens => "max_tokens",
        }
    }
}
impl ReviewedModelContract {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.model.is_empty()
                && self.model.len() <= 256
                && self.model.bytes().all(|b| b.is_ascii_graphic()),
            "invalid reviewed model identifier"
        );
        anyhow::ensure!(
            self.review_digest.len() == 64
                && self
                    .review_digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "missing canonical price review digest"
        );
        anyhow::ensure!(
            self.reviewed_at_ms < self.valid_until_ms,
            "invalid price review validity interval"
        );
        anyhow::ensure!(
            (1..=1024 * 1024).contains(&self.max_request_bytes),
            "invalid bounded request size"
        );
        microusd_as_conservative_usd(self.upper_bound_microusd()?)?;
        Ok(())
    }

    /// Round EACH billing component up to microUSD using integer arithmetic. Reserve the
    /// entire reviewed input AND output maximum, irrespective of caller's smaller output
    /// request. No tokenizer, assistant-message count or reported usage is trusted here.
    pub fn upper_bound_microusd(&self) -> anyhow::Result<u64> {
        anyhow::ensure!(
            self.input_microusd_per_million > 0 && self.output_microusd_per_million > 0,
            "unknown or zero token price"
        );
        anyhow::ensure!(
            (1..u64::MAX).contains(&self.max_billable_input_tokens)
                && (1..u64::MAX).contains(&self.max_billable_output_tokens),
            "missing or unbounded billable token maximum"
        );
        let cost = |tokens: u64, rate: u64| -> anyhow::Result<u128> {
            let product = u128::from(tokens)
                .checked_mul(u128::from(rate))
                .ok_or_else(|| anyhow::anyhow!("price multiplication overflow"))?;
            Ok(product
                .checked_add(999_999)
                .ok_or_else(|| anyhow::anyhow!("price rounding overflow"))?
                / 1_000_000)
        };
        let total = cost(
            self.max_billable_input_tokens,
            self.input_microusd_per_million,
        )?
        .checked_add(cost(
            self.max_billable_output_tokens,
            self.output_microusd_per_million,
        )?)
        .and_then(|v| v.checked_add(u128::from(self.fixed_call_microusd)))
        .ok_or_else(|| anyhow::anyhow!("price total overflow"))?;
        Ok(u64::try_from(total)?)
    }
}

fn microusd_as_conservative_usd(value: u64) -> anyhow::Result<f64> {
    anyhow::ensure!(
        value > 0 && value <= (1_u64 << 53),
        "reservation outside exact integer conversion range"
    );
    // Governance reports f64 dollars. Use this upward-rounded conversion only for the
    // local headroom comparison; the Restate wire and authoritative ledger stay integer.
    Ok(((value as f64) / 1_000_000.0).next_up())
}

fn validate_review_time(contract: &ReviewedModelContract, now_ms: u64) -> anyhow::Result<()> {
    anyhow::ensure!(
        contract.reviewed_at_ms <= now_ms && now_ms < contract.valid_until_ms,
        "price review expired or not yet valid"
    );
    Ok(())
}
fn current_time_ms() -> anyhow::Result<u64> {
    let elapsed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    Ok(u64::try_from(elapsed.as_millis())?)
}

// Bound decoded HTTP bodies before parsing, including responses without Content-Length.
// Never include upstream body data in errors, which may contain sensitive content.
async fn read_bounded_json<T: serde::de::DeserializeOwned>(
    mut response: reqwest::Response,
    limit: usize,
) -> anyhow::Result<T> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        anyhow::ensure!(
            chunk.len() <= limit.saturating_sub(body.len()),
            "gateway response exceeds limit"
        );
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| anyhow::anyhow!("invalid gateway JSON response"))
}

fn prepare_chat(
    contract: &ReviewedModelContract,
    model: &str,
    messages: &[serde_json::Value],
    max_output_tokens: u64,
    now_ms: u64,
) -> anyhow::Result<(serde_json::Value, u64)> {
    contract.validate()?;
    anyhow::ensure!(
        contract.model == model,
        "model does not match reviewed price contract"
    );
    validate_review_time(contract, now_ms)?;
    anyhow::ensure!(
        max_output_tokens > 0 && max_output_tokens <= contract.max_billable_output_tokens,
        "invalid output token limit"
    );
    anyhow::ensure!(
        !messages.is_empty() && messages.len() <= 1024,
        "chat requires bounded text messages"
    );
    for message in messages {
        let object = message
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("message must be an object"))?;
        anyhow::ensure!(
            object.len() == 2
                && matches!(
                    object.get("role").and_then(|v| v.as_str()),
                    Some("system" | "user" | "assistant")
                )
                && object.get("content").is_some_and(|v| v.is_string()),
            "only reviewed text content is supported; tools/media/extra fields are unpriced"
        );
    }
    let mut body =
        serde_json::json!({"model": model, "messages": messages, "n": 1, "stream": false});
    body[contract.output_limit_field.name()] = serde_json::json!(max_output_tokens);
    anyhow::ensure!(
        serde_json::to_vec(&body)?.len() <= contract.max_request_bytes,
        "chat request exceeds reviewed byte limit"
    );
    Ok((body, contract.upper_bound_microusd()?))
}

/// Per-call coordinates and requested output cap. There is intentionally no caller-supplied
/// dollar estimate. Ambiguous downstream failures retain the full worst-case reservation.
pub struct InferenceBudget<'a> {
    pub restate_url: &'a str,
    pub budget_id: &'a str,
    pub virtual_key_id: &'a str,
    pub max_output_tokens: u64,
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
    /// Configured alongside the credential by trusted bootstrap; never selected by a caller.
    governance_key_id: Option<String>,
    /// Exact trusted endpoint and unit ledger; per-call input cannot select either.
    budget_authority: Option<(String, String)>,
    /// Management bearer token for reading governance (budgets) — distinct from the VK.
    admin_key: String,
    http: reqwest::Client,
    reviewed_models: HashMap<String, ReviewedModelContract>,
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
            governance_key_id: None,
            budget_authority: None,
            admin_key: admin_key.into(),
            reviewed_models: HashMap::new(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .build()
                .expect("valid HTTP client configuration"),
        }
    }

    /// Bind the governance identity to this client's virtual-key credential at trusted
    /// bootstrap. The deployment must separately verify that the pair refers to the same key.
    pub fn with_governance_key_id(mut self, id: impl Into<String>) -> anyhow::Result<Self> {
        let id = id.into();
        anyhow::ensure!(
            self.governance_key_id.is_none(),
            "governance identity already bound"
        );
        anyhow::ensure!(
            !id.is_empty() && id.len() <= 256 && id.bytes().all(|b| b.is_ascii_graphic()),
            "invalid governance identity"
        );
        self.governance_key_id = Some(id);
        Ok(self)
    }

    /// Bind one unit's reservation authority at trusted bootstrap. A client is scoped to
    /// that unit; callers cannot replace the endpoint or obtain a fresh ledger per call.
    pub fn with_budget_authority(mut self, base: &str, unit: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(
            self.budget_authority.is_none(),
            "budget authority already bound"
        );
        let url = reqwest::Url::parse(base)?;
        anyhow::ensure!(
            matches!(url.scheme(), "http" | "https")
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "invalid budget authority URL"
        );
        anyhow::ensure!(
            !unit.is_empty()
                && unit.len() <= 256
                && unit
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
            "invalid unit budget key"
        );
        budget_reservation_url(base, unit)?;
        self.budget_authority = Some((base.to_owned(), unit.to_owned()));
        Ok(self)
    }

    /// Trusted bootstrap only. An unconfigured client denies all models. Duplicate model
    /// entries are rejected rather than silently replacing reviewed prices or limits.
    pub fn with_reviewed_model(mut self, contract: ReviewedModelContract) -> anyhow::Result<Self> {
        contract.validate()?;
        anyhow::ensure!(
            !self.reviewed_models.contains_key(&contract.model),
            "duplicate reviewed model contract"
        );
        self.reviewed_models
            .insert(contract.model.clone(), contract);
        Ok(self)
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
            self.governance_key_id.as_deref() == Some(budget.virtual_key_id),
            "governance identity is not bound to this client"
        );
        anyhow::ensure!(
            self.budget_authority
                .as_ref()
                .is_some_and(|(base, unit)| base == budget.restate_url && unit == budget.budget_id),
            "budget authority is not bound to this client"
        );
        let contract = self
            .reviewed_models
            .get(model)
            .ok_or_else(|| anyhow::anyhow!("model lacks reviewed price and token bounds"))?;
        let now = current_time_ms()?;
        let (body, reservation_microusd) =
            prepare_chat(contract, model, messages, budget.max_output_tokens, now)?;
        let remaining = self
            .remaining_budget(budget.virtual_key_id)
            .await
            .ok_or_else(|| anyhow::anyhow!("gateway budget unavailable"))?;
        anyhow::ensure!(
            microusd_as_conservative_usd(reservation_microusd)? <= remaining,
            "gateway budget exhausted"
        );
        // The virtual object's exclusive handler serializes concurrent reservations.
        let reservation_url = budget_reservation_url(budget.restate_url, budget.budget_id)?;
        let reservation_response = self
            .http
            .post(reservation_url)
            .json(&reservation_microusd)
            .send()
            .await?
            .error_for_status()?;
        let reserved: bool = read_bounded_json(reservation_response, 64).await?;
        anyhow::ensure!(reserved, "unit budget exhausted");
        // Governance/reservation can block long enough for a price review to expire. Retain
        // any reservation conservatively, but do not forward under expired configuration.
        validate_review_time(contract, current_time_ms()?)?;
        let resp = self
            .http
            .post(format!("{}/v1/chat/completions", self.base_url))
            .header("x-bf-vk", &self.virtual_key)
            .json(&body)
            .send()
            .await?;
        read_bounded_json(resp.error_for_status()?, 1024 * 1024).await
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
        let raw: Box<serde_json::value::RawValue> =
            read_bounded_json(resp, 1024 * 1024).await.ok()?;
        parse_remaining_budget(raw.get(), vk_id)
    }
}

fn budget_reservation_url(base: &str, budget_id: &str) -> anyhow::Result<reqwest::Url> {
    anyhow::ensure!(!budget_id.is_empty(), "missing unit budget key");
    let mut url = reqwest::Url::parse(base)?;
    let mut segments = url
        .path_segments_mut()
        .map_err(|_| anyhow::anyhow!("invalid Restate base URL"))?;
    segments.pop_if_empty().extend([
        "restate",
        "call",
        "BudgetCounter",
        budget_id,
        "try_spend_microusd",
    ]);
    drop(segments);
    Ok(url)
}

#[derive(serde::Deserialize)]
struct GovernanceBudget {
    max_limit: Box<serde_json::value::RawValue>,
    current_usage: Box<serde_json::value::RawValue>,
}
#[derive(serde::Deserialize)]
struct GovernanceKey {
    id: String,
    budgets: Vec<GovernanceBudget>,
}
#[derive(serde::Deserialize)]
struct GovernanceEnvelope {
    virtual_keys: Vec<GovernanceKey>,
}

fn parse_remaining_budget(json: &str, vk_id: &str) -> Option<f64> {
    if vk_id.is_empty() {
        return None;
    }
    let vks = serde_json::from_str::<Vec<GovernanceKey>>(json)
        .ok()
        .or_else(|| {
            serde_json::from_str::<GovernanceEnvelope>(json)
                .ok()
                .map(|e| e.virtual_keys)
        })?;
    let mut matching = vks.iter().filter(|v| v.id == vk_id);
    let vk = matching.next()?;
    if matching.next().is_some() {
        return None;
    }
    let budgets = &vk.budgets;
    if budgets.is_empty() {
        return None;
    }
    let mut remaining = f64::INFINITY;
    for b in budgets {
        // Missing usage or a malformed budget cannot be silently ignored.
        // RawValue retains each original decimal token for integer conversion.
        let max = decimal_microusd(b.max_limit.get(), false)?;
        let used = decimal_microusd(b.current_usage.get(), true)?;
        let micro = max.saturating_sub(used);
        let conservative = ((micro as f64) / 1_000_000.0).next_down().max(0.0);
        remaining = remaining.min(conservative);
    }
    Some(remaining)
}

// Conservative whole microdollars, flooring maxima and ceiling usage. Reject decimals
// outside the deliberately bounded integer representation rather than guessing.
fn decimal_microusd(value: &str, ceil: bool) -> Option<u64> {
    // Validate JSON numeric syntax without using its binary floating point value.
    if !serde_json::from_str::<serde_json::Value>(value)
        .ok()?
        .is_number()
    {
        return None;
    }
    if value.len() > 128 || value.starts_with('-') {
        return None;
    }
    let (mantissa, exp) = match value.find(['e', 'E']) {
        Some(i) => (&value[..i], value[i + 1..].parse::<i32>().ok()?),
        None => (value, 0),
    };
    if !(-1000..=1000).contains(&exp) {
        return None;
    }
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let digits = format!("{whole}{fraction}");
    let trimmed = digits.trim_start_matches('0');
    if trimmed.is_empty() {
        return Some(0);
    }
    let significand = trimmed.parse::<u128>().ok()?;
    let power = exp
        .checked_sub(i32::try_from(fraction.len()).ok()?)?
        .checked_add(6)?;
    let amount = if power >= 0 {
        significand.checked_mul(10_u128.checked_pow(u32::try_from(power).ok()?)?)?
    } else if power < -38 {
        u128::from(ceil)
    } else {
        let denominator = 10_u128.checked_pow(power.unsigned_abs())?;
        let quotient = significand / denominator;
        quotient.checked_add(u128::from(ceil && significand % denominator != 0))?
    };
    // Conversion to f64 is exact in this range; the subsequent division is rounded down.
    if amount > (1_u128 << 53) {
        return None;
    }
    u64::try_from(amount).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn caller_cannot_change_bound_budget_authority_or_unit() {
        use axum::{Router, http::StatusCode};
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(move || {
            let seen = seen.clone();
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                StatusCode::OK
            }
        });
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = GatewayClient::new(&base, "synthetic-vk", "synthetic-admin")
            .with_governance_key_id("key")
            .unwrap()
            .with_reviewed_model(reviewed_model())
            .unwrap();
        let budget = InferenceBudget {
            restate_url: &base,
            budget_id: "unit",
            virtual_key_id: "key",
            max_output_tokens: 1,
        };
        assert!(client.chat("test", &messages(), &budget).await.is_err());
        let client = client.with_budget_authority(&base, "unit").unwrap();
        let wrong_unit = InferenceBudget {
            budget_id: "other",
            ..budget
        };
        assert!(client.chat("test", &messages(), &wrong_unit).await.is_err());
        let other_base = format!("{base}/");
        let wrong_base = InferenceBudget {
            restate_url: &other_base,
            budget_id: "unit",
            ..budget
        };
        assert!(client.chat("test", &messages(), &wrong_base).await.is_err());
        assert!(client.with_budget_authority(&base, "unit").is_err());
        for bad in ["", ".", "..", "a/b", "a%2Fb", "é"] {
            assert!(
                GatewayClient::new(&base, "synthetic-vk", "synthetic-admin")
                    .with_budget_authority(&base, bad)
                    .is_err()
            );
        }
        for bad in [
            "file:///tmp/test",
            "http://user:pass@localhost",
            "http://localhost/?query=x",
            "http://localhost/#fragment",
        ] {
            assert!(
                GatewayClient::new(&base, "synthetic-vk", "synthetic-admin")
                    .with_budget_authority(bad, "unit")
                    .is_err()
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[tokio::test]
    async fn caller_cannot_select_governance_key_for_a_different_virtual_key() {
        use axum::{Router, http::StatusCode};
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let app = Router::new().fallback(move || {
            let seen = seen.clone();
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                StatusCode::OK
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let budget = InferenceBudget {
            restate_url: &base,
            budget_id: "unit",
            virtual_key_id: "other",
            max_output_tokens: 1,
        };
        let client = GatewayClient::new(&base, "synthetic-vk", "synthetic-admin")
            .with_budget_authority(&base, "unit")
            .unwrap()
            .with_reviewed_model(reviewed_model())
            .unwrap();
        assert!(client.chat("test", &messages(), &budget).await.is_err());
        let client = client.with_governance_key_id("key").unwrap();
        assert!(client.chat("test", &messages(), &budget).await.is_err());
        assert!(client.with_governance_key_id("other").is_err());
        for invalid in ["", "two words", "\n", "é"] {
            assert!(
                GatewayClient::new(&base, "synthetic-vk", "synthetic-admin")
                    .with_governance_key_id(invalid)
                    .is_err()
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[tokio::test]
    async fn bounded_json_rejects_oversized_stream_and_invalid_json() {
        use axum::{Router, routing::get};
        let app = Router::new()
            .route("/good", get(|| async { "{\"a\":1}" }))
            .route("/large", get(|| async { " ".repeat(1024) }))
            .route("/invalid", get(|| async { "not json" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::new();
        let good = client.get(format!("{base}/good")).send().await.unwrap();
        assert_eq!(
            read_bounded_json::<serde_json::Value>(good, 7)
                .await
                .unwrap(),
            serde_json::json!({"a":1})
        );
        let large = client.get(format!("{base}/large")).send().await.unwrap();
        assert!(
            read_bounded_json::<serde_json::Value>(large, 64)
                .await
                .is_err()
        );
        let invalid = client.get(format!("{base}/invalid")).send().await.unwrap();
        assert!(
            read_bounded_json::<serde_json::Value>(invalid, 64)
                .await
                .is_err()
        );
        server.abort();

        // A chunked response has no Content-Length; cumulative size still must be limited.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let sender = tokio::spawn(async move {
            let (mut stream, _) = socket.accept().await.unwrap();
            let mut request = [0_u8; 2048];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n    \r\n4\r\n    \r\n0\r\n\r\n").await.unwrap();
        });
        let response = client.get(format!("http://{addr}/")).send().await.unwrap();
        assert!(
            read_bounded_json::<serde_json::Value>(response, 7)
                .await
                .is_err()
        );
        sender.await.unwrap();
    }

    #[tokio::test]
    async fn oversized_responses_deny_without_additional_inference() {
        use axum::{
            Json, Router,
            routing::{get, post},
        };
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        for oversized_at in ["governance", "reservation", "inference"] {
            let inference_count = Arc::new(AtomicUsize::new(0));
            let observed = inference_count.clone();
            let app = Router::new()
                .route("/api/governance/virtual-keys", get(move || async move {
                    if oversized_at == "governance" { " ".repeat(1024 * 1024 + 1) } else {
                        serde_json::json!([{"id":"key", "budgets":[{"max_limit":1,"current_usage":0}]}]).to_string()
                    }
                }))
                .route("/restate/call/BudgetCounter/unit/try_spend_microusd", post(move || async move {
                    if oversized_at == "reservation" { " ".repeat(65) } else { "true".to_string() }
                }))
                .route("/v1/chat/completions", post(move || { let observed = observed.clone(); async move {
                    observed.fetch_add(1, Ordering::SeqCst);
                    if oversized_at == "inference" { " ".repeat(1024 * 1024 + 1) } else { Json(serde_json::json!({})).0.to_string() }
                }}));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let client = GatewayClient::new(&base, "synthetic-vk", "synthetic-admin")
                .with_governance_key_id("key")
                .unwrap()
                .with_budget_authority(&base, "unit")
                .unwrap()
                .with_reviewed_model(reviewed_model())
                .unwrap();
            let budget = InferenceBudget {
                restate_url: &base,
                budget_id: "unit",
                virtual_key_id: "key",
                max_output_tokens: 1,
            };
            assert!(client.chat("test", &messages(), &budget).await.is_err());
            assert_eq!(
                inference_count.load(Ordering::SeqCst),
                usize::from(oversized_at == "inference")
            );
            server.abort();
        }
    }

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
        assert_eq!(parse_remaining_budget(&json.to_string(), "requested"), None);
        for bad in [
            serde_json::json!([]),
            serde_json::json!([{"max_limit": 100}]),
            serde_json::json!([{"max_limit": 100, "current_usage": -1}]),
            serde_json::json!([{"max_limit": 100, "current_usage": 0}, {}]),
        ] {
            let json = serde_json::json!([{"id": "key", "budgets": bad}]);
            assert_eq!(parse_remaining_budget(&json.to_string(), "key"), None);
        }
    }

    #[test]
    fn governance_uses_tightest_valid_budget() {
        let json = serde_json::json!([{"id": "key", "budgets": [
            {"max_limit": 100, "current_usage": 2},
            {"max_limit": 1, "current_usage": 0.75}
        ]}]);
        let remaining = parse_remaining_budget(&json.to_string(), "key").unwrap();
        assert!(remaining <= 0.25 && remaining > 0.249);
    }

    #[test]
    fn decimal_rounding_never_inflates_governance_headroom() {
        for (input, floor, ceiling) in [
            ("1.0000001", 1_000_000, 1_000_001),
            ("1e-6", 1, 1),
            ("1e-7", 0, 1),
            ("1.234567e2", 123_456_700, 123_456_700),
            ("1e-400", 0, 1),
        ] {
            assert_eq!(decimal_microusd(input, false), Some(floor));
            assert_eq!(decimal_microusd(input, true), Some(ceiling));
        }
        for input in ["-1", "1e1001", "9007199254.740993"] {
            assert_eq!(decimal_microusd(input, false), None);
        }
        let exact = r#"[{"id":"key","budgets":[{"max_limit":1000000000.0000009,"current_usage":1000000000}]}]"#;
        assert_eq!(parse_remaining_budget(exact, "key"), Some(0.0));
        for invalid in ["\"1\"", "null", "true", "{}"] {
            assert_eq!(decimal_microusd(invalid, false), None);
        }
        for cents in 1..100 {
            let source = format!(
                r#"[{{"id":"key","budgets":[{{"max_limit":1000000000000000.{cents:02},"current_usage":1000000000000000}}]}}]"#
            );
            assert_eq!(parse_remaining_budget(&source, "key"), None);
        }
        for (max, used, upper) in [
            ("1.00000000000000009e15", "1e15", 0.09),
            ("1e-6", "9.999999999e-7", 1e-16),
            ("9007199254740993", "9007199254740992", 1.0),
            ("1e-320", "9e-321", 1e-321),
            ("1e-400", "0", 0.0),
        ] {
            let source = format!(
                r#"[{{"id":"key","budgets":[{{"max_limit":{max},"current_usage":{used}}}]}}]"#
            );
            if let Some(actual) = parse_remaining_budget(&source, "key") {
                assert!(actual <= upper, "max={max} used={used} actual={actual}");
            }
        }
    }
    #[test]
    fn duplicate_key_records_are_ambiguous_and_fail_closed() {
        let json = serde_json::json!([
            {"id":"key", "budgets":[{"max_limit":100,"current_usage":0}]},
            {"id":"key", "budgets":[{"max_limit":1,"current_usage":1}]}
        ]);
        assert_eq!(parse_remaining_budget(&json.to_string(), "key"), None);
    }

    fn reviewed_model() -> ReviewedModelContract {
        ReviewedModelContract {
            model: "test".into(),
            review_digest: "a".repeat(64),
            reviewed_at_ms: 0,
            valid_until_ms: u64::MAX,
            input_microusd_per_million: 1_000_000,
            output_microusd_per_million: 2_000_000,
            max_billable_input_tokens: 1000,
            max_billable_output_tokens: 100,
            fixed_call_microusd: 0,
            max_request_bytes: 4096,
            output_limit_field: OutputLimitField::MaxCompletionTokens,
        }
    }
    fn messages() -> Vec<serde_json::Value> {
        vec![serde_json::json!({"role":"user", "content":"synthetic prompt"})]
    }
    #[test]
    fn upper_bound_reserves_full_reviewed_limits_and_rounds_each_component_up() {
        let contract = reviewed_model();
        assert_eq!(contract.upper_bound_microusd().unwrap(), 1200);
        let mut tiny = contract;
        tiny.input_microusd_per_million = 1;
        tiny.output_microusd_per_million = 1;
        tiny.max_billable_input_tokens = 1;
        tiny.max_billable_output_tokens = 1;
        assert_eq!(tiny.upper_bound_microusd().unwrap(), 2);
        assert!(microusd_as_conservative_usd(2).unwrap() > 0.000002);
    }
    #[test]
    fn missing_negative_zero_and_overflowing_price_or_token_bounds_fail_closed() {
        let value = serde_json::to_value(reviewed_model()).unwrap();
        for field in [
            "input_microusd_per_million",
            "output_microusd_per_million",
            "max_billable_input_tokens",
            "max_billable_output_tokens",
            "fixed_call_microusd",
        ] {
            for invalid in [serde_json::json!(-1), serde_json::Value::Null] {
                let mut changed = value.clone();
                changed[field] = invalid;
                assert!(serde_json::from_value::<ReviewedModelContract>(changed).is_err());
            }
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<ReviewedModelContract>(missing).is_err());
        }
        let mut zero = reviewed_model();
        zero.max_billable_input_tokens = 0;
        assert!(zero.validate().is_err());
        zero = reviewed_model();
        zero.input_microusd_per_million = 0;
        assert!(zero.validate().is_err());
        let mut huge = reviewed_model();
        huge.input_microusd_per_million = u64::MAX;
        huge.max_billable_input_tokens = u64::MAX - 1;
        huge.output_microusd_per_million = u64::MAX;
        huge.max_billable_output_tokens = u64::MAX - 1;
        assert!(huge.upper_bound_microusd().is_err());
        assert!(microusd_as_conservative_usd(u64::MAX).is_err());
    }
    #[test]
    fn contract_and_payload_validation_precede_network_or_reservation() {
        let contract = reviewed_model();
        let (body, reserve) = prepare_chat(&contract, "test", &messages(), 1, 100).unwrap();
        assert_eq!(body["max_completion_tokens"], 1);
        assert_eq!(body["n"], 1);
        assert_eq!(body["stream"], false);
        assert_eq!(reserve, 1200);
        // Choosing a smaller output limit cannot lower the full worst-case reservation.
        assert_eq!(
            prepare_chat(&contract, "test", &messages(), 100, 100)
                .unwrap()
                .1,
            reserve
        );
        assert!(prepare_chat(&contract, "other", &messages(), 1, 100).is_err());
        for limit in [0, 101, u64::MAX] {
            assert!(prepare_chat(&contract, "test", &messages(), limit, 100).is_err());
        }
        for invalid in [
            vec![],
            vec![
                serde_json::json!({"role":"user", "content":[{"type":"image_url","image_url":"test"}]}),
            ],
            vec![serde_json::json!({"role":"assistant", "content":"x", "tool_calls":[]})],
        ] {
            assert!(prepare_chat(&contract, "test", &invalid, 1, 100).is_err());
        }
        let mut expired = contract.clone();
        expired.valid_until_ms = 100;
        assert!(prepare_chat(&expired, "test", &messages(), 1, 100).is_err());
        let mut future = contract.clone();
        future.reviewed_at_ms = 101;
        assert!(prepare_chat(&future, "test", &messages(), 1, 100).is_err());
        let mut small = contract;
        small.max_request_bytes = 1;
        assert!(prepare_chat(&small, "test", &messages(), 1, 100).is_err());
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
        // Governance, reservation failures and insufficient headroom must never forward.
        for (governance_ok, headroom, reservation_status, reservation_body, expected_calls) in [
            (true, 1.0, StatusCode::OK, serde_json::json!(false), 0),
            (
                true,
                1.0,
                StatusCode::OK,
                serde_json::json!({"error":"bad response"}),
                0,
            ),
            (
                true,
                1.0,
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!(true),
                0,
            ),
            (false, 1.0, StatusCode::OK, serde_json::json!(true), 0),
            (true, 0.001, StatusCode::OK, serde_json::json!(true), 0),
            (true, 1.0, StatusCode::OK, serde_json::json!(true), 1),
        ] {
            let inference_count = Arc::new(AtomicUsize::new(0));
            let count = inference_count.clone();
            let reservation_count = Arc::new(AtomicUsize::new(0));
            let reservations = reservation_count.clone();
            let app = Router::new()
                .route("/api/governance/virtual-keys", get(move || async move {
                    (if governance_ok { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE },
                     Json(serde_json::json!([{"id":"key", "budgets":[{"max_limit":headroom,"current_usage":0}]}])))
                }))
                .route("/restate/call/BudgetCounter/unit/try_spend_microusd", post(move |Json(amount): Json<u64>| {
                    let body = reservation_body.clone(); let count = reservations.clone();
                    async move {
                        count.fetch_add(1, Ordering::SeqCst);
                        assert_eq!(amount, 1200);
                        (reservation_status, Json(body))
                    }
                }))
                .route("/v1/chat/completions", post(move |Json(body): Json<serde_json::Value>| {
                    let count = count.clone();
                    async move {
                        assert_eq!(body["max_completion_tokens"], 1);
                        assert_eq!(body["n"], 1);
                        assert_eq!(body["stream"], false);
                        count.fetch_add(1, Ordering::SeqCst);
                        Json(serde_json::json!({}))
                    }
                }));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let client = GatewayClient::new(&base, "test-vk", "test-admin")
                .with_governance_key_id("key")
                .unwrap()
                .with_budget_authority(&base, "unit")
                .unwrap()
                .with_reviewed_model(reviewed_model())
                .unwrap();
            let budget = InferenceBudget {
                restate_url: &base,
                budget_id: "unit",
                virtual_key_id: "key",
                max_output_tokens: 1,
            };
            assert_eq!(
                client.chat("test", &messages(), &budget).await.is_ok(),
                expected_calls == 1
            );
            assert_eq!(inference_count.load(Ordering::SeqCst), expected_calls);
            assert_eq!(
                reservation_count.load(Ordering::SeqCst),
                usize::from(governance_ok && headroom >= 0.0012)
            );
            server.abort();
        }
    }

    #[tokio::test]
    async fn absent_or_expired_model_review_and_unpriced_payload_make_no_http_calls() {
        use axum::{Json, Router};
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let http_calls = Arc::new(AtomicUsize::new(0));
        let count = http_calls.clone();
        let app = Router::new().fallback(move || {
            let count = count.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                Json(serde_json::json!({}))
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let budget = InferenceBudget {
            restate_url: &base,
            budget_id: "unit",
            virtual_key_id: "key",
            max_output_tokens: 1,
        };
        let client = GatewayClient::new(&base, "test-vk", "test-admin")
            .with_governance_key_id("key")
            .unwrap()
            .with_budget_authority(&base, "unit")
            .unwrap();
        assert!(client.chat("test", &messages(), &budget).await.is_err());
        let reviewed = client.with_reviewed_model(reviewed_model()).unwrap();
        assert!(
            reviewed
                .chat("unknown", &messages(), &budget)
                .await
                .is_err()
        );
        assert!(
            reviewed
                .chat(
                    "test",
                    &[serde_json::json!({"role":"user","content":[],"tools":[]})],
                    &budget
                )
                .await
                .is_err()
        );
        assert!(reviewed.with_reviewed_model(reviewed_model()).is_err());
        let mut expired = reviewed_model();
        expired.valid_until_ms = 1;
        let expired_client = GatewayClient::new(&base, "test-vk", "test-admin")
            .with_governance_key_id("key")
            .unwrap()
            .with_budget_authority(&base, "unit")
            .unwrap()
            .with_reviewed_model(expired)
            .unwrap();
        assert!(
            expired_client
                .chat("test", &messages(), &budget)
                .await
                .is_err()
        );
        assert_eq!(http_calls.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[tokio::test]
    async fn gateway_ignores_environment_proxy_and_keeps_credentials_on_their_routes() {
        use axum::{
            Json, Router,
            http::{HeaderMap, StatusCode},
            routing::{get, post},
        };
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        if let Ok(base) = std::env::var("SF_GATEWAY_PROXY_TEST_CHILD") {
            let client = GatewayClient::new(&base, "synthetic-vk", "synthetic-admin")
                .with_governance_key_id("key")
                .unwrap()
                .with_budget_authority(&base, "unit")
                .unwrap()
                .with_reviewed_model(reviewed_model())
                .unwrap();
            let budget = InferenceBudget {
                restate_url: &base,
                budget_id: "unit",
                virtual_key_id: "key",
                max_output_tokens: 1,
            };
            assert!(client.chat("test", &messages(), &budget).await.is_ok());
            return;
        }
        let proxy_calls = Arc::new(AtomicUsize::new(0));
        let seen = proxy_calls.clone();
        let proxy = Router::new().fallback(move || {
            let seen = seen.clone();
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                StatusCode::BAD_GATEWAY
            }
        });
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_url = format!("http://{}", proxy_listener.local_addr().unwrap());
        let proxy_server = tokio::spawn(async move {
            axum::serve(proxy_listener, proxy).await.unwrap();
        });
        let app = Router::new()
            .route("/api/governance/virtual-keys", get(|headers: HeaderMap| async move {
                assert_eq!(headers.get("authorization").unwrap(), "Bearer synthetic-admin");
                assert!(!headers.contains_key("x-bf-vk"));
                Json(serde_json::json!([{"id":"key", "budgets":[{"max_limit":1,"current_usage":0}]}]))
            }))
            .route("/restate/call/BudgetCounter/unit/try_spend_microusd", post(|headers: HeaderMap, Json(amount): Json<u64>| async move {
                assert!(!headers.contains_key("authorization")); assert!(!headers.contains_key("x-bf-vk"));
                assert_eq!(amount, 1200); Json(true)
            }))
            .route("/v1/chat/completions", post(|headers: HeaderMap| async move {
                assert!(!headers.contains_key("authorization"));
                assert_eq!(headers.get("x-bf-vk").unwrap(), "synthetic-vk"); Json(serde_json::json!({}))
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let output = tokio::task::spawn_blocking(move || std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "gateway::tests::gateway_ignores_environment_proxy_and_keeps_credentials_on_their_routes"])
            .env("SF_GATEWAY_PROXY_TEST_CHILD", base)
            .env("HTTP_PROXY", &proxy_url).env("http_proxy", &proxy_url)
            .env("ALL_PROXY", &proxy_url).env("all_proxy", &proxy_url)
            .env_remove("NO_PROXY").env_remove("no_proxy")
            .output().unwrap()).await.unwrap();
        assert_eq!(proxy_calls.load(Ordering::SeqCst), 0);
        assert!(output.status.success(), "isolated gateway child failed");
        server.abort();
        proxy_server.abort();
    }

    #[tokio::test]
    async fn governance_redirect_does_not_forward_admin_credential() {
        use axum::{
            Router,
            http::{StatusCode, header},
            routing::get,
        };
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let destination = Router::new().fallback(move || {
            let seen = seen.clone();
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                StatusCode::OK
            }
        });
        let dst_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination_url = format!("http://{}/stolen", dst_listener.local_addr().unwrap());
        let dst_server = tokio::spawn(async move {
            axum::serve(dst_listener, destination).await.unwrap();
        });
        let app = Router::new().route(
            "/api/governance/virtual-keys",
            get(move || {
                let location = destination_url.clone();
                async move {
                    (
                        StatusCode::TEMPORARY_REDIRECT,
                        [(header::LOCATION, location)],
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = GatewayClient::new(&base, "synthetic-vk", "synthetic-admin");
        assert!(client.remaining_budget("key").await.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        server.abort();
        dst_server.abort();
    }

    #[tokio::test]
    async fn inference_redirect_does_not_forward_virtual_key() {
        use axum::{
            Json, Router,
            http::{StatusCode, header},
            routing::{get, post},
        };
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let destination = Router::new().fallback(move || {
            let seen = seen.clone();
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                StatusCode::OK
            }
        });
        let dst_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination_url = format!("http://{}/stolen", dst_listener.local_addr().unwrap());
        let dst_server = tokio::spawn(async move {
            axum::serve(dst_listener, destination).await.unwrap();
        });
        let app = Router::new()
            .route("/api/governance/virtual-keys", get(|| async { Json(serde_json::json!([{"id":"key","budgets":[{"max_limit":1,"current_usage":0}]}])) }))
            .route("/restate/call/BudgetCounter/unit/try_spend_microusd", post(|| async { Json(true) }))
            .route("/v1/chat/completions", post(move || { let location = destination_url.clone(); async move { (StatusCode::TEMPORARY_REDIRECT, [(header::LOCATION, location)]) } }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = GatewayClient::new(&base, "synthetic-vk", "synthetic-admin")
            .with_governance_key_id("key")
            .unwrap()
            .with_budget_authority(&base, "unit")
            .unwrap()
            .with_reviewed_model(reviewed_model())
            .unwrap();
        let budget = InferenceBudget {
            restate_url: &base,
            budget_id: "unit",
            virtual_key_id: "key",
            max_output_tokens: 1,
        };
        assert!(client.chat("test", &messages(), &budget).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        server.abort();
        dst_server.abort();
    }
}
