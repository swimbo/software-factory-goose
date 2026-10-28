//! Unregistered two-turn, single-object conversation experiment. Fixture only.
//! The service's callers must be trusted; it does not authenticate provider/tool attestations,
//! migrate a production ledger, implement daily accounting, or support general Goose streams.
use crate::{
    atomic_inference_fixture::Lease, gateway::ReviewedModelContract,
    goose_protocol::validate_goose_fixture_bytes,
};
use restate_sdk::{prelude::*, serde::Json};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const CAP: u64 = 750_000;
const MAX_BYTES: usize = 65_536;
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    pub lease: Lease,
    pub initial: Vec<u8>,
    pub tool: Value,
    pub max_tokens: u64,
    pub routes: Vec<ReviewedModelContract>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    pub call_id: String,
    pub turn: u8,
    pub request: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Exchange {
    pub call_id: String,
    pub assistant: Value,
    pub tool_result: Value,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
enum Phase {
    Initial,
    Reserved {
        admission: Admission,
    },
    Unknown {
        admission: Admission,
    },
    Bound {
        first_id: String,
        assistant: Value,
        tool_result: Value,
    },
    FinalReserved {
        first_id: String,
        admission: Admission,
    },
    FinalUnknown {
        first_id: String,
        admission: Admission,
    },
}
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct State {
    task: String,
    spec: Spec,
    phase: Phase,
    spent: u64,
    revoked: bool,
}
fn err(code: u16, msg: &str) -> TerminalError {
    TerminalError::new_with_code(code, msg)
}
fn valid_id(s: &str) -> bool {
    ulid::Ulid::from_string(s).is_ok_and(|v| v.to_string() == s)
}
fn valid_task(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
impl State {
    fn new(task: &str, spec: Spec, now: u64) -> Result<Self, TerminalError> {
        let l = &spec.lease;
        if !valid_task(task)
            || l.worker_id.is_empty()
            || !valid_id(&l.token)
            || l.attempt == 0
            || l.issued_ms >= l.expires_ms
            || l.expires_ms - l.issued_ms > 300_000
            || !(l.issued_ms..l.expires_ms).contains(&now)
            || spec.routes.len() != 2
        {
            return Err(err(400, "invalid fixture scope"));
        }
        let initial = validate_goose_fixture_bytes(
            &spec.initial,
            "auto",
            &spec.tool,
            spec.max_tokens,
            MAX_BYTES,
        )
        .map_err(|_| err(400, "invalid initial request"))?;
        if initial["messages"].as_array().map(Vec::len) != Some(2) {
            return Err(err(400, "invalid initial sequence"));
        }
        let s = Self {
            task: task.into(),
            spec,
            phase: Phase::Initial,
            spent: 0,
            revoked: false,
        };
        s.cost(now)?;
        Ok(s)
    }
    fn cost(&self, now: u64) -> Result<u64, TerminalError> {
        let mut names = std::collections::HashSet::new();
        let mut maximum = 0;
        for c in &self.spec.routes {
            // Independent synthetic route snapshot. This cannot attest Bifrost's live
            // routing configuration and is deliberately unsuitable for real inference.
            let minimum = match c.model.as_str() {
                "fixture-cheap" => 100,
                "fixture-expensive" => 200,
                _ => return Err(err(409, "route absent from fixture snapshot")),
            };
            if !names.insert(&c.model)
                || c.validate().is_err()
                || !(c.reviewed_at_ms..c.valid_until_ms).contains(&now)
                || c.max_billable_output_tokens < self.spec.max_tokens
                || !matches!(
                    c.output_limit_field,
                    crate::gateway::OutputLimitField::MaxTokens
                )
                || c.review_digest != "a".repeat(64)
                || c.input_microusd_per_million < minimum
                || c.output_microusd_per_million < minimum
                || c.max_billable_input_tokens < 1_000_000
                || c.max_billable_output_tokens < 1_000_000
            {
                return Err(err(409, "route review unavailable"));
            }
            maximum = maximum.max(
                c.upper_bound_microusd()
                    .map_err(|_| err(409, "route cost unavailable"))?,
            );
        }
        if maximum == 0 || maximum > CAP {
            return Err(err(409, "route cost exceeds budget"));
        }
        Ok(maximum)
    }
    fn check_live(&self, task: &str, now: u64) -> Result<(), TerminalError> {
        let l = &self.spec.lease;
        if self.task != task || self.revoked || !(l.issued_ms..l.expires_ms).contains(&now) {
            return Err(err(409, "lease unavailable"));
        }
        Ok(())
    }
    fn prepare(&mut self, task: &str, a: &Admission, now: u64) -> Result<(), TerminalError> {
        self.check_live(task, now)?;
        if !valid_id(&a.call_id) {
            return Err(err(400, "invalid call ID"));
        }
        if self
            .spec
            .routes
            .iter()
            .any(|c| a.request.len() > c.max_request_bytes)
        {
            return Err(err(400, "request exceeds reviewed limit"));
        }
        let value = validate_goose_fixture_bytes(
            &a.request,
            "auto",
            &self.spec.tool,
            self.spec.max_tokens,
            MAX_BYTES,
        )
        .map_err(|_| err(400, "invalid conversation"))?;
        let next = match &self.phase {
            Phase::Initial if a.turn == 0 && a.request == self.spec.initial => Phase::Reserved {
                admission: a.clone(),
            },
            Phase::Bound {
                first_id,
                assistant,
                tool_result,
            } if a.turn == 1 && &a.call_id != first_id => {
                let first = validate_goose_fixture_bytes(
                    &self.spec.initial,
                    "auto",
                    &self.spec.tool,
                    self.spec.max_tokens,
                    MAX_BYTES,
                )
                .map_err(|_| err(409, "invalid state"))?;
                let mut expected = first;
                let messages = expected["messages"]
                    .as_array_mut()
                    .ok_or_else(|| err(409, "invalid state"))?;
                messages.push(assistant.clone());
                messages.push(tool_result.clone());
                if value != expected {
                    return Err(err(403, "unattested continuation"));
                }
                Phase::FinalReserved {
                    first_id: first_id.clone(),
                    admission: a.clone(),
                }
            }
            _ => return Err(err(409, "call unavailable or ambiguous")),
        };
        let cost = self.cost(now)?;
        self.spent = self
            .spent
            .checked_add(cost)
            .filter(|n| *n <= CAP)
            .ok_or_else(|| err(429, "budget exhausted"))?;
        self.phase = next;
        Ok(())
    }
    fn begin(&mut self, task: &str, a: &Admission, now: u64) -> Result<(), TerminalError> {
        self.check_live(task, now)?;
        self.cost(now)?;
        self.phase = match &self.phase {
            Phase::Reserved { admission } if admission == a => Phase::Unknown {
                admission: a.clone(),
            },
            Phase::FinalReserved {
                first_id,
                admission,
            } if admission == a => Phase::FinalUnknown {
                first_id: first_id.clone(),
                admission: a.clone(),
            },
            _ => return Err(err(409, "call unavailable or ambiguous")),
        };
        Ok(())
    }
    fn bind(&mut self, task: &str, x: &Exchange, now: u64) -> Result<(), TerminalError> {
        self.check_live(task, now)?;
        let first_id = match &self.phase {
            Phase::Unknown { admission } if admission.call_id == x.call_id => {
                admission.call_id.clone()
            }
            _ => return Err(err(409, "no dispatched first call")),
        };
        let mut value = validate_goose_fixture_bytes(
            &self.spec.initial,
            "auto",
            &self.spec.tool,
            self.spec.max_tokens,
            MAX_BYTES,
        )
        .map_err(|_| err(409, "invalid state"))?;
        let messages = value["messages"]
            .as_array_mut()
            .ok_or_else(|| err(409, "invalid state"))?;
        messages.push(x.assistant.clone());
        messages.push(x.tool_result.clone());
        let encoded = serde_json::to_vec(&value).map_err(|_| err(400, "invalid exchange"))?;
        validate_goose_fixture_bytes(
            &encoded,
            "auto",
            &self.spec.tool,
            self.spec.max_tokens,
            MAX_BYTES,
        )
        .map_err(|_| err(400, "invalid exchange"))?;
        self.phase = Phase::Bound {
            first_id,
            assistant: x.assistant.clone(),
            tool_result: x.tool_result.clone(),
        };
        Ok(())
    }
}
async fn now_ms() -> HandlerResult<u64> {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| err(500, "clock unavailable"))?;
    u64::try_from(d.as_millis()).map_err(|_| err(500, "clock overflow").into())
}
/// Trusted fixture-only caller; never register on production ingress.
pub struct ConversationFixture;
#[restate_sdk::object]
impl ConversationFixture {
    #[handler]
    async fn initialize(&self, ctx: ObjectContext<'_>, spec: Json<Spec>) -> HandlerResult<()> {
        let now = ctx.run(now_ms).await?;
        let requested = State::new(ctx.key(), spec.0, now)?;
        if let Some(old) = ctx.get::<Json<State>>("state").await? {
            if serde_json::to_value(&old.0.spec).ok() != serde_json::to_value(&requested.spec).ok()
                || old.0.task != requested.task
            {
                return Err(err(409, "fixture scope already bound").into());
            }
            return Ok(());
        }
        ctx.set("state", Json(requested));
        Ok(())
    }
    #[handler]
    async fn prepare(
        &self,
        ctx: ObjectContext<'_>,
        a: Json<Admission>,
    ) -> HandlerResult<Json<bool>> {
        let mut s = ctx
            .get::<Json<State>>("state")
            .await?
            .ok_or_else(|| err(404, "fixture missing"))?
            .0;
        let now = ctx.run(now_ms).await?;
        s.prepare(ctx.key(), &a.0, now)?;
        ctx.set("state", Json(s));
        Ok(Json(true))
    }
    #[handler]
    async fn begin(&self, ctx: ObjectContext<'_>, a: Json<Admission>) -> HandlerResult<Json<bool>> {
        let mut s = ctx
            .get::<Json<State>>("state")
            .await?
            .ok_or_else(|| err(404, "fixture missing"))?
            .0;
        let now = ctx.run(now_ms).await?;
        s.begin(ctx.key(), &a.0, now)?;
        ctx.set("state", Json(s));
        Ok(Json(true))
    }
    #[handler]
    async fn bind(&self, ctx: ObjectContext<'_>, x: Json<Exchange>) -> HandlerResult<Json<bool>> {
        let mut s = ctx
            .get::<Json<State>>("state")
            .await?
            .ok_or_else(|| err(404, "fixture missing"))?
            .0;
        let now = ctx.run(now_ms).await?;
        s.bind(ctx.key(), &x.0, now)?;
        ctx.set("state", Json(s));
        Ok(Json(true))
    }
    #[handler]
    async fn revoke(
        &self,
        ctx: ObjectContext<'_>,
        lease: Json<Lease>,
    ) -> HandlerResult<Json<bool>> {
        let mut s = ctx
            .get::<Json<State>>("state")
            .await?
            .ok_or_else(|| err(404, "fixture missing"))?
            .0;
        if s.task != ctx.key() || s.spec.lease != lease.0 {
            return Err(err(403, "lease mismatch").into());
        }
        s.revoked = true;
        ctx.set("state", Json(s));
        Ok(Json(true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::OutputLimitField;
    use serde_json::json;
    fn spec() -> Spec {
        let tool = json!({"type":"function","function":{"name":"factory__shell","parameters":{"type":"object"}}});
        let request = json!({"model":"auto","messages":[{"role":"system","content":"system"},{"role":"user","content":"task"}],"tools":[tool.clone()],"max_tokens":100,"stream":true,"stream_options":{"include_usage":true}});
        let contract = |name: &str, rate: u64| ReviewedModelContract {
            model: name.into(),
            review_digest: "a".repeat(64),
            reviewed_at_ms: 100,
            valid_until_ms: 900,
            input_microusd_per_million: rate,
            output_microusd_per_million: rate,
            max_billable_input_tokens: 1_000_000,
            max_billable_output_tokens: 1_000_000,
            fixed_call_microusd: 0,
            max_request_bytes: MAX_BYTES,
            output_limit_field: OutputLimitField::MaxTokens,
        };
        Spec {
            lease: Lease {
                worker_id: "fixture".into(),
                token: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
                attempt: 1,
                issued_ms: 100,
                expires_ms: 1000,
            },
            initial: serde_json::to_vec(&request).unwrap(),
            tool,
            max_tokens: 100,
            routes: vec![
                contract("fixture-cheap", 100),
                contract("fixture-expensive", 200),
            ],
        }
    }
    fn first(s: &Spec) -> Admission {
        Admission {
            call_id: "01ARZ3NDEKTSV4RRFFQ69G5FAW".into(),
            turn: 0,
            request: s.initial.clone(),
        }
    }
    fn exchange() -> Exchange {
        Exchange {
            call_id: "01ARZ3NDEKTSV4RRFFQ69G5FAW".into(),
            assistant: json!({"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"factory__shell","arguments":"{\"command\":\"echo hi\"}"}}]}),
            tool_result: json!({"role":"tool","tool_call_id":"c1","content":"safe"}),
        }
    }
    fn second(s: &Spec, x: &Exchange) -> Admission {
        let mut v: Value = serde_json::from_slice(&s.initial).unwrap();
        v["messages"]
            .as_array_mut()
            .unwrap()
            .extend([x.assistant.clone(), x.tool_result.clone()]);
        Admission {
            call_id: "01ARZ3NDEKTSV4RRFFQ69G5FAX".into(),
            turn: 1,
            request: serde_json::to_vec(&v).unwrap(),
        }
    }
    #[test]
    fn only_exact_attested_continuation_can_reserve_and_begin_once() {
        let s = spec();
        let a = first(&s);
        let x = exchange();
        let b = second(&s, &x);
        let mut state = State::new("task", s, 200).unwrap();
        assert!(state.prepare("task", &b, 200).is_err());
        state.prepare("task", &a, 200).unwrap();
        assert_eq!(state.spent, 400);
        assert!(state.prepare("task", &a, 200).is_err());
        state.begin("task", &a, 201).unwrap();
        assert!(state.begin("task", &a, 201).is_err());
        let mut forged = x.clone();
        forged.tool_result["tool_call_id"] = json!("other");
        assert!(state.bind("task", &forged, 202).is_err());
        state.bind("task", &x, 202).unwrap();
        let mut forged_b = b.clone();
        let mut v: Value = serde_json::from_slice(&b.request).unwrap();
        v["messages"][3]["content"] = json!("forged");
        forged_b.request = serde_json::to_vec(&v).unwrap();
        assert!(state.prepare("task", &forged_b, 203).is_err());
        state.prepare("task", &b, 203).unwrap();
        assert_eq!(state.spent, 800);
        state.begin("task", &b, 204).unwrap();
        assert!(state.begin("task", &b, 204).is_err());
    }
    #[test]
    fn expiry_revocation_and_unknown_route_fail_without_spend() {
        let s = spec();
        let a = first(&s);
        let mut state = State::new("task", s, 200).unwrap();
        assert!(state.prepare("other", &a, 200).is_err());
        assert!(state.prepare("task", &a, 1000).is_err());
        state.revoked = true;
        assert!(state.prepare("task", &a, 200).is_err());
        assert_eq!(state.spent, 0);
        let mut bad = spec();
        bad.routes[1].input_microusd_per_million = 0;
        assert!(State::new("task", bad, 200).is_err());
        let mut unrelated = spec();
        unrelated.routes[1].model = "unrelated-cheap".into();
        unrelated.routes[1].input_microusd_per_million = 100;
        unrelated.routes[1].output_microusd_per_million = 100;
        assert!(State::new("task", unrelated, 200).is_err());
    }
    #[test]
    fn changed_route_snapshot_blocks_begin_after_reservation() {
        let config = spec();
        let admission = first(&config);
        let mut state = State::new("task", config, 200).unwrap();
        state.prepare("task", &admission, 200).unwrap();
        state.spec.routes[1].review_digest = "b".repeat(64);
        assert!(state.begin("task", &admission, 201).is_err());
        assert_eq!(state.spent, 400);
        assert!(matches!(state.phase, Phase::Reserved { .. }));
    }
}
