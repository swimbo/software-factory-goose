//! Unregistered inference dispatch fence experiment; no provider or production ingress.

use restate_sdk::{prelude::*, serde::Json};
use std::collections::HashSet;

const CAP_MICROUSD: u64 = 750_000;
const MAX_CALLS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareRequest {
    pub call_id: String,
    pub request_digest: String,
    pub review_digest: String,
    pub model: String,
    pub attempt: u32,
    pub amount_microusd: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Stage {
    Denied,
    Reserved,
    DispatchingUnknown,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    request: PrepareRequest,
    stage: Stage,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    schema: u8,
    scope: String,
    spent_microusd: u64,
    records: Vec<Record>,
}
fn err(code: u16, message: &str) -> TerminalError {
    TerminalError::new_with_code(code, message)
}
fn valid_scope(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid(r: &PrepareRequest) -> bool {
    ulid::Ulid::from_string(&r.call_id).is_ok_and(|id| id.to_string() == r.call_id)
        && digest(&r.request_digest)
        && digest(&r.review_digest)
        && !r.model.is_empty()
        && r.model.len() <= 256
        && r.model.bytes().all(|b| b.is_ascii_graphic())
        && r.attempt > 0
        && r.amount_microusd > 0
}
impl Ledger {
    fn new(scope: &str) -> Self {
        Self {
            schema: 1,
            scope: scope.into(),
            spent_microusd: 0,
            records: vec![],
        }
    }
    fn check(&self, scope: &str) -> Result<(), TerminalError> {
        if !valid_scope(scope)
            || self.scope != scope
            || self.schema != 1
            || self.records.len() > MAX_CALLS
        {
            return Err(err(409, "invalid inference ledger"));
        }
        let mut ids = HashSet::new();
        let mut spent: u64 = 0;
        for record in &self.records {
            if !valid(&record.request) || !ids.insert(&record.request.call_id) {
                return Err(err(409, "invalid inference record"));
            }
            let next = spent
                .checked_add(record.request.amount_microusd)
                .filter(|n| *n <= CAP_MICROUSD);
            if (record.stage != Stage::Denied) != next.is_some() {
                return Err(err(409, "invalid inference reservation"));
            }
            if let Some(next) = next {
                spent = next;
            }
        }
        if spent != self.spent_microusd {
            return Err(err(409, "inconsistent inference total"));
        }
        Ok(())
    }
    fn prepare(&mut self, scope: &str, request: &PrepareRequest) -> Result<Stage, TerminalError> {
        self.check(scope)?;
        if !valid(request) {
            return Err(err(400, "invalid inference binding"));
        }
        if let Some(record) = self
            .records
            .iter()
            .find(|r| r.request.call_id == request.call_id)
        {
            if record.request != *request {
                return Err(err(409, "inference identity conflict"));
            }
            return Ok(record.stage);
        }
        if self.records.len() >= MAX_CALLS {
            return Err(err(429, "inference history capacity exhausted"));
        }
        let next = self
            .spent_microusd
            .checked_add(request.amount_microusd)
            .filter(|n| *n <= CAP_MICROUSD);
        let stage = if next.is_some() {
            Stage::Reserved
        } else {
            Stage::Denied
        };
        if let Some(next) = next {
            self.spent_microusd = next;
        }
        self.records.push(Record {
            request: request.clone(),
            stage,
        });
        Ok(stage)
    }
    fn begin(&mut self, scope: &str, request: &PrepareRequest) -> Result<(), TerminalError> {
        self.check(scope)?;
        if !valid(request) {
            return Err(err(400, "invalid inference binding"));
        }
        let record = self
            .records
            .iter_mut()
            .find(|r| r.request.call_id == request.call_id)
            .ok_or_else(|| err(404, "inference not prepared"))?;
        if record.request != *request || record.stage != Stage::Reserved {
            return Err(err(409, "inference dispatch unavailable or ambiguous"));
        }
        record.stage = Stage::DispatchingUnknown;
        Ok(())
    }
}

/// Unregistered fixture prototype only. A begin result is not a reusable capability; the
/// trusted launcher must own the sole invocation and never retry a possibly sent provider call.
pub struct InferenceAuthority;
#[restate_sdk::object]
impl InferenceAuthority {
    #[handler]
    async fn prepare(
        &self,
        ctx: ObjectContext<'_>,
        request: Json<PrepareRequest>,
    ) -> HandlerResult<Json<Stage>> {
        let mut ledger = ctx
            .get::<Json<Ledger>>("ledger")
            .await?
            .map(|v| v.0)
            .unwrap_or_else(|| Ledger::new(ctx.key()));
        let before = ledger.clone();
        let stage = ledger.prepare(ctx.key(), &request.0)?;
        if ledger != before {
            ctx.set("ledger", Json(ledger));
        }
        Ok(Json(stage))
    }
    #[handler]
    async fn begin(
        &self,
        ctx: ObjectContext<'_>,
        request: Json<PrepareRequest>,
    ) -> HandlerResult<()> {
        let mut ledger = ctx
            .get::<Json<Ledger>>("ledger")
            .await?
            .ok_or_else(|| err(404, "inference not prepared"))?
            .0;
        ledger.begin(ctx.key(), &request.0)?;
        ctx.set("ledger", Json(ledger));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn req() -> PrepareRequest {
        PrepareRequest {
            call_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            request_digest: "a".repeat(64),
            review_digest: "b".repeat(64),
            model: "fixture".into(),
            attempt: 1,
            amount_microusd: 250_000,
        }
    }
    #[test]
    fn same_identity_replays_reservation_but_dispatch_is_consumed_once() {
        let mut l = Ledger::new("unit");
        assert_eq!(l.prepare("unit", &req()).unwrap(), Stage::Reserved);
        assert_eq!(l.prepare("unit", &req()).unwrap(), Stage::Reserved);
        assert_eq!(l.spent_microusd, 250_000);
        l.begin("unit", &req()).unwrap();
        assert_eq!(
            l.prepare("unit", &req()).unwrap(),
            Stage::DispatchingUnknown
        );
        assert!(l.begin("unit", &req()).is_err());
    }
    #[test]
    fn changed_request_same_id_or_wrong_scope_never_mutates() {
        let mut l = Ledger::new("unit");
        l.prepare("unit", &req()).unwrap();
        let before = l.clone();
        for field in 0..5 {
            let mut changed = req();
            match field {
                0 => changed.request_digest = "c".repeat(64),
                1 => changed.review_digest = "d".repeat(64),
                2 => changed.model = "other".into(),
                3 => changed.attempt = 2,
                _ => changed.amount_microusd = 1,
            };
            assert!(l.prepare("unit", &changed).is_err());
            assert!(l.begin("unit", &changed).is_err());
        }
        assert!(l.begin("other", &req()).is_err());
        assert_eq!(l, before);
    }
    #[test]
    fn rejected_budget_and_capacity_cannot_dispatch_or_reset() {
        let mut l = Ledger::new("unit");
        let mut denied = req();
        denied.amount_microusd = 750_001;
        assert_eq!(l.prepare("unit", &denied).unwrap(), Stage::Denied);
        assert!(l.begin("unit", &denied).is_err());
        for n in 0..MAX_CALLS - 1 {
            let mut item = req();
            item.call_id = ulid::Ulid::from(n as u128).to_string();
            item.amount_microusd = 1;
            l.prepare("unit", &item).unwrap();
        }
        let snapshot = l.clone();
        let mut extra = req();
        extra.call_id = "01ARZ3NDEKTSV4RRFFQ69G5FAW".into();
        assert!(l.prepare("unit", &extra).is_err());
        assert_eq!(l, snapshot);
        assert_eq!(l.prepare("unit", &denied).unwrap(), Stage::Denied);
    }
}
