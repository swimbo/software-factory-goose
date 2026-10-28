//! Unregistered fresh-namespace claim/inference ordering experiment. Fixture only.

use restate_sdk::{prelude::*, serde::Json};
use std::collections::HashSet;

const CAP: u64 = 750_000;
const MAX_RECORDS: usize = 256;
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub worker_id: String,
    pub token: String,
    pub attempt: u32,
    pub issued_ms: u64,
    pub expires_ms: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Call {
    pub call_id: String,
    pub request_digest: String,
    pub review_digest: String,
    pub model: String,
    pub amount_microusd: u64,
    pub worker_id: String,
    pub token: String,
    pub attempt: u32,
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
    call: Call,
    stage: Stage,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema: u8,
    task: String,
    lease: Lease,
    revoked: bool,
    spent: u64,
    records: Vec<Record>,
}
fn error(code: u16, message: &str) -> TerminalError {
    TerminalError::new_with_code(code, message)
}
fn scope(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}
fn ulid(s: &str) -> bool {
    ulid::Ulid::from_string(s).is_ok_and(|u| u.to_string() == s)
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn lease_valid(l: &Lease) -> bool {
    scope(&l.worker_id)
        && ulid(&l.token)
        && l.attempt > 0
        && l.issued_ms < l.expires_ms
        && l.expires_ms - l.issued_ms <= 300_000
}
fn call_valid(c: &Call, l: &Lease) -> bool {
    ulid(&c.call_id)
        && digest(&c.request_digest)
        && digest(&c.review_digest)
        && !c.model.is_empty()
        && c.model.len() <= 256
        && c.model.bytes().all(|c| c.is_ascii_graphic())
        && c.amount_microusd > 0
        && c.worker_id == l.worker_id
        && c.token == l.token
        && c.attempt == l.attempt
}
impl State {
    fn new(task: &str, lease: Lease) -> Result<Self, TerminalError> {
        if !scope(task) || !lease_valid(&lease) {
            return Err(error(400, "invalid fixture lease"));
        }
        Ok(Self {
            schema: 1,
            task: task.into(),
            lease,
            revoked: false,
            spent: 0,
            records: vec![],
        })
    }
    fn check(&self, task: &str) -> Result<(), TerminalError> {
        if self.schema != 1
            || !scope(task)
            || self.task != task
            || !lease_valid(&self.lease)
            || self.records.len() > MAX_RECORDS
        {
            return Err(error(409, "invalid fixture state"));
        }
        let mut seen = HashSet::new();
        let mut spent: u64 = 0;
        for r in &self.records {
            if !call_valid(&r.call, &self.lease) || !seen.insert(&r.call.call_id) {
                return Err(error(409, "invalid call history"));
            }
            let next = spent
                .checked_add(r.call.amount_microusd)
                .filter(|v| *v <= CAP);
            if (r.stage != Stage::Denied) != next.is_some() {
                return Err(error(409, "invalid budget history"));
            }
            if let Some(next) = next {
                spent = next;
            }
        }
        if spent != self.spent {
            return Err(error(409, "invalid budget total"));
        }
        Ok(())
    }
    fn live(&self, now: u64) -> Result<(), TerminalError> {
        if self.revoked || now < self.lease.issued_ms || now >= self.lease.expires_ms {
            return Err(error(409, "lease unavailable"));
        }
        Ok(())
    }
    fn prepare(&mut self, task: &str, call: &Call, now: u64) -> Result<Stage, TerminalError> {
        self.check(task)?;
        self.live(now)?;
        if !call_valid(call, &self.lease) {
            return Err(error(403, "lease or call mismatch"));
        }
        if let Some(r) = self.records.iter().find(|r| r.call.call_id == call.call_id) {
            if r.call != *call {
                return Err(error(409, "call identity conflict"));
            }
            return Ok(r.stage);
        }
        if self.records.len() >= MAX_RECORDS {
            return Err(error(429, "call history full"));
        }
        let next = self
            .spent
            .checked_add(call.amount_microusd)
            .filter(|v| *v <= CAP);
        let stage = if next.is_some() {
            Stage::Reserved
        } else {
            Stage::Denied
        };
        if let Some(next) = next {
            self.spent = next;
        }
        self.records.push(Record {
            call: call.clone(),
            stage,
        });
        Ok(stage)
    }
    fn begin(&mut self, task: &str, call: &Call, now: u64) -> Result<(), TerminalError> {
        self.check(task)?;
        self.live(now)?;
        if !call_valid(call, &self.lease) {
            return Err(error(403, "lease or call mismatch"));
        }
        let r = self
            .records
            .iter_mut()
            .find(|r| r.call.call_id == call.call_id)
            .ok_or_else(|| error(404, "call not prepared"))?;
        if r.call != *call || r.stage != Stage::Reserved {
            return Err(error(409, "call unavailable or unknown"));
        }
        r.stage = Stage::DispatchingUnknown;
        Ok(())
    }
    fn revoke(&mut self, task: &str, lease: &Lease) -> Result<(), TerminalError> {
        self.check(task)?;
        if *lease != self.lease {
            return Err(error(403, "lease mismatch"));
        }
        self.revoked = true;
        Ok(())
    }
    fn inspect(&self, task: &str, call: &Call) -> Result<Stage, TerminalError> {
        self.check(task)?;
        let r = self
            .records
            .iter()
            .find(|r| r.call.call_id == call.call_id)
            .ok_or_else(|| error(404, "call not found"))?;
        if r.call != *call {
            return Err(error(409, "call mismatch"));
        }
        Ok(r.stage)
    }
}
async fn now_ms() -> HandlerResult<u64> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| error(500, "clock unavailable"))?;
    u64::try_from(duration.as_millis()).map_err(|_| error(500, "clock overflow").into())
}

/// Fixture namespace: this is not the existing claim or budget authority and must not be
/// deployed alongside them for the same unit. Trusted lease provisioning is not implemented.
pub struct AtomicInferenceFixture;
#[restate_sdk::object]
impl AtomicInferenceFixture {
    #[handler]
    async fn initialize(&self, ctx: ObjectContext<'_>, lease: Json<Lease>) -> HandlerResult<()> {
        let requested = State::new(ctx.key(), lease.0)?;
        if let Some(existing) = ctx.get::<Json<State>>("state").await? {
            existing.0.check(ctx.key())?;
            if existing.0.lease != requested.lease {
                return Err(error(409, "lease already bound").into());
            }
            return Ok(());
        }
        let now = ctx.run(now_ms).await?;
        requested.live(now)?;
        ctx.set("state", Json(requested));
        Ok(())
    }
    #[handler]
    async fn prepare(
        &self,
        ctx: ObjectContext<'_>,
        call: Json<Call>,
    ) -> HandlerResult<Json<Stage>> {
        let mut state = ctx
            .get::<Json<State>>("state")
            .await?
            .ok_or_else(|| error(404, "lease missing"))?
            .0;
        let before = state.clone();
        let now = ctx.run(now_ms).await?;
        let stage = state.prepare(ctx.key(), &call.0, now)?;
        if state != before {
            ctx.set("state", Json(state));
        }
        Ok(Json(stage))
    }
    #[handler]
    async fn begin(&self, ctx: ObjectContext<'_>, call: Json<Call>) -> HandlerResult<()> {
        let mut state = ctx
            .get::<Json<State>>("state")
            .await?
            .ok_or_else(|| error(404, "lease missing"))?
            .0;
        let now = ctx.run(now_ms).await?;
        state.begin(ctx.key(), &call.0, now)?;
        ctx.set("state", Json(state));
        Ok(())
    }
    #[handler]
    async fn revoke(&self, ctx: ObjectContext<'_>, lease: Json<Lease>) -> HandlerResult<()> {
        let mut state = ctx
            .get::<Json<State>>("state")
            .await?
            .ok_or_else(|| error(404, "lease missing"))?
            .0;
        let before = state.clone();
        state.revoke(ctx.key(), &lease.0)?;
        if state != before {
            ctx.set("state", Json(state));
        }
        Ok(())
    }
    #[handler]
    async fn inspect(
        &self,
        ctx: SharedObjectContext<'_>,
        call: Json<Call>,
    ) -> HandlerResult<Json<Stage>> {
        let state = ctx
            .get::<Json<State>>("state")
            .await?
            .ok_or_else(|| error(404, "lease missing"))?
            .0;
        Ok(Json(state.inspect(ctx.key(), &call.0)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn lease() -> Lease {
        Lease {
            worker_id: "worker".into(),
            token: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            attempt: 1,
            issued_ms: 100,
            expires_ms: 1000,
        }
    }
    fn call() -> Call {
        Call {
            call_id: "01ARZ3NDEKTSV4RRFFQ69G5FAW".into(),
            request_digest: "a".repeat(64),
            review_digest: "b".repeat(64),
            model: "fixture".into(),
            amount_microusd: 250_000,
            worker_id: "worker".into(),
            token: lease().token,
            attempt: 1,
        }
    }
    #[test]
    fn revocation_before_begin_denies_without_refund() {
        let mut s = State::new("task", lease()).unwrap();
        assert_eq!(s.prepare("task", &call(), 200).unwrap(), Stage::Reserved);
        s.revoke("task", &lease()).unwrap();
        assert!(s.begin("task", &call(), 201).is_err());
        assert_eq!(s.spent, 250_000);
    }
    #[test]
    fn begin_before_revocation_is_unknown_and_never_replayed() {
        let mut s = State::new("task", lease()).unwrap();
        s.prepare("task", &call(), 200).unwrap();
        s.begin("task", &call(), 201).unwrap();
        s.revoke("task", &lease()).unwrap();
        assert_eq!(
            s.inspect("task", &call()).unwrap(),
            Stage::DispatchingUnknown
        );
        assert!(s.begin("task", &call(), 202).is_err());
    }
    #[test]
    fn expired_or_changed_binding_fails_closed() {
        let mut s = State::new("task", lease()).unwrap();
        s.prepare("task", &call(), 200).unwrap();
        let snapshot = s.clone();
        assert!(s.begin("task", &call(), 1000).is_err());
        let mut changed = call();
        changed.request_digest = "c".repeat(64);
        assert!(s.begin("task", &changed, 201).is_err());
        changed = call();
        changed.token = "01ARZ3NDEKTSV4RRFFQ69G5FAX".into();
        assert!(s.begin("task", &changed, 201).is_err());
        assert_eq!(s, snapshot);
    }
}
