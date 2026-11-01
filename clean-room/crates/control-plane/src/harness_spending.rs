//! Sole-owner harness spending journal; deliberately unregistered.
//! A private adapter must authenticate root bootstrap, the live launch/lease binding,
//! revocation and route state, and the billing collector. JSON digests bind evidence;
//! they do not authenticate it. Never expose these handlers directly to workers.
//! Before use, reconcile and fence ALL predecessor task/day ledgers and alternate
//! dispatch paths. This module does not migrate, register, dispatch, refund or enable
//! a harness. An unavailable day inventory denies calls, including after midnight.

use restate_sdk::{prelude::*, serde::Json};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const DAY_MS: u64 = 86_400_000;
const MAX_TIME_MS: u64 = 253_402_300_799_999;
const TASK_CAP: u64 = 750_000;
const DAILY_CAP: u64 = 5_000_000;
const MAX_RECORDS: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChargeBound {
    pub id: String,
    /// Reviewed maximum across every invocation/retry of this component, including
    /// all input/output/reasoning/cache/fixed charges. A digest is not price proof.
    pub max_charge_microusd: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteBound {
    pub route_sha256: String,
    pub review_sha256: String,
    /// Root-reviewed tariff for AUDITED USAGE-RATED COSTS, a performance metric.
    /// Absent means provider-billed evidence; existing scope digests remain stable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage_tariff_sha256: Option<String>,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
    pub max_request_bytes: u64,
    pub max_output_tokens: u64,
    /// Sum all components, conservatively including alternative fallback paths.
    /// The protected reviewer must attest that this list covers EVERY possible bill.
    pub components: Vec<ChargeBound>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptScope {
    pub task: String,
    pub attempt: u32,
    pub generation: String,
    pub worker: String,
    pub lease_sha256: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub route: RouteBound,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    pub owner: String,
    pub policy_sha256: String,
    /// Root-authored proof of exclusive reconciliation/fencing; not self-authenticating.
    pub predecessor_fence_sha256: String,
    pub inventory_sha256: String,
    pub observed_at_ms: u64,
    pub approved_daily_cap_microusd: u64,
    pub daily_cap_microusd: u64,
    /// Explicit opening reservation totals; neither map has a missing -> zero default.
    pub opening_tasks: BTreeMap<String, u64>,
    pub opening_days: BTreeMap<u64, u64>,
    pub scopes: Vec<AttemptScope>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Call {
    pub call_id: String,
    pub scope_sha256: String,
    pub request_sha256: String,
    pub sequence: u32,
    pub request_bytes: u64,
    pub output_tokens: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stage {
    Denied,
    Reserved,
    Unknown,
    Complete,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DayInventory {
    pub day: u64,
    pub already_reserved_microusd: u64,
    pub inventory_sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationClaim {
    pub call_id: String,
    pub request_sha256: String,
    pub scope_sha256: String,
    pub manifest_sha256: String,
    /// Authenticated collector evidence IDs. Rated scopes require usage_<64 hex>
    /// derived from stable protected physical dispatch IDs, never provider IDs.
    /// Provider-billed scopes reserve that namespace and use provider evidence IDs.
    pub generation_ids: BTreeSet<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorReceipt {
    pub call_id: String,
    pub request_sha256: String,
    pub scope_sha256: String,
    pub route_sha256: String,
    /// Digest of the complete canonical collector-validated manifest. The adapter
    /// authenticates the collector and verifies every expected component's evidence.
    pub manifest_sha256: String,
    /// Exact reviewed component IDs, including unused fallback alternatives. Each
    /// digest binds the collector's canonical component evidence: either complete
    /// provider-billed receipts, or an authenticated dispatch-journal closure that
    /// proves this alternative was not dispatched. Missing logs/usage are NEVER
    /// a zero-cost disposition. The protected collector must verify that distinction.
    pub components: BTreeMap<String, String>,
    pub generation_ids: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billed_microusd: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage_rating: Option<UsageRatingEvidence>,
}
/// Collector-authenticated audited usage rating; hashes bind, never authenticate,
/// model data. This metric never refunds a conservative spending reservation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageRatingEvidence {
    pub tariff_sha256: String,
    pub audit_sha256: String,
    pub usage_rated_microusd: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    call: Call,
    task: String,
    day: u64,
    reserved_microusd: u64,
    stage: Stage,
    receipt: Option<CollectorReceipt>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema: u8,
    bootstrap: Bootstrap,
    task_totals: BTreeMap<String, u64>,
    day_totals: BTreeMap<u64, u64>,
    day_admissions: BTreeMap<u64, DayInventory>,
    revoked: BTreeSet<String>,
    records: Vec<Record>,
    generation_claims: BTreeMap<String, String>,
    claims: BTreeMap<String, GenerationClaim>,
    #[serde(default)]
    admitted_scopes: BTreeMap<String, AttemptScope>,
}
fn err(code: u16, message: &str) -> TerminalError {
    TerminalError::new_with_code(code, message)
}
fn id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.:/".contains(&b))
}
fn hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn interval(a: u64, b: u64) -> bool {
    a > 0 && a < b && b <= MAX_TIME_MS
}
impl AttemptScope {
    pub fn digest(&self) -> Result<String, TerminalError> {
        let raw = serde_json::to_vec(self).map_err(|_| err(400, "invalid scope"))?;
        Ok(format!("{:x}", Sha256::digest(raw)))
    }
    fn bound(&self) -> Result<u64, TerminalError> {
        let r = &self.route;
        if !id(&self.task)
            || !id(&self.generation)
            || !id(&self.worker)
            || self.attempt == 0
            || !hex(&self.lease_sha256)
            || !interval(self.issued_at_ms, self.expires_at_ms)
            || !interval(r.valid_from_ms, r.valid_until_ms)
            || !hex(&r.route_sha256)
            || !hex(&r.review_sha256)
            || r.usage_tariff_sha256.as_ref().is_some_and(|v| !hex(v))
            || !(1..=1_048_576).contains(&r.max_request_bytes)
            || !(1..=1_000_000).contains(&r.max_output_tokens)
            || r.components.is_empty()
            || r.components.len() > 32
        {
            return Err(err(400, "invalid reviewed scope"));
        }
        let mut seen = BTreeSet::new();
        let mut total = 0_u64;
        for c in &r.components {
            if !id(&c.id) || c.max_charge_microusd == 0 || !seen.insert(&c.id) {
                return Err(err(400, "invalid route components"));
            }
            total = total
                .checked_add(c.max_charge_microusd)
                .ok_or_else(|| err(400, "route bound overflow"))?;
        }
        Ok(total)
    }
    fn live(&self, now: u64) -> bool {
        (self.issued_at_ms..self.expires_at_ms).contains(&now)
            && (self.route.valid_from_ms..self.route.valid_until_ms).contains(&now)
    }
}
impl Bootstrap {
    fn validate(&self, owner: &str) -> Result<(), TerminalError> {
        if !id(owner)
            || self.owner != owner
            || !hex(&self.policy_sha256)
            || !hex(&self.predecessor_fence_sha256)
            || !hex(&self.inventory_sha256)
            || self.observed_at_ms == 0
            || self.observed_at_ms > MAX_TIME_MS
            || self.daily_cap_microusd == 0
            || self.approved_daily_cap_microusd > DAILY_CAP
            || self.daily_cap_microusd > self.approved_daily_cap_microusd
            || self.opening_tasks.is_empty()
            || self.opening_tasks.len() > 4096
            || self.opening_days.is_empty()
            || self.opening_days.len() > 3660
            || self.scopes.len() > 1024
        {
            return Err(err(400, "invalid spending bootstrap"));
        }
        if self
            .opening_tasks
            .iter()
            .any(|(k, v)| !id(k) || *v > TASK_CAP)
            || self.opening_days.keys().any(|v| *v > MAX_TIME_MS / DAY_MS)
        {
            return Err(err(400, "invalid opening inventory"));
        }
        let mut scopes = BTreeSet::new();
        let mut attempts = BTreeSet::new();
        for scope in &self.scopes {
            scope.bound()?;
            if !self.opening_tasks.contains_key(&scope.task)
                || !scopes.insert(scope.digest()?)
                || !attempts.insert((&scope.task, scope.attempt))
            {
                return Err(err(400, "duplicate or uninventoried attempt"));
            }
        }
        Ok(())
    }
}
impl State {
    fn new(owner: &str, bootstrap: Bootstrap, now: u64) -> Result<Self, TerminalError> {
        bootstrap.validate(owner)?;
        if now > MAX_TIME_MS
            || now < bootstrap.observed_at_ms
            || now - bootstrap.observed_at_ms > 300_000
            || !bootstrap.opening_days.contains_key(&(now / DAY_MS))
        {
            return Err(err(409, "current inventory unavailable"));
        }
        Ok(Self {
            schema: 1,
            task_totals: bootstrap.opening_tasks.clone(),
            day_totals: bootstrap.opening_days.clone(),
            bootstrap,
            day_admissions: BTreeMap::new(),
            revoked: BTreeSet::new(),
            records: vec![],
            generation_claims: BTreeMap::new(),
            claims: BTreeMap::new(),
            admitted_scopes: BTreeMap::new(),
        })
    }
    fn scope(&self, digest: &str) -> Result<&AttemptScope, TerminalError> {
        self.bootstrap
            .scopes
            .iter()
            .find(|s| s.digest().ok().as_deref() == Some(digest))
            .or_else(|| self.admitted_scopes.get(digest))
            .ok_or_else(|| err(403, "scope unavailable"))
    }
    fn check(&self, owner: &str) -> Result<(), TerminalError> {
        self.bootstrap.validate(owner)?;
        let mut identities = BTreeSet::new();
        for s in self
            .bootstrap
            .scopes
            .iter()
            .chain(self.admitted_scopes.values())
        {
            s.bound()?;
            if !self.bootstrap.opening_tasks.contains_key(&s.task)
                || !identities.insert((&s.task, s.attempt))
            {
                return Err(err(409, "invalid admitted scope"));
            }
        }
        for (digest, scope) in &self.admitted_scopes {
            if &scope.digest()? != digest || scope.expires_at_ms - scope.issued_at_ms > 300_000 {
                return Err(err(409, "invalid admitted scope digest"));
            }
        }
        if self.schema != 1
            || identities.len() > 1024
            || self.records.len() > MAX_RECORDS
            || self.day_admissions.len() + self.bootstrap.opening_days.len() > 3660
            || self.generation_claims.len() > MAX_RECORDS * 32
            || self.claims.len() > self.records.len()
            || self.revoked.iter().any(|v| self.scope(v).is_err())
        {
            return Err(err(409, "invalid spending state"));
        }
        let mut tasks = self.bootstrap.opening_tasks.clone();
        let mut days = self.bootstrap.opening_days.clone();
        for (day, inv) in &self.day_admissions {
            if *day != inv.day
                || *day > MAX_TIME_MS / DAY_MS
                || !hex(&inv.inventory_sha256)
                || days.insert(*day, inv.already_reserved_microusd).is_some()
            {
                return Err(err(409, "invalid day inventory"));
            }
        }
        let mut seen = BTreeSet::new();
        let mut sequence: BTreeMap<&str, (u32, Stage)> = BTreeMap::new();
        for r in &self.records {
            let scope = self.scope(&r.call.scope_sha256)?;
            self.validate_call(&r.call, scope)?;
            let expected = sequence.get(r.call.scope_sha256.as_str());
            let start = scope.issued_at_ms.max(scope.route.valid_from_ms);
            let end = scope.expires_at_ms.min(scope.route.valid_until_ms);
            let day_start = r
                .day
                .checked_mul(DAY_MS)
                .ok_or_else(|| err(409, "invalid reservation day"))?;
            let day_end = day_start
                .checked_add(DAY_MS)
                .ok_or_else(|| err(409, "invalid reservation day"))?;
            if day_start >= end || day_end <= start || start >= end {
                return Err(err(409, "reservation outside scoped time"));
            }
            if !seen.insert(&r.call.call_id)
                || r.task != scope.task
                || r.reserved_microusd != scope.bound()?
                || expected.map_or(r.call.sequence != 0, |(n, stage)| {
                    *stage != Stage::Complete || n.checked_add(1) != Some(r.call.sequence)
                })
            {
                return Err(err(409, "invalid spending history"));
            }
            sequence.insert(&r.call.scope_sha256, (r.call.sequence, r.stage));
            let t = tasks
                .get_mut(&r.task)
                .ok_or_else(|| err(409, "unknown task inventory"))?;
            let d = days
                .get_mut(&r.day)
                .ok_or_else(|| err(409, "unknown day inventory"))?;
            let next_task = t.checked_add(r.reserved_microusd);
            let next_day = d.checked_add(r.reserved_microusd);
            let admitted = next_task.is_some_and(|v| v <= TASK_CAP)
                && next_day.is_some_and(|v| v <= self.bootstrap.daily_cap_microusd);
            if (r.stage != Stage::Denied) != admitted {
                return Err(err(409, "inconsistent spending reservation"));
            }
            if admitted {
                *t = next_task.unwrap();
                *d = next_day.unwrap();
            }
            if (r.stage == Stage::Complete) != r.receipt.is_some() {
                return Err(err(409, "invalid receipt state"));
            }
            if let Some(receipt) = &r.receipt {
                self.validate_receipt(r, receipt)?;
            }
        }
        if tasks != self.task_totals || days != self.day_totals {
            return Err(err(409, "inconsistent spending totals"));
        }
        for (generation, call_id) in &self.generation_claims {
            let claim = self
                .claims
                .get(call_id)
                .ok_or_else(|| err(409, "missing generation claim"))?;
            if !claim.generation_ids.contains(generation) {
                return Err(err(409, "conflicting generation claim"));
            }
        }
        for (call_id, claim) in &self.claims {
            self.validate_claim(claim)?;
            if call_id != &claim.call_id
                || claim
                    .generation_ids
                    .iter()
                    .any(|v| self.generation_claims.get(v) != Some(call_id))
            {
                return Err(err(409, "incomplete generation claim"));
            }
        }
        Ok(())
    }
    fn admit_attempt(
        &mut self,
        owner: &str,
        scope: &AttemptScope,
        now: u64,
    ) -> Result<String, TerminalError> {
        self.check(owner)?;
        scope.bound()?;
        let digest = scope.digest()?;
        if let Ok(old) = self.scope(&digest) {
            return if old == scope {
                Ok(digest)
            } else {
                Err(err(409, "scope identity conflict"))
            };
        }
        if self.bootstrap.scopes.len() + self.admitted_scopes.len() >= 1024
            || !self.bootstrap.opening_tasks.contains_key(&scope.task)
            || !scope.live(now)
            || scope.expires_at_ms - scope.issued_at_ms > 300_000
        {
            return Err(err(409, "new attempt unavailable"));
        }
        for prior in self
            .bootstrap
            .scopes
            .iter()
            .chain(self.admitted_scopes.values())
            .filter(|s| s.task == scope.task)
        {
            if scope.attempt <= prior.attempt || !self.revoked.contains(&prior.digest()?) {
                return Err(err(409, "predecessor attempt not closed"));
            }
        }
        if self
            .records
            .iter()
            .any(|r| r.task == scope.task && matches!(r.stage, Stage::Reserved | Stage::Unknown))
        {
            return Err(err(409, "predecessor inference unresolved"));
        }
        self.admitted_scopes.insert(digest.clone(), scope.clone());
        Ok(digest)
    }
    fn validate_call(&self, c: &Call, scope: &AttemptScope) -> Result<(), TerminalError> {
        if !id(&c.call_id)
            || !hex(&c.scope_sha256)
            || !hex(&c.request_sha256)
            || c.request_bytes == 0
            || c.request_bytes > scope.route.max_request_bytes
            || c.output_tokens == 0
            || c.output_tokens > scope.route.max_output_tokens
        {
            return Err(err(400, "invalid inference binding"));
        }
        Ok(())
    }
    fn reserve(&mut self, owner: &str, call: &Call, now: u64) -> Result<Stage, TerminalError> {
        self.check(owner)?;
        let scope = self.scope(&call.scope_sha256)?;
        self.validate_call(call, scope)?;
        if let Some(r) = self.records.iter().find(|r| r.call.call_id == call.call_id) {
            return if r.call == *call {
                Ok(r.stage)
            } else {
                Err(err(409, "call identity conflict"))
            };
        }
        if self.records.len() >= MAX_RECORDS
            || !scope.live(now)
            || self.revoked.contains(&call.scope_sha256)
        {
            return Err(err(409, "attempt unavailable"));
        }
        if let Some(prior) = self
            .records
            .iter()
            .rev()
            .find(|r| r.call.scope_sha256 == call.scope_sha256)
        {
            if prior.stage != Stage::Complete
                || prior.call.sequence.checked_add(1) != Some(call.sequence)
            {
                return Err(err(409, "unresolved or reused sequence"));
            }
        } else if call.sequence != 0 {
            return Err(err(409, "sequence unavailable"));
        }
        let task = scope.task.clone();
        let amount = scope.bound()?;
        let day = now / DAY_MS;
        let t = self
            .task_totals
            .get(&task)
            .ok_or_else(|| err(409, "task inventory unavailable"))?;
        let d = self
            .day_totals
            .get(&day)
            .ok_or_else(|| err(409, "day inventory unavailable"))?;
        let next_task = t.checked_add(amount).filter(|v| *v <= TASK_CAP);
        let next_day = d
            .checked_add(amount)
            .filter(|v| *v <= self.bootstrap.daily_cap_microusd);
        let stage = if let (Some(t), Some(d)) = (next_task, next_day) {
            self.task_totals.insert(task.clone(), t);
            self.day_totals.insert(day, d);
            Stage::Reserved
        } else {
            Stage::Denied
        };
        self.records.push(Record {
            call: call.clone(),
            task,
            day,
            reserved_microusd: amount,
            stage,
            receipt: None,
        });
        Ok(stage)
    }
    fn begin(&mut self, owner: &str, call: &Call, now: u64) -> Result<(), TerminalError> {
        self.check(owner)?;
        let scope = self.scope(&call.scope_sha256)?;
        if !scope.live(now) || self.revoked.contains(&call.scope_sha256) {
            return Err(err(409, "attempt unavailable"));
        }
        let r = self
            .records
            .iter_mut()
            .find(|r| r.call.call_id == call.call_id)
            .ok_or_else(|| err(404, "call not reserved"))?;
        if r.call != *call || r.stage != Stage::Reserved || r.day != now / DAY_MS {
            return Err(err(409, "dispatch unavailable or ambiguous"));
        }
        r.stage = Stage::Unknown;
        Ok(())
    }
    fn validate_claim(&self, claim: &GenerationClaim) -> Result<(), TerminalError> {
        let r = self
            .records
            .iter()
            .find(|r| r.call.call_id == claim.call_id)
            .ok_or_else(|| err(404, "dispatched call unavailable"))?;
        let rated = self
            .scope(&r.call.scope_sha256)?
            .route
            .usage_tariff_sha256
            .is_some();
        if !matches!(r.stage, Stage::Unknown | Stage::Complete)
            || r.call.request_sha256 != claim.request_sha256
            || r.call.scope_sha256 != claim.scope_sha256
            || !hex(&claim.manifest_sha256)
            || claim.generation_ids.is_empty()
            || claim.generation_ids.len() > 32
            || claim.generation_ids.iter().any(|v| {
                !id(v)
                    || if rated {
                        !v.strip_prefix("usage_").is_some_and(hex)
                    } else {
                        v.starts_with("usage_")
                    }
            })
        {
            return Err(err(403, "invalid generation claim"));
        }
        Ok(())
    }
    fn claim_receipts(
        &mut self,
        owner: &str,
        claim: &GenerationClaim,
    ) -> Result<(), TerminalError> {
        self.check(owner)?;
        self.validate_claim(claim)?;
        let previous = self.claims.get(&claim.call_id);
        if previous.is_some_and(|v| v != claim)
            || claim.generation_ids.iter().any(|v| {
                self.generation_claims
                    .get(v)
                    .is_some_and(|old| old != &claim.call_id)
            })
            || self
                .generation_claims
                .len()
                .checked_add(
                    claim
                        .generation_ids
                        .iter()
                        .filter(|v| !self.generation_claims.contains_key(*v))
                        .count(),
                )
                .is_none_or(|n| n > MAX_RECORDS * 32)
        {
            return Err(err(409, "generation identity conflict"));
        }
        for generation in &claim.generation_ids {
            self.generation_claims
                .insert(generation.clone(), claim.call_id.clone());
        }
        self.claims.insert(claim.call_id.clone(), claim.clone());
        Ok(())
    }
    fn validate_receipt(
        &self,
        r: &Record,
        receipt: &CollectorReceipt,
    ) -> Result<(), TerminalError> {
        let scope = self.scope(&r.call.scope_sha256)?;
        let expected: BTreeSet<_> = scope
            .route
            .components
            .iter()
            .map(|v| v.id.as_str())
            .collect();
        let actual: BTreeSet<_> = receipt.components.keys().map(String::as_str).collect();
        let claim = GenerationClaim {
            call_id: receipt.call_id.clone(),
            request_sha256: receipt.request_sha256.clone(),
            scope_sha256: receipt.scope_sha256.clone(),
            manifest_sha256: receipt.manifest_sha256.clone(),
            generation_ids: receipt.generation_ids.clone(),
        };
        let amount = match (
            &scope.route.usage_tariff_sha256,
            receipt.billed_microusd,
            &receipt.usage_rating,
        ) {
            (None, Some(billed), None) => billed,
            (Some(tariff), None, Some(rating))
                if &rating.tariff_sha256 == tariff
                    && hex(&rating.tariff_sha256)
                    && hex(&rating.audit_sha256) =>
            {
                rating.usage_rated_microusd
            }
            _ => return Err(err(403, "receipt evidence mode or tariff mismatch")),
        };
        if receipt.call_id != r.call.call_id
            || receipt.request_sha256 != r.call.request_sha256
            || receipt.scope_sha256 != r.call.scope_sha256
            || receipt.route_sha256 != scope.route.route_sha256
            || !hex(&receipt.manifest_sha256)
            || expected != actual
            || receipt.components.values().any(|v| !hex(v))
            || amount > r.reserved_microusd
        {
            return Err(err(403, "incomplete or conflicting billing receipt"));
        }
        self.validate_claim(&claim)?;
        if self.claims.get(&claim.call_id) != Some(&claim)
            || claim
                .generation_ids
                .iter()
                .any(|v| self.generation_claims.get(v) != Some(&claim.call_id))
        {
            return Err(err(403, "unclaimed billing receipt"));
        }
        Ok(())
    }
    fn complete(&mut self, owner: &str, receipt: &CollectorReceipt) -> Result<(), TerminalError> {
        self.check(owner)?;
        let r = self
            .records
            .iter()
            .find(|r| r.call.call_id == receipt.call_id)
            .ok_or_else(|| err(404, "dispatched call unavailable"))?;
        self.validate_receipt(r, receipt)?;
        if r.stage == Stage::Complete {
            return if r.receipt.as_ref() == Some(receipt) {
                Ok(())
            } else {
                Err(err(409, "billing identity conflict"))
            };
        }
        if r.stage != Stage::Unknown {
            return Err(err(409, "call not dispatched"));
        }
        let r = self
            .records
            .iter_mut()
            .find(|r| r.call.call_id == receipt.call_id)
            .unwrap();
        r.stage = Stage::Complete;
        r.receipt = Some(receipt.clone());
        Ok(())
    }
    fn admit_day(
        &mut self,
        owner: &str,
        inv: &DayInventory,
        now: u64,
    ) -> Result<(), TerminalError> {
        self.check(owner)?;
        if now > MAX_TIME_MS || inv.day != now / DAY_MS || !hex(&inv.inventory_sha256) {
            return Err(err(400, "current day inventory required"));
        }
        if let Some(old) = self.day_admissions.get(&inv.day) {
            return if old == inv {
                Ok(())
            } else {
                Err(err(409, "day already inventoried"))
            };
        }
        if self.day_totals.contains_key(&inv.day) || self.day_totals.len() >= 3660 {
            return Err(err(409, "day already inventoried or history full"));
        }
        self.day_admissions.insert(inv.day, inv.clone());
        self.day_totals
            .insert(inv.day, inv.already_reserved_microusd);
        Ok(())
    }
    fn revoke(&mut self, owner: &str, scope: &str) -> Result<(), TerminalError> {
        self.check(owner)?;
        self.scope(scope)?;
        self.revoked.insert(scope.into());
        Ok(())
    }
}

async fn now_ms() -> HandlerResult<u64> {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| err(500, "clock unavailable"))?;
    u64::try_from(d.as_millis()).map_err(|_| err(500, "clock overflow").into())
}
async fn load(ctx: &ObjectContext<'_>) -> HandlerResult<State> {
    Ok(ctx
        .get::<Json<State>>("state")
        .await?
        .ok_or_else(|| err(404, "spending authority unavailable"))?
        .0)
}
#[cfg(feature = "registry-sidecar")]
fn enter_registry() -> Result<Option<crate::registry_journal_gate::JournalAdmission>, TerminalError>
{
    crate::registry_journal_gate::enter_production()
        .map_err(|_| err(503, "registry transition blocks spending mutation"))
}
#[cfg(not(feature = "registry-sidecar"))]
fn enter_registry() -> Result<Option<()>, TerminalError> {
    Ok(None)
}
/// Trusted-adapter-only journal. Not registered in any endpoint. These handlers
/// provide serialization, not ingress authentication or proof of exclusive ownership.
pub struct HarnessSpending;
#[restate_sdk::object]
impl HarnessSpending {
    #[handler]
    async fn admit_attempt(
        &self,
        ctx: ObjectContext<'_>,
        scope: Json<AttemptScope>,
    ) -> HandlerResult<Json<String>> {
        let _admission = enter_registry()?;
        let mut s = load(&ctx).await?;
        let now = ctx.run(now_ms).await?;
        let digest = s.admit_attempt(ctx.key(), &scope.0, now)?;
        ctx.set("state", Json(s));
        Ok(Json(digest))
    }
    #[handler]
    async fn initialize(
        &self,
        ctx: ObjectContext<'_>,
        bootstrap: Json<Bootstrap>,
    ) -> HandlerResult<()> {
        let _admission = enter_registry()?;
        if let Some(old) = ctx.get::<Json<State>>("state").await? {
            old.0.check(ctx.key())?;
            if old.0.bootstrap != bootstrap.0 {
                return Err(err(409, "bootstrap already bound").into());
            }
            return Ok(());
        }
        let now = ctx.run(now_ms).await?;
        ctx.set("state", Json(State::new(ctx.key(), bootstrap.0, now)?));
        Ok(())
    }
    #[handler]
    async fn reserve(
        &self,
        ctx: ObjectContext<'_>,
        call: Json<Call>,
    ) -> HandlerResult<Json<Stage>> {
        let _admission = enter_registry()?;
        let mut s = load(&ctx).await?;
        let now = ctx.run(now_ms).await?;
        let stage = s.reserve(ctx.key(), &call.0, now)?;
        ctx.set("state", Json(s));
        Ok(Json(stage))
    }
    #[handler]
    async fn begin(&self, ctx: ObjectContext<'_>, call: Json<Call>) -> HandlerResult<Json<bool>> {
        let _admission = enter_registry()?;
        let mut s = load(&ctx).await?;
        let now = ctx.run(now_ms).await?;
        s.begin(ctx.key(), &call.0, now)?;
        ctx.set("state", Json(s));
        Ok(Json(true))
    }
    #[handler]
    async fn claim_receipts(
        &self,
        ctx: ObjectContext<'_>,
        claim: Json<GenerationClaim>,
    ) -> HandlerResult<()> {
        let _admission = enter_registry()?;
        let mut s = load(&ctx).await?;
        s.claim_receipts(ctx.key(), &claim.0)?;
        ctx.set("state", Json(s));
        Ok(())
    }
    #[handler]
    async fn complete(
        &self,
        ctx: ObjectContext<'_>,
        receipt: Json<CollectorReceipt>,
    ) -> HandlerResult<()> {
        let _admission = enter_registry()?;
        let mut s = load(&ctx).await?;
        s.complete(ctx.key(), &receipt.0)?;
        ctx.set("state", Json(s));
        Ok(())
    }
    #[handler]
    async fn admit_day(
        &self,
        ctx: ObjectContext<'_>,
        inventory: Json<DayInventory>,
    ) -> HandlerResult<()> {
        let _admission = enter_registry()?;
        let mut s = load(&ctx).await?;
        let now = ctx.run(now_ms).await?;
        s.admit_day(ctx.key(), &inventory.0, now)?;
        ctx.set("state", Json(s));
        Ok(())
    }
    #[handler]
    async fn revoke(&self, ctx: ObjectContext<'_>, scope_sha256: String) -> HandlerResult<()> {
        let _admission = enter_registry()?;
        let mut s = load(&ctx).await?;
        s.revoke(ctx.key(), &scope_sha256)?;
        ctx.set("state", Json(s));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_daily_ceiling_cannot_be_raised_by_bootstrap() {
        let mut b = bootstrap();
        b.approved_daily_cap_microusd = 5_000_001;
        b.daily_cap_microusd = 5_000_001;
        assert!(State::new("factory", b, 100).is_err());
    }
    #[test]
    fn future_attempts_require_closed_predecessors_and_retain_task_spend() {
        let mut s = State::new("factory", bootstrap(), 100).unwrap();
        let first = call(&s, "task", 0);
        s.reserve("factory", &first, 101).unwrap();
        s.begin("factory", &first, 102).unwrap();
        let mut next = scope("task");
        next.attempt = 2;
        next.issued_at_ms = 200;
        next.expires_at_ms = 1000;
        let before = s.clone();
        assert!(s.admit_attempt("factory", &next, 201).is_err());
        assert_eq!(s, before);
        s.revoke("factory", &first.scope_sha256).unwrap();
        assert!(s.admit_attempt("factory", &next, 201).is_err());
        let r = receipt(&s, &first);
        claim(&mut s, &r);
        s.complete("factory", &r).unwrap();
        let digest = s.admit_attempt("factory", &next, 201).unwrap();
        let before = s.clone();
        assert_eq!(s.admit_attempt("factory", &next, 1001).unwrap(), digest);
        assert_eq!(s, before);
        let second = Call {
            call_id: "task-second".into(),
            scope_sha256: digest.clone(),
            ..first.clone()
        };
        s.reserve("factory", &second, 202).unwrap();
        assert_eq!(s.task_totals["task"], 600_000);
        s.begin("factory", &second, 203).unwrap();
        let r = receipt(&s, &second);
        claim(&mut s, &r);
        s.complete("factory", &r).unwrap();
        s.revoke("factory", &digest).unwrap();
        next.attempt = 3;
        next.issued_at_ms = 300;
        next.expires_at_ms = 1000;
        let digest = s.admit_attempt("factory", &next, 301).unwrap();
        assert_eq!(
            s.reserve(
                "factory",
                &Call {
                    call_id: "task-third".into(),
                    scope_sha256: digest,
                    ..first
                },
                302
            )
            .unwrap(),
            Stage::Denied
        );
        let decoded: State = serde_json::from_slice(&serde_json::to_vec(&s).unwrap()).unwrap();
        decoded.check("factory").unwrap();
        assert_eq!(decoded.task_totals["task"], 600_000);
    }
    #[test]
    fn empty_catalog_accepts_later_root_attempt_without_new_task_inventory() {
        let mut b = bootstrap();
        b.scopes.clear();
        let mut s = State::new("factory", b, 100).unwrap();
        let mut next = scope("task");
        next.expires_at_ms = 1000;
        assert!(s.admit_attempt("factory", &next, 101).is_ok());
        let mut unknown = next;
        unknown.task = "not-inventoried".into();
        let before = s.clone();
        assert!(s.admit_attempt("factory", &unknown, 101).is_err());
        assert_eq!(s, before);
    }
    fn bootstrap() -> Bootstrap {
        Bootstrap {
            owner: "factory".into(),
            policy_sha256: "a".repeat(64),
            predecessor_fence_sha256: "b".repeat(64),
            inventory_sha256: "c".repeat(64),
            observed_at_ms: 100,
            approved_daily_cap_microusd: 1_000_000,
            daily_cap_microusd: 1_000_000,
            opening_tasks: [("task".into(), 0), ("other".into(), 0)].into(),
            opening_days: [(0, 0)].into(),
            scopes: vec![scope("task"), scope("other")],
        }
    }
    fn scope(task: &str) -> AttemptScope {
        AttemptScope {
            task: task.into(),
            attempt: 1,
            generation: "generation".into(),
            worker: "worker".into(),
            lease_sha256: "d".repeat(64),
            issued_at_ms: 100,
            expires_at_ms: DAY_MS * 2,
            route: RouteBound {
                route_sha256: "e".repeat(64),
                review_sha256: "f".repeat(64),
                usage_tariff_sha256: None,
                valid_from_ms: 100,
                valid_until_ms: DAY_MS * 2,
                max_request_bytes: 65536,
                max_output_tokens: 100,
                components: vec![
                    ChargeBound {
                        id: "classifier".into(),
                        max_charge_microusd: 100_000,
                    },
                    ChargeBound {
                        id: "answer".into(),
                        max_charge_microusd: 200_000,
                    },
                ],
            },
        }
    }
    fn call(s: &State, task: &str, sequence: u32) -> Call {
        let scope = s.bootstrap.scopes.iter().find(|v| v.task == task).unwrap();
        Call {
            call_id: format!("{task}-{sequence}"),
            scope_sha256: scope.digest().unwrap(),
            request_sha256: "1".repeat(64),
            sequence,
            request_bytes: 1024,
            output_tokens: 100,
        }
    }
    fn receipt(s: &State, c: &Call) -> CollectorReceipt {
        let record = s.records.iter().find(|r| r.call == *c).unwrap();
        CollectorReceipt {
            call_id: c.call_id.clone(),
            request_sha256: c.request_sha256.clone(),
            scope_sha256: c.scope_sha256.clone(),
            route_sha256: "e".repeat(64),
            manifest_sha256: "2".repeat(64),
            generation_ids: [format!("provider/{}", c.call_id)].into(),
            components: [
                ("classifier".into(), "3".repeat(64)),
                ("answer".into(), "4".repeat(64)),
            ]
            .into(),
            billed_microusd: Some(record.reserved_microusd - 1),
            usage_rating: None,
        }
    }
    fn claim(s: &mut State, r: &CollectorReceipt) {
        s.claim_receipts(
            "factory",
            &GenerationClaim {
                call_id: r.call_id.clone(),
                request_sha256: r.request_sha256.clone(),
                scope_sha256: r.scope_sha256.clone(),
                manifest_sha256: r.manifest_sha256.clone(),
                generation_ids: r.generation_ids.clone(),
            },
        )
        .unwrap();
    }
    #[test]
    fn both_caps_atomic_idempotent_and_unknown_never_released() {
        let mut s = State::new("factory", bootstrap(), 100).unwrap();
        let c = call(&s, "task", 0);
        assert_eq!(s.reserve("factory", &c, 101).unwrap(), Stage::Reserved);
        let before = s.clone();
        assert_eq!(s.reserve("factory", &c, 101).unwrap(), Stage::Reserved);
        assert_eq!(s, before);
        s.begin("factory", &c, 102).unwrap();
        assert!(s.begin("factory", &c, 102).is_err());
        assert!(s.reserve("factory", &call(&s, "task", 1), 103).is_err());
        assert_eq!(s.task_totals["task"], 300_000);
        assert_eq!(s.day_totals[&0], 300_000);
        let r = receipt(&s, &c);
        claim(&mut s, &r);
        s.complete("factory", &r).unwrap();
        assert_eq!(s.task_totals["task"], 300_000); // No refund from actual cost.
        s.reserve("factory", &call(&s, "task", 1), 104).unwrap();
        assert_eq!(s.day_totals[&0], 600_000);
    }
    #[test]
    fn daily_across_tasks_task_across_days_no_default_reset() {
        let mut b = bootstrap();
        b.opening_days.insert(0, 500_000);
        let mut s = State::new("factory", b, 100).unwrap();
        let a = call(&s, "task", 0);
        s.reserve("factory", &a, 101).unwrap();
        let other = call(&s, "other", 0);
        assert_eq!(s.reserve("factory", &other, 101).unwrap(), Stage::Denied);
        assert_eq!(s.task_totals["other"], 0);
        s.begin("factory", &a, 102).unwrap();
        let r = receipt(&s, &a);
        claim(&mut s, &r);
        s.complete("factory", &r).unwrap();
        let next = call(&s, "task", 1);
        assert!(s.reserve("factory", &next, DAY_MS + 1).is_err());
        s.admit_day(
            "factory",
            &DayInventory {
                day: 1,
                already_reserved_microusd: 0,
                inventory_sha256: "5".repeat(64),
            },
            DAY_MS + 1,
        )
        .unwrap();
        s.reserve("factory", &next, DAY_MS + 1).unwrap();
        assert_eq!(s.task_totals["task"], 600_000);
        s.begin("factory", &next, DAY_MS + 2).unwrap();
        let r = receipt(&s, &next);
        claim(&mut s, &r);
        s.complete("factory", &r).unwrap();
        assert_eq!(
            s.reserve("factory", &call(&s, "task", 2), DAY_MS + 3)
                .unwrap(),
            Stage::Denied
        );
        assert_eq!(s.day_totals[&1], 300_000);
    }
    #[test]
    fn wrong_identity_expiry_changed_payload_and_incomplete_receipts_do_not_mutate() {
        let mut s = State::new("factory", bootstrap(), 100).unwrap();
        let c = call(&s, "task", 0);
        let before = s.clone();
        assert!(s.reserve("other", &c, 101).is_err());
        assert!(s.reserve("factory", &c, DAY_MS * 2).is_err());
        let mut bad = c.clone();
        bad.scope_sha256 = "9".repeat(64);
        assert!(s.reserve("factory", &bad, 101).is_err());
        assert_eq!(s, before);
        s.reserve("factory", &c, 101).unwrap();
        let before = s.clone();
        bad = c.clone();
        bad.request_sha256 = "8".repeat(64);
        assert!(s.reserve("factory", &bad, 101).is_err());
        assert_eq!(s, before);
        assert!(s.begin("factory", &c, DAY_MS + 1).is_err());
        s.begin("factory", &c, 102).unwrap();
        let before = s.clone();
        let mut r = receipt(&s, &c);
        r.components.remove("classifier");
        assert!(s.complete("factory", &r).is_err());
        assert_eq!(s, before);
        let r = receipt(&s, &c);
        claim(&mut s, &r);
        s.complete("factory", &r).unwrap();
        let before = s.clone();
        claim(&mut s, &r);
        s.complete("factory", &r).unwrap();
        assert_eq!(s, before);
        let mut altered = r;
        altered.manifest_sha256 = "6".repeat(64);
        assert!(s.complete("factory", &altered).is_err());
        assert_eq!(s, before);
    }
    #[test]
    fn generation_claims_atomic_global_and_durable_in_state() {
        let mut s = State::new("factory", bootstrap(), 100).unwrap();
        let a = call(&s, "task", 0);
        let b = call(&s, "other", 0);
        for c in [&a, &b] {
            s.reserve("factory", c, 101).unwrap();
            s.begin("factory", c, 102).unwrap();
        }
        let r = receipt(&s, &a);
        let before = s.clone();
        assert!(s.complete("factory", &r).is_err());
        assert_eq!(s, before);
        claim(&mut s, &r);
        let serialized = serde_json::to_vec(&s).unwrap();
        let mut restored: State = serde_json::from_slice(&serialized).unwrap();
        restored.check("factory").unwrap();
        let mut conflicting = GenerationClaim {
            call_id: b.call_id.clone(),
            request_sha256: b.request_sha256.clone(),
            scope_sha256: b.scope_sha256.clone(),
            manifest_sha256: "8".repeat(64),
            generation_ids: r.generation_ids.clone(),
        };
        conflicting.generation_ids.insert("provider/new-id".into());
        let before = restored.clone();
        assert!(restored.claim_receipts("factory", &conflicting).is_err());
        assert_eq!(restored, before); // New ID was not partially claimed.
        restored.complete("factory", &r).unwrap();
        assert_eq!(restored.task_totals["task"], 300_000);
    }
    #[test]
    fn revocation_and_cross_midnight_begin_never_dispatch() {
        let mut s = State::new("factory", bootstrap(), 100).unwrap();
        let c = call(&s, "task", 0);
        s.reserve("factory", &c, 101).unwrap();
        assert!(s.begin("factory", &c, DAY_MS + 1).is_err());
        s.revoke("factory", &c.scope_sha256).unwrap();
        let before = s.clone();
        assert!(s.begin("factory", &c, 102).is_err());
        assert_eq!(s, before);
        assert_eq!(s.task_totals["task"], 300_000);
    }
    #[test]
    fn explicit_inventory_and_policy_required_and_immutable() {
        for change in 0..6 {
            let mut b = bootstrap();
            match change {
                0 => {
                    b.opening_days.clear();
                }
                1 => {
                    b.opening_tasks.remove("task");
                }
                2 => b.daily_cap_microusd = 1_000_001,
                3 => b.approved_daily_cap_microusd = 0,
                4 => b.predecessor_fence_sha256.clear(),
                _ => b
                    .opening_tasks
                    .insert("task".into(), 750_001)
                    .map(|_| ())
                    .unwrap_or(()),
            }
            assert!(State::new("factory", b, 100).is_err());
        }
        let s = State::new("factory", bootstrap(), 100).unwrap();
        let mut corrupt = s.clone();
        corrupt.day_totals.insert(0, 1);
        assert!(corrupt.check("factory").is_err());
        let mut corrupt = s;
        corrupt.task_totals.insert("task".into(), 1);
        assert!(corrupt.check("factory").is_err());
    }
    #[test]
    fn usage_rated_wire_is_accepted() {
        let mut wire = serde_json::to_value(scope("task")).unwrap();
        wire["route"]["usage_tariff_sha256"] = serde_json::json!("a".repeat(64));
        let scope: AttemptScope = serde_json::from_value(wire).expect("reviewed usage tariff");
        scope.bound().unwrap();
        assert_eq!(
            scope.digest().unwrap(),
            "a90e0900014ee1acd203ffc03f142cc4043005045b39a7f813f3b5f5ec017b54"
        );
    }

    fn rated_state() -> State {
        let mut b = bootstrap();
        for scope in &mut b.scopes {
            scope.route.usage_tariff_sha256 = Some("a".repeat(64));
        }
        State::new("factory", b, 100).unwrap()
    }
    fn rated_receipt(s: &State, c: &Call) -> CollectorReceipt {
        let mut r = receipt(s, c);
        r.billed_microusd = None;
        r.usage_rating = Some(UsageRatingEvidence {
            tariff_sha256: "a".repeat(64),
            audit_sha256: "b".repeat(64),
            usage_rated_microusd: 1,
        });
        r.generation_ids = [format!(
            "usage_{}",
            if c.call_id.starts_with("task") {
                "c"
            } else {
                "d"
            }
            .repeat(64)
        )]
        .into();
        r
    }
    fn receipt_claim(r: &CollectorReceipt) -> GenerationClaim {
        GenerationClaim {
            call_id: r.call_id.clone(),
            request_sha256: r.request_sha256.clone(),
            scope_sha256: r.scope_sha256.clone(),
            manifest_sha256: r.manifest_sha256.clone(),
            generation_ids: r.generation_ids.clone(),
        }
    }
    #[test]
    fn legacy_wire_scope_digest_and_completed_state_stay_identical() {
        let scope = scope("task");
        assert_eq!(
            scope.digest().unwrap(),
            "fbba1cce5b33e3a6fbe52dffd6b04f1b586ba9c9f183d9e04bd8ab93ce8229a7"
        );
        let raw = serde_json::to_vec(&scope).unwrap();
        let decoded: AttemptScope = serde_json::from_slice(&raw).unwrap();
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), raw);
        assert!(!String::from_utf8(raw).unwrap().contains("usage_tariff"));
        let mut s = State::new("factory", bootstrap(), 100).unwrap();
        let c = call(&s, "task", 0);
        s.reserve("factory", &c, 101).unwrap();
        s.begin("factory", &c, 102).unwrap();
        let r = receipt(&s, &c);
        assert_eq!(
            serde_json::to_value(&r).unwrap()["billed_microusd"],
            299_999
        );
        claim(&mut s, &r);
        s.complete("factory", &r).unwrap();
        let raw = serde_json::to_vec(&s).unwrap();
        assert!(!String::from_utf8(raw.clone())
            .unwrap()
            .contains("usage_rating"));
        let mut restored: State = serde_json::from_slice(&raw).unwrap();
        restored.check("factory").unwrap();
        restored.complete("factory", &r).unwrap();
        assert_eq!(serde_json::to_vec(&restored).unwrap(), raw);
        let mut rerated = r;
        rerated.billed_microusd = None;
        rerated.usage_rating = rated_receipt(&restored, &c).usage_rating;
        assert!(restored.complete("factory", &rerated).is_err());
    }
    #[test]
    fn rated_evidence_is_strict_and_never_refunds_or_resets_reservations() {
        let mut s = rated_state();
        let c = call(&s, "task", 0);
        s.reserve("factory", &c, 101).unwrap();
        s.begin("factory", &c, 102).unwrap();
        let r = rated_receipt(&s, &c);
        claim(&mut s, &r);
        for change in 0..7 {
            let mut bad = r.clone();
            match change {
                0 => bad.usage_rating.as_mut().unwrap().tariff_sha256 = "f".repeat(64),
                1 => bad.billed_microusd = Some(0),
                2 => bad.usage_rating.as_mut().unwrap().audit_sha256.clear(),
                3 => bad.usage_rating.as_mut().unwrap().usage_rated_microusd = 300_001,
                4 => bad.usage_rating = None,
                5 => {
                    bad.billed_microusd = Some(1);
                    bad.usage_rating = None;
                }
                _ => bad.usage_rating.as_mut().unwrap().audit_sha256 = "G".repeat(64),
            }
            let before = s.clone();
            assert!(s.complete("factory", &bad).is_err(), "case {change}");
            assert_eq!(s, before);
        }
        s.complete("factory", &r).unwrap();
        let raw = serde_json::to_vec(&s).unwrap();
        let mut restored: State = serde_json::from_slice(&raw).unwrap();
        restored.check("factory").unwrap();
        claim(&mut restored, &r);
        restored.complete("factory", &r).unwrap();
        assert_eq!(serde_json::to_vec(&restored).unwrap(), raw);
        let mut changed = r.clone();
        changed.usage_rating.as_mut().unwrap().usage_rated_microusd = 2;
        assert!(restored.complete("factory", &changed).is_err());
        assert_eq!(restored.task_totals["task"], 300_000);
        assert_eq!(restored.day_totals[&0], 300_000);
        let next = call(&restored, "task", 1);
        restored.reserve("factory", &next, 103).unwrap();
        restored.begin("factory", &next, 104).unwrap();
        let mut r2 = rated_receipt(&restored, &next);
        let before = restored.clone();
        assert!(restored
            .claim_receipts("factory", &receipt_claim(&r2))
            .is_err());
        assert_eq!(restored, before); // Stable physical evidence cannot be claimed twice.
        r2.generation_ids = [format!("usage_{}", "e".repeat(64))].into();
        claim(&mut restored, &r2);
        restored.complete("factory", &r2).unwrap();
        assert_eq!(
            restored
                .reserve("factory", &call(&restored, "task", 2), 105)
                .unwrap(),
            Stage::Denied
        );
        assert_eq!(restored.task_totals["task"], 600_000);
        assert_eq!(restored.day_totals[&0], 600_000);
        assert!(restored
            .reserve("factory", &call(&restored, "other", 0), DAY_MS + 1)
            .is_err());
    }
    #[test]
    fn evidence_namespace_and_root_tariff_are_enforced_before_claim_mutation() {
        let mut invalid = scope("task");
        invalid.route.usage_tariff_sha256 = Some("not-a-hash".into());
        assert!(invalid.bound().is_err());
        for rated in [false, true] {
            let mut s = if rated {
                rated_state()
            } else {
                State::new("factory", bootstrap(), 100).unwrap()
            };
            let c = call(&s, "task", 0);
            s.reserve("factory", &c, 101).unwrap();
            s.begin("factory", &c, 102).unwrap();
            let r = if rated {
                rated_receipt(&s, &c)
            } else {
                receipt(&s, &c)
            };
            let mut bad = receipt_claim(&r);
            for name in if rated {
                vec![
                    "provider/id".to_string(),
                    "usage_short".into(),
                    format!("usage_{}", "G".repeat(64)),
                ]
            } else {
                vec![format!("usage_{}", "c".repeat(64)), "usage_short".into()]
            } {
                bad.generation_ids = [name].into();
                let before = s.clone();
                assert!(s.claim_receipts("factory", &bad).is_err());
                assert_eq!(s, before);
            }
            let raw = serde_json::to_vec(&s).unwrap();
            let mut restored: State = serde_json::from_slice(&raw).unwrap();
            assert!(restored.begin("factory", &c, 103).is_err());
            assert!(restored
                .reserve("factory", &call(&restored, "task", 1), 103)
                .is_err());
            claim(&mut restored, &r);
            let raw = serde_json::to_vec(&restored).unwrap();
            let mut restored: State = serde_json::from_slice(&raw).unwrap();
            let mut conflict = receipt_claim(&r);
            conflict.manifest_sha256 = "9".repeat(64);
            assert!(restored.claim_receipts("factory", &conflict).is_err());
            assert_eq!(serde_json::to_vec(&restored).unwrap(), raw);
        }
    }
}
