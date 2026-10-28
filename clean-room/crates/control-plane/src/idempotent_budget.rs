//! Unregistered fresh-namespace budget experiment; never dual-run with an existing unit ledger.

use restate_sdk::{prelude::*, serde::Json};
use std::collections::HashSet;

const CAP_MICROUSD: u64 = 750_000;
const MAX_RESERVATIONS: usize = 256;
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationRequest {
    pub reservation_id: String,
    pub amount_microusd: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    id: String,
    amount_microusd: u64,
    admitted: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    schema: u8,
    scope: String,
    spent_microusd: u64,
    records: Vec<Record>,
}

fn valid_scope(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn valid_id(s: &str) -> bool {
    ulid::Ulid::from_string(s).is_ok_and(|id| id.to_string() == s)
}
fn err(code: u16, message: &str) -> TerminalError {
    TerminalError::new_with_code(code, message)
}
impl Ledger {
    fn new(scope: &str) -> Self {
        Self {
            schema: 1,
            scope: scope.into(),
            spent_microusd: 0,
            records: Vec::new(),
        }
    }
    fn check(&self, scope: &str) -> Result<(), TerminalError> {
        if !valid_scope(scope)
            || self.scope != scope
            || self.schema != 1
            || self.records.len() > MAX_RESERVATIONS
        {
            return Err(err(409, "invalid retained budget state"));
        }
        let mut ids = HashSet::new();
        let mut spent: u64 = 0;
        for record in &self.records {
            if !valid_id(&record.id) || record.amount_microusd == 0 || !ids.insert(&record.id) {
                return Err(err(409, "invalid reservation history"));
            }
            let next = spent
                .checked_add(record.amount_microusd)
                .filter(|next| *next <= CAP_MICROUSD);
            if record.admitted != next.is_some() {
                return Err(err(409, "inconsistent reservation outcome"));
            }
            if let Some(next) = next {
                spent = next;
            }
        }
        if spent != self.spent_microusd {
            return Err(err(409, "inconsistent reservation total"));
        }
        Ok(())
    }
    fn reserve(&mut self, scope: &str, id: &str, amount: u64) -> Result<bool, TerminalError> {
        self.check(scope)?;
        if !valid_id(id) || amount == 0 {
            return Err(err(400, "invalid reservation request"));
        }
        if let Some(record) = self.records.iter().find(|r| r.id == id) {
            if record.amount_microusd != amount {
                return Err(err(
                    409,
                    "reservation identity reused with different amount",
                ));
            }
            return Ok(record.admitted);
        }
        if self.records.len() >= MAX_RESERVATIONS {
            return Err(err(429, "reservation history capacity exhausted"));
        }
        let next = self
            .spent_microusd
            .checked_add(amount)
            .filter(|next| *next <= CAP_MICROUSD);
        let admitted = next.is_some();
        if let Some(next) = next {
            self.spent_microusd = next;
        }
        self.records.push(Record {
            id: id.into(),
            amount_microusd: amount,
            admitted,
        });
        Ok(admitted)
    }
}

/// Fresh object namespace only. No automatic migration, public listener, reset or eviction.
/// Deployments must authenticate/bind scope and persist trusted reservation IDs before use.
pub struct IdempotentBudgetCounter;
#[restate_sdk::object]
impl IdempotentBudgetCounter {
    #[handler]
    async fn reserve(
        &self,
        ctx: ObjectContext<'_>,
        request: Json<ReservationRequest>,
    ) -> HandlerResult<bool> {
        let mut ledger = ctx
            .get::<Json<Ledger>>("ledger")
            .await?
            .map(|v| v.0)
            .unwrap_or_else(|| Ledger::new(ctx.key()));
        let before = ledger.clone();
        let admitted = ledger.reserve(
            ctx.key(),
            &request.0.reservation_id,
            request.0.amount_microusd,
        )?;
        if ledger != before {
            ctx.set("ledger", Json(ledger));
        }
        Ok(admitted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const A: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    const B: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAW";
    #[test]
    fn exact_retry_is_stable_and_changed_amount_conflicts() {
        let mut ledger = Ledger::new("unit");
        assert!(ledger.reserve("unit", A, 250_000).unwrap());
        let before = ledger.clone();
        assert!(ledger.reserve("unit", A, 250_000).unwrap());
        assert_eq!(ledger, before);
        assert!(ledger.reserve("unit", A, 1).is_err());
        assert!(ledger.reserve("other", A, 250_000).is_err());
        assert_eq!(ledger, before);
    }
    #[test]
    fn denial_is_immutable_and_capacity_never_evicts() {
        let mut ledger = Ledger::new("unit");
        assert!(ledger.reserve("unit", A, 750_000).unwrap());
        assert!(!ledger.reserve("unit", B, 1).unwrap());
        assert!(!ledger.reserve("unit", B, 1).unwrap());
        for n in 0..(MAX_RESERVATIONS - 2) {
            let id = ulid::Ulid::from(n as u128).to_string();
            assert!(!ledger.reserve("unit", &id, 1).unwrap());
        }
        let before = ledger.clone();
        assert!(
            ledger
                .reserve("unit", "01ARZ3NDEKTSV4RRFFQ69G5FAX", 1)
                .is_err()
        );
        assert_eq!(ledger, before);
        assert!(ledger.reserve("unit", A, 750_000).unwrap());
    }
    #[test]
    fn invalid_input_and_corruption_fail_before_mutation() {
        let mut ledger = Ledger::new("unit");
        for (id, amount) in [("bad", 1), (A, 0)] {
            assert!(ledger.reserve("unit", id, amount).is_err());
        }
        ledger.reserve("unit", A, 10).unwrap();
        ledger.spent_microusd = 1;
        let before = ledger.clone();
        assert!(ledger.reserve("unit", B, 1).is_err());
        assert_eq!(ledger, before);
    }
}
