//! Unregistered fresh-namespace inventory fixture, not a deployment genesis proof.
//!
//! Issuance creates new namespaced IDs; there is no import operation. This object does not
//! establish a fresh Restate installation, sole authority, authenticated ingress, complete
//! cross-object inventory, or absence of legacy services. Its caller must secure all of those
//! boundaries before using inventory membership for an actual task or inference decision.
use restate_sdk::{prelude::*, serde::Json};
use std::collections::HashSet;

const MAX_TASKS: usize = 128;
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issue {
    pub request_id: String,
    pub intent_id: String,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issued {
    pub request: Issue,
    pub task_id: String,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    schema: u8,
    namespace: String,
    records: Vec<Issued>,
}
fn canonical(value: &str) -> bool {
    ulid::Ulid::from_string(value).is_ok_and(|id| id.to_string() == value)
}
fn error(code: u16, text: &'static str) -> TerminalError {
    TerminalError::new_with_code(code, text)
}
impl Inventory {
    fn new(namespace: &str) -> Result<Self, TerminalError> {
        if !canonical(namespace) {
            return Err(error(400, "invalid fresh namespace"));
        }
        Ok(Self {
            schema: 1,
            namespace: namespace.into(),
            records: Vec::new(),
        })
    }
    fn check(&self, namespace: &str) -> Result<(), TerminalError> {
        if self.schema != 1
            || !canonical(namespace)
            || self.namespace != namespace
            || self.records.len() > MAX_TASKS
        {
            return Err(error(409, "invalid genesis inventory"));
        }
        let mut requests = HashSet::new();
        let mut tasks = HashSet::new();
        for record in &self.records {
            let Some(suffix) = record.task_id.strip_prefix(&format!("{namespace}_")) else {
                return Err(error(409, "invalid inventory task"));
            };
            if !canonical(suffix)
                || !canonical(&record.request.request_id)
                || !canonical(&record.request.intent_id)
                || !requests.insert(&record.request.request_id)
                || !tasks.insert(&record.task_id)
            {
                return Err(error(409, "invalid inventory record"));
            }
        }
        Ok(())
    }
    fn issue(
        &mut self,
        namespace: &str,
        request: &Issue,
        generated: &str,
    ) -> Result<Issued, TerminalError> {
        self.check(namespace)?;
        if !canonical(&request.request_id)
            || !canonical(&request.intent_id)
            || !canonical(generated)
        {
            return Err(error(400, "invalid issue request"));
        }
        if let Some(existing) = self
            .records
            .iter()
            .find(|r| r.request.request_id == request.request_id)
        {
            if existing.request != *request {
                return Err(error(409, "request identity conflict"));
            }
            return Ok(existing.clone());
        }
        if self.records.len() >= MAX_TASKS {
            return Err(error(429, "genesis inventory full"));
        }
        let task_id = format!("{namespace}_{generated}");
        if self.records.iter().any(|r| r.task_id == task_id) {
            return Err(error(409, "generated task identity conflict"));
        }
        let issued = Issued {
            request: request.clone(),
            task_id,
        };
        self.records.push(issued.clone());
        Ok(issued)
    }
    fn contains(&self, namespace: &str, task: &str) -> Result<bool, TerminalError> {
        self.check(namespace)?;
        Ok(self.records.iter().any(|r| r.task_id == task))
    }
}

/// Fresh-namespace experiment. Registration, instance creation and private ingress are
/// deliberately absent. Never deploy it as a parallel replacement for an existing ledger.
pub struct GenesisInventoryFixture;
#[restate_sdk::object]
impl GenesisInventoryFixture {
    #[handler]
    async fn bootstrap(&self, ctx: ObjectContext<'_>) -> HandlerResult<()> {
        if let Some(state) = ctx.get::<Json<Inventory>>("inventory").await? {
            state.0.check(ctx.key())?;
        } else {
            ctx.set("inventory", Json(Inventory::new(ctx.key())?));
        }
        Ok(())
    }
    #[handler]
    async fn issue(
        &self,
        ctx: ObjectContext<'_>,
        request: Json<Issue>,
    ) -> HandlerResult<Json<Issued>> {
        let mut inventory = ctx
            .get::<Json<Inventory>>("inventory")
            .await?
            .ok_or_else(|| error(404, "genesis not bootstrapped"))?
            .0;
        let generated = ctx.run(|| async { Ok(shared::new_id()) }).await?;
        let before = inventory.clone();
        let issued = inventory.issue(ctx.key(), &request.0, &generated)?;
        if inventory != before {
            ctx.set("inventory", Json(inventory));
        }
        Ok(Json(issued))
    }
    #[handler]
    async fn contains(
        &self,
        ctx: SharedObjectContext<'_>,
        task: Json<String>,
    ) -> HandlerResult<Json<bool>> {
        let inventory = ctx
            .get::<Json<Inventory>>("inventory")
            .await?
            .ok_or_else(|| error(404, "genesis not bootstrapped"))?
            .0;
        Ok(Json(inventory.contains(ctx.key(), &task.0)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const NS: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    const REQUEST: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAW";
    const INTENT: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAX";
    const OTHER: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAY";
    const CHILD: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAZ";
    #[test]
    fn genesis_issues_only_inventory_backed_namespaced_tasks_and_replays_exactly() {
        let mut state = Inventory::new(NS).unwrap();
        let request = Issue {
            request_id: REQUEST.into(),
            intent_id: INTENT.into(),
        };
        let first = state.issue(NS, &request, CHILD).unwrap();
        assert_eq!(first.task_id, format!("{NS}_{CHILD}"));
        assert_eq!(state.issue(NS, &request, OTHER).unwrap(), first);
        assert!(state.contains(NS, &first.task_id).unwrap());
        assert!(!state.contains(NS, CHILD).unwrap());
        assert!(!state.contains(NS, &format!("{NS}_{OTHER}")).unwrap());
        assert!(
            state
                .issue(
                    NS,
                    &Issue {
                        request_id: REQUEST.into(),
                        intent_id: OTHER.into()
                    },
                    OTHER
                )
                .is_err()
        );
        assert!(state.issue(OTHER, &request, OTHER).is_err());
    }
    #[test]
    fn full_inventory_does_not_evict_or_reassign_existing_tasks() {
        let mut state = Inventory::new(NS).unwrap();
        let mut first = None;
        for i in 1..=MAX_TASKS {
            let request = Issue {
                request_id: ulid::Ulid::from(i as u128).to_string(),
                intent_id: INTENT.into(),
            };
            let issued = state
                .issue(
                    NS,
                    &request,
                    &ulid::Ulid::from((i + 1000) as u128).to_string(),
                )
                .unwrap();
            if i == 1 {
                first = Some(issued);
            }
        }
        let request = Issue {
            request_id: ulid::Ulid::from(999u128).to_string(),
            intent_id: INTENT.into(),
        };
        assert!(state.issue(NS, &request, OTHER).is_err());
        let first = first.unwrap();
        assert_eq!(state.issue(NS, &first.request, OTHER).unwrap(), first);
        assert!(state.contains(NS, &first.task_id).unwrap());
    }
    #[test]
    fn import_fields_and_unknown_wire_values_are_refused() {
        let request =
            serde_json::json!({"request_id": REQUEST, "intent_id": INTENT, "task_id": CHILD});
        assert!(serde_json::from_value::<Issue>(request).is_err());
        let request = serde_json::json!({"request_id": REQUEST, "intent_id": INTENT});
        assert!(serde_json::from_value::<Issue>(request).is_ok());
    }
    #[test]
    fn generated_identity_collision_is_rejected_without_mutation() {
        let mut state = Inventory::new(NS).unwrap();
        let first = Issue {
            request_id: REQUEST.into(),
            intent_id: INTENT.into(),
        };
        state.issue(NS, &first, CHILD).unwrap();
        let second = Issue {
            request_id: OTHER.into(),
            intent_id: INTENT.into(),
        };
        assert!(state.issue(NS, &second, CHILD).is_err());
        assert_eq!(state.records.len(), 1);
    }
    #[test]
    fn inventory_checks_schema_and_rejects_forged_history() {
        let mut state = Inventory::new(NS).unwrap();
        let request = Issue {
            request_id: REQUEST.into(),
            intent_id: INTENT.into(),
        };
        state.issue(NS, &request, CHILD).unwrap();
        state.records[0].task_id = CHILD.into();
        assert!(state.contains(NS, CHILD).is_err());
        assert!(Inventory::new("legacy").is_err());
    }
}
