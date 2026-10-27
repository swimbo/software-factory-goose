//! Shared contract types flowing between the factory's planes.
//!
//! These are the typed, versioned artifacts the debate mandated (consensus R6 + the
//! contract-schema blind spot). Every cross-plane message is one of these.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Time-sortable unique ID (ULID). String form is the wire representation.
pub type Id = String;

/// New helper for ULIDs.
pub fn new_id() -> Id {
    ulid::Ulid::new().to_string()
}

/// The result of a single Goose run (consensus R6).
///
/// `git diff` is *payload* inside `Completed`, never the status itself. The status
/// discriminator is the `#[serde(tag)]`, parsed from `goose run --output-format json`
/// stdout. A non-JSON stdout is `Failed` with a parse-error marker, not a silent fallback.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Receipt {
    Completed {
        sha: String,
        diff: String,
        turn_count: u32,
        exit_code: i32,
        wall_time_ms: u64,
        /// Cost accrued by this run (R7) — the pipeline's budget ledger consumes this.
        spend_usd: f64,
    },
    TimedOut {
        sha: String,
        turn_count: u32,
        wall_time_ms: u64,
    },
    Failed {
        exit_code: i32,
        stderr_tail: String,
    },
    Crashed {
        signal: i32,
        core_dumped: bool,
    },
}

impl Receipt {
    /// True only for a positively-asserted, complete result.
    pub fn is_completed(&self) -> bool {
        matches!(self, Receipt::Completed { exit_code: 0, spend_usd, .. }
            if spend_usd.is_finite() && *spend_usd >= 0.0)
    }

    /// Cost accrued by this run (R7) — 0 for non-completions.
    pub fn spend_usd(&self) -> f64 {
        match self {
            Receipt::Completed { spend_usd, .. } => *spend_usd,
            _ => 0.0,
        }
    }
}

/// A claim on a work package: who owns it, against what exact git revision, until when.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Claim {
    pub id: Id,
    pub work_package_id: Id,
    pub worker_id: Id,
    pub git_revision: String,
    pub lease_expiry: chrono::DateTime<chrono::Utc>,
    pub status: ClaimStatus,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Open,
    Released,
    Expired,
    Fulfilled,
}

/// A credential grant issued by the broker. The *reference* is stored; the secret value
/// never appears in this record (or in any agent context).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CredentialGrant {
    pub id: Id,
    pub work_package_id: Id,
    /// single-repo, single-action scope (e.g. `git:push:agent/<wp>`).
    pub scope: String,
    pub kind: CredentialKind,
    pub ttl_secs: u64,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub human_approval_required: bool,
    pub approved_by: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// Low-stakes, self-issued (agent-mail channel).
    SelfIssued,
    /// Broker-issued short-lived token (model gateway virtual key).
    BrokerIssued,
    /// Privileged/destructive class — always human-approved.
    Privileged,
}

/// The qualifier's lane decision for an incoming intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualifierDecision {
    pub intent_id: Id,
    pub score: f64,
    pub lane: Lane,
    pub reason: String,
    /// Fatal safety flag overrides any score to the human lane.
    pub fatal: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Lane {
    Dark,
    Human,
}

impl fmt::Display for Lane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Lane::Dark => write!(f, "dark"),
            Lane::Human => write!(f, "human"),
        }
    }
}

/// A promotion decision (Gate 1). First promotion is a human act.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotionRecord {
    pub id: Id,
    pub work_package_id: Id,
    pub target_env: String,
    pub is_first_promotion: bool,
    pub human_approval: ApprovalState,
    pub approved_by: Option<String>,
    pub promoted_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    Pending,
    Approved,
    Denied,
}

/// An append-only audit event ("lights off, nothing unseen").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Id,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub actor: Actor,
    pub action: String,
    pub entity_id: Id,
    pub entity_type: String,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Actor {
    Human,
    Agent,
    System,
}

/// An evaluation run result from the wall (operator-facing; never shown to the generator).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationResult {
    pub scenario_id: Id,
    pub run_number: u8,
    pub passed: bool,
    pub failure_message: Option<String>,
}

/// A unit of work in the coordinator's dependency graph (R15). `blocked_by` gates dispatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: Id,
    pub subject: String,
    #[serde(default)]
    pub description: String,
    pub status: TaskStatus,
    #[serde(default)]
    pub blocked_by: Vec<Id>,
    #[serde(default)]
    pub blocks: Vec<Id>,
    pub owner: Option<Id>,
    #[serde(default)]
    pub active_form: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Pending,
    InProgress,
    Completed,
    Deleted,
}

impl Task {
    pub fn new(id: Id, subject: impl Into<String>) -> Self {
        Task {
            id,
            subject: subject.into(),
            description: String::new(),
            status: TaskStatus::Pending,
            blocked_by: Vec::new(),
            blocks: Vec::new(),
            owner: None,
            active_form: String::new(),
        }
    }

    /// A task is dispatchable when it is pending and every blocker is completed.
    pub fn is_dispatchable(&self, all: &[Task]) -> bool {
        self.status == TaskStatus::Pending
            && self.blocked_by.iter().all(|b| {
                all.iter()
                    .find(|t| &t.id == b)
                    .is_some_and(|t| t.status == TaskStatus::Completed)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_legacy_shapes_match_derived_contracts() {
        fn check<T: JsonSchema>(name: &str, snapshot: &str) {
            let mut generated = serde_json::to_value(schemars::schema_for!(T)).unwrap();
            generated["$id"] = format!("urn:software-factory:legacy-shape:{name}:v1").into();
            let saved: serde_json::Value = serde_json::from_str(snapshot).unwrap();
            assert_eq!(generated, saved, "legacy shape changed for {name}");
        }
        check::<Receipt>(
            "receipt",
            include_str!("../schemas/legacy-shape/v1/receipt.schema.json"),
        );
        check::<Claim>(
            "claim",
            include_str!("../schemas/legacy-shape/v1/claim.schema.json"),
        );
        check::<CredentialGrant>(
            "credential-grant",
            include_str!("../schemas/legacy-shape/v1/credential-grant.schema.json"),
        );
    }

    #[test]
    fn receipt_tag_roundtrips() {
        let r = Receipt::Completed {
            sha: "abc123".into(),
            diff: "diff".into(),
            turn_count: 3,
            exit_code: 0,
            wall_time_ms: 1000,
            spend_usd: 0.0,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"status\":\"completed\""));
        let back: Receipt = serde_json::from_str(&s).unwrap();
        assert!(back.is_completed());
    }

    #[test]
    fn receipt_failed_is_not_completed() {
        let r = Receipt::Failed {
            exit_code: 1,
            stderr_tail: "boom".into(),
        };
        assert!(!r.is_completed());
    }

    #[test]
    fn contradictory_completion_receipts_fail_closed() {
        for (exit_code, spend_usd) in [(1, 0.1), (0, -0.1), (0, f64::NAN), (0, f64::INFINITY)] {
            let receipt = Receipt::Completed {
                sha: "abc".into(),
                diff: String::new(),
                turn_count: 1,
                exit_code,
                wall_time_ms: 1,
                spend_usd,
            };
            assert!(!receipt.is_completed());
        }
    }

    #[test]
    fn new_id_is_unique() {
        assert_ne!(new_id(), new_id());
    }
}
