//! The control-plane domain logic — the qualifier, gates, work-package state machine, and
//! gateway budget. Exposed as a library so `main.rs` (the thin HTTP entry point) and any
//! future wiring call into it without dead-code warnings.

pub mod driver;
pub mod gates;
pub mod gateway;
#[cfg(test)]
mod goose_fixture_gateway;
pub mod goose_protocol;
pub mod memory;
pub mod pipeline;
pub mod projection;
pub mod qualifier;
pub mod state;

#[cfg(feature = "restate")]
pub mod workflow;

pub use qualifier::{DARK_LANE_THRESHOLD, IntentFeatures, decide};
pub mod approval;
#[cfg(feature = "restate")]
pub mod approval_workflow;
pub mod operator_transport;
pub mod promotion_eligibility;

#[cfg(feature = "restate")]
pub mod idempotent_budget;
#[cfg(feature = "restate")]
pub mod inference_authority;

pub mod intake;
#[cfg(all(feature = "restate", unix))]
pub mod intake_adapter;
#[cfg(feature = "restate")]
pub mod intake_workflow;

#[cfg(feature = "restate")]
pub mod worker_queue;

#[cfg(all(feature = "restate", unix))]
pub mod operator_adapter;
#[cfg(feature = "restate")]
pub mod promotion_decision;
#[cfg(all(feature = "restate", unix))]
pub mod promotion_execution;
#[cfg(feature = "restate")]
pub mod worker_adapter;
