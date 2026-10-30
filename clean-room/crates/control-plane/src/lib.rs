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
pub mod atomic_inference_fixture;
#[cfg(all(feature = "restate", unix))]
pub mod atomic_peer_gate;
#[cfg(feature = "restate")]
pub mod conversation_fixture;
#[cfg(feature = "restate")]
pub mod genesis_fixture;
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

#[cfg(feature = "restate")]
pub mod runtime_intake;

#[cfg(feature = "restate")]
pub mod catalog_registry;

#[cfg(all(feature = "restate", unix))]
pub mod private_runtime;

#[cfg(all(feature = "restate", unix))]
pub mod runtime_loopback_backend;

#[cfg(feature = "restate")]
pub mod launch_reservation;

#[cfg(feature = "restate")]
pub mod private_database_genesis;

#[cfg(all(feature = "restate", unix))]
pub mod root_launch_grant;
