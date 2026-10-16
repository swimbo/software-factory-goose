//! The control-plane domain logic — the qualifier, gates, work-package state machine, and
//! gateway budget. Exposed as a library so `main.rs` (the thin HTTP entry point) and any
//! future wiring call into it without dead-code warnings.

pub mod driver;
pub mod gateway;
pub mod gates;
pub mod memory;
pub mod pipeline;
pub mod projection;
pub mod qualifier;
pub mod state;

#[cfg(feature = "restate")]
pub mod workflow;

pub use qualifier::{decide, IntentFeatures, DARK_LANE_THRESHOLD};
