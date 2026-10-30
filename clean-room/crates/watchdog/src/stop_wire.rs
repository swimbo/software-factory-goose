//! Fixed, bounded protocol shared by the stop frontend and root authority.
use crate::root_cgroup::{StopObservation, StopResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootStopRequest {
    pub target: String,
    pub operation: RootOperation,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootOperation {
    Stop,
    Status,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootStopReply {
    pub outcome: String,
    pub containment: Option<StopResult>,
    pub observation: Option<StopObservation>,
}
