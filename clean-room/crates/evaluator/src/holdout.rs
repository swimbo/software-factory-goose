//! Bounded, revision-bound collection of the holdout flakiness prefilter (R2).
//!
//! This is an in-process collector, not a scenario runner, holdout store, authentication
//! boundary or promotion verdict. A trusted evaluator must supply the complete manifest
//! digest/count and bind actual runner results to the issued handles. This module cannot
//! prove that supplied votes came from execution. Do not deserialize worker claims into it.
//! No scenario body, runner output, error text or caller-chosen feedback label is accepted.

use serde::Serialize;
use std::fmt;

const MAX_SCENARIOS: usize = 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunOutcome {
    Pass,
    Fail,
    /// Transport/runner failure, cancellation or unknown outcome; never a negative vote.
    Unavailable,
}

/// Issued only by a session. This is an in-process correlation handle, not a credential.
/// No deserializer or public constructor permits arbitrary caller-assigned identities.
#[derive(Clone)]
pub struct ScenarioHandle {
    session: String,
    index: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrefilterStatus {
    Passed,
    Rejected,
    Incomplete,
}

/// The only intentionally serializable output. Excludes internal manifest/session/revision
/// bindings, vote counts, scenario bodies and logs. This is feedback, never authorization.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct GeneratorFeedback {
    pub status: PrefilterStatus,
    pub messages: Vec<String>,
}

pub struct PrefilterReport {
    candidate_sha: String,
    manifest_digest: String,
    feedback: GeneratorFeedback,
}

impl PrefilterReport {
    pub fn candidate_sha(&self) -> &str {
        &self.candidate_sha
    }

    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    pub fn feedback(&self) -> &GeneratorFeedback {
        &self.feedback
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HoldoutError {
    InvalidConfiguration,
    InvalidObservation,
}

impl fmt::Display for HoldoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "invalid holdout configuration",
            Self::InvalidObservation => "invalid holdout observation",
        })
    }
}
impl std::error::Error for HoldoutError {}

/// Immutable manifest selection and candidate binding, with exactly three slots per scenario.
/// Any duplicate, foreign handle or binding error invalidates the entire attempt permanently.
/// Start a fresh session after failed collection; never retry into an uncertain old attempt.
pub struct PrefilterSession {
    candidate_sha: String,
    manifest_digest: String,
    session: String,
    scenarios: Vec<ScenarioHandle>,
    runs: Vec<[Option<RunOutcome>; 3]>,
    invalidated: bool,
}

fn canonical_hex(value: &str, lengths: &[usize]) -> bool {
    lengths.contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl PrefilterSession {
    /// Manifest digest is canonical SHA-256 of the trusted caller's complete manifest.
    /// This validates its shape and binds observations; it does not compute or authenticate it.
    pub fn begin(
        candidate_sha: &str,
        manifest_digest: &str,
        scenario_count: usize,
    ) -> Result<Self, HoldoutError> {
        if !canonical_hex(candidate_sha, &[40, 64])
            || !canonical_hex(manifest_digest, &[64])
            || !(1..=MAX_SCENARIOS).contains(&scenario_count)
        {
            return Err(HoldoutError::InvalidConfiguration);
        }
        let session = shared::new_id();
        Ok(Self {
            candidate_sha: candidate_sha.to_owned(),
            manifest_digest: manifest_digest.to_owned(),
            scenarios: (0..scenario_count)
                .map(|index| ScenarioHandle {
                    session: session.clone(),
                    index,
                })
                .collect(),
            session,
            runs: vec![[None; 3]; scenario_count],
            invalidated: false,
        })
    }

    pub fn scenarios(&self) -> &[ScenarioHandle] {
        &self.scenarios
    }

    /// Record one authoritative runner observation, with a zero-based slot in 0..3.
    /// Error strings never reflect submitted data. Invalid observations poison the attempt
    /// so a caller cannot ignore a protocol error and later publish passing evidence.
    pub fn record(
        &mut self,
        candidate_sha: &str,
        manifest_digest: &str,
        scenario: &ScenarioHandle,
        slot: usize,
        outcome: RunOutcome,
    ) -> Result<(), HoldoutError> {
        let valid = !self.invalidated
            && candidate_sha == self.candidate_sha
            && manifest_digest == self.manifest_digest
            && scenario.session == self.session
            && scenario.index < self.runs.len()
            && slot < 3
            && self.runs[scenario.index][slot].is_none();
        if !valid {
            self.invalidated = true;
            return Err(HoldoutError::InvalidObservation);
        }
        self.runs[scenario.index][slot] = Some(outcome);
        Ok(())
    }

    /// Consumes the collector: late observations cannot alter this report.
    pub fn finish(self) -> PrefilterReport {
        let incomplete = self.invalidated
            || self
                .runs
                .iter()
                .flatten()
                .any(|run| matches!(run, None | Some(RunOutcome::Unavailable)));
        let feedback = if incomplete {
            GeneratorFeedback {
                status: PrefilterStatus::Incomplete,
                messages: vec!["evaluation incomplete".to_owned()],
            }
        } else {
            let votes: Vec<Vec<bool>> = self
                .runs
                .iter()
                .map(|runs| {
                    runs.iter()
                        .map(|run| *run == Some(RunOutcome::Pass))
                        .collect()
                })
                .collect();
            if crate::aggregate_passes(&votes) {
                GeneratorFeedback {
                    status: PrefilterStatus::Passed,
                    messages: Vec::new(),
                }
            } else {
                let mut messages: Vec<String> = votes
                    .iter()
                    .enumerate()
                    .filter(|(_, runs)| !crate::scenario_passes(runs))
                    .map(|(index, _)| format!("SCN-{:06} failed", index + 1))
                    .collect();
                if messages.is_empty() {
                    messages.push("holdout prefilter failed".to_owned());
                }
                GeneratorFeedback {
                    status: PrefilterStatus::Rejected,
                    messages,
                }
            }
        };
        PrefilterReport {
            candidate_sha: self.candidate_sha,
            manifest_digest: self.manifest_digest,
            feedback,
        }
    }
}
