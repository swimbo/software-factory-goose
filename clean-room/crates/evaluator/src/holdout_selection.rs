//! Fixture-only binding of evaluator selection to a holdout report.
//!
//! Neither constructor authenticates its input: a future protected task registry must own
//! selection, candidate-path resolution, and a fresh snapshot. The comparison below is not
//! atomic with task state changes or promotion. Cross-UID transfer and OS containment remain
//! separate activation gates. This module has no listener, persistence, or dispatch route.

use crate::holdout::PrefilterReport;

/// Trusted configuration only; never deserialize a generator-provided selection.
#[derive(Clone, PartialEq, Eq)]
pub struct SelectionConfig {
    pub task_id: String,
    pub repository: String,
    pub target_ref: String,
    pub base_sha: String,
    pub candidate_sha: String,
    pub manifest_digest: String,
    pub generation: u64,
}

/// An immutable correlation binding, not a capability or proof of source provenance.
#[derive(PartialEq, Eq)]
pub struct EvaluationSelection(SelectionConfig);

#[derive(Debug, Clone, Copy)]
pub struct SelectionError;
impl std::fmt::Display for SelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("evaluation selection unavailable")
    }
}
impl std::error::Error for SelectionError {}

fn text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
fn hex(value: &str, lengths: &[usize]) -> bool {
    lengths.contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl EvaluationSelection {
    pub fn from_trusted_config(config: SelectionConfig) -> Result<Self, SelectionError> {
        if !text(&config.task_id)
            || !text(&config.repository)
            || !text(&config.target_ref)
            || !config.target_ref.starts_with("refs/heads/")
            || config.target_ref.len() == "refs/heads/".len()
            || !hex(&config.base_sha, &[40, 64])
            || !hex(&config.candidate_sha, &[40, 64])
            || !hex(&config.manifest_digest, &[64])
            || config.generation == 0
        {
            return Err(SelectionError);
        }
        Ok(Self(config))
    }
    /// Trusted evaluator/control-plane code may inspect the binding. The config has no
    /// serializer and must not be sent to the generator.
    pub fn config(&self) -> &SelectionConfig {
        &self.0
    }
    pub fn candidate_sha(&self) -> &str {
        &self.0.candidate_sha
    }
    pub fn manifest_digest(&self) -> &str {
        &self.0.manifest_digest
    }
    /// Caller must obtain `current` from the same trusted authority after execution.
    /// A read alone cannot prevent concurrent mutation; never use this as promotion authority.
    pub fn bind_report(
        &self,
        current: &Self,
        report: PrefilterReport,
    ) -> Result<BoundEvaluation, SelectionError> {
        if self != current
            || report.candidate_sha() != self.candidate_sha()
            || report.manifest_digest() != self.manifest_digest()
        {
            return Err(SelectionError);
        }
        Ok(BoundEvaluation {
            selection: Self(self.0.clone()),
            report,
        })
    }
}
/// Keep the full binding private to evaluator/control-plane integration. Only the report's
/// `feedback()` is intended for the generator, not this wrapper or its selection.
pub struct BoundEvaluation {
    selection: EvaluationSelection,
    report: PrefilterReport,
}
impl BoundEvaluation {
    pub fn selection(&self) -> &EvaluationSelection {
        &self.selection
    }
    pub fn report(&self) -> &PrefilterReport {
        &self.report
    }
}

/// Run only the pinned manifest and candidate revision. The candidate path still must be
/// resolved by a trusted registry, and the caller must bind against a fresh selection after
/// execution before retaining any result.
pub async fn run_selected_fixture(
    selection: &EvaluationSelection,
    candidate: &std::path::Path,
    manifest: &crate::holdout_runner::FixtureManifest,
    limits: crate::holdout_runner::FixtureLimits,
) -> Result<PrefilterReport, SelectionError> {
    if manifest.digest() != selection.manifest_digest() {
        return Err(SelectionError);
    }
    crate::holdout_runner::run_fixture_holdouts(
        candidate,
        selection.candidate_sha(),
        manifest,
        limits,
    )
    .await
    .map_err(|_| SelectionError)
}
