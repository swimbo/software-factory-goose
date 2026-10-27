//! The verification plane — "the wall".
//!
//! Consensus R2/R11: the LLM validator is a *flakiness pre-filter*; the real verdict is the
//! deterministic verifier (typecheck/tests/secret-scan) plus a human promotion oracle. The
//! planned holdout store requires a distinct UID and Seatbelt deny-read boundary (R1).
//! The commit-verifier fixtures do not establish that deployed holdout boundary.
//!
//! Exposed as a library so the control-plane driver can call the wall from the build-result
//! callback.

use shared::Receipt;
use std::path::Path;

/// The deterministic verifier: no learned weights, cannot be sycophantic (R2).
#[derive(Debug, Clone, PartialEq)]
pub struct DeterministicVerdict {
    pub typecheck: bool,
    pub tests_pass: bool,
    pub secret_scan_clean: bool,
}

impl DeterministicVerdict {
    pub fn all_pass(&self) -> bool {
        self.typecheck && self.tests_pass && self.secret_scan_clean
    }
}

mod bounded_git;
mod verification;
pub use verification::{
    VerificationEvidence, promote_verified_commit, promote_verified_commit_to_ref,
    promotion_target_matches, promotion_target_revision, verify_worktree_evidence,
};
pub mod holdout;
pub mod holdout_runner;
pub mod holdout_selection;
pub mod holdout_store;
#[cfg(unix)]
pub mod holdout_transfer;

/// A receipt supplies an expected revision, never evidence that checks passed.
/// Missing repositories, changed revisions and unavailable isolation fail closed.
pub fn verify_worktree(worktree: &Path, receipt: &Receipt) -> DeterministicVerdict {
    verify_worktree_evidence(worktree, receipt)
        .map(|e| e.verdict)
        .unwrap_or(DeterministicVerdict {
            typecheck: false,
            tests_pass: false,
            secret_scan_clean: false,
        })
}

/// A deliberately small, deterministic secret-scan: flags obvious credential-shaped strings in
/// a diff. This is the *pre-gate* (R11) — cheap, fast, unconditional.
pub fn contains_secret(diff: &str) -> bool {
    const PATTERNS: [&str; 6] = [
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "api_key",
        "AKIA",
        "ghp_",
        "sk-",
    ];
    PATTERNS.iter().any(|p| diff.contains(p))
}

/// Holdout-scenario gate (R2): a flakiness-tolerant tiebreaker — 2-of-3 runs must pass.
pub fn scenario_passes(runs: &[bool]) -> bool {
    runs.len() == 3 && runs.iter().filter(|&&p| p).count() >= 2
}

/// Every scenario must contain exactly three runs and pass its 2-of-3 gate. The aggregate
/// ≥90% threshold is an additional prefilter; other successes cannot erase a failed scenario.
pub fn aggregate_passes(all_runs: &[Vec<bool>]) -> bool {
    if all_runs.is_empty() || !all_runs.iter().all(|runs| scenario_passes(runs)) {
        return false;
    }
    let total: usize = all_runs.iter().map(Vec::len).sum();
    let passes: usize = all_runs.iter().flatten().filter(|&&p| p).count();
    // ceil(90% * total), without floating-point boundaries or multiplication overflow.
    passes >= total - total / 10
}

/// Feed back only a preassigned opaque scenario ID. Reject prose, paths, control characters,
/// and oversized values instead of reflecting them into the generator context. Callers must
/// supply server-owned identifiers; this syntax guard does not classify arbitrary secrets.
pub fn opaque_failure(scenario_id: &str) -> String {
    let safe_id = !scenario_id.is_empty()
        && scenario_id.len() <= 64
        && scenario_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'));
    if safe_id {
        format!("{scenario_id} failed")
    } else {
        "scenario failed".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_of_three_requires_two() {
        assert!(scenario_passes(&[true, true, false]));
        assert!(!scenario_passes(&[true, false, false]));
        assert!(scenario_passes(&[true, true, true]));
    }

    #[test]
    fn scenario_rejects_every_length_except_three() {
        for length in [0, 1, 2, 4, 30] {
            assert!(
                !scenario_passes(&vec![true; length]),
                "accepted {length} runs"
            );
        }
    }

    #[test]
    fn aggregate_rejects_malformed_scenarios_even_among_successes() {
        for length in [0, 1, 2, 4, 30] {
            let mut runs = vec![vec![true; 3]; 10];
            runs.push(vec![true; length]);
            assert!(!aggregate_passes(&runs), "accepted a {length}-run scenario");
        }
    }

    #[test]
    fn failed_scenario_cannot_be_washed_out_by_other_successes() {
        let mut runs = vec![vec![true; 3]; 9];
        runs.push(vec![true, false, false]); // 28/30 aggregate, but this scenario fails.
        assert!(!aggregate_passes(&runs));
        runs[9] = vec![false; 3]; // Exactly 90% overall still cannot override a scenario.
        assert!(!aggregate_passes(&runs));
    }

    #[test]
    fn aggregate_is_ninety_percent_with_three_runs_per_scenario() {
        // The old 9/10 fixture contained a malformed one-run fourth scenario. Use valid
        // 3-run scenarios: 27/30 passes at the boundary, 26/30 fails while all are 2-of-3.
        let mut runs = vec![vec![true; 3]; 10];
        for scenario in runs.iter_mut().take(3) {
            scenario[2] = false;
        }
        assert!(runs.iter().all(|r| scenario_passes(r)));
        assert!(aggregate_passes(&runs));
        runs[3][2] = false;
        assert!(runs.iter().all(|r| scenario_passes(r)));
        assert!(!aggregate_passes(&runs));
    }

    #[test]
    fn opaque_feedback_exposes_only_a_safe_identifier() {
        assert_eq!(
            opaque_failure("SCN_001-acceptance"),
            "SCN_001-acceptance failed"
        );
        for unsafe_id in [
            "",
            "holdout body\nSECRET=hidden",
            "/var/holdout/private",
            "scenario secret body",
            "<script>",
            &"x".repeat(65),
        ] {
            assert_eq!(opaque_failure(unsafe_id), "scenario failed");
        }
    }

    #[test]
    fn empty_aggregate_fails_closed() {
        assert!(!aggregate_passes(&[]));
    }

    #[test]
    fn secret_scan_flags_credentials() {
        assert!(contains_secret("let key = \"sk-abcdef\";"));
        assert!(contains_secret("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(!contains_secret("fn main() { println!(\"hi\"); }"));
    }

    #[test]
    fn non_completed_receipt_fails_deterministic_verify() {
        let r = Receipt::Failed {
            exit_code: 1,
            stderr_tail: "boom".into(),
        };
        assert!(!verify_worktree(Path::new("/tmp/wt"), &r).all_pass());
    }
}
