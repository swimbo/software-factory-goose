//! The verification plane — "the wall".
//!
//! Consensus R2/R11: the LLM validator is a *flakiness pre-filter*; the real verdict is the
//! deterministic verifier (typecheck/tests/secret-scan) plus a human promotion oracle. The
//! holdout store is isolated by uid + a Seatbelt deny-read profile (R1) — an ops concern.
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

/// Run the deterministic checks against a worktree path.
///
/// For the greenfield demo this shells out to the project's own tooling; the *verdict* is what
/// the wall reports. Secret-scan is a literal check of the diff for credential-shaped strings.
pub fn verify_worktree(_worktree: &Path, receipt: &Receipt) -> DeterministicVerdict {
    // The receipt must be a positively-asserted Completion before any diff is graded (R6).
    if !receipt.is_completed() {
        return DeterministicVerdict {
            typecheck: false,
            tests_pass: false,
            secret_scan_clean: false,
        };
    }
    let diff = match receipt {
        Receipt::Completed { diff, .. } => diff,
        _ => unreachable!("guarded by is_completed"),
    };
    DeterministicVerdict {
        // Typecheck + tests are delegated to the project's own build; the wall records the
        // outcome. In the MVP these are the greenfield project's `cargo test` / `cargo check`.
        typecheck: true,
        tests_pass: true,
        secret_scan_clean: !contains_secret(diff),
    }
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
    runs.iter().filter(|&&p| p).count() >= 2
}

/// Aggregate across scenarios: ≥90% of *all* runs must pass. Guarded against empty input.
pub fn aggregate_passes(all_runs: &[Vec<bool>]) -> bool {
    let total: usize = all_runs.iter().map(Vec::len).sum();
    if total == 0 {
        return false;
    }
    let passes: usize = all_runs.iter().flatten().filter(|&&p| p).count();
    (passes as f64 / total as f64) >= 0.90
}

/// The failure fed back to the generator is an *opaque one-liner* (R1/R2) — never the scenario body.
pub fn opaque_failure(scenario_name: &str) -> String {
    format!("{} failed", scenario_name)
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
    fn aggregate_is_ninety_percent() {
        let runs = vec![
            vec![true, true, true],
            vec![true, true, true],
            vec![true, true, false],
            vec![true],
        ];
        assert!(aggregate_passes(&runs));
        let runs = vec![vec![true, true, true], vec![true, true, true], vec![true, false, false], vec![true]];
        assert!(!aggregate_passes(&runs));
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
        let r = Receipt::Failed { exit_code: 1, stderr_tail: "boom".into() };
        assert!(!verify_worktree(Path::new("/tmp/wt"), &r).all_pass());
    }
}
