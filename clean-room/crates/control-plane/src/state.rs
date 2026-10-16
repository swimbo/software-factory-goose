//! Pure work-package lifecycle state machine (consensus R3/R5/R7).
//!
//! This is the domain logic that Restate journals — deliberately SDK-independent so it is
//! unit-testable in isolation. The Restate workflow wraps these transitions in a replay-based
//! journal; this module encodes *what* a transition may do, not *how* it is persisted.

use shared::Receipt;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Queued,
    Claimed,
    Building,
    Evaluating,
    Merged,
    Failed,
    HumanLane,
}

/// Max attempts per work package (report: ~3/spec).
pub const MAX_ATTEMPTS: u32 = 3;

#[derive(Debug, Clone)]
pub struct WorkPackageState {
    pub stage: Stage,
    pub attempts: u32,
    /// Backoff before the next attempt (exponential).
    pub cooldown: Duration,
    /// Spend accumulated this unit (R7 — the dollar ceiling, not just retry count).
    pub unit_spent_usd: f64,
}

impl Default for WorkPackageState {
    fn default() -> Self {
        WorkPackageState {
            stage: Stage::Queued,
            attempts: 0,
            cooldown: Duration::ZERO,
            unit_spent_usd: 0.0,
        }
    }
}

/// Claim a queued package. Returns an error if it isn't claimable (double-claim prevention).
pub fn claim(state: &mut WorkPackageState) -> Result<(), &'static str> {
    if state.stage != Stage::Queued {
        return Err("package not queued");
    }
    state.stage = Stage::Claimed;
    Ok(())
}

/// A completed Goose run advances Building → Evaluating; a non-completion triggers retry.
pub fn on_build_complete(state: &mut WorkPackageState, receipt: &Receipt) {
    state.attempts += 1;
    if receipt.is_completed() {
        state.stage = Stage::Evaluating;
    } else {
        // TimedOut / Failed / Crashed → retry with backoff, capped at MAX_ATTEMPTS.
        if state.attempts >= MAX_ATTEMPTS {
            state.stage = Stage::Failed;
        } else {
            state.cooldown = backoff(state.attempts);
            state.stage = Stage::Building; // stays in the build loop, re-claim next cycle
        }
    }
}

/// Exponential backoff: 1s, 2s, 4s, ... capped.
pub fn backoff(attempts: u32) -> Duration {
    Duration::from_secs(1u64 << attempts.min(6))
}

/// The wall passes → Merged; otherwise retry or fail.
pub fn on_evaluation(state: &mut WorkPackageState, passed: bool) {
    if passed {
        state.stage = Stage::Merged;
    } else if state.attempts >= MAX_ATTEMPTS {
        state.stage = Stage::Failed;
    } else {
        state.cooldown = backoff(state.attempts);
        state.stage = Stage::Building;
    }
}

/// Route to the human lane (e.g. qualifier fatal flag, or an exhausted budget that needs a
/// human decision).
pub fn to_human_lane(state: &mut WorkPackageState) {
    state.stage = Stage::HumanLane;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn completed() -> Receipt {
        Receipt::Completed {
            sha: "abc".into(),
            diff: "diff".into(),
            turn_count: 1,
            exit_code: 0,
            wall_time_ms: 1,
            spend_usd: 0.0,
        }
    }

    fn failed() -> Receipt {
        Receipt::Failed {
            exit_code: 1,
            stderr_tail: "boom".into(),
        }
    }

    #[test]
    fn claim_requires_queued() {
        let mut s = WorkPackageState::default();
        assert!(claim(&mut s).is_ok());
        assert_eq!(s.stage, Stage::Claimed);
        // double-claim is rejected.
        assert!(claim(&mut s).is_err());
    }

    #[test]
    fn completed_build_moves_to_evaluating() {
        let mut s = WorkPackageState::default();
        claim(&mut s).unwrap();
        s.stage = Stage::Building;
        on_build_complete(&mut s, &completed());
        assert_eq!(s.stage, Stage::Evaluating);
        assert_eq!(s.attempts, 1);
    }

    #[test]
    fn failed_build_retries_then_fails() {
        let mut s = WorkPackageState::default();
        claim(&mut s).unwrap();
        for i in 0..MAX_ATTEMPTS {
            s.stage = Stage::Building;
            on_build_complete(&mut s, &failed());
            if i < MAX_ATTEMPTS - 1 {
                assert_eq!(s.stage, Stage::Building);
                assert!(!s.cooldown.is_zero());
            }
        }
        assert_eq!(s.stage, Stage::Failed);
        assert_eq!(s.attempts, MAX_ATTEMPTS);
    }

    #[test]
    fn evaluation_pass_merges() {
        let mut s = WorkPackageState::default();
        claim(&mut s).unwrap();
        s.stage = Stage::Evaluating;
        on_evaluation(&mut s, true);
        assert_eq!(s.stage, Stage::Merged);
    }

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(backoff(0), Duration::from_secs(1));
        assert_eq!(backoff(2), Duration::from_secs(4));
        assert_eq!(backoff(100), Duration::from_secs(64)); // capped at 1<<6
    }
}
