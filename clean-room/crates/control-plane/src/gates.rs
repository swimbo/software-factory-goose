//! The three human gates — pure, unit-testable logic (consensus R7/R8/R9).
//!
//! Gate 1: first production promotion requires human approval.
//! Gate 2: agents spend within a budget envelope; only a human raises it.
//! Gate 3: privileged/destructive credentials require human approval.

use shared::{ApprovalState, CredentialKind};

/// Budget ledger (R7). Agents spend inside the envelope; only a human raises it.
#[derive(Debug, Clone)]
pub struct Budget {
    pub per_unit_cap_usd: f64,
    pub per_day_cap_usd: f64,
    pub spent_today_usd: f64,
    /// A run that hits the per-unit cap is a terminal state, not a retryable error.
    pub unit_spent_usd: f64,
}

impl Budget {
    /// True iff a call of `estimate_usd` may proceed (consensus R7: fail-closed).
    pub fn can_spend(&self, estimate_usd: f64) -> bool {
        self.unit_spent_usd + estimate_usd <= self.per_unit_cap_usd
            && self.spent_today_usd + estimate_usd <= self.per_day_cap_usd
    }
}

/// Gate 1: promotion. The 90% verification is a *precondition*; final authority is the human.
pub fn promotion_requires_human(is_first_promotion: bool, verification_passed: bool) -> bool {
    // First promotion is always a human act; later drift may go dark, but a below-bar
    // promotion is never auto-approved (consensus R2/R11).
    is_first_promotion || !verification_passed
}

/// Gate 3: whether a credential grant needs human approval.
pub fn credential_requires_human(kind: CredentialKind) -> bool {
    matches!(kind, CredentialKind::Privileged)
}

/// State transition for a promotion under human approval.
pub fn apply_promotion_approval(
    current: ApprovalState,
    human_approved: bool,
) -> ApprovalState {
    match (current, human_approved) {
        (ApprovalState::Pending, true) => ApprovalState::Approved,
        (ApprovalState::Pending, false) => ApprovalState::Denied,
        (s, _) => s, // already decided: idempotent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_fails_closed_at_unit_cap() {
        let b = Budget {
            per_unit_cap_usd: 0.75,
            per_day_cap_usd: 100.0,
            spent_today_usd: 0.0,
            unit_spent_usd: 0.70,
        };
        // 0.10 would exceed the 0.75 unit cap.
        assert!(!b.can_spend(0.10));
        assert!(b.can_spend(0.05));
    }

    #[test]
    fn budget_fails_closed_at_day_cap() {
        let b = Budget {
            per_unit_cap_usd: 100.0,
            per_day_cap_usd: 10.0,
            spent_today_usd: 9.9,
            unit_spent_usd: 0.0,
        };
        assert!(!b.can_spend(0.20));
    }

    #[test]
    fn first_promotion_needs_human() {
        assert!(promotion_requires_human(true, true));
        assert!(promotion_requires_human(true, false));
    }

    #[test]
    fn below_bar_promotion_never_auto_approves() {
        assert!(promotion_requires_human(false, false));
        // Later drift with a passing verification may go dark.
        assert!(!promotion_requires_human(false, true));
    }

    #[test]
    fn only_privileged_credentials_need_human() {
        assert!(credential_requires_human(CredentialKind::Privileged));
        assert!(!credential_requires_human(CredentialKind::SelfIssued));
        assert!(!credential_requires_human(CredentialKind::BrokerIssued));
    }

    #[test]
    fn promotion_approval_is_idempotent() {
        assert_eq!(
            apply_promotion_approval(ApprovalState::Pending, true),
            ApprovalState::Approved
        );
        // Re-approving an already-approved promotion is a no-op.
        assert_eq!(
            apply_promotion_approval(ApprovalState::Approved, true),
            ApprovalState::Approved
        );
    }
}
