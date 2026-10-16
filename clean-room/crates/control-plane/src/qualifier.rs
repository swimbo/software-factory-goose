//! The qualifier — the lane-routing function ("the real product" per gethuman.sh).
//!
//! Consensus O3: inputs → score Q ∈ [0,1] + a fatal safety flag → dark-lane iff
//! `Q < 0.60` (a low risk score means "safe to automate") or the fatal flag is set.

use shared::{Lane, QualifierDecision};

/// Raw features the qualifier scores from an incoming intent.
#[derive(Debug, Clone)]
pub struct IntentFeatures {
    /// 0..1 — how precisely the acceptance criteria are machine-checkable (executable
    /// assertions vs. vague prose). Higher = more machine-derivable = safer to automate.
    pub spec_clarity: f64,
    /// 0..1 — blast-radius: 0 = reversible greenfield toy, 1 = irreversible prod/destructive.
    pub blast_radius: f64,
    /// 0..1 — dependency/domain novelty: 0 = well-trodden, 1 = novel/unknown.
    pub novelty: f64,
    /// 0..1 — reversibility of the change: 0 = trivially reversible, 1 = irreversible.
    pub reversibility: f64,
    /// Whether the target repo has the required codified knowledge (`AGENTS.md` etc.).
    pub has_codified_knowledge: bool,
    /// Whether any safety sub-score is a hard zero (overrides the aggregate).
    pub fatal: bool,
}

/// The qualifier: pure, deterministic, unit-testable.
pub fn score(features: &IntentFeatures) -> f64 {
    // Higher Q = higher risk = more likely human lane. Weighted mean of the risk factors,
    // with blast-radius and irreversibility carrying the most weight (they dominate the
    // decision, per the report's "irreversible changes" framing).
    let weighted = 0.45 * features.blast_radius
        + 0.30 * features.reversibility
        + 0.15 * features.novelty
        + 0.10 * (1.0 - features.spec_clarity);
    weighted.clamp(0.0, 1.0)
}

/// Dark-lane threshold (O3). `Q < threshold` → dark; hard gates override → human.
pub const DARK_LANE_THRESHOLD: f64 = 0.60;

/// Hard gates that force the human lane regardless of score:
/// - `fatal` (a safety sub-score is a hard zero), and
/// - missing codified knowledge (`AGENTS.md` etc.) — "automating chaos" (report §4).
fn hard_blocked(f: &IntentFeatures) -> bool {
    f.fatal || !f.has_codified_knowledge
}

pub fn decide(intent_id: &str, features: &IntentFeatures) -> QualifierDecision {
    let q = score(features);
    let lane = if hard_blocked(features) || q >= DARK_LANE_THRESHOLD {
        Lane::Human
    } else {
        Lane::Dark
    };
    QualifierDecision {
        intent_id: intent_id.to_string(),
        score: q,
        lane,
        reason: reason(features, q),
        fatal: features.fatal,
    }
}

fn reason(f: &IntentFeatures, q: f64) -> String {
    if f.fatal {
        return "fatal safety flag set".to_string();
    }
    if !f.has_codified_knowledge {
        return "repo lacks codified knowledge (AGENTS.md) — human lane".to_string();
    }
    if q >= DARK_LANE_THRESHOLD {
        format!(
            "risk score {:.2} >= {:.2} (blast radius {:.2}, reversibility {:.2})",
            q, DARK_LANE_THRESHOLD, f.blast_radius, f.reversibility
        )
    } else {
        format!("risk score {:.2} < {:.2} — dark lane", q, DARK_LANE_THRESHOLD)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn low_risk() -> IntentFeatures {
        IntentFeatures {
            spec_clarity: 0.9,
            blast_radius: 0.1,
            novelty: 0.1,
            reversibility: 0.0,
            has_codified_knowledge: true,
            fatal: false,
        }
    }

    #[test]
    fn low_risk_goes_dark() {
        let d = decide("i1", &low_risk());
        assert_eq!(d.lane, Lane::Dark);
        assert!(d.score < DARK_LANE_THRESHOLD);
    }

    #[test]
    fn high_blast_radius_goes_human() {
        let mut f = low_risk();
        f.blast_radius = 0.95;
        f.reversibility = 0.9;
        let d = decide("i2", &f);
        assert_eq!(d.lane, Lane::Human);
    }

    #[test]
    fn missing_knowledge_penalized() {
        let mut f = low_risk();
        f.has_codified_knowledge = false;
        let d = decide("i3", &f);
        assert_eq!(d.lane, Lane::Human);
        assert!(d.reason.contains("codified knowledge"));
    }

    #[test]
    fn fatal_overrides_score() {
        let mut f = low_risk();
        f.fatal = true;
        let d = decide("i4", &f);
        assert_eq!(d.lane, Lane::Human);
        assert!(d.fatal);
    }
}
