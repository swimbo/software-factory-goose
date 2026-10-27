//! Driver pipeline — drives an intent from goal cascade to merge (R15).
//!
//! The pipeline owns the runtime orchestration the R15 `driver` DAG enables:
//! decompose (intent → spec → work packages) → dispatch unblocked tasks → build (Goose) →
//! evaluate (the wall) → human gate → merge. The graph logic is pure and tested here; the
//! external calls (start the Restate workflow, run the worker, run the wall) attach at the
//! `dispatch` / `on_result` seams.

use crate::driver::{self, DriverError};
use crate::gates;
use shared::{Lane, Receipt, Task, TaskStatus};

/// Default per-unit dollar ceiling (R7) — the pipeline's hard spend bound.
pub const DEFAULT_PER_UNIT_CAP_USD: f64 = 0.75;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Decomposed,
    Dispatched,
    Building,
    Verified,
    Failed,
}

/// The goal cascade: intent → work packages.
///
/// The greenfield demo decomposes into a small `scaffold → implement → test` DAG. A spec-driven
/// decomposition would parse the spec's modules into one task each; the DAG shape is what the
/// R15 driver consumes either way.
pub fn decompose(intent_id: &str, spec: &str) -> Vec<Task> {
    let mk = |suffix: &str, subject: &str, blocked_by: Vec<String>| {
        let mut t = Task::new(format!("{intent_id}:{suffix}"), subject);
        t.description = spec.to_string();
        t.blocked_by = blocked_by;
        t
    };
    let scaffold = mk("scaffold", "Scaffold the project", vec![]);
    let implement = mk("implement", "Implement the spec", vec![scaffold.id.clone()]);
    let test = mk(
        "test",
        "Add and pass the acceptance test",
        vec![implement.id.clone()],
    );
    vec![scaffold, implement, test]
}

pub struct Pipeline {
    pub intent_id: String,
    pub lane: Lane,
    pub tasks: Vec<Task>,
    /// Spend accumulated across the pipeline (R7 — the per-unit dollar ceiling).
    pub spent_usd: f64,
    /// The hard ceiling for this unit; only a human raises it (Gate 2).
    pub ceiling_usd: f64,
}

impl Pipeline {
    pub fn new(intent_id: &str, spec: &str, lane: Lane) -> Self {
        Pipeline {
            intent_id: intent_id.to_string(),
            lane,
            tasks: decompose(intent_id, spec),
            spent_usd: 0.0,
            ceiling_usd: DEFAULT_PER_UNIT_CAP_USD,
        }
    }

    /// The pure budget check (R7): may the pipeline spend `estimate_usd` more?
    pub fn can_spend(&self, estimate_usd: f64) -> bool {
        gates::Budget {
            per_unit_cap_usd: self.ceiling_usd,
            per_day_cap_usd: f64::MAX,
            spent_today_usd: 0.0,
            unit_spent_usd: self.spent_usd,
        }
        .can_spend(estimate_usd)
    }

    /// Accrue spend from a worker result (R7).
    pub fn accrue(&mut self, usd: f64) {
        if !usd.is_finite() || usd < 0.0 {
            self.spent_usd = f64::INFINITY;
        } else {
            self.spent_usd += usd;
        }
    }

    /// Whether the budget is exhausted — a terminal state that loops to a human.
    pub fn budget_exhausted(&self) -> bool {
        !self.spent_usd.is_finite()
            || !self.ceiling_usd.is_finite()
            || self.spent_usd < 0.0
            || self.spent_usd >= self.ceiling_usd
    }

    /// Tasks ready to dispatch (pending with all blockers completed).
    pub fn next_work(&self) -> Vec<&Task> {
        if self.stage() == Stage::Failed || self.budget_exhausted() {
            return Vec::new();
        }
        driver::dispatchable(&self.tasks)
    }

    /// The full dependency order of the work packages.
    pub fn order(&self) -> Result<Vec<String>, DriverError> {
        driver::dispatch_order(&self.tasks)
    }

    /// Mark a task dispatched to a worker.
    pub fn dispatch(&mut self, task_id: &str) {
        if !self.next_work().iter().any(|t| t.id == task_id) {
            return;
        }
        if let Some(t) = self.tasks.iter_mut().find(|t| t.id == task_id) {
            t.status = TaskStatus::InProgress;
        }
    }

    /// Apply a worker **build** result (the build callback): a completed Receipt keeps the task
    /// in progress, awaiting the wall; anything else fails the task (and the pipeline).
    /// Returns whether the build completed (i.e. is ready for evaluation).
    pub fn on_build(&mut self, task_id: &str, receipt: &Receipt) -> bool {
        let Some(t) = self.tasks.iter_mut().find(|t| t.id == task_id) else {
            return false;
        };
        if t.status != TaskStatus::InProgress {
            return false;
        }
        if receipt.is_completed() {
            true // stays InProgress, awaiting evaluation
        } else {
            t.status = TaskStatus::Deleted;
            false
        }
    }

    /// Apply the **wall's** verdict (the evaluate callback): a pass completes the task and
    /// unblocks its dependents; a fail terminates it.
    pub fn on_eval(&mut self, task_id: &str, passed: bool) {
        if !self
            .tasks
            .iter()
            .any(|t| t.id == task_id && t.status == TaskStatus::InProgress)
        {
            return;
        }
        if passed {
            let id = task_id.to_string();
            let _ = driver::complete(&mut self.tasks, &id);
        } else if let Some(t) = self.tasks.iter_mut().find(|t| t.id == task_id) {
            t.status = TaskStatus::Deleted;
        }
    }

    /// The pipeline stage, derived from the task graph.
    pub fn stage(&self) -> Stage {
        if self.tasks.iter().any(|t| t.status == TaskStatus::Deleted) {
            return Stage::Failed;
        }
        if self.tasks.iter().all(|t| t.status == TaskStatus::Completed) {
            return Stage::Verified;
        }
        if self
            .tasks
            .iter()
            .any(|t| t.status == TaskStatus::InProgress)
        {
            return Stage::Building;
        }
        if self.tasks.iter().any(|t| t.status == TaskStatus::Completed) {
            return Stage::Dispatched;
        }
        Stage::Decomposed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_or_unknown_tasks_cannot_accept_results() {
        let mut p = Pipeline::new("int1", "spec", Lane::Dark);
        assert!(!p.on_build("int1:scaffold", &complete()));
        assert!(!p.on_build("int1:implement", &complete()));
        assert!(!p.on_build("unknown", &complete()));
        assert_eq!(p.stage(), Stage::Decomposed);
    }

    #[test]
    fn blocked_task_cannot_be_dispatched() {
        let mut p = Pipeline::new("int1", "spec", Lane::Dark);
        p.dispatch("int1:implement");
        assert_eq!(p.tasks[1].status, TaskStatus::Pending);
    }

    #[test]
    fn failed_pipeline_never_dispatches_more_work() {
        let mut p = Pipeline::new("int1", "spec", Lane::Dark);
        p.dispatch("int1:scaffold");
        p.on_eval("int1:scaffold", false);
        assert!(p.next_work().is_empty());
    }

    #[test]
    fn evaluation_cannot_complete_an_undispatched_task() {
        let mut p = Pipeline::new("int1", "spec", Lane::Dark);
        p.on_eval("int1:scaffold", true);
        assert_eq!(p.tasks[0].status, TaskStatus::Pending);
    }

    fn complete() -> Receipt {
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
    fn decompose_builds_a_scaffold_implement_test_dag() {
        let tasks = decompose("int1", "build a hello CLI");
        assert_eq!(tasks.len(), 3);
        assert_eq!(tasks[0].id, "int1:scaffold");
        assert!(tasks[0].blocked_by.is_empty());
        assert_eq!(tasks[1].blocked_by, vec!["int1:scaffold".to_string()]);
        assert_eq!(tasks[2].blocked_by, vec!["int1:implement".to_string()]);
    }

    #[test]
    fn only_scaffold_dispatches_first() {
        let p = Pipeline::new("int1", "spec", Lane::Dark);
        let ready = p.next_work();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].id, "int1:scaffold");
    }

    #[test]
    fn completing_scaffold_unblocks_implement() {
        let mut p = Pipeline::new("int1", "spec", Lane::Dark);
        p.dispatch("int1:scaffold");
        assert!(p.on_build("int1:scaffold", &complete()));
        p.on_eval("int1:scaffold", true);
        let ready = p.next_work();
        assert_eq!(ready[0].id, "int1:implement");
    }

    #[test]
    fn evaluation_alone_never_claims_a_git_merge() {
        let mut p = Pipeline::new("int1", "spec", Lane::Dark);
        assert_eq!(p.stage(), Stage::Decomposed);
        for id in ["int1:scaffold", "int1:implement", "int1:test"] {
            p.dispatch(id);
            p.on_build(id, &complete());
            p.on_eval(id, true);
        }
        assert_eq!(p.stage(), Stage::Verified);
    }

    #[test]
    fn failed_build_fails_the_pipeline() {
        let mut p = Pipeline::new("int1", "spec", Lane::Dark);
        p.dispatch("int1:scaffold");
        assert!(!p.on_build("int1:scaffold", &failed()));
        assert_eq!(p.stage(), Stage::Failed);
    }

    #[test]
    fn failed_eval_fails_the_pipeline() {
        let mut p = Pipeline::new("int1", "spec", Lane::Dark);
        p.dispatch("int1:scaffold");
        let built = p.on_build("int1:scaffold", &complete());
        assert!(built);
        // Build completed but the wall rejected it.
        p.on_eval("int1:scaffold", false);
        assert_eq!(p.stage(), Stage::Failed);
    }

    #[test]
    fn order_is_dependency_sorted() {
        let p = Pipeline::new("int1", "spec", Lane::Dark);
        assert_eq!(
            p.order().unwrap(),
            vec!["int1:scaffold", "int1:implement", "int1:test"]
        );
    }

    #[test]
    fn budget_blocks_when_it_would_exceed_the_ceiling() {
        let mut p = Pipeline::new("int1", "spec", Lane::Dark);
        assert!(p.can_spend(0.10));
        p.accrue(0.70);
        assert!(!p.can_spend(0.10)); // 0.80 > 0.75 ceiling → denied
        assert!(p.can_spend(0.05));
    }

    #[test]
    fn budget_is_exhausted_at_the_ceiling() {
        let mut p = Pipeline::new("int1", "spec", Lane::Dark);
        p.accrue(DEFAULT_PER_UNIT_CAP_USD);
        assert!(p.budget_exhausted());
    }
}
