//! Driver pipeline — drives an intent from goal cascade to merge (R15).
//!
//! The pipeline owns the runtime orchestration the R15 `driver` DAG enables:
//! decompose (intent → spec → work packages) → dispatch unblocked tasks → build (Goose) →
//! evaluate (the wall) → human gate → merge. The graph logic is pure and tested here; the
//! external calls (start the Restate workflow, run the worker, run the wall) attach at the
//! `dispatch` / `on_result` seams.

use crate::driver::{self, DriverError};
use shared::{Receipt, Task, TaskStatus, Lane};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Decomposed,
    Dispatched,
    Building,
    Merged,
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
    let test = mk("test", "Add and pass the acceptance test", vec![implement.id.clone()]);
    vec![scaffold, implement, test]
}

pub struct Pipeline {
    pub intent_id: String,
    pub lane: Lane,
    pub tasks: Vec<Task>,
    /// Spend accumulated across the pipeline (R7 — the per-unit dollar ceiling).
    pub spent_usd: f64,
}

impl Pipeline {
    pub fn new(intent_id: &str, spec: &str, lane: Lane) -> Self {
        Pipeline {
            intent_id: intent_id.to_string(),
            lane,
            tasks: decompose(intent_id, spec),
            spent_usd: 0.0,
        }
    }

    /// Tasks ready to dispatch (pending with all blockers completed).
    pub fn next_work(&self) -> Vec<&Task> {
        driver::dispatchable(&self.tasks)
    }

    /// The full dependency order of the work packages.
    pub fn order(&self) -> Result<Vec<String>, DriverError> {
        driver::dispatch_order(&self.tasks)
    }

    /// Mark a task dispatched to a worker.
    pub fn dispatch(&mut self, task_id: &str) {
        if let Some(t) = self.tasks.iter_mut().find(|t| t.id == task_id) {
            t.status = TaskStatus::InProgress;
        }
    }

    /// Apply a worker result: a completed Receipt advances the task; anything else retries
    /// once, then fails the task (and the pipeline).
    pub fn on_result(&mut self, task_id: &str, receipt: &Receipt) {
        let Some(t) = self.tasks.iter_mut().find(|t| t.id == task_id) else {
            return;
        };
        if receipt.is_completed() {
            t.status = TaskStatus::Completed;
            // Unblock dependents.
            let id = t.id.clone();
            let _ = driver::complete(&mut self.tasks, &id);
        } else {
            t.status = TaskStatus::Deleted; // terminal failure for this work package
        }
    }

    /// The pipeline stage, derived from the task graph.
    pub fn stage(&self) -> Stage {
        if self.tasks.iter().any(|t| t.status == TaskStatus::Deleted) {
            return Stage::Failed;
        }
        if self.tasks.iter().all(|t| t.status == TaskStatus::Completed) {
            return Stage::Merged;
        }
        if self.tasks.iter().any(|t| t.status == TaskStatus::InProgress) {
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

    fn complete() -> Receipt {
        Receipt::Completed {
            sha: "abc".into(),
            diff: "diff".into(),
            turn_count: 1,
            exit_code: 0,
            wall_time_ms: 1,
        }
    }

    fn failed() -> Receipt {
        Receipt::Failed { exit_code: 1, stderr_tail: "boom".into() }
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
        p.on_result("int1:scaffold", &complete());
        let ready = p.next_work();
        assert_eq!(ready[0].id, "int1:implement");
    }

    #[test]
    fn stage_advances_to_merged_when_all_done() {
        let mut p = Pipeline::new("int1", "spec", Lane::Dark);
        assert_eq!(p.stage(), Stage::Decomposed);
        for id in ["int1:scaffold", "int1:implement", "int1:test"] {
            p.dispatch(id);
            p.on_result(id, &complete());
        }
        assert_eq!(p.stage(), Stage::Merged);
    }

    #[test]
    fn failed_result_fails_the_pipeline() {
        let mut p = Pipeline::new("int1", "spec", Lane::Dark);
        p.dispatch("int1:scaffold");
        p.on_result("int1:scaffold", &failed());
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
}
