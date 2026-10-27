//! Coordinator / driver (R15) — work packages as a first-class dependency graph.
//!
//! The driver owns the DAG logic: which tasks are ready to dispatch, the topological order, and
//! how completion unblocks dependents. It is pure and deterministic; the actual worker dispatch
//! (Goose in a worktree) happens in the execution plane.

use shared::{Task, TaskStatus};
use std::collections::HashMap;

#[derive(Debug, PartialEq, Eq)]
pub enum DriverError {
    Cycle,
    UnknownTask(String),
}

/// Tasks that are pending and whose blockers are all completed — ready to dispatch.
pub fn dispatchable(tasks: &[Task]) -> Vec<&Task> {
    tasks.iter().filter(|t| t.is_dispatchable(tasks)).collect()
}

/// Topological order of task ids (blockers before dependents). Errors on a cycle.
pub fn dispatch_order(tasks: &[Task]) -> Result<Vec<String>, DriverError> {
    fn visit(
        id: &str,
        index: &HashMap<String, &Task>,
        state: &mut HashMap<String, u8>, // 0 unvisited · 1 visiting · 2 done
        order: &mut Vec<String>,
    ) -> Result<(), DriverError> {
        match state.get(id).copied() {
            Some(2) => return Ok(()),
            Some(1) => return Err(DriverError::Cycle),
            _ => {}
        }
        let task = index
            .get(id)
            .ok_or_else(|| DriverError::UnknownTask(id.to_string()))?;
        state.insert(id.to_string(), 1);
        for b in &task.blocked_by {
            visit(b, index, state, order)?;
        }
        state.insert(id.to_string(), 2);
        order.push(id.to_string());
        Ok(())
    }

    let index: HashMap<String, &Task> = tasks.iter().map(|t| (t.id.clone(), t)).collect();
    let mut state: HashMap<String, u8> = HashMap::new();
    let mut order = Vec::new();
    for t in tasks {
        visit(&t.id, &index, &mut state, &mut order)?;
    }
    Ok(order)
}

/// Mark a task completed and remove it from every dependent's `blocked_by`.
pub fn complete(tasks: &mut [Task], id: &str) -> Result<(), DriverError> {
    if !tasks.iter().any(|t| t.id == id) {
        return Err(DriverError::UnknownTask(id.to_string()));
    }
    for t in tasks.iter_mut() {
        if t.id == id {
            t.status = TaskStatus::Completed;
        }
        t.blocked_by.retain(|b| b != id);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(id: &str, blocked_by: &[&str]) -> Task {
        let mut t = Task::new(id.to_string(), format!("do {id}"));
        t.blocked_by = blocked_by.iter().map(|s| s.to_string()).collect();
        t
    }

    #[test]
    fn topological_order_respects_blockers() {
        let tasks = vec![task("c", &["b"]), task("a", &[]), task("b", &["a"])];
        let order = dispatch_order(&tasks).unwrap();
        assert_eq!(order, vec!["a", "b", "c"]);
    }

    #[test]
    fn cycle_is_rejected() {
        let tasks = vec![task("a", &["b"]), task("b", &["a"])];
        assert_eq!(dispatch_order(&tasks), Err(DriverError::Cycle));
    }

    #[test]
    fn only_unblocked_tasks_dispatch() {
        let tasks = vec![task("a", &[]), task("b", &["a"])];
        let ready = dispatchable(&tasks);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].id, "a");
    }

    #[test]
    fn completion_unblocks_dependent() {
        let mut tasks = vec![task("a", &[]), task("b", &["a"])];
        complete(&mut tasks, "a").unwrap();
        let ready = dispatchable(&tasks);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].id, "b");
    }

    #[test]
    fn completing_unknown_task_errors() {
        let mut tasks = vec![task("a", &[])];
        assert_eq!(
            complete(&mut tasks, "z"),
            Err(DriverError::UnknownTask("z".into()))
        );
    }
}
