//! Bounded, unregistered worker delivery queue backed by the existing claim journal.
//!
//! ClaimLeaseJournal remains the sole lease authority. This object stores immutable schedule
//! records and pull receipts, not independently mutable lease state. A repeated pull returns
//! the original receipt, including its original deadline: it is not fresh spawn authorization.
//! No worker process, retry/reassignment, eviction or DAG scheduler is implemented here.
//! Before activation a private adapter must authenticate every request, enforce separate
//! scheduler/worker permissions, and validate the active lease before starting a process.

use crate::workflow::{
    ActiveLease, ClaimLeaseJournalClient, ClaimLeaseState, ClaimRequest, CompleteLeaseRequest,
    LeaseProof, LeaseSpec, MAX_LEASE_MS,
};
use restate_sdk::{prelude::*, serde::Json};

const MAX_ENTRIES: usize = 256;
const MAX_PULLS: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleRequest {
    pub work_package_id: String,
    pub spec: LeaseSpec,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullRequest {
    pub request_id: String,
    pub ttl_ms: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PullOutcome {
    Empty,
    Assigned {
        work_package_id: String,
        spec: LeaseSpec,
        lease: ActiveLease,
    },
    /// This task cannot be retried through this queue. Reap/repair needs a separate protocol.
    Unavailable {
        work_package_id: String,
        code: u16,
    },
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueCompletion {
    pub request_id: String,
    pub proof: LeaseProof,
    pub receipt: shared::Receipt,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Entry {
    request: ScheduleRequest,
    issued: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct PullRecord {
    request: PullRequest,
    outcome: PullOutcome,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct QueueState {
    queue_id: String,
    worker_id: String,
    entries: Vec<Entry>,
    pulls: Vec<PullRecord>,
}
fn error(code: u16, message: &str) -> TerminalError {
    TerminalError::new_with_code(code, message)
}
fn canonical_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
// Queue and work-package IDs become Restate URL path segments in the private worker
// adapter. Reject ambiguous forms before persisting work the adapter cannot safely use.
fn canonical_transport_key(value: &str) -> bool {
    canonical_text(value)
        && value != "."
        && value != ".."
        && !value
            .chars()
            .any(|c| matches!(c, '/' | '\\' | '%' | '?' | '#'))
}
fn canonical_id(value: &str) -> bool {
    ulid::Ulid::from_string(value).is_ok_and(|id| id.to_string() == value)
}
fn validate_schedule(request: &ScheduleRequest) -> Result<(), TerminalError> {
    if !canonical_transport_key(&request.work_package_id)
        || !canonical_text(&request.spec.repository)
        || !matches!(request.spec.base_revision.len(), 40 | 64)
        || !request
            .spec
            .base_revision
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(error(400, "invalid immutable queue task spec"));
    }
    Ok(())
}
impl QueueState {
    fn new(queue_id: &str, worker_id: &str) -> Self {
        Self {
            queue_id: queue_id.into(),
            worker_id: worker_id.into(),
            entries: Vec::new(),
            pulls: Vec::new(),
        }
    }
    fn check_binding(&self, key: &str, worker: &str) -> Result<(), TerminalError> {
        if !canonical_transport_key(key) || self.queue_id != key || self.worker_id != worker {
            return Err(error(403, "queue scope mismatch"));
        }
        Ok(())
    }
    fn check_schedule(&self, request: &ScheduleRequest) -> Result<bool, TerminalError> {
        validate_schedule(request)?;
        if let Some(entry) = self
            .entries
            .iter()
            .find(|e| e.request.work_package_id == request.work_package_id)
        {
            if entry.request != *request {
                return Err(error(409, "task schedule is immutable"));
            }
            return Ok(true);
        }
        if self.entries.len() >= MAX_ENTRIES {
            return Err(error(429, "queue schedule capacity exhausted"));
        }
        Ok(false)
    }
    fn record_schedule(&mut self, request: ScheduleRequest) -> Result<(), TerminalError> {
        if !self.check_schedule(&request)? {
            self.entries.push(Entry {
                request,
                issued: false,
            });
        }
        Ok(())
    }
    fn previous_pull(&self, request: &PullRequest) -> Result<Option<PullOutcome>, TerminalError> {
        if !canonical_id(&request.request_id)
            || request.ttl_ms == 0
            || request.ttl_ms > MAX_LEASE_MS
        {
            return Err(error(400, "invalid pull identity or lease lifetime"));
        }
        if let Some(record) = self
            .pulls
            .iter()
            .find(|r| r.request.request_id == request.request_id)
        {
            if record.request != *request {
                return Err(error(409, "pull identity reused with changed parameters"));
            }
            return Ok(Some(record.outcome.clone()));
        }
        if self.pulls.len() >= MAX_PULLS {
            return Err(error(429, "queue pull capacity exhausted"));
        }
        Ok(None)
    }
    fn next_pending(&self) -> Option<&ScheduleRequest> {
        self.entries.iter().find(|e| !e.issued).map(|e| &e.request)
    }
    fn record_pull(
        &mut self,
        request: PullRequest,
        outcome: PullOutcome,
    ) -> Result<(), TerminalError> {
        if let Some(old) = self.previous_pull(&request)? {
            return if old == outcome {
                Ok(())
            } else {
                Err(error(409, "pull outcome is immutable"))
            };
        }
        let task = match &outcome {
            PullOutcome::Assigned {
                work_package_id,
                spec,
                lease,
            } => {
                if self
                    .next_pending()
                    .is_none_or(|r| r.work_package_id != *work_package_id || r.spec != *spec)
                    || lease.worker_id != self.worker_id
                    || lease.attempt != 1
                    || !canonical_id(&lease.token)
                    || lease.issued_at_ms >= lease.expires_at_ms
                    || lease.expires_at_ms > lease.hard_deadline_ms
                    || lease.expires_at_ms - lease.issued_at_ms != request.ttl_ms
                    || lease.hard_deadline_ms.checked_sub(lease.issued_at_ms) != Some(MAX_LEASE_MS)
                {
                    return Err(error(500, "claim journal returned inconsistent assignment"));
                }
                Some(work_package_id)
            }
            PullOutcome::Unavailable {
                work_package_id,
                code,
            } => {
                if !matches!(code, 409 | 410)
                    || self
                        .next_pending()
                        .is_none_or(|r| r.work_package_id != *work_package_id)
                {
                    return Err(error(500, "invalid unavailable claim outcome"));
                }
                Some(work_package_id)
            }
            PullOutcome::Empty => {
                if self.next_pending().is_some() {
                    return Err(error(500, "empty outcome with pending work"));
                }
                None
            }
        };
        if let Some(task) = task {
            // No eviction or reset: retaining issued tasks prevents an expired attempt from
            // becoming eligible again without a separately verified process-reap protocol.
            self.entries
                .iter_mut()
                .find(|e| e.request.work_package_id == *task)
                .unwrap()
                .issued = true;
        }
        self.pulls.push(PullRecord { request, outcome });
        Ok(())
    }
    fn completion_target(
        &self,
        request_id: &str,
        proof: &LeaseProof,
    ) -> Result<&str, TerminalError> {
        self.pulls
            .iter()
            .find_map(|record| {
                if record.request.request_id != request_id {
                    return None;
                }
                match &record.outcome {
                    PullOutcome::Assigned {
                        work_package_id,
                        lease,
                        ..
                    } if lease.worker_id == self.worker_id
                        && lease.attempt == proof.attempt
                        && lease.token == proof.token =>
                    {
                        Some(work_package_id.as_str())
                    }
                    _ => None,
                }
            })
            .ok_or_else(|| error(409, "completion is not bound to this pull and lease"))
    }
}

/// Configuration is scope, not caller authentication. MUST remain unregistered until private
/// ingress preserves authenticated worker identity and independently authorizes scheduling.
/// The ClaimLeaseJournal deployment must use the same configured worker scope.
pub struct WorkerQueueJournal {
    worker_id: String,
    scopes: Option<Vec<(String, String)>>,
}
impl WorkerQueueJournal {
    pub fn new_for_private_ingress(worker_id: String) -> anyhow::Result<Self> {
        anyhow::ensure!(canonical_text(&worker_id), "invalid queue worker scope");
        Ok(Self {
            worker_id,
            scopes: None,
        })
    }
    pub fn new_with_preserved_queue(
        worker_id: String,
        queue: String,
        old_worker: String,
        old_queue: String,
    ) -> anyhow::Result<Self> {
        Self::new_with_queue_scopes(vec![(old_queue, old_worker), (queue, worker_id)])
    }
    pub fn new_with_queue_scopes(scopes: Vec<(String, String)>) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !scopes.is_empty() && scopes.len() <= 3,
            "invalid queue scope count"
        );
        let mut seen = std::collections::BTreeSet::new();
        for (queue, worker) in &scopes {
            anyhow::ensure!(
                canonical_transport_key(queue) && canonical_text(worker) && seen.insert(queue),
                "queue scopes collide or are invalid"
            );
        }
        Ok(Self {
            worker_id: scopes[0].1.clone(),
            scopes: Some(scopes),
        })
    }
    fn worker_for(&self, key: &str) -> Result<&str, TerminalError> {
        match &self.scopes {
            None => Ok(&self.worker_id),
            Some(scopes) => scopes
                .iter()
                .find(|(queue, _)| queue == key)
                .map(|(_, worker)| worker.as_str())
                .ok_or_else(|| error(403, "queue outside root catalog")),
        }
    }
    async fn load(&self, ctx: &ObjectContext<'_>) -> HandlerResult<QueueState> {
        let worker = self.worker_for(ctx.key())?;
        let state = ctx
            .get::<Json<QueueState>>("queue")
            .await?
            .map(|s| s.0)
            .unwrap_or_else(|| QueueState::new(ctx.key(), worker));
        state.check_binding(ctx.key(), worker)?;
        Ok(state)
    }
}
#[restate_sdk::object]
impl WorkerQueueJournal {
    #[handler]
    async fn schedule(
        &self,
        ctx: ObjectContext<'_>,
        request: Json<ScheduleRequest>,
    ) -> HandlerResult<()> {
        let mut state = self.load(&ctx).await?;
        if state.check_schedule(&request.0)? {
            return Ok(());
        }
        // Awaited SDK RPC is journaled, so a crash between child initialization and this
        // state write replays the same call; initialize is also immutable/idempotent.
        let initialized = ctx
            .object_client::<ClaimLeaseJournalClient>(&request.0.work_package_id)
            .initialize(Json(request.0.spec.clone()))
            .call()
            .await?;
        if initialized.0.work_package_id != request.0.work_package_id
            || initialized.0.spec != request.0.spec
        {
            return Err(error(500, "initialized claim binding mismatch").into());
        }
        state.record_schedule(request.0)?;
        ctx.set("queue", Json(state));
        Ok(())
    }
    #[handler]
    async fn pull(
        &self,
        ctx: ObjectContext<'_>,
        request: Json<PullRequest>,
    ) -> HandlerResult<Json<PullOutcome>> {
        let mut state = self.load(&ctx).await?;
        if let Some(previous) = state.previous_pull(&request.0)? {
            return Ok(Json(previous));
        }
        let outcome = if let Some(task) = state.next_pending().cloned() {
            // The precondition is enforced atomically inside the lease authority. A
            // separate status read followed by an unconditional claim would race.
            match ctx
                .object_client::<ClaimLeaseJournalClient>(&task.work_package_id)
                .claim(Json(ClaimRequest {
                    ttl_ms: request.0.ttl_ms,
                    expected_previous_attempt: Some(0),
                }))
                .call()
                .await
            {
                Ok(lease) => PullOutcome::Assigned {
                    work_package_id: task.work_package_id,
                    spec: task.spec,
                    lease: lease.0,
                },
                Err(e) if matches!(e.code(), 409 | 410) => PullOutcome::Unavailable {
                    work_package_id: task.work_package_id,
                    code: e.code(),
                },
                Err(e) => return Err(e.into()),
            }
        } else {
            PullOutcome::Empty
        };
        state.record_pull(request.0, outcome.clone())?;
        ctx.set("queue", Json(state));
        Ok(Json(outcome))
    }
    /// Read-only completion lookup. Never calls claim or creates a pull receipt.
    #[handler]
    async fn lookup_pull(
        &self,
        ctx: SharedObjectContext<'_>,
        request_id: String,
    ) -> HandlerResult<Json<Option<PullOutcome>>> {
        if !canonical_id(&request_id) {
            return Err(error(400, "invalid pull request ID").into());
        }
        let Some(state) = ctx.get::<Json<QueueState>>("queue").await? else {
            return Ok(Json(None));
        };
        state
            .0
            .check_binding(ctx.key(), self.worker_for(ctx.key())?)?;
        Ok(Json(
            state
                .0
                .pulls
                .iter()
                .find(|record| record.request.request_id == request_id)
                .map(|record| record.outcome.clone()),
        ))
    }

    #[handler]
    async fn complete(
        &self,
        ctx: ObjectContext<'_>,
        request: Json<QueueCompletion>,
    ) -> HandlerResult<Json<ClaimLeaseState>> {
        let state = self.load(&ctx).await?;
        let task = state.completion_target(&request.0.request_id, &request.0.proof)?;
        // The child atomically checks live expiry, worker, attempt, token and receipt
        // idempotency. This retained queue receipt cannot override any of those checks.
        Ok(ctx
            .object_client::<ClaimLeaseJournalClient>(task)
            .complete(Json(CompleteLeaseRequest {
                proof: request.0.proof,
                receipt: request.0.receipt,
            }))
            .call()
            .await?)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn three_queue_scopes_are_exact_and_duplicate_queue_is_denied() {
        let q = super::WorkerQueueJournal::new_with_queue_scopes(vec![
            ("a".into(), "w1".into()),
            ("b".into(), "w2".into()),
            ("c".into(), "w3".into()),
        ])
        .unwrap();
        assert_eq!(q.worker_for("a").unwrap(), "w1");
        assert_eq!(q.worker_for("b").unwrap(), "w2");
        assert_eq!(q.worker_for("c").unwrap(), "w3");
        assert!(q.worker_for("other").is_err());
        assert!(
            super::WorkerQueueJournal::new_with_queue_scopes(vec![
                ("a".into(), "w1".into()),
                ("a".into(), "w2".into())
            ])
            .is_err()
        );
    }
    #[test]
    fn protected_two_queue_binding_rejects_unknown_and_collisions() {
        let q = super::WorkerQueueJournal::new_with_preserved_queue(
            "new-worker".into(),
            "new-queue".into(),
            "old-worker".into(),
            "old-queue".into(),
        )
        .unwrap();
        assert_eq!(q.worker_for("old-queue").unwrap(), "old-worker");
        assert_eq!(q.worker_for("new-queue").unwrap(), "new-worker");
        assert!(q.worker_for("other").is_err());
        assert!(
            super::WorkerQueueJournal::new_with_preserved_queue(
                "new-worker".into(),
                "same".into(),
                "old-worker".into(),
                "same".into()
            )
            .is_err()
        );
    }

    use super::*;
    fn request() -> ScheduleRequest {
        ScheduleRequest {
            work_package_id: "task-1".into(),
            spec: LeaseSpec {
                repository: "repo".into(),
                base_revision: "a".repeat(40),
            },
        }
    }
    fn pull() -> PullRequest {
        PullRequest {
            request_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            ttl_ms: 1000,
        }
    }
    fn lease() -> ActiveLease {
        ActiveLease {
            worker_id: "worker".into(),
            attempt: 1,
            token: "01ARZ3NDEKTSV4RRFFQ69G5FAW".into(),
            issued_at_ms: 10,
            expires_at_ms: 1010,
            hard_deadline_ms: 300010,
        }
    }
    #[test]
    fn schedule_is_immutable_and_survives_serialization() {
        let mut q = QueueState::new("queue", "worker");
        q.record_schedule(request()).unwrap();
        let mut restored: QueueState =
            serde_json::from_str(&serde_json::to_string(&q).unwrap()).unwrap();
        restored.record_schedule(request()).unwrap();
        assert_eq!(restored, q);
        let mut changed = request();
        changed.spec.base_revision = "b".repeat(40);
        assert!(restored.record_schedule(changed).is_err());
        assert!(restored.check_binding("queue", "other").is_err());
    }
    #[test]
    fn queue_and_task_keys_reject_ambiguous_transport_segments() {
        for invalid in [".", "..", "%2e", "a/b", "a\\b", "a?b", "a#b"] {
            let mut req = request();
            req.work_package_id = invalid.into();
            assert!(
                validate_schedule(&req).is_err(),
                "accepted task key {invalid}"
            );
            let q = QueueState::new(invalid, "worker");
            assert!(
                q.check_binding(invalid, "worker").is_err(),
                "accepted queue key {invalid}"
            );
        }
        let mut req = request();
        req.work_package_id = "unit:task-1".into();
        assert!(validate_schedule(&req).is_ok());
        assert!(
            QueueState::new("queue:1", "worker")
                .check_binding("queue:1", "worker")
                .is_ok()
        );
    }
    #[test]
    fn lost_ack_returns_original_assignment_without_new_claim() {
        let mut q = QueueState::new("queue", "worker");
        q.record_schedule(request()).unwrap();
        let result = PullOutcome::Assigned {
            work_package_id: "task-1".into(),
            spec: request().spec,
            lease: lease(),
        };
        q.record_pull(pull(), result.clone()).unwrap();
        let restored: QueueState =
            serde_json::from_str(&serde_json::to_string(&q).unwrap()).unwrap();
        assert_eq!(restored.previous_pull(&pull()).unwrap(), Some(result));
        assert!(
            restored.next_pending().is_none(),
            "issued tasks never auto-requeue"
        );
        let mut changed = pull();
        changed.ttl_ms += 1;
        assert!(restored.previous_pull(&changed).is_err());
    }
    #[test]
    fn empty_poll_is_stable_and_new_id_can_observe_new_work() {
        let mut q = QueueState::new("queue", "worker");
        q.record_pull(pull(), PullOutcome::Empty).unwrap();
        q.record_schedule(request()).unwrap();
        assert_eq!(q.previous_pull(&pull()).unwrap(), Some(PullOutcome::Empty));
        let mut next = pull();
        next.request_id = "01ARZ3NDEKTSV4RRFFQ69G5FAX".into();
        assert!(q.previous_pull(&next).unwrap().is_none());
        assert!(q.next_pending().is_some());
    }
    #[test]
    fn completion_is_bound_to_delivery_and_exact_lease() {
        let mut q = QueueState::new("queue", "worker");
        q.record_schedule(request()).unwrap();
        q.record_pull(
            pull(),
            PullOutcome::Assigned {
                work_package_id: "task-1".into(),
                spec: request().spec,
                lease: lease(),
            },
        )
        .unwrap();
        let proof = LeaseProof {
            attempt: 1,
            token: lease().token,
        };
        assert_eq!(
            q.completion_target(&pull().request_id, &proof).unwrap(),
            "task-1"
        );
        assert!(
            q.completion_target(
                &pull().request_id,
                &LeaseProof {
                    attempt: 2,
                    ..proof.clone()
                }
            )
            .is_err()
        );
        assert!(
            q.completion_target(
                &pull().request_id,
                &LeaseProof {
                    token: "forged".into(),
                    ..proof
                }
            )
            .is_err()
        );
        assert!(
            q.completion_target(
                "missing",
                &LeaseProof {
                    attempt: 1,
                    token: lease().token
                }
            )
            .is_err()
        );
    }
    #[test]
    fn capacity_and_invalid_inputs_fail_closed() {
        let mut q = QueueState::new("queue", "worker");
        for n in 0..MAX_ENTRIES {
            let mut r = request();
            r.work_package_id = format!("task-{n}");
            q.record_schedule(r).unwrap();
        }
        let mut overflow = request();
        overflow.work_package_id = "extra".into();
        assert!(q.record_schedule(overflow).is_err());
        q.record_schedule(request()).unwrap();
        let mut bad = pull();
        bad.ttl_ms = 0;
        assert!(q.previous_pull(&bad).is_err());
        bad = pull();
        bad.request_id = "arbitrary".into();
        assert!(q.previous_pull(&bad).is_err());
        let mut invalid = request();
        invalid.spec.base_revision = "HEAD".into();
        assert!(validate_schedule(&invalid).is_err());
    }
    #[test]
    fn unavailable_task_is_retained_without_blocking_next_task() {
        let mut q = QueueState::new("queue", "worker");
        q.record_schedule(request()).unwrap();
        let mut second = request();
        second.work_package_id = "task-2".into();
        q.record_schedule(second.clone()).unwrap();
        let unavailable = PullOutcome::Unavailable {
            work_package_id: "task-1".into(),
            code: 409,
        };
        q.record_pull(pull(), unavailable.clone()).unwrap();
        q.record_schedule(request()).unwrap();
        assert_eq!(q.next_pending(), Some(&second));
        assert_eq!(q.previous_pull(&pull()).unwrap(), Some(unavailable));
        assert!(q.record_pull(pull(), PullOutcome::Empty).is_err());
    }
    #[test]
    fn inconsistent_child_assignment_cannot_mutate_queue() {
        let mut q = QueueState::new("queue", "worker");
        q.record_schedule(request()).unwrap();
        let before = q.clone();
        for invalid in [
            ActiveLease {
                worker_id: "foreign".into(),
                ..lease()
            },
            ActiveLease {
                attempt: 2,
                ..lease()
            },
            ActiveLease {
                expires_at_ms: 1011,
                ..lease()
            },
        ] {
            assert!(
                q.record_pull(
                    pull(),
                    PullOutcome::Assigned {
                        work_package_id: "task-1".into(),
                        spec: request().spec,
                        lease: invalid
                    }
                )
                .is_err()
            );
            assert_eq!(q, before);
        }
    }
    #[test]
    fn pull_capacity_preserves_prior_receipts_and_does_not_evict() {
        let mut q = QueueState::new("queue", "worker");
        for n in 0..MAX_PULLS {
            let r = PullRequest {
                request_id: ulid::Ulid::from(n as u128).to_string(),
                ttl_ms: 1000,
            };
            q.record_pull(r, PullOutcome::Empty).unwrap();
        }
        assert!(q.previous_pull(&pull()).is_err());
        let first = PullRequest {
            request_id: ulid::Ulid::from(0u128).to_string(),
            ttl_ms: 1000,
        };
        assert_eq!(q.previous_pull(&first).unwrap(), Some(PullOutcome::Empty));
        q.record_pull(first, PullOutcome::Empty).unwrap();
        assert_eq!(q.pulls.len(), MAX_PULLS);
    }
}
