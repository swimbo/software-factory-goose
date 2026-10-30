//! Fixed private-namespace adapter. The caller must verify namespace and bootstrap identity.
use crate::{
    intake::{IntakeRequest, StoredIntake, valid_principal},
    intake_adapter::IntakeBackend,
    runtime_intake::QualifiedHandoff,
    worker_adapter::{AdapterError, WorkerBackend},
    worker_queue::{PullOutcome, PullRequest, QueueCompletion},
    workflow::{ClaimLeaseState, LeaseSpec},
};
use serde::{Serialize, de::DeserializeOwned};

pub struct RuntimeLoopbackBackend {
    client: reqwest::Client,
    base: String,
    principal: String,
    intent: String,
    task: String,
    queue: String,
    spec: LeaseSpec,
}
impl RuntimeLoopbackBackend {
    pub fn new(
        port: u16,
        principal: String,
        intent: String,
        task: String,
        queue: String,
        spec: LeaseSpec,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            port >= 1024
                && valid_principal(&principal)
                && intent != task
                && queue.len() <= 256
                && [&intent, &task]
                    .iter()
                    .all(|s| ulid::Ulid::from_string(s).is_ok_and(|u| u.to_string() == **s))
                && !queue.is_empty()
                && queue
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
            "invalid private backend scope"
        );
        Ok(Self {
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(15))
                .build()?,
            base: format!("http://127.0.0.1:{port}"),
            principal,
            intent,
            task,
            queue,
            spec,
        })
    }
    async fn call<T: Serialize + Sync, R: DeserializeOwned>(
        &self,
        service: &str,
        key: &str,
        handler: &str,
        value: Option<&T>,
    ) -> Result<R, AdapterError> {
        let url = format!("{}/restate/call/{service}/{key}/{handler}", self.base);
        let mut request = self.client.post(url);
        if let Some(value) = value {
            request = request.json(value);
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| AdapterError::new(503, "durable outcome unknown; retry same identity"))?;
        let status = response.status();
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| AdapterError::new(503, "durable response incomplete"))?
        {
            if bytes.len().saturating_add(chunk.len()) > 262144 {
                return Err(AdapterError::new(502, "durable response too large"));
            }
            bytes.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            return Err(AdapterError::new(
                if matches!(status.as_u16(), 400 | 403 | 404 | 409 | 410 | 429) {
                    status.as_u16()
                } else {
                    502
                },
                "durable request rejected",
            ));
        }
        serde_json::from_slice(&bytes)
            .map_err(|_| AdapterError::new(502, "durable response invalid"))
    }
    async fn plan(&self) -> Result<QualifiedHandoff, AdapterError> {
        let found: Option<QualifiedHandoff> = self
            .call::<(), _>("RuntimeIntakeJournal", &self.intent, "inspect", None)
            .await?;
        let plan = found.ok_or_else(|| AdapterError::new(409, "qualified handoff unavailable"))?;
        if plan.schedule.work_package_id != self.task
            || plan.schedule.spec != self.spec
            || plan.intake.submitted_by != self.principal
            || plan.intake.intent_id != self.intent
            || plan.intake.idempotency_key != self.intent
        {
            return Err(AdapterError::new(409, "qualified handoff scope mismatch"));
        }
        Ok(plan)
    }
}
impl IntakeBackend for RuntimeLoopbackBackend {
    fn principal(&self) -> &str {
        &self.principal
    }
    async fn submit(
        &self,
        key: String,
        request: IntakeRequest,
    ) -> Result<StoredIntake, AdapterError> {
        if key != self.intent {
            return Err(AdapterError::new(403, "intake outside catalog"));
        }
        let result: QualifiedHandoff = self
            .call(
                "RuntimeIntakeJournal",
                &key,
                "submit_and_schedule",
                Some(&request),
            )
            .await?;
        if result.schedule.work_package_id != self.task || result.schedule.spec != self.spec {
            return Err(AdapterError::new(502, "handoff reply mismatch"));
        }
        Ok(result.intake)
    }
    async fn inspect(&self, key: String) -> Result<Option<StoredIntake>, AdapterError> {
        if key != self.intent {
            return Err(AdapterError::new(403, "intake outside catalog"));
        }
        let result: Option<QualifiedHandoff> = self
            .call::<(), _>("RuntimeIntakeJournal", &key, "inspect", None)
            .await?;
        match result {
            Some(plan)
                if plan.schedule.work_package_id == self.task
                    && plan.schedule.spec == self.spec
                    && plan.intake.submitted_by == self.principal
                    && plan.intake.intent_id == self.intent
                    && plan.intake.idempotency_key == self.intent =>
            {
                Ok(Some(plan.intake))
            }
            Some(_) => Err(AdapterError::new(502, "handoff reply mismatch")),
            None => Ok(None),
        }
    }
}
impl WorkerBackend for RuntimeLoopbackBackend {
    async fn pull(&self, queue: String, request: PullRequest) -> Result<PullOutcome, AdapterError> {
        if queue != self.queue {
            return Err(AdapterError::new(403, "queue scope mismatch"));
        }
        self.plan().await?;
        let result: PullOutcome = self
            .call("WorkerQueueJournal", &queue, "pull", Some(&request))
            .await?;
        if let PullOutcome::Assigned {
            work_package_id,
            spec,
            ..
        } = &result
            && (work_package_id != &self.task || spec != &self.spec)
        {
            return Err(AdapterError::new(409, "assignment scope mismatch"));
        }
        if let PullOutcome::Unavailable {
            work_package_id, ..
        } = &result
            && work_package_id != &self.task
        {
            return Err(AdapterError::new(409, "assignment scope mismatch"));
        }
        Ok(result)
    }
    async fn lookup_pull(
        &self,
        queue: String,
        request_id: String,
    ) -> Result<Option<PullOutcome>, AdapterError> {
        if queue != self.queue {
            return Err(AdapterError::new(403, "queue scope mismatch"));
        }
        self.plan().await?;
        let result: Option<PullOutcome> = self
            .call(
                "WorkerQueueJournal",
                &queue,
                "lookup_pull",
                Some(&request_id),
            )
            .await?;
        if let Some(PullOutcome::Assigned {
            work_package_id,
            spec,
            ..
        }) = &result
            && (work_package_id != &self.task || spec != &self.spec)
        {
            return Err(AdapterError::new(409, "assignment scope mismatch"));
        }
        if let Some(PullOutcome::Unavailable {
            work_package_id, ..
        }) = &result
            && work_package_id != &self.task
        {
            return Err(AdapterError::new(409, "assignment scope mismatch"));
        }
        Ok(result)
    }
    async fn status(&self, task: String) -> Result<Option<ClaimLeaseState>, AdapterError> {
        if task != self.task {
            return Err(AdapterError::new(403, "task scope mismatch"));
        }
        self.call::<(), _>("ClaimLeaseJournal", &task, "status", None)
            .await
    }
    async fn complete(
        &self,
        queue: String,
        request: QueueCompletion,
    ) -> Result<ClaimLeaseState, AdapterError> {
        if queue != self.queue {
            return Err(AdapterError::new(403, "queue scope mismatch"));
        }
        self.plan().await?;
        self.call("WorkerQueueJournal", &queue, "complete", Some(&request))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, routing::post};
    use std::{
        net::SocketAddr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    #[tokio::test]
    async fn no_published_qualification_means_no_worker_pull() {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let app = Router::new()
            .route(
                "/restate/call/RuntimeIntakeJournal/01J00000000000000000000000/inspect",
                post(|| async { Json(serde_json::Value::Null) }),
            )
            .route(
                "/restate/call/WorkerQueueJournal/queue/pull",
                post(move || {
                    let count = count.clone();
                    async move {
                        count.fetch_add(1, Ordering::SeqCst);
                        Json("Empty")
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let backend = RuntimeLoopbackBackend::new(
            addr.port(),
            "operator".into(),
            "01J00000000000000000000000".into(),
            "01J00000000000000000000001".into(),
            "queue".into(),
            LeaseSpec {
                repository: "r".into(),
                base_revision: "a".repeat(40),
            },
        )
        .unwrap();
        let request = PullRequest {
            request_id: "01J00000000000000000000002".into(),
            ttl_ms: 1000,
        };
        assert!(backend.pull("other".into(), request.clone()).await.is_err());
        assert!(backend.pull("queue".into(), request).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        server.abort();
    }
}
