use super::*;
use crate::{operator_transport::fixture_policy, state::Stage};
use evaluator::{
    DeterministicVerdict,
    holdout::{PrefilterSession, RunOutcome},
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::{Mutex, OwnedMutexGuard};
use tower::ServiceExt;

struct Evidence {
    snapshot: PromotionSnapshot,
    wall: VerificationEvidence,
    holdout: PrefilterReport,
}
impl PromotionGuard for OwnedMutexGuard<Evidence> {
    fn snapshot(&self) -> &PromotionSnapshot {
        &self.snapshot
    }
    fn verification(&self) -> &VerificationEvidence {
        &self.wall
    }
    fn holdout(&self) -> &PrefilterReport {
        &self.holdout
    }
}
struct Authority(Arc<Mutex<Evidence>>);
impl PromotionAuthority for Authority {
    type Guard = OwnedMutexGuard<Evidence>;
    async fn acquire(&self, task: &str) -> Result<Self::Guard, OperatorError> {
        let guard = self.0.clone().lock_owned().await;
        if guard.snapshot.task_id != task {
            return Err(OperatorError::unavailable());
        }
        Ok(guard)
    }
}
struct Journal {
    records: Mutex<std::collections::BTreeMap<String, ApprovalRecord>>,
    operator: TrustedOperator,
    issues: AtomicUsize,
    consumes: AtomicUsize,
    lost_ack: AtomicBool,
    lost_issue_ack: AtomicBool,
    corrupt_issue_reply: AtomicBool,
    consume_started: tokio::sync::Notify,
}
impl ApprovalBackend for Journal {
    async fn issue(
        &self,
        nonce: String,
        request: IssueRequest,
    ) -> Result<ApprovalRecord, OperatorError> {
        self.issues.fetch_add(1, Ordering::SeqCst);
        let record = approval::issue_with_nonce(
            request.action,
            nonce.clone(),
            &self.operator,
            now_ms()?,
            request.ttl_ms,
        )
        .unwrap();
        self.records.lock().await.insert(nonce, record.clone());
        if self.lost_issue_ack.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        let mut reply = record;
        if self.corrupt_issue_reply.load(Ordering::SeqCst) {
            reply.operator_uid = 0;
        }
        Ok(reply)
    }
    async fn status(&self, nonce: String) -> Result<Option<ApprovalRecord>, OperatorError> {
        Ok(self.records.lock().await.get(&nonce).cloned())
    }
    async fn consume(&self, request: ConsumeRequest) -> Result<ApprovalRecord, OperatorError> {
        self.consumes.fetch_add(1, Ordering::SeqCst);
        let mut records = self.records.lock().await;
        let stored = records.get_mut(&request.nonce).unwrap();
        let mut presented = stored.clone();
        presented.action = request.action;
        approval::consume(stored, &presented, &self.operator, "fixture", now_ms()?)
            .map_err(|_| OperatorError::unavailable())?;
        let record = stored.clone();
        drop(records);
        self.consume_started.notify_one();
        if self.lost_ack.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        Ok(record)
    }
}
async fn fixture() -> (Router, Arc<Authority>, Arc<Journal>) {
    let (a, b) = tokio::net::UnixStream::pair().unwrap();
    let uid = a.peer_cred().unwrap().uid();
    drop((a, b));
    let snapshot = PromotionSnapshot {
        task_id: "task".into(),
        repository: "configured-repo".into(),
        target_ref: "refs/heads/main".into(),
        candidate_sha: "a".repeat(40),
        base_sha: "b".repeat(40),
        manifest_digest: "c".repeat(64),
        generation: 1,
        stage: Stage::AwaitingPromotion,
        stopped: false,
        active_claim: false,
    };
    let wall = VerificationEvidence {
        sha: snapshot.candidate_sha.clone(),
        verdict: DeterministicVerdict {
            typecheck: true,
            tests_pass: true,
            secret_scan_clean: true,
        },
        isolation: "seatbelt_offline_ephemeral_snapshot",
    };
    let mut session =
        PrefilterSession::begin(&snapshot.candidate_sha, &snapshot.manifest_digest, 1).unwrap();
    let handle = session.scenarios()[0].clone();
    for slot in 0..3 {
        session
            .record(
                &snapshot.candidate_sha,
                &snapshot.manifest_digest,
                &handle,
                slot,
                RunOutcome::Pass,
            )
            .unwrap();
    }
    let authority = Arc::new(Authority(Arc::new(Mutex::new(Evidence {
        snapshot,
        wall,
        holdout: session.finish(),
    }))));
    let config = OperatorAdapterConfig {
        operator_uid: uid,
        service_uid: uid + 1,
        generator_uid: uid + 2,
        evaluator_uid: uid + 3,
        audience: "fixture".into(),
        ttl_ms: 30_000,
        request_timeout: Duration::from_millis(100),
    };
    let journal = Arc::new(Journal {
        records: Mutex::new(Default::default()),
        operator: approval::authenticate_operator(uid, uid, &[uid + 1, uid + 2, uid + 3]).unwrap(),
        issues: AtomicUsize::new(0),
        consumes: AtomicUsize::new(0),
        lost_ack: AtomicBool::new(false),
        lost_issue_ack: AtomicBool::new(false),
        corrupt_issue_reply: AtomicBool::new(false),
        consume_started: tokio::sync::Notify::new(),
    });
    let router = scoped_router(
        fixture_policy(uid),
        config,
        authority.clone(),
        journal.clone(),
    );
    (router, authority, journal)
}

struct Running {
    path: std::path::PathBuf,
    task: tokio::task::JoinHandle<()>,
    client: reqwest::Client,
}
impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_dir(self.path.parent().unwrap());
    }
}
impl Running {
    async fn new(router: Router) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let parent = std::env::temp_dir().join(format!("operator-adapter-{}", shared::new_id()));
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = parent.join("socket");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                router
                    .into_make_service_with_connect_info::<crate::operator_transport::OperatorPeer>(
                    ),
            )
            .await
            .unwrap();
        });
        let client = reqwest::Client::builder()
            .unix_socket(path.clone())
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        Self { path, task, client }
    }
    async fn post(&self, path: &str, body: serde_json::Value) -> reqwest::Response {
        self.client
            .post(format!("http://localhost{path}"))
            .json(&body)
            .send()
            .await
            .unwrap()
    }
    async fn prepare(&self) -> serde_json::Value {
        let response = self
            .post(
                "/prepare",
                serde_json::json!({"task_id":"task","reason":"reviewed"}),
            )
            .await;
        assert_eq!(response.status(), 200);
        response.json().await.unwrap()
    }
}

#[tokio::test]
async fn corrupt_issue_reply_retains_nonce_for_status_reconciliation() {
    let (router, _, journal) = fixture().await;
    journal.corrupt_issue_reply.store(true, Ordering::SeqCst);
    let server = Running::new(router).await;
    let response = server
        .post(
            "/prepare",
            serde_json::json!({"task_id":"task","reason":"reviewed"}),
        )
        .await;
    assert_eq!(response.status(), 503);
    let unknown: serde_json::Value = response.json().await.unwrap();
    assert_eq!(unknown["code"], "approval_outcome_unknown");
    let nonce = unknown["nonce"].as_str().unwrap();
    assert!(nonce_valid(nonce));
    let status = server
        .post("/status", serde_json::json!({"nonce":nonce}))
        .await;
    assert_eq!(status.status(), 200);
    let record: serde_json::Value = status.json().await.unwrap();
    assert_eq!(record["record"]["nonce"], nonce);
    assert_eq!(record["execution"], "not_executed");
    assert_eq!(journal.issues.load(Ordering::SeqCst), 1);
    assert_eq!(journal.consumes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn missing_connection_context_denies_before_authority_or_journal() {
    let (router, _, journal) = fixture().await;
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/prepare")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"task_id":"task","reason":"reviewed"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    assert_eq!(journal.issues.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn real_unix_peer_gets_server_resolved_action_and_exact_single_consume() {
    let (router, _, journal) = fixture().await;
    let server = Running::new(router).await;
    let shown = server.prepare().await;
    assert_eq!(shown["record"]["action"]["repository"], "configured-repo");
    assert_eq!(shown["record"]["action"]["candidate_sha"], "a".repeat(40));
    let request = serde_json::json!({"nonce":shown["record"]["nonce"],"presentation_digest":shown["presentation_digest"]});
    let response = server.post("/consume", request.clone()).await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.json::<serde_json::Value>().await.unwrap()["execution"],
        "not_executed"
    );
    assert_eq!(server.post("/consume", request).await.status(), 409);
    assert_eq!(journal.consumes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn spoofed_uid_client_evidence_and_wrong_presentation_are_refused() {
    let (router, _, journal) = fixture().await;
    let server = Running::new(router).await;
    for field in [
        "operator_uid",
        "candidate_sha",
        "evidence_digest",
        "snapshot",
    ] {
        let mut body = serde_json::json!({"task_id":"task","reason":"reviewed"});
        body[field] = serde_json::json!("forged");
        assert_eq!(server.post("/prepare", body).await.status(), 422);
    }
    assert_eq!(journal.issues.load(Ordering::SeqCst), 0);
    let shown = server.prepare().await;
    assert_eq!(server.post("/consume",serde_json::json!({"nonce":shown["record"]["nonce"],"presentation_digest":"0".repeat(64)})).await.status(),409);
    assert_eq!(journal.consumes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn changed_authoritative_generation_and_stopped_state_prevent_consumption() {
    let (router, authority, journal) = fixture().await;
    let server = Running::new(router).await;
    let shown = server.prepare().await;
    authority.0.lock().await.snapshot.generation += 1;
    let request = serde_json::json!({"nonce":shown["record"]["nonce"],"presentation_digest":shown["presentation_digest"]});
    assert_eq!(server.post("/consume", request).await.status(), 409);
    authority.0.lock().await.snapshot.stopped = true;
    assert_eq!(
        server
            .post(
                "/prepare",
                serde_json::json!({"task_id":"task","reason":"reviewed"})
            )
            .await
            .status(),
        409
    );
    assert_eq!(journal.consumes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn lost_consume_ack_returns_unknown_without_execution_and_status_reconciles() {
    let (router, _, journal) = fixture().await;
    let server = Running::new(router).await;
    let shown = server.prepare().await;
    journal.lost_ack.store(true, Ordering::SeqCst);
    let request = serde_json::json!({"nonce":shown["record"]["nonce"],"presentation_digest":shown["presentation_digest"]});
    let response = server.post("/consume", request.clone()).await;
    assert_eq!(response.status(), 503);
    let error: serde_json::Value = response.json().await.unwrap();
    assert_eq!(error["code"], "approval_outcome_unknown");
    let response = server
        .post(
            "/status",
            serde_json::json!({"nonce":shown["record"]["nonce"]}),
        )
        .await;
    assert_eq!(response.status(), 200);
    assert!(
        response.json::<serde_json::Value>().await.unwrap()["record"]["consumed_at_ms"].is_number()
    );
    assert_eq!(server.post("/consume", request).await.status(), 409);
    assert_eq!(journal.consumes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn actual_mismatched_peer_cannot_override_identity_with_header() {
    let (router, _, journal) = fixture().await;
    let expected = journal.operator.uid() + 10;
    let router = router.layer(middleware::from_fn_with_state(
        fixture_policy(expected),
        require_operator,
    ));
    let server = Running::new(router).await;
    let response = server
        .client
        .post("http://localhost/prepare")
        .header("x-operator-uid", expected)
        .json(&serde_json::json!({"task_id":"task","reason":"reviewed"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    assert_eq!(journal.issues.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn oversized_input_and_expired_approval_never_reach_consume() {
    let (router, _, journal) = fixture().await;
    let server = Running::new(router).await;
    assert_eq!(
        server
            .post(
                "/prepare",
                serde_json::json!({"task_id":"task","reason":"x".repeat(20_000)})
            )
            .await
            .status(),
        413
    );
    assert_eq!(journal.issues.load(Ordering::SeqCst), 0);
    let shown = server.prepare().await;
    let nonce = shown["record"]["nonce"].as_str().unwrap();
    let digest = {
        let mut records = journal.records.lock().await;
        let record = records.get_mut(nonce).unwrap();
        let now = now_ms().unwrap();
        record.issued_at_ms = now - 40_000;
        record.expires_at_ms = now - 10_000;
        presentation_digest(record).unwrap()
    };
    assert_eq!(
        server
            .post(
                "/consume",
                serde_json::json!({"nonce":nonce,"presentation_digest":digest})
            )
            .await
            .status(),
        409
    );
    assert_eq!(journal.consumes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn wrong_journal_identity_or_audience_never_returns_approval() {
    let (router, _, journal) = fixture().await;
    let server = Running::new(router).await;
    let shown = server.prepare().await;
    let nonce = shown["record"]["nonce"].as_str().unwrap();
    for identity in [true, false] {
        {
            let mut records = journal.records.lock().await;
            let record = records.get_mut(nonce).unwrap();
            record.operator_uid = if identity {
                journal.operator.uid() + 1
            } else {
                journal.operator.uid()
            };
            if !identity {
                record.action.audience = "other".into();
            }
        }
        let response = server
            .post("/status", serde_json::json!({"nonce":nonce}))
            .await;
        assert_eq!(response.status(), 503);
        let body: serde_json::Value = response.json().await.unwrap();
        assert!(body.get("record").is_none());
    }
}

#[tokio::test]
async fn lost_issue_ack_returns_recovery_nonce_without_presentation() {
    let (router, _, journal) = fixture().await;
    let server = Running::new(router).await;
    journal.lost_issue_ack.store(true, Ordering::SeqCst);
    let response = server
        .post(
            "/prepare",
            serde_json::json!({"task_id":"task","reason":"reviewed"}),
        )
        .await;
    assert_eq!(response.status(), 503);
    let unknown: serde_json::Value = response.json().await.unwrap();
    assert!(unknown.get("record").is_none());
    let response = server
        .post("/status", serde_json::json!({"nonce":unknown["nonce"]}))
        .await;
    assert_eq!(response.status(), 200);
    assert!(
        response.json::<serde_json::Value>().await.unwrap()["record"]["consumed_at_ms"].is_null()
    );
    assert_eq!(journal.consumes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn guard_is_held_during_call_but_timeout_does_not_claim_remote_atomicity() {
    let (router, authority, journal) = fixture().await;
    let server = Running::new(router).await;
    let shown = server.prepare().await;
    journal.lost_ack.store(true, Ordering::SeqCst);
    let request=server.post("/consume",serde_json::json!({"nonce":shown["record"]["nonce"],"presentation_digest":shown["presentation_digest"]}));
    tokio::pin!(request);
    tokio::select! {_response=&mut request=>panic!("request finished before consume"), _=journal.consume_started.notified()=>{}}
    assert!(authority.0.try_lock().is_err());
    assert_eq!(request.await.status(), 503);
    assert!(authority.0.try_lock().is_ok());
    assert_eq!(journal.consumes.load(Ordering::SeqCst), 1);
}
