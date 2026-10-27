//! Real journal contract fixture, not a cross-UID operator authentication proof.
#[cfg(all(feature = "restate", unix))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use control_plane::{
        approval::{ApprovalAction, ApprovalRecord, Operation},
        approval_workflow::{ConsumeRequest, IssueRequest},
        operator_adapter::{ApprovalBackend, UnixApprovalBackend},
    };
    use std::path::PathBuf;
    fn presentation(record: &ApprovalRecord) -> ConsumeRequest {
        ConsumeRequest {
            action: record.action.clone(),
            nonce: record.nonce.clone(),
            issued_at_ms: record.issued_at_ms,
            expires_at_ms: record.expires_at_ms,
        }
    }
    let path = PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("missing protected fixture socket"))?,
    );
    let lost_path = PathBuf::from(
        std::env::args()
            .nth(2)
            .ok_or_else(|| anyhow::anyhow!("missing lost-reply fixture socket"))?,
    );
    let (a, b) = tokio::net::UnixStream::pair()?;
    let uid = a.peer_cred()?.uid();
    drop((a, b));
    let backend = UnixApprovalBackend::new(path, uid).await?;
    let nonce = shared::new_id();
    anyhow::ensure!(
        backend
            .status(nonce.clone())
            .await
            .map_err(|e| anyhow::anyhow!("initial status: {e:?}"))?
            .is_none(),
        "unexpected existing approval"
    );
    let request = IssueRequest {
        action: ApprovalAction {
            operation: Operation::Promote,
            task_id: format!("unix-approval-fixture-{nonce}"),
            repository: "synthetic-fixture-repository".into(),
            target_ref: "refs/heads/main".into(),
            candidate_sha: "a".repeat(40),
            base_sha: "b".repeat(40),
            evidence_digest: "c".repeat(64),
            reason: "synthetic contract check; no Git execution".into(),
            audience: "fixture".into(),
        },
        ttl_ms: 300_000,
    };
    let record = backend
        .issue(nonce.clone(), request.clone())
        .await
        .map_err(|e| anyhow::anyhow!("issue: {e:?}"))?;
    anyhow::ensure!(
        record.action == request.action
            && record.nonce == nonce
            && record.operator_uid == 1001
            && record.consumed_at_ms.is_none()
            && record.expires_at_ms - record.issued_at_ms == request.ttl_ms,
        "incorrect fixture approval bindings"
    );
    anyhow::ensure!(
        backend
            .status(nonce.clone())
            .await
            .map_err(|e| anyhow::anyhow!("issued status: {e:?}"))?
            == Some(record.clone()),
        "status changed issued record"
    );
    anyhow::ensure!(
        backend
            .issue(nonce.clone(), request.clone())
            .await
            .map_err(|e| anyhow::anyhow!("repeat issue: {e:?}"))?
            == record,
        "issuance retry changed lifetime or action"
    );
    let mut wrong_issue = request.clone();
    wrong_issue.action.candidate_sha = "d".repeat(40);
    anyhow::ensure!(
        backend.issue(nonce.clone(), wrong_issue).await.is_err(),
        "same nonce accepted another action"
    );
    let mut altered = presentation(&record);
    altered.action.candidate_sha = "d".repeat(40);
    anyhow::ensure!(
        backend.consume(altered).await.is_err(),
        "changed action consumed approval"
    );
    anyhow::ensure!(
        backend
            .status(nonce.clone())
            .await
            .map_err(|e| anyhow::anyhow!("mismatch status: {e:?}"))?
            == Some(record.clone()),
        "mismatch changed journal state"
    );
    let consumed = backend
        .consume(presentation(&record))
        .await
        .map_err(|e| anyhow::anyhow!("consume: {e:?}"))?;
    anyhow::ensure!(
        consumed.action == record.action
            && consumed.nonce == nonce
            && consumed.consumed_at_ms.is_some(),
        "missing durable consume decision"
    );
    anyhow::ensure!(
        backend.consume(presentation(&record)).await.is_err(),
        "replayed consumption accepted"
    );
    anyhow::ensure!(
        backend
            .status(nonce.clone())
            .await
            .map_err(|e| anyhow::anyhow!("consumed status: {e:?}"))?
            == Some(consumed.clone()),
        "status lost consumed decision"
    );
    anyhow::ensure!(
        backend
            .issue(nonce, request.clone())
            .await
            .map_err(|e| anyhow::anyhow!("reissue consumed: {e:?}"))?
            == consumed,
        "reissue reopened consumed approval"
    );

    // A separate private relay forwards this request, observes the first upstream response
    // bytes, then drops the reply. Only this dedicated nonce uses that fault-injection path.
    let lost_nonce = shared::new_id();
    let mut lost_request = request;
    lost_request.action.task_id = format!("unix-lost-approval-{lost_nonce}");
    let lost_record = backend
        .issue(lost_nonce.clone(), lost_request)
        .await
        .map_err(|e| anyhow::anyhow!("lost-reply issue: {e:?}"))?;
    let lossy = UnixApprovalBackend::new(lost_path, uid).await?;
    anyhow::ensure!(
        lossy.consume(presentation(&lost_record)).await.is_err(),
        "lost reply unexpectedly reported success"
    );
    let recovered = backend
        .status(lost_nonce.clone())
        .await
        .map_err(|e| anyhow::anyhow!("lost-reply status: {e:?}"))?
        .ok_or_else(|| anyhow::anyhow!("lost reply removed approval"))?;
    anyhow::ensure!(
        recovered.action == lost_record.action
            && recovered.nonce == lost_nonce
            && recovered.consumed_at_ms.is_some(),
        "consumption did not persist before lost acknowledgement"
    );
    anyhow::ensure!(
        backend.consume(presentation(&lost_record)).await.is_err(),
        "lost-ack retry reopened consumption"
    );
    anyhow::ensure!(
        backend
            .status(lost_nonce)
            .await
            .map_err(|e| anyhow::anyhow!("recovery status: {e:?}"))?
            == Some(recovered),
        "recovery changed durable decision"
    );
    println!(
        "PASS: real UnixApprovalBackend issue/status/consume, immutable issuance, action mismatch/replay refusal and persisted consume after dropped reply; synthetic journal principal, no Git or cross-UID proof"
    );
    Ok(())
}
#[cfg(not(all(feature = "restate", unix)))]
fn main() {
    eprintln!("fixture requires restate feature and Unix");
    std::process::exit(1);
}
