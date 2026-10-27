//! Disposable same-object journal verification; no authentication or Git execution proof.
#[cfg(feature = "restate")]
mod fixture {
    use control_plane::{
        approval_workflow::ConsumeRequest, promotion_decision::*,
        promotion_eligibility::PromotionSnapshot, state::Stage,
    };
    use evaluator::{
        DeterministicVerdict, VerificationEvidence,
        holdout::{PrefilterSession, RunOutcome},
    };
    use serde::{Deserialize, Serialize};
    use std::{io::Write, os::unix::fs::OpenOptionsExt, path::PathBuf, time::Duration};
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Checkpoint {
        task: String,
        issue: DecisionIssueRequest,
        approved: DecisionApproval,
        decision: PromotionDecision,
        publication: EligibilityPublication,
        summary: DecisionSummary,
    }
    struct Client {
        http: reqwest::Client,
        base: String,
    }
    impl Client {
        async fn call<T: Serialize + Sync>(
            &self,
            handler: &str,
            body: Option<&T>,
        ) -> anyhow::Result<reqwest::Response> {
            let request = self.http.post(format!("{}/{handler}", self.base));
            Ok(if let Some(value) = body {
                request.json(value)
            } else {
                request
            }
            .send()
            .await?)
        }
        async fn read<T: Serialize + Sync, R: serde::de::DeserializeOwned>(
            &self,
            handler: &str,
            body: Option<&T>,
        ) -> anyhow::Result<R> {
            self.call(handler, body)
                .await?
                .error_for_status()?
                .json()
                .await
                .map_err(Into::into)
        }
    }
    fn publication(task: &str, generation: u64) -> anyhow::Result<EligibilityPublication> {
        let snapshot = PromotionSnapshot {
            task_id: task.into(),
            repository: "synthetic-repository".into(),
            target_ref: "refs/heads/main".into(),
            candidate_sha: "a".repeat(40),
            base_sha: "b".repeat(40),
            manifest_digest: "c".repeat(64),
            generation,
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
        let mut prefilter =
            PrefilterSession::begin(&snapshot.candidate_sha, &snapshot.manifest_digest, 1)
                .map_err(|_| anyhow::anyhow!("fixture prefilter failed"))?;
        let handle = prefilter.scenarios()[0].clone();
        for slot in 0..3 {
            prefilter
                .record(
                    &snapshot.candidate_sha,
                    &snapshot.manifest_digest,
                    &handle,
                    slot,
                    RunOutcome::Pass,
                )
                .map_err(|_| anyhow::anyhow!("fixture result failed"))?;
        }
        EligibilityPublication::from_authoritative(
            shared::new_id(),
            &snapshot,
            &wall,
            &prefilter.finish(),
            "fixture",
        )
    }
    fn issue_request() -> DecisionIssueRequest {
        DecisionIssueRequest {
            request_id: shared::new_id(),
            reason: "synthetic same-object decision".into(),
            ttl_ms: 300_000,
        }
    }
    fn presented(approved: &DecisionApproval) -> ConsumeRequest {
        ConsumeRequest {
            action: approved.record.action.clone(),
            nonce: approved.record.nonce.clone(),
            issued_at_ms: approved.record.issued_at_ms,
            expires_at_ms: approved.record.expires_at_ms,
        }
    }
    pub async fn run() -> anyhow::Result<()> {
        let args: Vec<String> = std::env::args().collect();
        anyhow::ensure!(
            args.len() == 4,
            "port, exercise/verify and checkpoint required"
        );
        let port: u16 = args[1].parse()?;
        anyhow::ensure!(port > 0, "explicit loopback port required");
        let mode = &args[2];
        let path = PathBuf::from(&args[3]);
        let fixture_home = PathBuf::from(std::env::var("HOME")?).canonicalize()?;
        anyhow::ensure!(
            path.parent()
                .ok_or_else(|| anyhow::anyhow!("checkpoint parent absent"))?
                .canonicalize()?
                == fixture_home,
            "checkpoint must be inside disposable fixture home"
        );
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()?;
        if mode == "exercise" {
            let task = format!("promotion-fixture-{}", shared::new_id());
            let client = Client {
                http,
                base: format!(
                    "http://127.0.0.1:{port}/restate/call/PromotionDecisionJournal/{task}"
                ),
            };
            let first = publication(&task, 1)?;
            let receipt: GenerationReceipt = client.read("publish", Some(&first)).await?;
            anyhow::ensure!(receipt.generation == 1, "wrong first generation");
            let request = issue_request();
            let approved: DecisionApproval = client.read("issue", Some(&request)).await?;
            anyhow::ensure!(
                client
                    .read::<_, DecisionApproval>("issue", Some(&request))
                    .await?
                    == approved,
                "issue retry changed record"
            );
            let mut altered = presented(&approved);
            altered.action.candidate_sha = "d".repeat(40);
            anyhow::ensure!(
                client.call("consume", Some(&altered)).await?.status() == 409,
                "altered action was not refused"
            );
            anyhow::ensure!(
                client
                    .read::<_, Option<DecisionApproval>>("lookup", Some(&request.request_id))
                    .await?
                    == Some(approved.clone()),
                "mismatch changed approval"
            );
            let mut short = issue_request();
            short.ttl_ms = 50;
            let expired: DecisionApproval = client.read("issue", Some(&short)).await?;
            tokio::time::sleep(Duration::from_millis(100)).await;
            anyhow::ensure!(
                client
                    .call("consume", Some(&presented(&expired)))
                    .await?
                    .status()
                    == 410,
                "expired approval was not refused"
            );
            let update = publication(&task, 2)?;
            let receipt2: GenerationReceipt = client.read("publish", Some(&update)).await?;
            anyhow::ensure!(receipt2.generation == 2, "wrong updated generation");
            anyhow::ensure!(
                client
                    .call("consume", Some(&presented(&approved)))
                    .await?
                    .status()
                    == 409,
                "stale generation was not refused"
            );
            anyhow::ensure!(
                client
                    .read::<_, GenerationReceipt>("publish", Some(&first))
                    .await?
                    == receipt,
                "historical publication retry changed receipt"
            );
            anyhow::ensure!(
                client
                    .read::<(), DecisionSummary>("inspect", None)
                    .await?
                    .generation
                    == 2,
                "old publication reopened state"
            );
            let a_request = issue_request();
            let b_request = issue_request();
            let a: DecisionApproval = client.read("issue", Some(&a_request)).await?;
            let b: DecisionApproval = client.read("issue", Some(&b_request)).await?;
            let a_presented = presented(&a);
            let b_presented = presented(&b);
            let (a_result, b_result) = tokio::join!(
                client.call("consume", Some(&a_presented)),
                client.call("consume", Some(&b_presented))
            );
            let a_result = a_result?;
            let b_result = b_result?;
            let (winner, winning_request, decision) =
                if a_result.status() == 200 && b_result.status() == 409 {
                    (a, a_request, a_result.json::<PromotionDecision>().await?)
                } else if b_result.status() == 200 && a_result.status() == 409 {
                    (b, b_request, b_result.json::<PromotionDecision>().await?)
                } else {
                    anyhow::bail!("concurrent approvals did not produce exactly one decision")
                };
            anyhow::ensure!(
                decision.action == winner.record.action
                    && decision.generation == 2
                    && decision.execution == DecisionExecution::NotRequested,
                "incorrect serialized decision"
            );
            let consumed = client
                .read::<_, Option<DecisionApproval>>("lookup", Some(&winning_request.request_id))
                .await?
                .ok_or_else(|| anyhow::anyhow!("missing consumed approval"))?;
            anyhow::ensure!(
                consumed.record.consumed_at_ms == Some(decision.decided_at_ms)
                    && consumed.decision == Some(decision.clone()),
                "consumption and decision disagree"
            );
            anyhow::ensure!(
                client
                    .call("consume", Some(&presented(&winner)))
                    .await?
                    .status()
                    == 409,
                "decision replay accepted"
            );
            let invalidation = InvalidateRequest {
                request_id: shared::new_id(),
                expected_generation: 2,
            };
            let invalidated: GenerationReceipt =
                client.read("invalidate", Some(&invalidation)).await?;
            anyhow::ensure!(
                invalidated.generation == 3,
                "invalidation did not advance generation"
            );
            anyhow::ensure!(
                client.call("issue", Some(&issue_request())).await?.status() == 409,
                "invalidated state issued approval"
            );
            let summary: DecisionSummary = client.read::<(), _>("inspect", None).await?;
            anyhow::ensure!(
                !summary.eligible && summary.current_decision.is_none(),
                "invalidation preserved current authority"
            );
            let checkpoint = Checkpoint {
                task,
                issue: winning_request,
                approved: consumed,
                decision,
                publication: update,
                summary,
            };
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(&serde_json::to_vec(&checkpoint)?)?;
            file.sync_all()?;
            println!(
                "PASS: real same-object publish/issue/expiry/stale-generation/invalidation and racing consume produced one durable approval decision; no Git execution"
            );
        } else if mode == "verify" {
            let bytes = std::fs::read(path)?;
            anyhow::ensure!(bytes.len() <= 65_536, "fixture checkpoint too large");
            let checkpoint: Checkpoint = serde_json::from_slice(&bytes)?;
            let client = Client {
                http,
                base: format!(
                    "http://127.0.0.1:{port}/restate/call/PromotionDecisionJournal/{}",
                    checkpoint.task
                ),
            };
            anyhow::ensure!(
                client
                    .read::<_, Option<DecisionApproval>>(
                        "lookup",
                        Some(&checkpoint.issue.request_id)
                    )
                    .await?
                    == Some(checkpoint.approved.clone()),
                "consumed approval/decision did not survive restart"
            );
            anyhow::ensure!(
                checkpoint.approved.decision == Some(checkpoint.decision),
                "invalid checkpoint decision"
            );
            anyhow::ensure!(
                client.read::<(), DecisionSummary>("inspect", None).await? == checkpoint.summary,
                "generation/invalidation changed across restart"
            );
            anyhow::ensure!(
                client
                    .call("consume", Some(&presented(&checkpoint.approved)))
                    .await?
                    .status()
                    == 409,
                "restart reopened consumed approval"
            );
            anyhow::ensure!(
                client
                    .read::<_, DecisionApproval>("issue", Some(&checkpoint.issue))
                    .await?
                    == checkpoint.approved,
                "reissue after restart reset consumption or lifetime"
            );
            anyhow::ensure!(
                client
                    .read::<_, GenerationReceipt>("publish", Some(&checkpoint.publication))
                    .await?
                    .generation
                    == 2,
                "historical update receipt lost"
            );
            anyhow::ensure!(
                client.read::<(), DecisionSummary>("inspect", None).await? == checkpoint.summary,
                "historical publication reopened invalidated state"
            );
            println!(
                "PASS: consumed approval and exact same-object decision survived Restate SIGKILL; historical retries did not reopen invalidated generation"
            );
        } else {
            anyhow::bail!("unsupported fixture mode")
        }
        Ok(())
    }
}
#[cfg(feature = "restate")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fixture::run().await
}
#[cfg(not(feature = "restate"))]
fn main() {
    eprintln!("fixture requires restate feature");
    std::process::exit(1);
}
