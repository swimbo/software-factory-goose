//! Disposable loopback-only integration: real GatewayClient and real Restate BudgetCounter,
//! synthetic governance/provider. No listener is registered as a production route.
use axum::{
    Json, Router,
    http::StatusCode,
    routing::{get, post},
};
use control_plane::gateway::{
    GatewayClient, InferenceBudget, OutputLimitField, ReviewedModelContract,
};
use serde_json::{Value, json};
use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Fixture-only fixed-route proxy: read a real committed reservation acknowledgement, then
/// close the first downstream connection without transmitting it. No arbitrary forwarding.
async fn lost_ack_proxy(
    base: String,
) -> anyhow::Result<(String, tokio::task::JoinHandle<()>, Arc<AtomicUsize>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = format!("http://{}", listener.local_addr()?);
    let confirmed = Arc::new(AtomicUsize::new(0));
    let counter = confirmed.clone();
    let task = tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                let byte = stream.read_u8().await.unwrap();
                header.push(byte);
                assert!(header.len() <= 8192, "fixture header too large");
            }
            let text = std::str::from_utf8(&header).unwrap();
            assert_eq!(
                text.lines().next().unwrap(),
                "POST /restate/call/BudgetCounter/gateway-lost-ack/try_spend_microusd HTTP/1.1"
            );
            let length: usize = text
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find_map(|(name, value)| {
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .unwrap();
            assert_eq!(length, 6);
            let mut body = vec![0; length];
            stream.read_exact(&mut body).await.unwrap();
            assert_eq!(body, b"250000");
            let response = client
                .post(format!(
                    "{base}/restate/call/BudgetCounter/gateway-lost-ack/try_spend_microusd"
                ))
                .json(&250_000_u64)
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap();
            let result: bool = response.json().await.unwrap();
            let index = counter.fetch_add(1, Ordering::SeqCst);
            if index == 0 {
                assert!(result, "first reservation not committed");
                // Drop connection after the acknowledged Restate commit, before replying.
                continue;
            }
            let payload = if result { "true" } else { "false" };
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                payload.len(),
                payload
            );
            stream.write_all(reply.as_bytes()).await.unwrap();
        }
    });
    Ok((address, task, confirmed))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let base = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing Restate URL"))?;
    let mode = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing fixture phase"))?;
    anyhow::ensure!(
        args.next().is_none() && matches!(mode.as_str(), "exercise" | "verify"),
        "invalid fixture phase"
    );
    let parsed = reqwest::Url::parse(&base)?;
    anyhow::ensure!(
        parsed.scheme() == "http"
            && parsed
                .host_str()
                .and_then(|h| h.parse::<IpAddr>().ok())
                .is_some_and(|ip| ip.is_loopback())
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.query().is_none()
            && parsed.fragment().is_none()
            && parsed.path() == "/",
        "fixture requires literal loopback Restate URL"
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let fail = Arc::new(AtomicBool::new(false));
    let provider_calls = calls.clone();
    let provider_fail = fail.clone();
    let app = Router::new()
        .route("/api/governance/virtual-keys", get(|| async { Json(json!([{"id":"fixture-key","budgets":[{"max_limit":10,"current_usage":0}]}])) }))
        .route("/v1/chat/completions", post(move |Json(body): Json<Value>| {
            let calls = provider_calls.clone(); let fail = provider_fail.clone();
            async move {
                assert_eq!(body["model"], "fixture-model");
                assert_eq!(body["max_tokens"], 1);
                assert_eq!(body["stream"], false);
                calls.fetch_add(1, Ordering::SeqCst);
                if fail.load(Ordering::SeqCst) { (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error":"fixture"}))) }
                else { (StatusCode::OK, Json(json!({"choices":[{"message":{"role":"assistant","content":"synthetic"}}]}))) }
            }
        }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let provider = format!("http://{}", listener.local_addr()?);
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let contract = ReviewedModelContract {
        model: "fixture-model".into(),
        review_digest: "a".repeat(64),
        reviewed_at_ms: now.saturating_sub(60_000),
        valid_until_ms: now
            .checked_add(600_000)
            .ok_or_else(|| anyhow::anyhow!("time overflow"))?,
        input_microusd_per_million: 1,
        output_microusd_per_million: 1,
        max_billable_input_tokens: 1,
        max_billable_output_tokens: 1,
        fixed_call_microusd: 249_998,
        max_request_bytes: 8192,
        output_limit_field: OutputLimitField::MaxTokens,
    };
    anyhow::ensure!(
        contract.upper_bound_microusd()? == 250_000,
        "incorrect synthetic reservation"
    );
    let gateway = GatewayClient::new(&provider, "fixture-vk", "fixture-admin")
        .with_governance_key_id("fixture-key")?
        .with_budget_authority(&base, "gateway-fixture")?
        .with_reviewed_model(contract.clone())?;
    let budget = InferenceBudget {
        restate_url: &base,
        budget_id: "gateway-fixture",
        virtual_key_id: "fixture-key",
        max_output_tokens: 1,
    };
    let messages = vec![json!({"role":"user","content":"synthetic prompt"})];
    if mode == "exercise" {
        for _ in 0..3 {
            gateway.chat("fixture-model", &messages, &budget).await?;
        }
        anyhow::ensure!(
            gateway
                .chat("fixture-model", &messages, &budget)
                .await
                .is_err()
                && calls.load(Ordering::SeqCst) == 3,
            "budget exhaustion forwarded inference"
        );
        let failure_gateway = GatewayClient::new(&provider, "fixture-vk", "fixture-admin")
            .with_governance_key_id("fixture-key")?
            .with_budget_authority(&base, "gateway-failure")?
            .with_reviewed_model(contract.clone())?;
        let failure_budget = InferenceBudget {
            restate_url: &base,
            budget_id: "gateway-failure",
            virtual_key_id: "fixture-key",
            max_output_tokens: 1,
        };
        fail.store(true, Ordering::SeqCst);
        anyhow::ensure!(
            failure_gateway
                .chat("fixture-model", &messages, &failure_budget)
                .await
                .is_err(),
            "synthetic provider failure accepted"
        );
        fail.store(false, Ordering::SeqCst);
        for _ in 0..2 {
            failure_gateway
                .chat("fixture-model", &messages, &failure_budget)
                .await?;
        }
        anyhow::ensure!(
            failure_gateway
                .chat("fixture-model", &messages, &failure_budget)
                .await
                .is_err()
                && calls.load(Ordering::SeqCst) == 6,
            "failed provider reservation was refunded or denial forwarded"
        );
        let (proxy, proxy_task, acknowledgements) = lost_ack_proxy(base.clone()).await?;
        let lost_gateway = GatewayClient::new(&provider, "fixture-vk", "fixture-admin")
            .with_governance_key_id("fixture-key")?
            .with_budget_authority(&proxy, "gateway-lost-ack")?
            .with_reviewed_model(contract.clone())?;
        let lost_budget = InferenceBudget {
            restate_url: &proxy,
            budget_id: "gateway-lost-ack",
            virtual_key_id: "fixture-key",
            max_output_tokens: 1,
        };
        let before = calls.load(Ordering::SeqCst);
        anyhow::ensure!(
            lost_gateway
                .chat("fixture-model", &messages, &lost_budget)
                .await
                .is_err()
                && acknowledgements.load(Ordering::SeqCst) == 1
                && calls.load(Ordering::SeqCst) == before,
            "lost acknowledgement contacted provider or failed to commit"
        );
        lost_gateway
            .chat("fixture-model", &messages, &lost_budget)
            .await?;
        lost_gateway
            .chat("fixture-model", &messages, &lost_budget)
            .await?;
        anyhow::ensure!(
            lost_gateway
                .chat("fixture-model", &messages, &lost_budget)
                .await
                .is_err()
                && acknowledgements.load(Ordering::SeqCst) == 4
                && calls.load(Ordering::SeqCst) == before + 2,
            "retry reservation accounting mismatch"
        );
        proxy_task.abort();
        println!(
            "PASS gateway exercised real Restate; three reservations, denial before inference, and failed-provider reservation retained"
        );
    } else {
        anyhow::ensure!(
            gateway
                .chat("fixture-model", &messages, &budget)
                .await
                .is_err()
                && calls.load(Ordering::SeqCst) == 0,
            "exhausted budget lost across restart"
        );
        let lost_gateway = GatewayClient::new(&provider, "fixture-vk", "fixture-admin")
            .with_governance_key_id("fixture-key")?
            .with_budget_authority(&base, "gateway-lost-ack")?
            .with_reviewed_model(contract)?;
        let lost_budget = InferenceBudget {
            restate_url: &base,
            budget_id: "gateway-lost-ack",
            virtual_key_id: "fixture-key",
            max_output_tokens: 1,
        };
        anyhow::ensure!(
            lost_gateway
                .chat("fixture-model", &messages, &lost_budget)
                .await
                .is_err()
                && calls.load(Ordering::SeqCst) == 0,
            "lost-ack ledger lost across restart"
        );
        println!("PASS exhausted real Restate budget survives restart; no provider call");
    }
    server.abort();
    Ok(())
}
