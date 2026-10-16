//! The control plane — orchestrator + qualifier + gates + HTTP API + durable serving.
//!
//! Two servers run side-by-side:
//! - Axum on `:8080` — the `sfctl` CLI surface (submit/inspect/status/gates).
//! - Restate on `:9080` — the durable workflow + budget object (gated behind `--features restate`).
//!
//! Postgres is the *read projection* (consensus R3); the Restate journal is the source of truth.

use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use control_plane::{gates, memory, pipeline, projection, qualifier};
use serde_json::{Value, json};
use shared::{new_id, CredentialGrant, CredentialKind, QualifierDecision};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Application state. The in-memory intent cache is the stand-in for the Postgres read model;
/// `pool` is the real projection when `DATABASE_URL` is set; `pipelines` are the R15 driver
/// pipelines (intent → task DAG → merge).
struct AppState {
    intents: Mutex<HashMap<String, QualifierDecision>>,
    pool: Option<sqlx::PgPool>,
    pipelines: Mutex<HashMap<String, pipeline::Pipeline>>,
    grants: Mutex<HashMap<String, CredentialGrant>>,
}

impl Default for AppState {
    fn default() -> Self {
        AppState {
            intents: Mutex::new(HashMap::new()),
            pool: None,
            pipelines: Mutex::new(HashMap::new()),
            grants: Mutex::new(HashMap::new()),
        }
    }
}

type SharedState = Arc<AppState>;

/// Build the HTTP router (extracted so integration tests can drive it in-process).
fn app(state: SharedState) -> Router {
    Router::new()
        .route("/v1/intents", post(submit_intent))
        .route("/v1/intents/{id}", get(inspect_intent))
        .route("/v1/work-packages", get(list_work_packages))
        .route("/v1/work-packages/{id}", get(get_work_package))
        .route("/v1/promotions/{id}/approve", post(approve_promotion))
        .route("/v1/grants/{id}/approve", post(approve_grant))
        .route("/v1/budget/raise", post(raise_budget))
        .route("/v1/work-packages/{id}/stop", post(stop_work_package))
        .route("/v1/work-packages/{id}/result", post(work_package_result))
        .route("/v1/work-packages/{id}/credentials", post(request_credential))
        .route("/v1/memory/dependents/{symbol}", get(memory_dependents))
        .route("/v1/pipelines/{id}", get(get_pipeline))
        .route("/v1/pipelines/{id}/dispatch", post(dispatch_pipeline))
        .with_state(state)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    // Postgres read projection (best-effort: connect + migrate when DATABASE_URL is set).
    let pool = match std::env::var("DATABASE_URL") {
        Ok(url) => {
            let pool = sqlx::PgPool::connect(&url).await?;
            projection::migrate(&pool).await?;
            tracing::info!("postgres projection ready");
            Some(pool)
        }
        Err(_) => {
            tracing::warn!("DATABASE_URL not set; Postgres projection disabled");
            None
        }
    };

    // Durable serving: Restate endpoint for the workflow + budget object.
    #[cfg(feature = "restate")]
    let restate = tokio::spawn(serve_restate());

    let state = Arc::new(AppState {
        intents: Mutex::new(HashMap::new()),
        pool,
        pipelines: Mutex::new(HashMap::new()),
        grants: Mutex::new(HashMap::new()),
    });
    let app = app(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8081").await?;
    tracing::info!("control-plane listening on 0.0.0.0:8081");
    axum::serve(listener, app).await?;

    #[cfg(feature = "restate")]
    let _ = restate.await;
    Ok(())
}

/// Serve the Restate workflow + budget object on `:9080`.
#[cfg(feature = "restate")]
async fn serve_restate() {
    use restate_sdk::prelude::*;
    let endpoint = Endpoint::builder()
        .bind(control_plane::workflow::WorkPackageWorkflow)
        .bind(control_plane::workflow::BudgetCounter)
        .build();
    tracing::info!("restate serving on 0.0.0.0:9080");
    HttpServer::new(endpoint)
        .listen_and_serve("0.0.0.0:9080".parse().unwrap())
        .await;
}

/// POST /v1/intents — score + route via the qualifier, then project the decision (R3).
async fn submit_intent(
    State(state): State<SharedState>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let intent_id = new_id();
    let features = qualifier::IntentFeatures {
        spec_clarity: body.get("acceptance").and_then(|a| a.as_str()).map_or(0.3, |a| {
            // Rough heuristic: a non-empty acceptance string that names a test is "clear".
            if a.contains("test") || a.contains("assert") { 0.8 } else { 0.4 }
        }),
        blast_radius: 0.1, // greenfield demo default
        novelty: 0.1,
        reversibility: 0.0,
        has_codified_knowledge: true,
        fatal: false,
    };
    let decision = qualifier::decide(&intent_id, &features);
    state.intents.lock().unwrap().insert(intent_id.clone(), decision.clone());
    // R15: a dark-lane intent is decomposed into a work-package pipeline (goal cascade).
    if decision.lane == shared::Lane::Dark {
        let spec = body.get("description").and_then(|d| d.as_str()).unwrap_or("");
        let p = pipeline::Pipeline::new(&intent_id, spec, decision.lane);
        state.pipelines.lock().unwrap().insert(intent_id.clone(), p);
    }
    if let Some(pool) = &state.pool {
        let _ = projection::project_qualifier_decision(pool, &decision).await;
    }
    Json(serde_json::to_value(decision).unwrap_or(json!({})))
}

/// GET /v1/intents/{id}
async fn inspect_intent(
    State(state): State<SharedState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    let intents = state.intents.lock().unwrap();
    match intents.get(&id) {
        Some(d) => Json(serde_json::to_value(d).unwrap_or(json!({}))),
        None => Json(json!({"error": "not found"})),
    }
}

/// GET /v1/work-packages — dispatchable tasks across all pipelines (R15).
async fn list_work_packages(State(state): State<SharedState>) -> Json<Value> {
    let pipes = state.pipelines.lock().unwrap();
    let mut ready: Vec<shared::Task> = Vec::new();
    for p in pipes.values() {
        ready.extend(p.next_work().into_iter().cloned());
    }
    Json(json!({ "work_packages": ready, "pipelines": pipes.len() }))
}

/// GET /v1/pipelines/{intent_id} — the pipeline stage + task DAG.
async fn get_pipeline(
    State(state): State<SharedState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    let pipes = state.pipelines.lock().unwrap();
    match pipes.get(&id) {
        Some(p) => Json(json!({
            "intent_id": p.intent_id,
            "stage": format!("{:?}", p.stage()),
            "spent_usd": p.spent_usd,
            "tasks": p.tasks,
        })),
        None => Json(json!({ "error": "not found" })),
    }
}

/// POST /v1/pipelines/{id}/dispatch — submit the pipeline's unblocked work packages to Restate.
///
/// This is the seam that turns the pipeline from a description into a driver: each ready task
/// starts a `WorkPackageWorkflow.run`, which then awaits its worker's durable promise (R5).
async fn dispatch_pipeline(
    State(state): State<SharedState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    let restate_url =
        std::env::var("RESTATE_URL").unwrap_or_else(|_| "http://localhost:8090".to_string());

    // Collect ready task ids (and the budget state) under the lock, then release it before
    // awaiting (guards aren't Send).
    let (ready, exhausted) = {
        let pipes = state.pipelines.lock().unwrap();
        match pipes.get(&id) {
            Some(p) => (
                p.next_work().iter().map(|t| t.id.clone()).collect::<Vec<_>>(),
                p.budget_exhausted(),
            ),
            None => return Json(json!({ "error": "not found" })),
        }
    };
    // Gate 2 (R7): a unit that has spent its ceiling does not dispatch — it loops to a human.
    if exhausted {
        return Json(json!({ "outcome": "budget_exhausted" }));
    }

    let client = reqwest::Client::new();
    let mut submitted = Vec::new();
    for task_id in &ready {
        let url = format!("{restate_url}/restate/call/WorkPackageWorkflow/{task_id}/run");
        let ok = client
            .post(url)
            .json(task_id)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false);
        if ok {
            submitted.push(task_id.clone());
        }
    }

    if let Ok(mut pipes) = state.pipelines.lock()
        && let Some(p) = pipes.get_mut(&id)
    {
        for task_id in &submitted {
            p.dispatch(task_id);
        }
    }
    Json(json!({ "dispatched": submitted, "restate_url": restate_url }))
}

async fn get_work_package(
    State(_): State<SharedState>,
    axum::extract::Path(_id): axum::extract::Path<String>,
) -> Json<Value> {
    Json(json!({"error": "not found"}))
}

/// POST /v1/promotions/{task_id}/approve — Gate 1: a human completes a gated work package.
async fn approve_promotion(
    State(state): State<SharedState>,
    axum::extract::Path(task_id): axum::extract::Path<String>,
) -> Json<Value> {
    let mut pipes = state.pipelines.lock().unwrap();
    for p in pipes.values_mut() {
        if p.tasks.iter().any(|t| t.id == task_id) {
            p.on_eval(&task_id, true);
            return Json(json!({ "status": "approved", "stage": format!("{:?}", p.stage()) }));
        }
    }
    Json(json!({ "error": "task not found" }))
}

/// POST /v1/work-packages/{task_id}/result — the build→evaluate runtime callback.
///
/// Body: `{ "pipeline_id", "receipt", "worktree", "is_first_promotion"? }`. Applies the build
/// result, runs the wall (deterministic verifier), then the promotion gate, and advances the
/// pipeline: merge (auto) | awaiting_gate (human) | wall_failed | build_failed.
async fn work_package_result(
    State(state): State<SharedState>,
    axum::extract::Path(task_id): axum::extract::Path<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let pipeline_id = body.get("pipeline_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let worktree = body.get("worktree").and_then(|v| v.as_str()).unwrap_or(".").to_string();
    let is_first = body.get("is_first_promotion").and_then(|v| v.as_bool()).unwrap_or(true);
    let receipt: shared::Receipt = match serde_json::from_value(
        body.get("receipt").cloned().unwrap_or(Value::Null),
    ) {
        Ok(r) => r,
        Err(e) => return Json(json!({ "error": format!("bad receipt: {e}") })),
    };

    // 1. Build result.
    let built = {
        let mut pipes = state.pipelines.lock().unwrap();
        match pipes.get_mut(&pipeline_id) {
            Some(p) => p.on_build(&task_id, &receipt),
            None => return Json(json!({ "error": "pipeline not found" })),
        }
    };
    if !built {
        return Json(json!({ "outcome": "build_failed" }));
    }

    // Accrue the run's cost and enforce the per-unit ceiling (R7) — a terminal state.
    if let Ok(mut pipes) = state.pipelines.lock()
        && let Some(p) = pipes.get_mut(&pipeline_id)
    {
        p.accrue(receipt.spend_usd());
        if p.budget_exhausted() {
            p.on_eval(&task_id, false);
            let (spent, stage) = (p.spent_usd, format!("{:?}", p.stage()));
            return Json(json!({
                "outcome": "budget_exhausted",
                "spent_usd": spent,
                "stage": stage,
            }));
        }
    }

    // 2. The wall — the deterministic verifier (R2/R11).
    let wall_passed = evaluator::verify_worktree(std::path::Path::new(&worktree), &receipt).all_pass();

    // 3. Gate 1 — the first promotion is a human act.
    let needs_human = gates::promotion_requires_human(is_first, wall_passed);

    // 4. Advance the pipeline.
    let (outcome, stage) = {
        let mut pipes = state.pipelines.lock().unwrap();
        match pipes.get_mut(&pipeline_id) {
            Some(p) => {
                let outcome = if !wall_passed {
                    p.on_eval(&task_id, false);
                    "wall_failed"
                } else if !needs_human {
                    p.on_eval(&task_id, true);
                    "merged"
                } else {
                    "awaiting_gate"
                };
                (outcome, format!("{:?}", p.stage()))
            }
            None => ("unknown", "unknown".to_string()),
        }
    };
    Json(json!({
        "outcome": outcome,
        "wall_passed": wall_passed,
        "needs_human": needs_human,
        "stage": stage,
    }))
}

/// POST /v1/grants/{id}/approve — Gate 3: a human approves a privileged credential grant.
async fn approve_grant(
    State(state): State<SharedState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    let mut grants = state.grants.lock().unwrap();
    match grants.get_mut(&id) {
        Some(g) if g.human_approval_required => {
            g.approved_by = Some("operator".to_string());
            Json(json!({ "grant_id": id, "status": "issued" }))
        }
        Some(_) => Json(json!({ "grant_id": id, "status": "already_issued" })),
        None => Json(json!({ "error": "grant not found" })),
    }
}

/// POST /v1/work-packages/{id}/credentials — request a task-scoped grant (Gate 3 / R8).
///
/// Body: `{ "scope", "kind"?, "ttl_secs"? }`. A privileged grant is `pending` (human approval);
/// self-issued and broker-issued grants are issued immediately. The secret value is never
/// returned — only a grant id (the broker injects the token out-of-band).
async fn request_credential(
    State(state): State<SharedState>,
    axum::extract::Path(wp_id): axum::extract::Path<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let scope = body.get("scope").and_then(|v| v.as_str()).unwrap_or("*").to_string();
    let kind = match body.get("kind").and_then(|v| v.as_str()) {
        Some("privileged") => CredentialKind::Privileged,
        Some("broker_issued") => CredentialKind::BrokerIssued,
        _ => CredentialKind::SelfIssued,
    };
    let needs_human = gates::credential_requires_human(kind);
    let ttl = body.get("ttl_secs").and_then(|v| v.as_u64()).unwrap_or(900);
    let now = chrono::Utc::now();
    let grant = CredentialGrant {
        id: new_id(),
        work_package_id: wp_id,
        scope,
        kind,
        ttl_secs: ttl,
        issued_at: now,
        expires_at: now + chrono::Duration::seconds(ttl as i64),
        human_approval_required: needs_human,
        approved_by: if needs_human { None } else { Some("auto".to_string()) },
    };
    let (id, expires) = (grant.id.clone(), grant.expires_at);
    state.grants.lock().unwrap().insert(id.clone(), grant);
    Json(json!({
        "grant_id": id,
        "status": if needs_human { "pending" } else { "issued" },
        "human_approval_required": needs_human,
        "expires_at": expires,
    }))
}

/// POST /v1/budget/raise — Gate 2 (human-only).
async fn raise_budget(Json(body): Json<Value>) -> Json<Value> {
    let to_usd = body.get("to_usd").and_then(|v| v.as_f64()).unwrap_or(0.0);
    Json(json!({"status": "raised", "to_usd": to_usd}))
}

/// POST /v1/work-packages/{id}/stop — kill switch (consensus R9: out-of-band brake, not the
/// operator token alone).
async fn stop_work_package(axum::extract::Path(_id): axum::extract::Path<String>) -> Json<Value> {
    Json(json!({"status": "stopping"}))
}

/// GET /v1/memory/dependents/{symbol} — R16 AST-graph query (deterministic, no LLM).
async fn memory_dependents(
    State(state): State<SharedState>,
    axum::extract::Path(symbol): axum::extract::Path<String>,
) -> Json<Value> {
    match &state.pool {
        Some(pool) => match memory::dependents_from_db(pool, &symbol).await {
            Ok(deps) => Json(json!({ "symbol": symbol, "dependents": deps })),
            Err(e) => Json(json!({ "error": e.to_string() })),
        },
        None => Json(json!({ "error": "no database configured" })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// INT-01: submitting an intent returns a lane decision (dark for low-risk greenfield).
    #[tokio::test]
    async fn submit_intent_returns_dark_lane() {
        let app = app(Arc::new(AppState::default()));
        let req = Request::builder()
            .method("POST")
            .uri("/v1/intents")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"title":"t","description":"d","acceptance":"has a passing test"}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 200);

        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["lane"], "dark");
        assert_eq!(v["fatal"], false);
    }

    /// INT-01 (cont.): inspect round-trips the stored decision.
    #[tokio::test]
    async fn inspect_returns_stored_intent() {
        let app = app(Arc::new(AppState::default()));
        let submit = Request::builder()
            .method("POST")
            .uri("/v1/intents")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"title":"t","description":"d","acceptance":"test"}"#))
            .unwrap();
        let resp = app.clone().oneshot(submit).await.unwrap();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let id = v["intent_id"].as_str().unwrap().to_string();

        let get = Request::builder()
            .method("GET")
            .uri(format!("/v1/intents/{id}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(get).await.unwrap();
        assert_eq!(resp.status(), 200);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["lane"], "dark");
    }
}
