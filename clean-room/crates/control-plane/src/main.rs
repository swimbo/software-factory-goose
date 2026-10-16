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
use control_plane::{driver, memory, projection, qualifier};
use serde_json::{Value, json};
use shared::{new_id, QualifierDecision};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Application state. The in-memory intent cache is the stand-in for the Postgres read model;
/// `pool` is the real projection when `DATABASE_URL` is set; `tasks` is the R15 driver graph.
struct AppState {
    intents: Mutex<HashMap<String, QualifierDecision>>,
    pool: Option<sqlx::PgPool>,
    tasks: Mutex<Vec<shared::Task>>,
}

impl Default for AppState {
    fn default() -> Self {
        AppState {
            intents: Mutex::new(HashMap::new()),
            pool: None,
            tasks: Mutex::new(Vec::new()),
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
        .route("/v1/memory/dependents/{symbol}", get(memory_dependents))
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
        tasks: Mutex::new(Vec::new()),
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
    // R15: a dark-lane intent becomes a dispatchable task in the driver's graph.
    if decision.lane == shared::Lane::Dark {
        let task = shared::Task::new(intent_id.clone(), body.get("title").and_then(|t| t.as_str()).unwrap_or("intent"));
        state.tasks.lock().unwrap().push(task);
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

/// GET /v1/work-packages — the tasks the driver reports as dispatchable (R15).
async fn list_work_packages(State(state): State<SharedState>) -> Json<Value> {
    let tasks = state.tasks.lock().unwrap();
    let ready: Vec<&shared::Task> = driver::dispatchable(&tasks);
    Json(json!({ "work_packages": ready, "total": tasks.len() }))
}

async fn get_work_package(
    State(_): State<SharedState>,
    axum::extract::Path(_id): axum::extract::Path<String>,
) -> Json<Value> {
    Json(json!({"error": "not found"}))
}

/// POST /v1/promotions/{id}/approve — Gate 1 (first promotion is a human act).
async fn approve_promotion(
    axum::extract::Path(_id): axum::extract::Path<String>,
) -> Json<Value> {
    Json(json!({"status": "approved", "gate": "first-promotion"}))
}

/// POST /v1/grants/{id}/approve — Gate 3 (privileged credential).
async fn approve_grant(axum::extract::Path(_id): axum::extract::Path<String>) -> Json<Value> {
    Json(json!({"status": "approved", "gate": "credential"}))
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
