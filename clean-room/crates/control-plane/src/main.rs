//! The control plane — orchestrator + qualifier + gates + HTTP API + durable serving.
//!
//! Two servers run side-by-side:
//! - Axum on loopback `:8081` — the diagnostic `sfctl` CLI surface.
//! - Restate on `:9080` — the durable workflow + budget object (gated behind `--features restate`).
//!
//! Consensus R3 requires Postgres as a read projection of Restate authority. The HTTP
//! pipeline below is still diagnostic memory; privileged runtime routes remain unavailable.

use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use control_plane::{memory, pipeline, projection, qualifier};
use serde_json::{Value, json};
use shared::new_id;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Application state. The in-memory intent cache is the stand-in for the Postgres read model;
/// `pool` is the real projection when `DATABASE_URL` is set; `pipelines` are the R15 driver
/// pipelines (intent → task DAG → merge).
struct AppState {
    intents: Mutex<HashMap<String, Value>>,
    pool: Option<sqlx::PgPool>,
    pipelines: Mutex<HashMap<String, pipeline::Pipeline>>,
}

impl Default for AppState {
    fn default() -> Self {
        AppState {
            intents: Mutex::new(HashMap::new()),
            pool: None,
            pipelines: Mutex::new(HashMap::new()),
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
        .route(
            "/v1/work-packages/{id}/result",
            post(work_package_result)
                .route_layer(axum::middleware::from_fn(require_runtime_authority)),
        )
        .route(
            "/v1/work-packages/{id}/credentials",
            post(request_credential),
        )
        .route("/v1/memory/dependents/{symbol}", get(memory_dependents))
        .route("/v1/pipelines/{id}", get(get_pipeline))
        .route(
            "/v1/pipelines/{id}/dispatch",
            post(dispatch_pipeline)
                .route_layer(axum::middleware::from_fn(require_runtime_authority)),
        )
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
    });
    let app = app(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8081").await?;
    tracing::info!("control-plane listening on 127.0.0.1:8081");
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
    tracing::info!(
        "restate diagnostic endpoint on 127.0.0.1:9080; private ingress authentication remains required"
    );
    HttpServer::new(endpoint)
        .listen_and_serve("127.0.0.1:9080".parse().unwrap())
        .await;
}

/// POST /v1/intents — diagnostic score and in-memory demonstration only.
async fn submit_intent(State(state): State<SharedState>, Json(body): Json<Value>) -> Json<Value> {
    let intent_id = new_id();
    let features = qualifier::IntentFeatures {
        spec_clarity: body
            .get("acceptance")
            .and_then(|a| a.as_str())
            .map_or(0.3, |a| {
                // Rough heuristic: a non-empty acceptance string that names a test is "clear".
                if a.contains("test") || a.contains("assert") {
                    0.8
                } else {
                    0.4
                }
            }),
        blast_radius: 0.1, // greenfield demo default
        novelty: 0.1,
        reversibility: 0.0,
        has_codified_knowledge: has_repository_knowledge(&body),
        fatal: false,
    };
    let decision = qualifier::decide(&intent_id, &features);
    let mut inspection = serde_json::to_value(&decision).expect("serializable decision");
    inspection["features"] = serde_json::to_value(&features).expect("serializable features");
    inspection["authority"] = json!("diagnostic_only");
    state
        .intents
        .lock()
        .unwrap()
        .insert(intent_id.clone(), inspection.clone());
    // R15: a dark-lane intent is decomposed into a work-package pipeline (goal cascade).
    if decision.lane == shared::Lane::Dark {
        let spec = body
            .get("description")
            .and_then(|d| d.as_str())
            .unwrap_or("");
        let p = pipeline::Pipeline::new(&intent_id, spec, decision.lane);
        state.pipelines.lock().unwrap().insert(intent_id.clone(), p);
    }
    // These provisional features do not come from the durable qualifier authority. Never
    // write the result to its read model, where the diagnostic-only label would be lost.
    Json(inspection)
}

/// US-3 / INT-12: knowledge is evidence from the selected repository, not a caller flag.
fn has_repository_knowledge(body: &Value) -> bool {
    use std::io::Read;
    let Some(repo) = body.get("repo").and_then(Value::as_str) else {
        return false;
    };
    let path = std::path::Path::new(repo).join("AGENTS.md");
    let Ok(metadata) = std::fs::symlink_metadata(&path) else {
        return false;
    };
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 65_536 {
        return false;
    }
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut text = String::new();
    file.take(65_537).read_to_string(&mut text).is_ok()
        && text.len() <= 65_536
        && !text.trim().is_empty()
}

/// GET /v1/intents/{id}
async fn inspect_intent(
    State(state): State<SharedState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    let intents = state.intents.lock().unwrap();
    match intents.get(&id) {
        Some(d) => Json(d.clone()),
        None => Json(json!({"error": "not found"})),
    }
}

/// GET /v1/work-packages — active tasks, including running and dependency-blocked work.
async fn list_work_packages(State(state): State<SharedState>) -> Json<Value> {
    let pipes = state.pipelines.lock().unwrap();
    let mut active = Vec::new();
    for p in pipes.values() {
        for task in p.tasks.iter().filter(|task| {
            matches!(
                task.status,
                shared::TaskStatus::Pending | shared::TaskStatus::InProgress
            )
        }) {
            let mut row = serde_json::to_value(task).expect("serializable task");
            row["pipeline_id"] = json!(p.intent_id);
            row["pipeline_stage"] = json!(format!("{:?}", p.stage()));
            row["pipeline_spent_usd"] = json!(p.spent_usd);
            // No claim/receipt authority exists in this diagnostic cache.
            row["git_revision"] = Value::Null;
            active.push(row);
        }
    }
    active.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    Json(
        json!({ "work_packages": active, "pipelines": pipes.len(), "authority": "diagnostic_only" }),
    )
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
                p.next_work()
                    .iter()
                    .map(|t| t.id.clone())
                    .collect::<Vec<_>>(),
                p.budget_exhausted(),
            ),
            None => return Json(json!({ "error": "not found" })),
        }
    };
    // Gate 2 (R7): a unit that has spent its ceiling does not dispatch — it loops to a human.
    if exhausted {
        return Json(json!({ "outcome": "budget_exhausted" }));
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("HTTP client");
    let mut submitted = Vec::new();
    for task_id in &ready {
        let url = format!("{restate_url}/restate/send/WorkPackageWorkflow/{task_id}/run");
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
    State(state): State<SharedState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    for p in state.pipelines.lock().unwrap().values() {
        if let Some(task) = p.tasks.iter().find(|t| t.id == id) {
            return Json(
                json!({"task": task, "pipeline_id": p.intent_id, "stage": format!("{:?}", p.stage()), "spent_usd": p.spent_usd}),
            );
        }
    }
    Json(json!({"error": "not found"}))
}

// These gates must never synthesize approval or success while the operator authority,
// durable decision record, credential broker, and independent watchdog are absent.
fn unavailable(reason: &str) -> (axum::http::StatusCode, Json<Value>) {
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error": reason})),
    )
}

// The current HTTP pipeline is an in-memory diagnostic model. Until dispatch and result
// submission are authenticated and bound to durable claims, never run work or a wall
// command using a caller-supplied path. There is intentionally no environment bypass.
async fn require_runtime_authority(
    _request: axum::extract::Request,
    _next: axum::middleware::Next,
) -> (axum::http::StatusCode, Json<Value>) {
    unavailable("runtime unavailable: authenticated durable claims and isolated worker required")
}

async fn approve_promotion() -> (axum::http::StatusCode, Json<Value>) {
    unavailable(
        "promotion unavailable: authenticated, durable approval and exact-revision merge binding required",
    )
}

/// POST /v1/work-packages/{task_id}/result — the build→evaluate runtime callback.
///
/// Body: `{ "pipeline_id", "receipt", "worktree" }`. Diagnostic callback held behind
/// the runtime readiness guard. A wall pass never grants promotion authority.
async fn work_package_result(
    State(state): State<SharedState>,
    axum::extract::Path(task_id): axum::extract::Path<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let pipeline_id = body
        .get("pipeline_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let worktree = body
        .get("worktree")
        .and_then(|v| v.as_str())
        .unwrap_or(".")
        .to_string();
    let receipt: shared::Receipt =
        match serde_json::from_value(body.get("receipt").cloned().unwrap_or(Value::Null)) {
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
    let wall_passed =
        evaluator::verify_worktree(std::path::Path::new(&worktree), &receipt).all_pass();

    // A caller cannot bypass the human gate or claim an actual merge from evaluation.
    let (outcome, stage) = {
        let mut pipes = state.pipelines.lock().unwrap();
        match pipes.get_mut(&pipeline_id) {
            Some(p) => {
                let outcome = if !wall_passed {
                    p.on_eval(&task_id, false);
                    "wall_failed"
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
        "needs_human": true,
        "stage": stage,
    }))
}

async fn approve_grant() -> (axum::http::StatusCode, Json<Value>) {
    unavailable(
        "credential approval unavailable: authenticated authority and credential broker required",
    )
}

async fn request_credential() -> (axum::http::StatusCode, Json<Value>) {
    unavailable("credential issuance unavailable: scoped broker is not provisioned")
}

async fn raise_budget() -> (axum::http::StatusCode, Json<Value>) {
    unavailable(
        "budget raise unavailable: authenticated approval and durable budget update required",
    )
}

async fn stop_work_package() -> (axum::http::StatusCode, Json<Value>) {
    unavailable("stop unavailable: independent watchdog is not provisioned; no process was stopped")
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

    struct KnowledgeFixture(std::path::PathBuf);
    impl KnowledgeFixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("factory-knowledge-{}", new_id()));
            std::fs::create_dir(&path).unwrap();
            std::fs::write(path.join("AGENTS.md"), "Run cargo test before completion.").unwrap();
            Self(path)
        }
        fn intent(&self) -> String {
            json!({"title":"t", "description":"d", "acceptance":"has a passing test", "repo": self.0}).to_string()
        }
    }
    impl Drop for KnowledgeFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn missing_repository_knowledge_routes_to_human() {
        let response = app(Arc::new(AppState::default())).oneshot(Request::builder().method("POST")
            .uri("/v1/intents").header("content-type", "application/json")
            .body(Body::from(r#"{"title":"t","description":"d","acceptance":"has a passing test","repo":"/missing-factory-project"}"#)).unwrap()).await.unwrap();
        let value: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(value["lane"], "human");
    }

    #[tokio::test]
    async fn unsupported_gates_never_report_success_or_complete_tasks() {
        let state = Arc::new(AppState::default());
        state.pipelines.lock().unwrap().insert(
            "p".into(),
            pipeline::Pipeline::new("p", "spec", shared::Lane::Dark),
        );
        let router = app(state.clone());
        for route in [
            "/v1/promotions/p:scaffold/approve",
            "/v1/grants/g/approve",
            "/v1/budget/raise",
            "/v1/work-packages/p:scaffold/stop",
            "/v1/work-packages/p:scaffold/credentials",
            "/v1/pipelines/p/dispatch",
            "/v1/work-packages/p:scaffold/result",
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(route)
                        .header("content-type", "application/json")
                        .body(Body::from(r#"{"to_usd":100,"scope":"*"}"#))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), 503, "{route}");
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let value: Value = serde_json::from_slice(&body).unwrap();
            assert!(value["error"].is_string(), "{route}: {value}");
        }
        let pipes = state.pipelines.lock().unwrap();
        assert_eq!(pipes["p"].tasks[0].status, shared::TaskStatus::Pending);
        assert_eq!(pipes["p"].ceiling_usd, 0.75);
    }

    #[tokio::test]
    async fn status_inspects_an_existing_task() {
        let state = Arc::new(AppState::default());
        state.pipelines.lock().unwrap().insert(
            "p".into(),
            pipeline::Pipeline::new("p", "spec", shared::Lane::Dark),
        );
        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/v1/work-packages/p:scaffold")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["task"]["id"], "p:scaffold");
        assert_eq!(value["task"]["status"], "pending");
    }

    /// A disposable SQL fixture verifies that diagnostic output is not projected as authority.
    #[tokio::test]
    #[ignore = "requires the disposable diagnostic PostgreSQL fixture"]
    async fn diagnostic_submission_does_not_write_authoritative_qualifier_projection() {
        let url = std::env::var("SFACTORY_DIAGNOSTIC_FIXTURE_DATABASE_URL")
            .expect("run through the disposable diagnostic fixture");
        assert!(url.starts_with("postgres://sfactory@127.0.0.1:"));
        assert!(url.ends_with("/sfactory_diagnostic_fixture"));
        let pool = sqlx::PgPool::connect(&url).await.unwrap();
        projection::migrate(&pool).await.unwrap();
        let count = || async {
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM qualifier_decisions")
                .fetch_one(&pool)
                .await
                .unwrap()
        };
        assert_eq!(count().await, 0, "fixture database must start empty");
        let knowledge = KnowledgeFixture::new();
        let state = Arc::new(AppState {
            pool: Some(pool.clone()),
            ..AppState::default()
        });
        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/intents")
                    .header("content-type", "application/json")
                    .body(Body::from(knowledge.intent()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let value: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(value["authority"], "diagnostic_only");
        assert_eq!(value["lane"], "dark");
        assert_eq!(
            count().await,
            0,
            "diagnostic decision must not enter authoritative read model"
        );
        let separately_produced = qualifier::decide(
            "fixture-projection",
            &qualifier::IntentFeatures {
                spec_clarity: 0.0,
                blast_radius: 1.0,
                novelty: 1.0,
                reversibility: 1.0,
                has_codified_knowledge: false,
                fatal: true,
            },
        );
        projection::project_qualifier_decision(&pool, &separately_produced)
            .await
            .unwrap();
        assert_eq!(
            count().await,
            1,
            "separate projection API remains available"
        );
        pool.close().await;
    }

    /// INT-01: submitting an intent returns a diagnostic lane decision.
    #[tokio::test]
    async fn submit_intent_returns_dark_lane() {
        let knowledge = KnowledgeFixture::new();
        let app = app(Arc::new(AppState::default()));
        let req = Request::builder()
            .method("POST")
            .uri("/v1/intents")
            .header("content-type", "application/json")
            .body(Body::from(knowledge.intent()))
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
        let knowledge = KnowledgeFixture::new();
        let app = app(Arc::new(AppState::default()));
        let submit = Request::builder()
            .method("POST")
            .uri("/v1/intents")
            .header("content-type", "application/json")
            .body(Body::from(knowledge.intent()))
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
        assert_eq!(v["features"]["spec_clarity"], 0.8);
        assert_eq!(v["features"]["blast_radius"], 0.1);
        assert_eq!(v["features"]["novelty"], 0.1);
        assert_eq!(v["features"]["reversibility"], 0.0);
    }

    #[tokio::test]
    async fn status_lists_in_progress_and_blocked_tasks() {
        let state = Arc::new(AppState::default());
        let mut pipeline = pipeline::Pipeline::new("p", "spec", shared::Lane::Dark);
        pipeline.dispatch("p:scaffold");
        state.pipelines.lock().unwrap().insert("p".into(), pipeline);
        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/v1/work-packages")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let value: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        let tasks = value["work_packages"].as_array().unwrap();
        assert_eq!(tasks.len(), 3);
        assert_eq!(tasks[0]["id"], "p:implement");
        assert_eq!(tasks[1]["id"], "p:scaffold");
        assert_eq!(tasks[1]["status"], "in_progress");
        assert_eq!(tasks[1]["pipeline_spent_usd"], 0.0);
        assert!(tasks[1]["git_revision"].is_null());
    }
}
