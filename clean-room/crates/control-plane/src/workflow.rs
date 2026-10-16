//! Restate workflow — the durable orchestration layer (consensus R3/R5).
//!
//! Restate 0.12 API (verified against the live SDK):
//! - `#[restate_sdk::workflow]` / `#[object]` go on the **impl block**, not the struct.
//! - Handlers are `#[handler]`, take `&self` + a context with a lifetime, return `HandlerResult<T>`.
//!
//! Consensus constraints encoded here:
//! - The Goose subprocess runs *outside* the journal (in the execution plane); only its outcome
//!   is awaited here via a durable promise (R5). Replay never re-runs the model.
//! - The deterministic state transition is a pure function — no side effect to journal (R5).
//! - The budget is a journaled K/V object the gateway reads, defaulting-deny (R7).

use restate_sdk::prelude::*;

/// A work-package workflow: await the worker's Goose run, then apply the deterministic
/// lifecycle transition.
pub struct WorkPackageWorkflow;

#[restate_sdk::workflow]
impl WorkPackageWorkflow {
    #[handler]
    async fn run(&self, ctx: WorkflowContext<'_>, _work_package_id: String) -> HandlerResult<String> {
        // Await the worker's outcome via a durable promise (R5). The Goose subprocess ran
        // outside this journal, in the execution plane; that plane resolves `worker.done`
        // with the typed Receipt JSON once Goose exits.
        let receipt_json: String = ctx.promise::<String>("worker.done").await?;
        let receipt: shared::Receipt = serde_json::from_str(&receipt_json)?;

        // Deterministic lifecycle transition — pure, replayed naturally, no side effect.
        let mut st = crate::state::WorkPackageState::default();
        let _ = crate::state::claim(&mut st);
        st.stage = crate::state::Stage::Building;
        crate::state::on_build_complete(&mut st, &receipt);

        let stage = format!("{:?}", st.stage);
        ctx.set("stage", stage.clone());
        Ok(stage)
    }

    /// Called by the execution plane when Goose finishes; resolves the run handler's promise.
    #[handler]
    async fn complete(
        &self,
        ctx: SharedWorkflowContext<'_>,
        receipt_json: String,
    ) -> HandlerResult<()> {
        ctx.resolve_promise::<String>("worker.done", receipt_json);
        Ok(())
    }
}

/// A budget state object (R7): the cumulative spend counter, journaled atomically with each
/// billable call. The gateway reads this and defaults-deny if it cannot.
pub struct BudgetCounter;

#[restate_sdk::object]
impl BudgetCounter {
    #[handler]
    async fn try_spend(&self, ctx: ObjectContext<'_>, estimate_usd: f64) -> HandlerResult<bool> {
        let spent: f64 = ctx.get::<f64>("spent").await?.unwrap_or(0.0);
        let cap: f64 = ctx.get::<f64>("cap").await?.unwrap_or(0.75);
        if spent + estimate_usd > cap {
            return Ok(false);
        }
        ctx.set("spent", spent + estimate_usd);
        Ok(true)
    }
}
