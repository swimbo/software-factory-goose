//! Restate-backed immutable intake. Intentionally not registered on any endpoint.
//!
//! One exclusive virtual-object key is the client-generated canonical ULID. There is no
//! application TTL that could turn a retry into fresh intake. Only Restate state determines
//! admission; the diagnostic memory cache and Postgres are not consulted. Public HTTP/CLI
//! routing, trusted repository resolution, grounded qualification and queue integration remain
//! separate work. No method in this object dispatches work or grants a privileged action.

use crate::intake::{IntakeError, IntakeRequest, StoredIntake, submit_once, valid_principal};
use restate_sdk::{prelude::*, serde::Json};

/// Configuration binds stored records to one principal; it does NOT authenticate a caller.
/// Keep unregistered until a private ingress adapter authenticates every request and binds
/// this configured scope to that request. Never accept principal identity from HTTP JSON.
pub struct IntakeJournal {
    submitter: String,
}
impl IntakeJournal {
    pub fn new_for_private_ingress(submitter: String) -> anyhow::Result<Self> {
        anyhow::ensure!(
            valid_principal(&submitter),
            "invalid intake submitter scope"
        );
        Ok(Self { submitter })
    }
}

#[restate_sdk::object]
impl IntakeJournal {
    #[handler]
    async fn submit(
        &self,
        ctx: ObjectContext<'_>,
        request: Json<IntakeRequest>,
    ) -> HandlerResult<Json<StoredIntake>> {
        let existing = ctx.get::<Json<StoredIntake>>("intake").await?;
        if let Some(stored) = existing {
            // Do not read time or rewrite state on identical redelivery. This also preserves
            // original admission under clock rollback and later configuration changes.
            return submit_once(Some(&stored.0), ctx.key(), &self.submitter, request.0, 0)
                .map(Json)
                .map_err(|e| intake_terminal(e).into());
        }
        // Validate before adding a journaled clock side effect for a refused request.
        let mut record =
            submit_once(None, ctx.key(), &self.submitter, request.0, 0).map_err(intake_terminal)?;
        record.created_at_ms = ctx.run(intake_clock_millis).await?;
        ctx.set("intake", Json(record.clone()));
        Ok(Json(record))
    }

    #[handler]
    async fn inspect(
        &self,
        ctx: SharedObjectContext<'_>,
    ) -> HandlerResult<Json<Option<StoredIntake>>> {
        let stored = ctx.get::<Json<StoredIntake>>("intake").await?;
        let checked = stored
            .map(|stored| {
                submit_once(
                    Some(&stored.0),
                    ctx.key(),
                    &self.submitter,
                    stored.0.request.clone(),
                    0,
                )
            })
            .transpose()
            .map_err(intake_terminal)?;
        Ok(Json(checked))
    }
}

fn intake_terminal(error: IntakeError) -> TerminalError {
    let code = match error {
        IntakeError::ConflictingReuse => 409,
        IntakeError::PrincipalMismatch => 403,
        IntakeError::StoredBindingMismatch => 500,
        _ => 400,
    };
    TerminalError::new_with_code(code, error.to_string())
}
async fn intake_clock_millis() -> HandlerResult<u64> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| TerminalError::new_with_code(500, "intake clock before epoch"))?;
    u64::try_from(elapsed.as_millis())
        .map_err(|_| TerminalError::new_with_code(500, "intake clock overflow").into())
}
