//! Running one claimed async execution, start to terminal state.
//!
//! This is the test seam: integration tests insert a row and call
//! [`run_claim`] directly rather than waiting on the loop, matching the
//! established pattern for the maintenance sweeps (backdate with raw SQL, then
//! invoke the function).

use std::time::Duration;

use sqlx::PgPool;
use tokio::sync::{OwnedSemaphorePermit, watch};

use overslash_db::repos::execution::{AsyncClaim, AsyncOutcome};
use overslash_db::scopes::SystemScope;

use crate::AppState;
use crate::services::action_caller::{AuditSource, ReplayPayload};
use crate::services::audit_capture::AuditResponseBodyMode;
use crate::services::events::{self, EventDraft, EventType};
use crate::services::stored_call::{self, StoredCallCtx, StoredOutcome};

/// Wrapper that always releases its permit, whatever the job does.
pub(super) async fn run_claim(
    state: AppState,
    db: PgPool,
    claim: AsyncClaim,
    _permit: OwnedSemaphorePermit,
) {
    let id = claim.id;
    if let Err(e) = execute(state, db, claim, crate::services::shutdown::subscribe()).await {
        tracing::error!("async execution {id} failed unexpectedly: {e}");
    }
}

/// Run one claimed row to a terminal state.
///
/// `shutdown` is taken as a parameter rather than read from the process-global
/// so a test can drive the release path with its own channel instead of
/// tripping a `OnceLock` that every other test in the binary would then see.
pub async fn execute(
    state: AppState,
    db: PgPool,
    claim: AsyncClaim,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let ext = axum::http::Extensions::default();
    let system = SystemScope::new_internal(db.clone());
    let scope = system.scope_for_org(claim.org_id);
    let worker_id = super::worker_id();

    let payload = match ReplayPayload::from_stored(&claim.request) {
        Ok(p) => p,
        Err(e) => {
            finish(
                &state,
                &system,
                &scope,
                &claim,
                worker_id,
                AsyncOutcome::Failed(&format!("unreadable stored payload: {e}")),
            )
            .await;
            return Ok(());
        }
    };

    // The D56 budget resolved when the call was accepted, re-clamped against
    // today's ceilings — same discipline as approval replay, so an org that
    // tightened its policy after the call was queued still binds.
    // A failed read degrades to "no org opinion", leaving the deployment
    // ceiling — same choice the replay path makes, and for the same reason:
    // refusing to run because a settings read blipped is strictly worse.
    let org_call_settings = match overslash_db::repos::org::get_call_settings(&db, claim.org_id)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "org call settings read failed; running async call with deployment defaults");
            None
        }
    };
    // Note the async ceiling, not `call_timeout_max_ms`: the 110s sync ceiling
    // exists to sit under a proxy's request cap, and no proxy is counting here.
    let timeout = crate::services::call_timeout::reclamp_stored(
        payload.stored_timeout_ms(),
        org_call_settings
            .as_ref()
            .and_then(|s| s.max_call_timeout_ms)
            .map(|v| v as u64),
        state.config.call_timeout_ms,
        state.config.async_execution.call_timeout_max_ms,
    );
    let audit_body_mode = org_call_settings
        .as_ref()
        .map(|s| AuditResponseBodyMode::parse_or_off(&s.audit_response_body_mode))
        .unwrap_or(AuditResponseBodyMode::Off);

    let ctx = StoredCallCtx {
        state: &state,
        ext: &ext,
        scope: &scope,
        org_id: claim.org_id,
        identity_id: claim.identity_id,
        ip: claim.client_ip.as_deref(),
        description: claim.description.as_deref(),
        tags: &claim.tags,
        audit_source: AuditSource::Async {
            execution_id: claim.id,
        },
        audit_body_mode,
        timeout: Some(timeout),
        wall: state.config.async_wall_clock(),
        metrics_tpl: claim.template_key.as_deref().unwrap_or("unknown"),
    };

    // Three arms. The middle one is the point: the heartbeat renews the lease
    // AND polls for cancellation in a single statement, so "I still own this
    // row" and "I should stop" can never be observed inconsistently.
    //
    // The third is what makes the shutdown story true rather than aspirational.
    // Without it the worker stops *claiming* on SIGTERM but in-flight jobs run
    // on until SIGKILL, their leases are never handed back, and the reclaim
    // sweep charges each one an attempt ~60s later — which, at the default
    // `max_attempts = 1`, fails the job outright instead of requeueing it.
    // A job claimed in the same tick the signal arrived would never observe a
    // *change*, only an already-true value — so check before selecting.
    // `borrow_and_update` also marks the current value seen, which is what
    // makes the `changed()` arm below fire only on a genuine transition.
    if *shutdown.borrow_and_update() {
        release_at_shutdown(&state, &system, &claim, worker_id).await;
        return Ok(());
    }

    let heartbeat_every = state.config.async_heartbeat_interval();
    let outcome = tokio::select! {
        outcome = stored_call::run_stored(ctx, payload) => Some(outcome),
        // `changed()` only fires on a *transition*, so the already-shutting-down
        // case is handled by the pre-check above.
        _ = shutdown.changed() => {
            // Dropping the upstream future cancels the in-flight request.
            release_at_shutdown(&state, &system, &claim, worker_id).await;
            return Ok(());
        }
        stop = heartbeat_until_stop(&system, claim.id, worker_id, state.config.async_execution.lease_ttl_secs as i64, heartbeat_every) => {
            match stop {
                // Cancel observed: drop the in-flight future, which cancels the
                // reqwest call. The upstream request may already have landed —
                // cancelling means we stop waiting, not that nothing happened.
                Stop::Cancelled => {
                    finish(&state, &system, &scope, &claim, worker_id, AsyncOutcome::Cancelled).await;
                    return Ok(());
                }
                // Lease lost: another worker may already own this row, so
                // abandon without finalizing rather than racing it.
                Stop::LeaseLost => {
                    tracing::warn!(
                        execution_id = %claim.id,
                        "async execution lost its lease mid-flight; abandoning without finalizing"
                    );
                    return Ok(());
                }
            }
        }
    };

    let Some(outcome) = outcome else {
        return Ok(());
    };
    let terminal = match &outcome {
        StoredOutcome::Executed { result, .. } => AsyncOutcome::Executed(result),
        StoredOutcome::Failed { message } => AsyncOutcome::Failed(message),
        // A worker has no caller to surface a rejection to, so a credential
        // that could not be re-minted is simply a failed row.
        StoredOutcome::Rejected { message, .. } => AsyncOutcome::Failed(message),
    };
    finish(&state, &system, &scope, &claim, worker_id, terminal).await;
    Ok(())
}

/// Hand a claimed row back to the queue at shutdown, without charging an
/// attempt.
///
/// `attempts` counts leases *lost*, not claims, precisely so this is free: a
/// row released here is picked up by another replica within a tick, whereas
/// letting the lease expire would cost ~60s and — at the default
/// `max_attempts = 1` — fail the job outright instead of retrying it.
///
/// `expires_at` is pushed out at the same time so `expire_stale` cannot sweep
/// the row before anyone can take it.
async fn release_at_shutdown(
    state: &AppState,
    system: &SystemScope,
    claim: &AsyncClaim,
    worker_id: &str,
) {
    match system
        .release_async_execution(
            claim.id,
            worker_id,
            state.config.execution_pending_ttl_secs as i64,
        )
        .await
    {
        Ok(true) => tracing::info!(
            execution_id = %claim.id,
            "released async execution lease at shutdown; another worker will pick it up"
        ),
        Ok(false) => tracing::warn!(
            execution_id = %claim.id,
            "async execution lease was already gone at shutdown"
        ),
        Err(e) => tracing::error!(
            execution_id = %claim.id,
            "failed to release async execution lease at shutdown: {e}"
        ),
    }
}

enum Stop {
    Cancelled,
    LeaseLost,
}

/// Renew the lease on a fixed interval until a cancel is requested or the
/// lease is lost. Never returns while the job should keep running.
async fn heartbeat_until_stop(
    system: &SystemScope,
    id: uuid::Uuid,
    worker_id: &str,
    lease_ttl_secs: i64,
    every: Duration,
) -> Stop {
    loop {
        tokio::time::sleep(every).await;
        match system
            .heartbeat_async_execution(id, worker_id, lease_ttl_secs)
            .await
        {
            Ok(Some(true)) => return Stop::Cancelled,
            Ok(Some(false)) => continue,
            Ok(None) => return Stop::LeaseLost,
            // A transient database error must not be read as "lease lost" —
            // that would abandon a perfectly good job. Keep running; a real
            // loss is caught on the next tick, and the reclaim sweep is the
            // backstop if the database stays down.
            Err(e) => {
                tracing::warn!("heartbeat for execution {id} failed: {e}");
                continue;
            }
        }
    }
}

/// Write the terminal row and emit the event.
async fn finish(
    state: &AppState,
    system: &SystemScope,
    scope: &overslash_db::scopes::OrgScope,
    claim: &AsyncClaim,
    worker_id: &str,
    outcome: AsyncOutcome<'_>,
) {
    let status = match &outcome {
        AsyncOutcome::Executed(_) => "executed",
        AsyncOutcome::Failed(_) => "failed",
        AsyncOutcome::Cancelled => "cancelled",
    };
    let event_type = match &outcome {
        AsyncOutcome::Executed(_) => EventType::ExecutionCompleted,
        AsyncOutcome::Failed(_) => EventType::ExecutionFailed,
        AsyncOutcome::Cancelled => EventType::ExecutionCancelled,
    };
    let error = match &outcome {
        AsyncOutcome::Failed(m) => Some((*m).to_string()),
        _ => None,
    };

    match system
        .finalize_async_execution(claim.org_id, claim.id, worker_id, outcome)
        .await
    {
        // Lost the lease between finishing and finalizing. Someone else owns
        // the row now, so do not emit an event for a transition we did not make.
        Ok(None) => {
            tracing::warn!(
                execution_id = %claim.id,
                "async execution finished but its lease was gone; result discarded"
            );
            return;
        }
        Err(e) => {
            tracing::error!(
                "finalizing async execution {claim_id}: {e}",
                claim_id = claim.id
            );
            return;
        }
        Ok(Some(_)) => {}
    }

    // Payload deliberately carries no `result`: webhook subscriptions are
    // org-wide, and an upstream response body is exactly where a credential
    // hides. `is_error` and the status are enough to route on; the body is
    // fetched through the authorized endpoint, which is also what marks it read.
    let audience = events::audience::for_execution(scope, claim.identity_id, None).await;
    events::emit(
        state.db.clone(),
        state.http_client.clone(),
        EventDraft {
            org_id: claim.org_id,
            event_type,
            payload: serde_json::json!({
                "execution_id": claim.id,
                "status": status,
                "origin": if claim.approval_id.is_some() { "approval" } else { "async_call" },
                "approval_id": claim.approval_id,
                "identity_id": claim.identity_id,
                "error": error,
            }),
            audience,
        },
    );
}
