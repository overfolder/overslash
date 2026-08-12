//! HTTP-runtime replay — the `ReplayPayload::Http` branch of
//! `execute_claimed_approval`.
//!
//! The dialling itself lives in [`crate::services::stored_call`], shared with
//! the async worker. What stays here is the half that is genuinely
//! approval-specific: owning the `executions` row and turning an outcome into
//! the tuple the metrics / audit / webhook tail consumes.

use super::*;

use crate::services::call_timeout::CallTimeout;
use crate::services::stored_call::{self, StoredCallCtx, StoredOutcome};

use super::replay::fail_and_return;

/// Replay a stored HTTP call (`ReplayPayload::Http`). Returns the
/// `(finalised, succeeded, upstream_errored, result_summary)` tuple the shared
/// metrics / audit / webhook tail in `execute_claimed_approval` consumes.
#[allow(clippy::too_many_arguments)]
pub(super) async fn replay_http(
    state: &AppState,
    ext: &axum::http::Extensions,
    scope: &OrgScope,
    approval: &overslash_db::repos::approval::ApprovalRow,
    claimed: ExecutionRow,
    stored: action_caller::StoredCallRequest,
    id: Uuid,
    execution_id: Uuid,
    ip: Option<&str>,
    audit_body_mode: audit_capture::AuditResponseBodyMode,
    // The per-call budget (inner). Bounds the upstream request itself.
    call_timeout: CallTimeout,
    // The wall (outer). Bounds the whole replay future, including the DB work
    // after the upstream answers, so a wedged replay can't hold the execution
    // row in `executing` forever. Always wider than `call_timeout`.
    replay_timeout: std::time::Duration,
    replay_tpl: &str,
) -> Result<(ExecutionRow, bool, bool, Option<serde_json::Value>)> {
    let ctx = StoredCallCtx {
        state,
        ext,
        scope,
        org_id: scope.org_id(),
        identity_id: approval.identity_id, // requester identity for audit/rate-limit
        ip,
        description: Some(approval.action_summary.as_str()),
        tags: &approval.tags,
        audit_source: AuditSource::Replay {
            approval_id: id,
            execution_id,
        },
        audit_body_mode,
        timeout: Some(call_timeout),
        wall: replay_timeout,
        metrics_tpl: replay_tpl,
    };

    finalize(
        scope,
        claimed,
        execution_id,
        stored_call::run_stored(ctx, ReplayPayload::Http(stored)).await,
    )
    .await
}

/// Turn a [`StoredOutcome`] into the replay tuple, writing the terminal
/// execution row. Shared by all three runtime branches so the row can only
/// reach a terminal state one way.
pub(super) async fn finalize(
    scope: &OrgScope,
    claimed: ExecutionRow,
    execution_id: Uuid,
    outcome: StoredOutcome,
) -> Result<(ExecutionRow, bool, bool, Option<serde_json::Value>)> {
    Ok(match outcome {
        StoredOutcome::Executed {
            result,
            upstream_errored,
            summary,
        } => {
            let finalised = scope
                .finalize_execution_executed(execution_id, &result)
                .await?
                .unwrap_or(claimed);
            (finalised, true, upstream_errored, Some(summary))
        }
        StoredOutcome::Failed { message } => {
            let finalised = scope
                .finalize_execution_failed(execution_id, &message)
                .await?
                .unwrap_or(claimed);
            (finalised, false, false, None)
        }
        // Credential re-resolution failed: mark the row and surface the error
        // to the HTTP caller, which is what `/approvals/{id}/call` has always
        // done for this class.
        StoredOutcome::Rejected { message, error } => {
            return fail_and_return(scope, execution_id, &message, error).await;
        }
    })
}
