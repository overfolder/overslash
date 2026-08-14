//! Platform-runtime replay — the `ReplayPayload::Platform` branch of
//! `execute_claimed_approval`.
//!
//! The dispatch and the `action.executed` audit row live in
//! [`crate::services::stored_call`], shared with the async worker; this file
//! owns the `executions` row.

use super::*;

use crate::services::stored_call::{self, StoredCallCtx};

use super::replay_http::finalize;

/// Replay a stored platform call (`ReplayPayload::Platform`). Returns the same
/// `(finalised, succeeded, upstream_errored, result_summary)` tuple as the other
/// runtime branches; `upstream_errored` is always false because platform
/// dispatch is in-process.
#[allow(clippy::too_many_arguments)]
pub(super) async fn replay_platform(
    state: &AppState,
    ext: &axum::http::Extensions,
    scope: &OrgScope,
    approval: &overslash_db::repos::approval::ApprovalRow,
    claimed: ExecutionRow,
    call: action_caller::StoredPlatformCall,
    id: Uuid,
    execution_id: Uuid,
    ip: Option<&str>,
    audit_org_id: Uuid,
    replay_timeout: std::time::Duration,
) -> Result<(ExecutionRow, bool, bool, Option<serde_json::Value>)> {
    let ctx = StoredCallCtx {
        state,
        ext,
        scope,
        org_id: audit_org_id,
        identity_id: approval.identity_id,
        ip,
        description: Some(approval.action_summary.as_str()),
        tags: &approval.tags,
        audit_source: AuditSource::Replay {
            approval_id: id,
            execution_id,
        },
        // Platform dispatch never reaches an upstream, so no response body can
        // be captured; the mode is irrelevant but must be supplied.
        audit_body_mode: audit_capture::AuditResponseBodyMode::Off,
        // Platform actions run in-process; only the outer wall applies.
        timeout: None,
        wall: replay_timeout,
        metrics_tpl: "",
    };

    finalize(
        scope,
        claimed,
        execution_id,
        stored_call::run_stored(ctx, ReplayPayload::Platform(call)).await,
    )
    .await
}
