//! MCP-runtime replay — the `ReplayPayload::Mcp` branch of
//! `execute_claimed_approval`.
//!
//! The dialling and the `action.executed` audit row live in
//! [`crate::services::stored_call`], shared with the async worker; this file
//! owns the `executions` row.

use super::*;

use crate::services::stored_call::{self, StoredCallCtx};

use super::replay_http::finalize;

/// Replay a stored MCP call (`ReplayPayload::Mcp`). Returns the same
/// `(finalised, succeeded, upstream_errored, result_summary)` tuple as the
/// other runtime branches.
#[allow(clippy::too_many_arguments)]
pub(super) async fn replay_mcp(
    state: &AppState,
    ext: &axum::http::Extensions,
    scope: &OrgScope,
    approval: &overslash_db::repos::approval::ApprovalRow,
    claimed: ExecutionRow,
    call: action_caller::StoredMcpCall,
    id: Uuid,
    execution_id: Uuid,
    ip: Option<&str>,
    audit_org_id: Uuid,
    audit_body_mode: audit_capture::AuditResponseBodyMode,
    replay_timeout: std::time::Duration,
    replay_tpl: &str,
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
        audit_body_mode,
        // MCP dials through its own executor, which carries its own budget;
        // only the outer wall applies here.
        timeout: None,
        wall: replay_timeout,
        metrics_tpl: replay_tpl,
    };

    finalize(
        scope,
        claimed,
        execution_id,
        stored_call::run_stored(ctx, ReplayPayload::Mcp(call)).await,
    )
    .await
}
