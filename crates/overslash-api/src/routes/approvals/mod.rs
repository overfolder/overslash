//! Approval-queue endpoints (`/v1/approvals`): reading the queue, resolving
//! an approval, and replaying the gated action once it has been allowed.
//!
//! Shared response DTOs (`ApprovalResponse`, `ExecutionSummary`) and the
//! helpers every group needs (`build_response`, `spawn_auto_call`,
//! `execution_conflict_error`) live here; the handlers live in the siblings.

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::util::fmt_time;

use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::execution::ExecutionRow;
use overslash_db::scopes::OrgScope;

use overslash_core::permissions::{
    DerivedKey, GroupCeilingResult, PermissionKey, parse_derived_key,
};
use overslash_core::registry::ServiceRegistry;
use overslash_core::types::service::Risk;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AuthContext, ClientIp, OrgAcl, ReqExt, WriteAcl},
    services::action_caller::{self, AuditSource, CallContext, CallOutcome, ReplayPayload},
    services::audit_capture,
    services::group_ceiling,
    services::mcp_caller,
    services::platform_caller,
};

/// Maximum bytes of `action_detail` returned on approval responses. The raw
/// payload is surfaced to reviewers (behind a "Show Raw Payload" disclosure);
/// the cap bounds response size and browser render cost. The original
/// untruncated size is still reported via `action_detail_size_bytes`.
const MAX_ACTION_DETAIL_BYTES: usize = 100 * 1024;

/// Maximum bytes of `execution.result` returned on approval responses. The
/// full upstream body lives in the `executions` row; the response returns a
/// truncated pretty-printed view so one oversized replay doesn't wedge the
/// dashboard.
const MAX_EXECUTION_RESULT_BYTES: usize = 256 * 1024;

mod dto;
mod read;
mod replay;
mod replay_http;
mod replay_mcp;
mod replay_platform;
mod resolve;

use dto::*;
use read::{get_approval, get_execution, list_approvals};
use replay::{call_approval, cancel_approval_execution, execute_claimed_approval};
use resolve::resolve_approval;

// `routes::actions` renders the same inline `pending_approval` envelope and
// must derive identical risk / action-detail strings.
pub(crate) use dto::{render_action_detail, risk_class};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/approvals", get(list_approvals))
        .route("/v1/approvals/{id}", get(get_approval))
        .route("/v1/approvals/{id}/resolve", post(resolve_approval))
        .route("/v1/approvals/{id}/call", post(call_approval))
        .route("/v1/approvals/{id}/cancel", post(cancel_approval_execution))
        .route("/v1/approvals/{id}/execution", get(get_execution))
}

#[derive(Serialize)]
struct ExecutionSummary {
    id: Uuid,
    /// One of: `pending`, `executing`, `executed`, `failed`, `cancelled`, `expired`.
    /// Passed through verbatim from the `executions.status` column.
    status: String,
    /// Populated when `status='executed'`. Truncated at `MAX_EXECUTION_RESULT_BYTES`.
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// `agent` | `user` | `auto`. Omitted from JSON while the execution is still pending.
    #[serde(skip_serializing_if = "Option::is_none")]
    triggered_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_at: Option<String>,
    expires_at: String,
    created_at: String,
    /// `http` | `mcp` — extracted from the result envelope. Disambiguates
    /// `http_status_code` (which is meaningless for MCP runtime calls).
    /// `None` while the execution hasn't completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime: Option<String>,
    /// Upstream HTTP status code for HTTP-runtime executions only. Used by
    /// the dashboard to render a status pill on completed-but-unread rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    http_status_code: Option<u16>,
    /// True once the requesting agent has read the result (the GET on
    /// `/v1/approvals/{id}/execution` from the agent identity stamps
    /// `result_viewed_at`). Drives the "called but output unread"
    /// pending-calls surface.
    output_read: bool,
}

impl ExecutionSummary {
    fn from_row(r: ExecutionRow) -> Self {
        let runtime = r.result.as_ref().and_then(extract_runtime);
        let http_status_code = if matches!(runtime.as_deref(), Some("http")) {
            r.result.as_ref().and_then(extract_http_status_code)
        } else {
            None
        };
        let output_read = r.result_viewed_at.is_some();
        let result = r.result.map(truncate_json_value);
        Self {
            id: r.id,
            status: r.status,
            result,
            error: r.error,
            triggered_by: r.triggered_by,
            started_at: r.started_at.map(fmt_time),
            completed_at: r.completed_at.map(fmt_time),
            expires_at: fmt_time(r.expires_at),
            created_at: fmt_time(r.created_at),
            runtime,
            http_status_code,
            output_read,
        }
    }
}

#[derive(Serialize)]
struct ApprovalResponse {
    id: Uuid,
    /// The identity that originally requested the action.
    identity_id: Uuid,
    /// Alias of `identity_id`, named explicitly for clarity in the bubbling model.
    requesting_identity_id: Uuid,
    /// The identity currently expected to act on this approval. Bubbles upward
    /// on explicit BubbleUp or via the auto-bubble timer.
    current_resolver_identity_id: Uuid,
    /// SPIFFE-style hierarchical path of the requesting identity
    /// (`spiffe://<org>/user/alice/agent/henry/...`). See
    /// `crate::services::identity_path`.
    identity_path: Option<String>,
    /// Identity ids for each `(kind, name)` unit in `identity_path`, in the
    /// same order. Excludes the org slug (which has no id), so the length
    /// matches the unit-segment count of `identity_path`. Empty when
    /// `identity_path` is `None`. The dashboard uses this to build
    /// `/agents/<id>` links for each clickable segment without resolving
    /// names → ids on the client.
    identity_path_ids: Vec<Uuid>,
    action_summary: String,
    /// System-derived metadata tags describing the gated call (`sql:write`,
    /// `table:wh/orders`, `service:metabase`, …). Shown as chips on the
    /// approval detail so a reviewer sees what the call actually touches.
    tags: Vec<String>,
    permission_keys: Vec<String>,
    derived_keys: Vec<overslash_core::permissions::DerivedKey>,
    suggested_tiers: Vec<overslash_core::permissions::SuggestedTier>,
    /// Pretty-printed serialization of the stored `action_detail` JSONB,
    /// truncated at a UTF-8 char boundary if the full form exceeds
    /// `MAX_ACTION_DETAIL_BYTES`. `None` when no detail was stored.
    action_detail: Option<String>,
    action_detail_truncated: bool,
    /// Byte length of the full pretty-printed `action_detail` prior to
    /// truncation. `0` when no detail was stored.
    action_detail_size_bytes: usize,
    /// Labeled, human-readable slice of the resolved request extracted via
    /// the template's `x-overslash-disclose` filters at approval-create
    /// time. Rendered as the "Summary" block above the raw payload on the
    /// review page. `None` when the template declared no disclose entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    disclosed_fields: Option<serde_json::Value>,
    status: String,
    token: String,
    expires_at: String,
    created_at: String,
    /// Replay lifecycle for the action gated by this approval. `None` on
    /// deny / bubble-up / pre-replay approvals; `Some` once /resolve allow
    /// has created the pending execution row.
    #[serde(skip_serializing_if = "Option::is_none")]
    execution: Option<ExecutionSummary>,
    /// Other pending approvals auto-resolved as a side effect of this call.
    /// Populated only on `/v1/approvals/{id}/call` when an "Allow & Remember"
    /// rule was committed and that rule structurally satisfied other pending
    /// approvals under the same placement identity. Empty / omitted in all
    /// other contexts.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    cascaded_approval_ids: Vec<Uuid>,
    /// Risk class for the gated action, used by the dashboard to color the
    /// approval card's risk top bar. Derived from the matching
    /// `ServiceAction.risk` in the live registry: `Read → "low"`,
    /// `Write → "med"`, `Delete → "high"`. Defaults to `"med"` when the
    /// service / action lookup misses.
    risk: String,
    /// Caller↔requester relationship from the *viewing* identity's
    /// perspective: `"self"` when the viewer is the requester, `"downstream"`
    /// when the viewer is an ancestor, `"not_in_your_chain"` otherwise.
    /// Populated only when the request carried an identity-bound auth
    /// (`auth.identity_id = Some`); omitted on dashboard-session reads where
    /// the relationship lookup has no defined viewer. MCP clients use this
    /// to pre-pick `overslash_approve_self` vs `overslash_approve`.
    #[serde(skip_serializing_if = "Option::is_none")]
    relationship: Option<String>,
}

impl ApprovalResponse {
    fn from_row(
        r: overslash_db::repos::approval::ApprovalRow,
        identity_path: Option<String>,
        identity_path_ids: Vec<Uuid>,
        execution: Option<ExecutionRow>,
        registry: &ServiceRegistry,
    ) -> Self {
        let derived_keys = overslash_core::permissions::derive_keys(&r.permission_keys);
        let suggested_tiers = overslash_core::permissions::suggest_tiers(&r.permission_keys);
        let risk = derive_risk_class(registry, &derived_keys);
        let (action_detail, action_detail_truncated, action_detail_size_bytes) =
            render_action_detail(r.action_detail.as_ref());
        Self {
            id: r.id,
            identity_id: r.identity_id,
            requesting_identity_id: r.identity_id,
            current_resolver_identity_id: r.current_resolver_identity_id,
            identity_path,
            identity_path_ids,
            action_summary: r.action_summary,
            tags: r.tags,
            permission_keys: r.permission_keys,
            derived_keys,
            suggested_tiers,
            action_detail,
            action_detail_truncated,
            action_detail_size_bytes,
            disclosed_fields: r.disclosed_fields,
            status: r.status,
            token: r.token,
            expires_at: fmt_time(r.expires_at),
            created_at: fmt_time(r.created_at),
            execution: execution.map(ExecutionSummary::from_row),
            cascaded_approval_ids: Vec::new(),
            risk,
            relationship: None,
        }
    }

    /// Decorate the response with the caller↔requester relationship from
    /// the given viewer's perspective. No-op when `viewer` is `None`
    /// (dashboard session reads), so the field is simply omitted.
    async fn decorate_relationship(
        &mut self,
        scope: &OrgScope,
        viewer: Option<Uuid>,
    ) -> Result<()> {
        let Some(viewer) = viewer else {
            return Ok(());
        };
        let rel = crate::services::permission_chain::classify_approval_relationship(
            scope,
            viewer,
            self.requesting_identity_id,
        )
        .await?;
        self.relationship = Some(rel.as_str().to_string());
        Ok(())
    }
}

async fn build_response(
    scope: &OrgScope,
    registry: &ServiceRegistry,
    row: overslash_db::repos::approval::ApprovalRow,
    viewer: Option<Uuid>,
) -> Result<ApprovalResponse> {
    let (identity_path, identity_path_ids) =
        crate::services::identity_path::build_for_identity(scope, row.identity_id)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!("failed to build identity_path for approval {}: {e}", row.id);
                None
            })
            .map(|(p, ids)| (Some(p), ids))
            .unwrap_or((None, Vec::new()));
    let execution = scope.get_execution_by_approval(row.id).await?;
    let mut resp =
        ApprovalResponse::from_row(row, identity_path, identity_path_ids, execution, registry);
    resp.decorate_relationship(scope, viewer).await?;
    Ok(resp)
}

/// Spawn the background auto-call-on-approve task for `approval`: atomically
/// claim its pending execution with `triggered_by="auto"` and run it to
/// terminal state. Losing the claim is fine — it means a manual `/call` beat
/// us to it. Shared between the `/resolve` path and cascade resolution.
///
/// Deliberately a plain fn (not `async`) that boxes the
/// `execute_claimed_approval` future as `dyn Future`: cascade resolution makes
/// `execute_claimed_approval` reach itself through this helper, and the type
/// erasure is what stops the compiler from chasing an infinitely recursive
/// opaque future type.
fn spawn_auto_call(
    state: AppState,
    ext: axum::http::Extensions,
    approval: overslash_db::repos::approval::ApprovalRow,
    ip: Option<String>,
    audit_org_id: Uuid,
    audit_identity_id: Option<Uuid>,
) {
    tokio::spawn(async move {
        let scope = OrgScope::new(approval.org_id, state.db_pool(&ext));
        let claim = match scope.claim_execution(approval.id, "auto").await {
            Ok(Some(row)) => row,
            Ok(None) => return,
            Err(e) => {
                tracing::warn!(
                    approval_id = %approval.id,
                    "auto-call claim failed: {e}"
                );
                return;
            }
        };
        let fut: std::pin::Pin<Box<dyn std::future::Future<Output = Result<_>> + Send>> =
            Box::pin(execute_claimed_approval(
                &state,
                &ext,
                &scope,
                &approval,
                claim,
                "auto",
                ip.as_deref(),
                audit_org_id,
                audit_identity_id,
            ));
        if let Err(e) = fut.await {
            tracing::warn!(
                approval_id = %approval.id,
                "auto-call execute failed: {e}"
            );
        }
    });
}

/// Map a "claim / cancel returned None" to a specific user-facing error.
/// Inspects the current execution row to disambiguate between already-running,
/// already-terminal, or expired.
fn execution_conflict_error(current: Option<ExecutionRow>) -> AppError {
    match current {
        None => AppError::Conflict("no pending execution for this approval".into()),
        Some(row) => match row.status.as_str() {
            "pending" => {
                // The row is still pending but the guard failed — either the
                // expiry has passed or it was claimed concurrently.
                if row.expires_at <= time::OffsetDateTime::now_utc() {
                    AppError::Gone("pending execution has expired".into())
                } else {
                    AppError::Conflict("execution is being processed concurrently".into())
                }
            }
            "executing" => AppError::Conflict("execution is already in progress".into()),
            // Terminal-with-output states name the recovery path. Under the
            // `auto_call_on_approve` default the agent's own /call loses this
            // race routinely, and the output it wanted is already sitting in
            // GET /v1/approvals/{id}/execution.
            "executed" => AppError::Conflict(
                "execution has already completed — fetch the output from \
                 GET /v1/approvals/{id}/execution (MCP: the overslash `get_result` \
                 action; CLI: `overslash get-result <approval_id>`)"
                    .into(),
            ),
            "failed" => AppError::Conflict(
                "execution already attempted and failed — fetch the error from \
                 GET /v1/approvals/{id}/execution (MCP: the overslash `get_result` \
                 action; CLI: `overslash get-result <approval_id>`)"
                    .into(),
            ),
            "cancelled" => AppError::Conflict("execution was cancelled".into()),
            "expired" => AppError::Gone("pending execution has expired".into()),
            other => AppError::Conflict(format!("execution in unexpected state: {other}")),
        },
    }
}
