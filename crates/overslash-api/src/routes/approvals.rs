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

/// Probe a stored execution `result` JSONB for the runtime tag. MCP envelopes
/// carry `{ "runtime": "mcp", ... }` from `mcp_caller`; HTTP envelopes don't
/// declare a runtime field, so we fall back to a `status_code` presence
/// check. Anything else (truncation sentinels, unknown shapes) returns None.
fn extract_runtime(v: &serde_json::Value) -> Option<String> {
    if let Some(rt) = v.get("runtime").and_then(|x| x.as_str()) {
        return Some(rt.to_string());
    }
    if v.get("status_code").is_some() {
        return Some("http".to_string());
    }
    None
}

fn extract_http_status_code(v: &serde_json::Value) -> Option<u16> {
    v.get("status_code")
        .and_then(|x| x.as_u64())
        .and_then(|n| u16::try_from(n).ok())
}

/// Truncate a JSON value's string representation to at most
/// `MAX_EXECUTION_RESULT_BYTES`. If the full serialization is under the cap we
/// return the value as-is; over the cap we swap in a compact sentinel so the
/// dashboard can render a "truncated" banner without parsing a gigantic body.
fn truncate_json_value(v: serde_json::Value) -> serde_json::Value {
    match serde_json::to_string(&v) {
        Ok(s) if s.len() > MAX_EXECUTION_RESULT_BYTES => serde_json::json!({
            "truncated": true,
            "size_bytes": s.len(),
            "limit_bytes": MAX_EXECUTION_RESULT_BYTES,
        }),
        _ => v,
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

/// Derive the dashboard-facing risk class (`"low" | "med" | "high"`) for an
/// approval by looking up the first derived key in the live service registry.
/// Misses fall back to `"med"` — a deliberately cautious default so the UI
/// errs on the side of "review carefully" rather than "low risk" when the
/// service template has been removed or renamed since the approval row was
/// written.
fn derive_risk_class(registry: &ServiceRegistry, derived_keys: &[DerivedKey]) -> String {
    let Some(first) = derived_keys.first() else {
        return "med".to_string();
    };
    let risk = registry
        .get(&first.service)
        .and_then(|svc| svc.actions.get(&first.action))
        .map(|action| action.risk);
    risk_class(risk)
}

/// Map an action's risk level to the dashboard-facing class string
/// (`"low" | "med" | "high"`). `None` → `"med"`, the same cautious default
/// `derive_risk_class` falls back to. Shared so the inline `pending_approval`
/// envelope (built in `routes::actions`) and the `GET /v1/approvals/{id}` read
/// path produce identical risk strings for the same action.
pub(crate) fn risk_class(risk: Option<Risk>) -> String {
    match risk {
        Some(Risk::Read) => "low",
        Some(Risk::Write) => "med",
        Some(Risk::Delete) => "high",
        None => "med",
    }
    .to_string()
}

/// Pretty-print a stored `action_detail` JSONB blob for the wire, truncating
/// at `MAX_ACTION_DETAIL_BYTES` on a UTF-8 boundary. Returns
/// `(rendered, truncated, full_size_bytes)` — `(None, false, 0)` when there
/// is no detail. Shared between `ApprovalResponse::from_row` and the inline
/// `pending_approval` envelope so the two can't drift on truncation rules.
pub(crate) fn render_action_detail(
    detail: Option<&serde_json::Value>,
) -> (Option<String>, bool, usize) {
    match detail.and_then(|v| serde_json::to_string_pretty(v).ok()) {
        Some(full) => {
            let size = full.len();
            if size > MAX_ACTION_DETAIL_BYTES {
                let trimmed = truncate_utf8(&full, MAX_ACTION_DETAIL_BYTES).to_string();
                (Some(trimmed), true, size)
            } else {
                (Some(full), false, size)
            }
        }
        None => (None, false, 0),
    }
}

/// Truncate a UTF-8 string to at most `max` bytes, walking backward from the
/// boundary so multibyte characters are never split.
fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut idx = max;
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    &s[..idx]
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

#[derive(Deserialize)]
struct ListQuery {
    /// Optional visibility filter (SPEC §5 — Visibility Scoping):
    ///   * `mine` — approvals the caller has requested
    ///     (`identity_id = caller`).
    ///   * `assigned` — approvals where the caller is the current resolver
    ///     right now (`current_resolver_identity_id = caller`). Strict
    ///     "inbox" view; does NOT include approvals sitting on descendants.
    ///   * `actionable` — approvals the caller could act on: caller is the
    ///     current resolver, or any descendant of theirs is. Excludes
    ///     approvals the caller requested themselves.
    ///
    /// Unset preserves the legacy org-wide listing.
    scope: Option<String>,
    /// Optional: list pending approvals for a specific identity (used by the
    /// identity hierarchy view). Caller must own the identity's org.
    identity_id: Option<Uuid>,
    /// Optional: filter results to a specific approval status
    /// (pending | allowed | denied | expired).
    status: Option<String>,
}

async fn list_approvals(
    State(state): State<AppState>,
    auth: AuthContext,
    scope: OrgScope,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<ApprovalResponse>>> {
    // ?identity_id= is the identity-hierarchy detail panel filter: list
    // pending approvals **requested by** that identity. Cross-tenant ids
    // return NotFound at the scope boundary.
    if let Some(identity_id) = q.identity_id {
        scope
            .get_identity(identity_id)
            .await?
            .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
        let rows = scope.list_mine_approvals(identity_id).await?;
        return Ok(Json(
            batch_responses(&scope, &state.registry, rows, auth.identity_id).await?,
        ));
    }
    let rows = match q.scope.as_deref() {
        Some("mine") => {
            let identity_id = auth.identity_id.ok_or_else(|| {
                AppError::BadRequest("scope=mine requires an identity-bound api key".into())
            })?;
            if let Some(ref status) = q.status {
                let rows = scope
                    .list_mine_approvals_by_status(identity_id, status)
                    .await?;
                return Ok(Json(
                    batch_responses(&scope, &state.registry, rows, auth.identity_id).await?,
                ));
            }
            scope.list_mine_approvals(identity_id).await?
        }
        Some("assigned") => {
            let identity_id = auth.identity_id.ok_or_else(|| {
                AppError::BadRequest("scope=assigned requires an identity-bound api key".into())
            })?;
            scope.list_assigned_approvals(identity_id).await?
        }
        Some("actionable") => {
            let identity_id = auth.identity_id.ok_or_else(|| {
                AppError::BadRequest("scope=actionable requires an identity-bound api key".into())
            })?;
            scope.list_actionable_approvals(identity_id).await?
        }
        Some(other) => {
            return Err(AppError::BadRequest(format!(
                "invalid scope '{other}': expected 'mine', 'assigned', or 'actionable'"
            )));
        }
        None => scope.list_pending_approvals().await?,
    };
    let mut rows = rows;
    if let Some(ref s) = q.status {
        rows.retain(|r| r.status == *s);
    }
    Ok(Json(
        batch_responses(&scope, &state.registry, rows, auth.identity_id).await?,
    ))
}

/// Assemble `ApprovalResponse`s for a list of approvals, batching the
/// execution lookup with a single `WHERE approval_id = ANY(...)` to avoid
/// the N+1 a per-row `build_response` would produce on that path. When
/// `viewer` is `Some`, each response is also decorated with the
/// caller↔requester relationship — that decoration walks the requester's
/// ancestor chain per row (still one query each, the existing recursive
/// CTE), so the function is no longer fully batch-shaped on identity-bound
/// callers. Worth revisiting if approval lists grow long enough to feel it
/// in latency; for now it's a single recursive CTE per row, not the wider
/// N+1 the execution batching avoids.
async fn batch_responses(
    scope: &OrgScope,
    registry: &ServiceRegistry,
    rows: Vec<overslash_db::repos::approval::ApprovalRow>,
    viewer: Option<Uuid>,
) -> Result<Vec<ApprovalResponse>> {
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let approval_ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let executions = scope.list_executions_by_approvals(&approval_ids).await?;
    let mut exec_map: std::collections::HashMap<Uuid, ExecutionRow> =
        executions.into_iter().map(|e| (e.approval_id, e)).collect();
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let (identity_path, identity_path_ids) =
            crate::services::identity_path::build_for_identity(scope, row.identity_id)
                .await
                .unwrap_or_else(|e| {
                    tracing::warn!("failed to build identity_path for approval {}: {e}", row.id);
                    None
                })
                .map(|(p, ids)| (Some(p), ids))
                .unwrap_or((None, Vec::new()));
        let execution = exec_map.remove(&row.id);
        let mut resp =
            ApprovalResponse::from_row(row, identity_path, identity_path_ids, execution, registry);
        resp.decorate_relationship(scope, viewer).await?;
        out.push(resp);
    }
    Ok(out)
}

async fn get_approval(
    State(state): State<AppState>,
    auth: AuthContext,
    scope: OrgScope,
    Path(id): Path<Uuid>,
) -> Result<Json<ApprovalResponse>> {
    let row = scope
        .get_approval(id)
        .await?
        .ok_or_else(|| AppError::NotFound("approval not found".into()))?;
    Ok(Json(
        build_response(&scope, &state.registry, row, auth.identity_id).await?,
    ))
}

async fn get_execution(
    State(_state): State<AppState>,
    auth: AuthContext,
    scope: OrgScope,
    Path(id): Path<Uuid>,
) -> Result<Json<ExecutionSummary>> {
    // Require the approval exists in this org (4xx-not-leaky).
    let approval = scope
        .get_approval(id)
        .await?
        .ok_or_else(|| AppError::NotFound("approval not found".into()))?;
    let exec = scope
        .get_execution_by_approval(id)
        .await?
        .ok_or_else(|| AppError::NotFound("no execution for this approval".into()))?;

    // Mark-as-read: only the *requesting* agent's first read flips
    // `result_viewed_at`. Dashboard reads (admin/resolver) leave the row
    // unread so the operator's view doesn't accidentally clear the
    // "agent hasn't pulled this yet" surface from the pending-calls list.
    let exec = if auth.identity_id == Some(approval.identity_id) {
        match scope.mark_execution_viewed(exec.id).await {
            Ok(true) => scope.get_execution_by_approval(id).await?.unwrap_or(exec),
            _ => exec,
        }
    } else {
        exec
    };

    Ok(Json(ExecutionSummary::from_row(exec)))
}

#[derive(Deserialize)]
struct ResolveRequest {
    resolution: String, // "allow", "deny", "allow_remember", "bubble_up"
    remember_keys: Option<Vec<String>>,
    ttl: Option<String>,
}

#[allow(clippy::too_many_arguments)]
async fn resolve_approval(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth_ctx: AuthContext,
    WriteAcl(acl): WriteAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<ResolveRequest>,
) -> Result<Json<ApprovalResponse>> {
    let auth = acl;
    // `auth` (`OrgAcl`) carries org/identity/access_level; `auth_ctx`
    // (`AuthContext`) carries the raw API-key context including
    // `mcp_client_id` — required to look up the binding on a self-approval.

    // Load the approval through the org-scoped lookup. A foreign id returns
    // None at the SQL boundary — 404 (not 403) avoids leaking existence.
    let approval_pre = scope
        .get_approval(id)
        .await?
        .ok_or_else(|| AppError::NotFound("approval not found".into()))?;

    // ── Authorize the caller via the caller↔requester classifier. The split
    // between `overslash_approve_self` and `overslash_approve` MCP
    // tools is purely UX (per-tool Claude Code permission rules); the actual
    // security boundary is here. See docs/design/agent-self-management.md §2.
    use crate::services::permission_chain::{ApprovalRelationship, classify_approval_relationship};
    use overslash_core::permissions::AccessLevel;
    let mut relationship: Option<ApprovalRelationship> = None;
    let mut self_approve_binding_id: Option<Uuid> = None;
    if let Some(caller_identity) = auth.identity_id {
        let rel = classify_approval_relationship(&scope, caller_identity, approval_pre.identity_id)
            .await?;
        match rel {
            ApprovalRelationship::SelfApproval => {
                // A trusted human at the keyboard authorizes self-approval by
                // flipping `self_approve_enabled` on their MCP binding. Pure
                // REST callers (no `mcp_client_id`) have no binding to consult
                // and are rejected.
                let client_id =
                    auth_ctx
                        .mcp_client_id
                        .as_deref()
                        .ok_or_else(|| AppError::NotInYourChain {
                            identity_id: caller_identity,
                            action: "approvals.resolve".into(),
                            reason: "self_approval_disabled".into(),
                        })?;
                let binding =
                    overslash_db::repos::mcp_client_agent_binding::get_for_agent_and_client(
                        state.db(&ext),
                        caller_identity,
                        client_id,
                    )
                    .await
                    .map_err(|e| AppError::Internal(format!("binding lookup failed: {e}")))?;
                let binding = binding.ok_or_else(|| AppError::NotInYourChain {
                    identity_id: caller_identity,
                    action: "approvals.resolve".into(),
                    reason: "self_approval_disabled".into(),
                })?;
                if !binding.self_approve_enabled {
                    return Err(AppError::NotInYourChain {
                        identity_id: caller_identity,
                        action: "approvals.resolve".into(),
                        reason: "self_approval_disabled".into(),
                    });
                }
                self_approve_binding_id = Some(binding.id);
            }
            ApprovalRelationship::Downstream => {
                // Existing ladder: a Downstream caller still has to be in the
                // resolver's ancestor chain (so a great-grandparent can't leap
                // over a delegated mid-chain reviewer). Admins keep the
                // existing bypass on this check.
                if auth.access_level < AccessLevel::Admin {
                    let allowed = crate::services::permission_chain::is_self_or_ancestor(
                        &scope,
                        caller_identity,
                        approval_pre.current_resolver_identity_id,
                    )
                    .await?;
                    if !allowed {
                        return Err(AppError::Forbidden(
                            "caller is not authorized to resolve this approval".into(),
                        ));
                    }
                }
            }
            ApprovalRelationship::NotInYourChain => {
                // Org admins can resolve any approval in their org regardless
                // of chain membership — preserves the historical "admin can
                // step in for any user" behavior the dashboard relies on.
                // Non-admins get the typed envelope. SelfApproval above is
                // intentionally NOT covered by this bypass: self-approval
                // requires a trusted human at the keyboard (binding flag),
                // not just elevated org permissions.
                if auth.access_level < AccessLevel::Admin {
                    return Err(AppError::NotInYourChain {
                        identity_id: caller_identity,
                        action: "approvals.resolve".into(),
                        reason: "caller is not in the requester's identity chain".into(),
                    });
                }
            }
        }
        relationship = Some(rel);
    }

    // ── BubbleUp: advance the resolver instead of resolving.
    if req.resolution == "bubble_up" {
        let perm_keys: Vec<PermissionKey> = approval_pre
            .permission_keys
            .iter()
            .map(|k| PermissionKey(k.clone()))
            .collect();
        let next = crate::services::permission_chain::find_next_resolver(
            &scope,
            approval_pre.identity_id,
            approval_pre.current_resolver_identity_id,
            &perm_keys,
        )
        .await?;
        if next == approval_pre.current_resolver_identity_id {
            return Err(AppError::Conflict(
                "approval is already at the final resolver".into(),
            ));
        }
        let updated = scope
            .update_approval_resolver(id, next, approval_pre.current_resolver_identity_id)
            .await?
            .ok_or_else(|| {
                AppError::Conflict(
                    "approval was concurrently resolved or bubbled by another caller".into(),
                )
            })?;

        let _ = scope
            .log_audit(AuditEntry {
                org_id: auth.org_id,
                identity_id: auth.identity_id,
                action: "approval.bubbled",
                resource_type: Some("approval"),
                resource_id: Some(id),
                detail: serde_json::json!({
                    "from": approval_pre.current_resolver_identity_id,
                    "to": next,
                }),
                description: None,
                ip_address: ip.0.as_deref(),
            })
            .await;

        return Ok(Json(
            build_response(&scope, &state.registry, updated, auth.identity_id).await?,
        ));
    }

    let (status, remember) = match req.resolution.as_str() {
        "allow" => ("allowed", false),
        "deny" => ("denied", false),
        "allow_remember" => ("allowed", true),
        other => return Err(AppError::BadRequest(format!("invalid resolution: {other}"))),
    };

    // ── Validate + normalise remember_keys / ttl (actual rule creation moves
    // to /call on success).
    let mut parsed_expires_at: Option<time::OffsetDateTime> = None;
    let mut remember_keys_to_store: Option<Vec<String>> = None;
    if remember {
        if let Some(t) = req.ttl.as_deref() {
            let dur = overslash_core::types::duration::parse_ttl(t)
                .ok_or_else(|| AppError::BadRequest(format!("invalid ttl: {t}")))?;
            if dur.as_secs() > 365 * 86400 {
                return Err(AppError::BadRequest("ttl must not exceed 365 days".into()));
            }
            let secs: i64 = dur
                .as_secs()
                .try_into()
                .map_err(|_| AppError::BadRequest("ttl value too large".into()))?;
            parsed_expires_at =
                time::OffsetDateTime::now_utc().checked_add(time::Duration::new(secs, 0));
        }
        let approval = &approval_pre;

        let effective_keys: Vec<String> = if let Some(ref keys) = req.remember_keys {
            if keys.is_empty() {
                return Err(AppError::BadRequest(
                    "remember_keys must not be empty".into(),
                ));
            }

            let tiers = overslash_core::permissions::suggest_tiers(&approval.permission_keys);
            let allowed_keys: std::collections::HashSet<&str> = tiers
                .iter()
                .flat_map(|t| t.keys.iter().map(|k| k.as_str()))
                .collect();

            for key in keys {
                if !allowed_keys.contains(key.as_str()) {
                    return Err(AppError::BadRequest(format!(
                        "remember_key '{key}' is not in any suggested tier"
                    )));
                }
            }

            keys.clone()
        } else {
            approval.permission_keys.clone()
        };

        // Validate keys don't exceed group ceiling (applies to both explicit and fallback keys)
        let ceiling_user_id =
            crate::services::group_ceiling::resolve_ceiling_user_id(&scope, approval.identity_id)
                .await?;

        let ceiling = crate::services::group_ceiling::load_ceiling(&scope, ceiling_user_id).await?;

        if ceiling.has_groups {
            for key in &effective_keys {
                let dk = parse_derived_key(key);
                let result = crate::services::group_ceiling::check_ceiling(
                    &ceiling,
                    &dk.service,
                    Risk::Read,
                );
                if let GroupCeilingResult::ExceedsCeiling(reason) = result {
                    return Err(AppError::BadRequest(format!(
                        "key '{key}' exceeds group ceiling: {reason}"
                    )));
                }
            }
        }

        remember_keys_to_store = Some(effective_keys);
    }

    let row = scope
        .resolve_approval(
            id,
            status,
            "user",
            remember,
            approval_pre.current_resolver_identity_id,
        )
        .await?
        .ok_or_else(|| {
            AppError::Conflict(
                "approval was concurrently resolved or bubbled by another caller".into(),
            )
        })?;

    // The approval row is now in its terminal status — record the resolution
    // metric *before* creating the pending execution so a downstream failure
    // there can't drop the resolution counter (the DB row is the source of
    // truth either way).
    let event_label = match row.status.as_str() {
        "allowed" => "approved",
        "denied" => "denied",
        other => other,
    };
    overslash_metrics::approvals::record_event(event_label, "user");
    let age = overslash_metrics::approvals::duration_since(
        time::OffsetDateTime::now_utc() - row.created_at,
    );
    overslash_metrics::approvals::record_resolution(event_label, age);

    // On allow/allow_remember, create the pending execution row. The actual
    // replay is triggered either by an explicit `POST /v1/approvals/{id}/call`
    // (manual path), or — when the requesting agent's identity has
    // `auto_call_on_approve` set (default: true) — by a background task
    // spawned right after this `/resolve` returns. The two paths share the
    // same atomic claim guard, so a manual click landing during an in-flight
    // auto-call cleanly loses with a `409`.
    let execution = if status == "allowed" {
        let ttl_secs = state.config.execution_pending_ttl_secs as i64;
        let expires_at = time::OffsetDateTime::now_utc() + time::Duration::seconds(ttl_secs);
        let row = scope
            .create_pending_execution(
                id,
                remember,
                remember_keys_to_store.as_deref(),
                parsed_expires_at,
                expires_at,
            )
            .await?;

        // Auto-call lookup: read the per-agent toggle off the requesting
        // agent's identity row. Lookup errors are non-fatal — they degrade
        // to manual-only by leaving auto-call disabled. The pre-migration
        // path keyed this on `mcp_client_agent_bindings.auto_call_on_approve`,
        // which excluded plain REST and white-label agents; moving it onto
        // the identity makes the toggle universal across surfaces.
        let auto_call_enabled = match overslash_db::repos::identity::get_by_id(
            state.db(&ext),
            approval_pre.org_id,
            approval_pre.identity_id,
        )
        .await
        {
            Ok(Some(i)) => i.auto_call_on_approve,
            Ok(None) => {
                tracing::warn!(
                    approval_id = %id,
                    "auto-call identity lookup returned no row"
                );
                false
            }
            Err(e) => {
                tracing::warn!(
                    approval_id = %id,
                    "auto-call identity lookup failed: {e}"
                );
                false
            }
        };
        // Suppress auto-call when an elicitation flow is mid-flight for this
        // approval. The elicitation receiver drives its own /resolve → /call
        // round-trip; an auto-call would race with that and force one side
        // into a 409. Non-MCP agents have no elicitation rows, so this check
        // is naturally a no-op for them.
        let elicitation_active =
            match overslash_db::repos::mcp_elicitation::has_active_for_approval(
                state.db(&ext),
                approval_pre.id,
            )
            .await
            {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(
                        approval_id = %id,
                        "auto-call elicitation lookup failed: {e}"
                    );
                    false
                }
            };

        if !elicitation_active && auto_call_enabled {
            spawn_auto_call(
                state.clone(),
                ext.clone(),
                approval_pre.clone(),
                ip.0.clone(),
                auth.org_id,
                auth.identity_id,
            );
        }

        Some(row)
    } else {
        None
    };

    // Audit detail tags the relationship every time so reviewers can filter
    // self-approvals out of "boring" downstream approvals at a glance. For
    // self-approvals we additionally record the MCP client + binding that
    // authorized it — that's the whole audit trail for "who let this
    // happen?".
    let mut audit_detail = serde_json::json!({
        "resolution": &req.resolution,
        "status": &row.status,
        "action_summary": &row.action_summary,
        "execution_id": execution.as_ref().map(|e| e.id),
        "relationship": relationship.map(|r| r.as_str()),
    });
    // Record who actually resolved it, separate from the approval's subject
    // (`identity_id` below). The audit read path enriches this into a
    // name/kind/path so the dashboard can render the approver distinctly.
    if let Some(resolver) = auth.identity_id {
        if let Some(obj) = audit_detail.as_object_mut() {
            obj.insert(
                "resolved_by_identity_id".into(),
                serde_json::json!(resolver),
            );
        }
    }
    if let ApprovalRelationship::SelfApproval =
        relationship.unwrap_or(ApprovalRelationship::NotInYourChain)
    {
        if let Some(obj) = audit_detail.as_object_mut() {
            obj.insert(
                "mcp_client_id".into(),
                serde_json::Value::String(auth_ctx.mcp_client_id.clone().unwrap_or_default()),
            );
            if let Some(b) = self_approve_binding_id {
                obj.insert("binding_id".into(), serde_json::json!(b));
            }
        }
    }
    let _ = scope
        .log_audit(AuditEntry {
            org_id: auth.org_id,
            // The event is *about* the approval's subject (the agent whose
            // action was pending), not the resolver — so it carries the
            // subject's user→agent path even when a user resolved it. The
            // resolver is in `detail.resolved_by_identity_id`.
            identity_id: Some(approval_pre.identity_id),
            action: "approval.resolved",
            resource_type: Some("approval"),
            resource_id: Some(id),
            detail: audit_detail,
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    // Dispatch webhook (fire-and-forget)
    {
        let db = state.db_pool(&ext);
        let client = state.http_client.clone();
        let org_id = auth.org_id;
        let approval_id = row.id;
        let summary = row.action_summary.clone();
        let final_status = row.status.clone();
        let exec_for_webhook = execution.as_ref().map(|e| {
            serde_json::json!({
                "id": e.id,
                "status": e.status,
                "expires_at": fmt_time(e.expires_at),
            })
        });
        tokio::spawn(async move {
            let mut payload = serde_json::json!({
                "approval_id": approval_id,
                "status": final_status,
                "action_summary": summary,
            });
            if let Some(exec) = exec_for_webhook {
                payload
                    .as_object_mut()
                    .expect("payload is a json object")
                    .insert("execution".into(), exec);
            }
            crate::services::webhook_dispatcher::dispatch(
                &db,
                &client,
                org_id,
                "approval.resolved",
                payload,
            )
            .await;
        });
    }

    let (identity_path, identity_path_ids) =
        crate::services::identity_path::build_for_identity(&scope, row.identity_id)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!("failed to build identity_path for approval {}: {e}", row.id);
                None
            })
            .map(|(p, ids)| (Some(p), ids))
            .unwrap_or((None, Vec::new()));
    let mut resp = ApprovalResponse::from_row(
        row,
        identity_path,
        identity_path_ids,
        execution,
        &state.registry,
    );
    resp.decorate_relationship(&scope, auth.identity_id).await?;
    Ok(Json(resp))
}

async fn call_approval(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: OrgAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<ApprovalResponse>> {
    let approval = scope
        .get_approval(id)
        .await?
        .ok_or_else(|| AppError::NotFound("approval not found".into()))?;

    if approval.status != "allowed" {
        return Err(AppError::Conflict(format!(
            "approval is not in 'allowed' state (status={})",
            approval.status
        )));
    }

    // Auth: the requesting agent may call directly (even without write
    // ACL). Otherwise we require the same resolver-auth as /resolve — write
    // ACL + must be the current resolver or an ancestor, and never the
    // requester (caught by the is_self check above).
    use overslash_core::permissions::AccessLevel;
    let caller_identity = auth
        .identity_id
        .ok_or_else(|| AppError::Forbidden("identity-bound credential required".into()))?;
    let triggered_by = if caller_identity == approval.identity_id {
        "agent"
    } else {
        if auth.access_level < AccessLevel::Write {
            return Err(AppError::Forbidden("write access required".into()));
        }
        if auth.access_level < AccessLevel::Admin {
            let allowed = crate::services::permission_chain::is_self_or_ancestor(
                &scope,
                caller_identity,
                approval.current_resolver_identity_id,
            )
            .await?;
            if !allowed {
                return Err(AppError::Forbidden(
                    "caller is not authorized to call this approval".into(),
                ));
            }
        }
        "user"
    };

    // ── Atomic claim: pending → executing. A `None` return means the row
    // isn't available (already executing/terminal) or has expired — we probe
    // the current state to produce a specific error. Validation lives
    // AFTER the claim to avoid TOCTOU with a concurrent claimer; on any
    // validation failure we finalize the row to `failed` so it never strands
    // in `executing`.
    let claimed = scope.claim_execution(id, triggered_by).await?;
    let Some(claimed) = claimed else {
        let current = scope.get_execution_by_approval(id).await?;
        return Err(execution_conflict_error(current));
    };

    let (finalised, _succeeded, cascaded_approval_ids) = execute_claimed_approval(
        &state,
        &ext,
        &scope,
        &approval,
        claimed,
        triggered_by,
        ip.0.as_deref(),
        auth.org_id,
        auth.identity_id,
    )
    .await?;

    let (identity_path, identity_path_ids) =
        crate::services::identity_path::build_for_identity(&scope, approval.identity_id)
            .await
            .unwrap_or(None)
            .map(|(p, ids)| (Some(p), ids))
            .unwrap_or((None, Vec::new()));
    let mut response = ApprovalResponse::from_row(
        approval,
        identity_path,
        identity_path_ids,
        Some(finalised),
        &state.registry,
    );
    response.cascaded_approval_ids = cascaded_approval_ids;
    response
        .decorate_relationship(&scope, auth.identity_id)
        .await?;
    Ok(Json(response))
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

/// Recover a registry-bounded `template_key` for replay metrics from the
/// approval's permission keys. Keys derive as `{service}:{action}:{arg}` or
/// `{service}:{METHOD}:{path}` (SPEC §8), so the prefix before the first
/// `:` is the service key. Anything that doesn't resolve to a registry
/// entry collapses to `"_unknown"` — same cardinality bound the inline
/// path applies via `bounded_template_key`.
fn replay_template_key(registry: &ServiceRegistry, permission_keys: &[String]) -> String {
    let service = permission_keys
        .first()
        .and_then(|k| k.split(':').next())
        .filter(|s| !s.is_empty());
    match service {
        Some(s) if registry.get(s).is_some() => s.to_string(),
        _ => "_unknown".to_string(),
    }
}

/// Run a *claimed* execution to terminal state. Shared between the manual
/// `POST /v1/approvals/{id}/call` path and the auto-call-on-approve
/// background task spawned by `resolve_approval`. The caller is responsible
/// for the atomic `pending → executing` claim before invoking this; on
/// return the row is `executed` / `failed` and any "Allow & Remember" rule
/// has been written + cascaded.
///
/// `triggered_by` is `"agent" | "user" | "auto"` and is recorded both on the
/// execution row (already stamped at claim time by the caller) and in the
/// audit / webhook trail this function emits.
#[allow(clippy::too_many_arguments)]
async fn execute_claimed_approval(
    state: &AppState,
    ext: &axum::http::Extensions,
    scope: &OrgScope,
    approval: &overslash_db::repos::approval::ApprovalRow,
    claimed: ExecutionRow,
    triggered_by: &'static str,
    ip: Option<&str>,
    audit_org_id: Uuid,
    audit_identity_id: Option<Uuid>,
) -> Result<(ExecutionRow, bool, Vec<Uuid>)> {
    let id = approval.id;
    let execution_id = claimed.id;
    overslash_metrics::approvals::record_event("called", triggered_by);

    // Validator: if any step fails, finalize the row and surface the error.
    // We own the row (unique claim) so this is race-free.
    async fn fail_and_return<T>(
        scope: &OrgScope,
        execution_id: Uuid,
        msg: &str,
        err: AppError,
    ) -> Result<T> {
        let _ = scope.finalize_execution_failed(execution_id, msg).await;
        Err(err)
    }

    // Prefer the raw `replay_payload` column — it carries the full
    // ActionRequest (HTTP), full MCP call (url/auth/tool/arguments), or full
    // platform call (action/params), unaffected by x-overslash-redact which
    // only reshapes the UI-facing `action_detail`.
    //
    // The `action_detail` fallback is for legacy HTTP/platform rows
    // (pre-`replay_payload`). Legacy platform projections (`{ runtime,
    // action, params, service }`) are themselves valid `StoredPlatformCall`
    // shapes and parse cleanly via the fallback. Legacy MCP rows are not
    // replayable — only a UI-redacted projection was stored, missing the
    // url/auth needed to actually replay.
    let replay_value = match approval.replay_payload.clone() {
        Some(v) => v,
        None => match approval.action_detail.clone() {
            Some(detail) => {
                let runtime = detail.get("runtime").and_then(|v| v.as_str());
                if runtime == Some("mcp") || detail.get("tool").is_some() {
                    return fail_and_return(
                        scope,
                        execution_id,
                        "mcp_replay_not_supported_legacy",
                        AppError::Conflict(
                            "replay of MCP-runtime approvals created before this feature \
                             is not supported"
                                .into(),
                        ),
                    )
                    .await;
                }
                detail
            }
            None => {
                return fail_and_return(
                    scope,
                    execution_id,
                    "no_replay_payload",
                    AppError::Internal(
                        "approval has no stored replay payload — cannot replay".into(),
                    ),
                )
                .await;
            }
        },
    };
    let payload = match ReplayPayload::from_stored(&replay_value) {
        Ok(p) => p,
        Err(e) => {
            let msg = format!("replay payload parse error: {e}");
            return fail_and_return(
                scope,
                execution_id,
                &msg,
                AppError::Internal(format!(
                    "approval replay payload is not a valid HTTP/MCP/Platform request: {e}"
                )),
            )
            .await;
        }
    };

    let replay_timeout = std::time::Duration::from_secs(state.config.execution_replay_timeout_secs);

    // Replays count toward the same execution/upstream metrics inline calls
    // record (they were invisible there before). The original call shape
    // isn't stored, so `mode = "replay"`; the template key is recovered from
    // the approval's permission keys.
    let replay_tpl = replay_template_key(&state.registry, &approval.permission_keys);
    let replay_start = std::time::Instant::now();

    // Each branch produces (finalised, succeeded, upstream_errored,
    // result_summary) for the shared metrics + audit + webhook +
    // rule-creation tail below. `upstream_errored` is true when the upstream
    // responded but reported failure (HTTP 5xx, MCP in-band `is_error`) —
    // a success from the approval's perspective, an outage from the
    // operator's.
    let (finalised, succeeded, upstream_errored, result_summary) = match payload {
        ReplayPayload::Http(stored) => {
            // Replay payloads are credential-free: when the original call
            // carried an OAuth header, only the service/instance it resolved
            // from was stored. Re-resolve a fresh token against the
            // requester's identity now — the stored request never holds one,
            // and the original token could have expired while the approval
            // sat pending. Pre-fix rows have no `service_key` and replay
            // their baked-in headers as-is.
            let auth_header = match stored.service_key.as_deref() {
                Some(service_key) => {
                    match crate::routes::actions::resolve_replay_auth_header(
                        state,
                        ext,
                        scope,
                        approval.identity_id,
                        service_key,
                        stored.instance_id,
                    )
                    .await
                    {
                        Ok(h) => Some(h),
                        Err(e) => {
                            let msg = format!("replay auth re-resolution failed: {e}");
                            return fail_and_return(scope, execution_id, &msg, e).await;
                        }
                    }
                }
                None => None,
            };

            // ── Replay with timeout. Streaming is forced off — the reviewer's
            // connection isn't the original caller's.
            let call_ctx = CallContext {
                state,
                scope,
                identity_id: approval.identity_id, // requester identity for audit/rate-limit
                ip,
                description: Some(approval.action_summary.as_str()),
                service_key: None,
                action_key: None,
                filter: stored.filter.clone(),
                prefer_stream: false,
                audit_source: AuditSource::Replay {
                    approval_id: id,
                    execution_id,
                },
            };

            let outcome = tokio::time::timeout(
                replay_timeout,
                action_caller::call_action_request(call_ctx, &stored.action, auth_header.as_ref()),
            )
            .await;

            match outcome {
                Ok(Ok(CallOutcome::Buffered { result, .. })) => {
                    // Upstream actually responded — count it, same as the
                    // inline buffered path. Transport failures land in the
                    // Ok(Err(..)) arm below and record nothing here.
                    overslash_metrics::actions::record_upstream_response(
                        &replay_tpl,
                        "http",
                        overslash_metrics::actions::status_class(result.status_code),
                    );
                    let mut result_json = serde_json::to_value(&result)
                        .unwrap_or_else(|_| serde_json::json!({"note": "result not serializable"}));
                    if stored.prefer_stream {
                        if let Some(obj) = result_json.as_object_mut() {
                            obj.insert("streamed_originally".into(), serde_json::Value::Bool(true));
                        }
                    }
                    let summary = serde_json::json!({
                        "status_code": result.status_code,
                        "duration_ms": result.duration_ms,
                    });
                    let upstream_errored = result.status_code >= 500;
                    let finalised = scope
                        .finalize_execution_executed(execution_id, &result_json)
                        .await?
                        .unwrap_or(claimed);
                    (finalised, true, upstream_errored, Some(summary))
                }
                Ok(Ok(CallOutcome::Streamed(_))) => {
                    // Defensive: replay forces prefer_stream=false so this variant is
                    // unreachable in practice. Record as failed rather than silently
                    // dropping the response.
                    let msg = "replay unexpectedly produced a streaming response";
                    let finalised = scope
                        .finalize_execution_failed(execution_id, msg)
                        .await?
                        .unwrap_or(claimed);
                    (finalised, false, false, None)
                }
                Ok(Err(app_err)) => {
                    let msg = app_err.to_string();
                    let finalised = scope
                        .finalize_execution_failed(execution_id, &msg)
                        .await?
                        .unwrap_or(claimed);
                    (finalised, false, false, None)
                }
                Err(_elapsed) => {
                    let msg = "replay_timeout";
                    let finalised = scope
                        .finalize_execution_failed(execution_id, msg)
                        .await?
                        .unwrap_or(claimed);
                    (finalised, false, false, None)
                }
            }
        }
        ReplayPayload::Mcp(call) => {
            // MCP replays go through mcp_caller::invoke, which returns the
            // same ActionResult envelope a fresh MCP call produces — keeping
            // the dashboard's execution-result rendering identical to inline
            // calls. Tool-level errors (`is_error: true`) live inside the
            // envelope and still count as successful execution from the
            // approval's perspective: the agent's call ran, the policy
            // decision was honored. Rule creation should still happen.
            let outcome = tokio::time::timeout(
                replay_timeout,
                mcp_caller::invoke(
                    state,
                    scope,
                    &call.url,
                    &call.auth,
                    &call.tool,
                    &call.arguments,
                ),
            )
            .await;
            match outcome {
                Ok(Ok(result)) => {
                    let result_json = serde_json::to_value(&result)
                        .unwrap_or_else(|_| serde_json::json!({"note": "result not serializable"}));
                    // Mirror the inline MCP call's `action.executed` audit
                    // shape so reviewers see runtime/tool/arguments/is_error
                    // for replays too. The HTTP replay path emits its own
                    // `action.executed` from action_caller; we do the
                    // equivalent here. `build_audit_detail` is shared with
                    // the inline executor so the two paths can't drift.
                    let (is_error, mut audit_detail) = mcp_caller::build_audit_detail(
                        &result,
                        &call.tool,
                        &call.url,
                        &call.arguments,
                    );
                    // Same in-band mapping as the inline MCP branch:
                    // transport succeeded, the tool's is_error flag is the
                    // upstream status. Transport failures land in
                    // Ok(Err(..)) below and record nothing here.
                    overslash_metrics::actions::record_upstream_response(
                        &replay_tpl,
                        "mcp",
                        if is_error { "error" } else { "2xx" },
                    );
                    {
                        let obj = audit_detail
                            .as_object_mut()
                            .expect("audit_detail is a json object");
                        obj.insert("replayed_from_approval".into(), serde_json::json!(id));
                        obj.insert("execution_id".into(), serde_json::json!(execution_id));
                    }
                    let _ = scope
                        .log_audit(AuditEntry {
                            org_id: audit_org_id,
                            identity_id: Some(approval.identity_id),
                            action: "action.executed",
                            resource_type: Some("mcp"),
                            resource_id: None,
                            detail: audit_detail,
                            description: Some(approval.action_summary.as_str()),
                            ip_address: ip,
                        })
                        .await;
                    let summary = serde_json::json!({
                        "runtime": "mcp",
                        "tool": call.tool,
                        "duration_ms": result.duration_ms,
                    });
                    let finalised = scope
                        .finalize_execution_executed(execution_id, &result_json)
                        .await?
                        .unwrap_or(claimed);
                    (finalised, true, is_error, Some(summary))
                }
                Ok(Err(app_err)) => {
                    let msg = app_err.to_string();
                    let finalised = scope
                        .finalize_execution_failed(execution_id, &msg)
                        .await?
                        .unwrap_or(claimed);
                    (finalised, false, false, None)
                }
                Err(_elapsed) => {
                    let finalised = scope
                        .finalize_execution_failed(execution_id, "replay_timeout")
                        .await?
                        .unwrap_or(claimed);
                    (finalised, false, false, None)
                }
            }
        }
        ReplayPayload::Platform(call) => {
            // Platform replays re-dispatch via the shared
            // `platform_caller::invoke` helper, mirroring the direct
            // `/v1/actions/call` happy path. The requester's ceiling user
            // (and thus their access level) is recomputed against current
            // state — if they've been demoted between approval-creation and
            // replay, the new ceiling applies.
            //
            // Ceiling-resolution failure (e.g. archived identity) falls
            // through with `(finalised, false, None)` like the other error
            // paths so the shared audit/webhook tail still emits
            // `approval.execution_failed`.
            let ceiling_outcome =
                group_ceiling::resolve_ceiling_user_id(scope, approval.identity_id).await;
            let outcome = match ceiling_outcome {
                Ok(ceiling_user_id) => {
                    let params: std::collections::HashMap<String, serde_json::Value> =
                        call.params.clone().into_iter().collect();
                    tokio::time::timeout(
                        replay_timeout,
                        platform_caller::invoke(
                            state,
                            ext,
                            scope,
                            approval.identity_id,
                            ceiling_user_id,
                            &call.action,
                            params,
                        ),
                    )
                    .await
                }
                Err(e) => Ok(Err(e)),
            };
            match outcome {
                Ok(Ok(value)) => {
                    let result = overslash_core::types::ActionResult {
                        status_code: 200,
                        body: serde_json::to_string(&value).unwrap_or_default(),
                        headers: std::collections::HashMap::new(),
                        duration_ms: 0,
                        filtered_body: None,
                    };
                    let mut result_json = serde_json::to_value(&result)
                        .unwrap_or_else(|_| serde_json::json!({"note": "result not serializable"}));
                    // Stamp a top-level `runtime` so `extract_runtime` (which
                    // probes the stored result for the `ExecutionSummary`
                    // payload) classifies platform executions correctly
                    // instead of falling through the `status_code` check and
                    // misreporting them as HTTP to the dashboard.
                    if let Some(obj) = result_json.as_object_mut() {
                        obj.insert("runtime".into(), serde_json::json!("platform"));
                    }
                    // Mirror the MCP branch's `action.executed` audit, stamped
                    // with replayed_from_approval / execution_id so reviewers
                    // can trace platform replays in the audit log.
                    let audit_detail = serde_json::json!({
                        "runtime": "platform",
                        "action": &call.action,
                        "service": &call.service,
                        "replayed_from_approval": id,
                        "execution_id": execution_id,
                    });
                    let _ = scope
                        .log_audit(AuditEntry {
                            org_id: audit_org_id,
                            identity_id: Some(approval.identity_id),
                            action: "action.executed",
                            resource_type: call.service.as_deref(),
                            resource_id: None,
                            detail: audit_detail,
                            description: Some(approval.action_summary.as_str()),
                            ip_address: ip,
                        })
                        .await;
                    let summary = serde_json::json!({
                        "runtime": "platform",
                        "action": &call.action,
                    });
                    let finalised = scope
                        .finalize_execution_executed(execution_id, &result_json)
                        .await?
                        .unwrap_or(claimed);
                    // Platform dispatch is in-process — there is no upstream
                    // to report on, so `upstream_errored` is always false.
                    (finalised, true, false, Some(summary))
                }
                Ok(Err(app_err)) => {
                    let msg = app_err.to_string();
                    let finalised = scope
                        .finalize_execution_failed(execution_id, &msg)
                        .await?
                        .unwrap_or(claimed);
                    (finalised, false, false, None)
                }
                Err(_elapsed) => {
                    let finalised = scope
                        .finalize_execution_failed(execution_id, "replay_timeout")
                        .await?
                        .unwrap_or(claimed);
                    (finalised, false, false, None)
                }
            }
        }
    };

    // Replays were previously invisible in execution metrics — record them
    // with the same status vocabulary the inline path uses so dashboards
    // can split inline vs replay volume and an upstream failing during
    // replay still shows as `upstream_error`, not silent success.
    let replay_status = if !succeeded {
        "failed"
    } else if upstream_errored {
        "upstream_error"
    } else {
        "called"
    };
    overslash_metrics::actions::record_execution(
        &replay_tpl,
        "replay",
        replay_status,
        replay_start.elapsed(),
    );

    // ── Rule creation for Allow & Remember. Only on successful replay —
    // a failed replay leaves no rule so the reviewer can retry after fixing
    // the underlying issue.
    let mut cascaded_approval_ids: Vec<Uuid> = Vec::new();
    if succeeded && finalised.remember {
        let placement_id =
            crate::services::permission_chain::rule_placement_for(scope, approval.identity_id)
                .await?;
        let keys_owned: Vec<String> = finalised
            .remember_keys
            .clone()
            .unwrap_or_else(|| approval.permission_keys.clone());
        for key in &keys_owned {
            let _ = scope
                .create_permission_rule(placement_id, key, "allow", finalised.remember_rule_ttl)
                .await;
        }

        // Cascade: re-evaluate other pending approvals under placement_id
        // that the new rules might now satisfy. Best-effort — never fail the
        // /call request just because the cascade hit a snag.
        if !keys_owned.is_empty() {
            let cascaded = match crate::services::permission_chain::cascade_resolve(
                state,
                scope,
                placement_id,
                id,
            )
            .await
            {
                Ok(resolved) => resolved,
                Err(e) => {
                    tracing::warn!(
                        approval_id = %id,
                        "cascade_resolve failed: {e}"
                    );
                    Vec::new()
                }
            };

            // Auto-call each cascaded approval whose *own* requesting agent
            // has `auto_call_on_approve` set, mirroring the `/resolve` path.
            // Cascaded executions carry `remember=false`, so these replays
            // can never write rules or cascade further. Lookup failures
            // degrade to manual-only, same as `/resolve`.
            for c in &cascaded {
                // No pending execution row (best-effort creation failed in
                // the cascade) → nothing to claim.
                if c.execution_id.is_none() {
                    continue;
                }
                let auto_call_enabled = match overslash_db::repos::identity::get_by_id(
                    state.db(ext),
                    c.approval.org_id,
                    c.approval.identity_id,
                )
                .await
                {
                    Ok(Some(i)) => i.auto_call_on_approve,
                    Ok(None) => {
                        tracing::warn!(
                            approval_id = %c.approval.id,
                            "cascade auto-call identity lookup returned no row"
                        );
                        false
                    }
                    Err(e) => {
                        tracing::warn!(
                            approval_id = %c.approval.id,
                            "cascade auto-call identity lookup failed: {e}"
                        );
                        false
                    }
                };
                if !auto_call_enabled {
                    continue;
                }
                // Same elicitation suppression as `/resolve`: an in-flight
                // elicitation drives its own /resolve → /call round-trip.
                let elicitation_active =
                    match overslash_db::repos::mcp_elicitation::has_active_for_approval(
                        state.db(ext),
                        c.approval.id,
                    )
                    .await
                    {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::warn!(
                                approval_id = %c.approval.id,
                                "cascade auto-call elicitation lookup failed: {e}"
                            );
                            false
                        }
                    };
                if elicitation_active {
                    continue;
                }
                // There is no human resolver here — attribute the execution
                // audit to the cascaded approval's subject, consistent with
                // `approval.cascade_resolved`.
                spawn_auto_call(
                    state.clone(),
                    ext.clone(),
                    c.approval.clone(),
                    ip.map(str::to_string),
                    c.approval.org_id,
                    Some(c.approval.identity_id),
                );
            }

            cascaded_approval_ids = cascaded.into_iter().map(|c| c.approval.id).collect();
        }
    }

    // ── Audit + webhook.
    let audit_action = if succeeded {
        "approval.executed"
    } else {
        "approval.execution_failed"
    };
    let _ = scope
        .log_audit(AuditEntry {
            org_id: audit_org_id,
            identity_id: audit_identity_id,
            action: audit_action,
            resource_type: Some("approval"),
            resource_id: Some(id),
            detail: serde_json::json!({
                "execution_id": execution_id,
                "triggered_by": triggered_by,
                "status": finalised.status,
                "error": finalised.error,
                "cascaded_approval_ids": &cascaded_approval_ids,
            }),
            description: None,
            ip_address: ip,
        })
        .await;

    {
        let db = state.db_pool(ext);
        let client = state.http_client.clone();
        let org_id = audit_org_id;
        let webhook_event = if succeeded {
            "approval.executed"
        } else {
            "approval.execution_failed"
        };
        let mut payload = serde_json::json!({
            "approval_id": id,
            "execution_id": execution_id,
            "status": finalised.status,
            "triggered_by": triggered_by,
            "error": finalised.error,
            "summary": result_summary,
        });
        // Auto-fired executions ship the result body in the webhook so
        // white-label platforms can render the outcome without a follow-up
        // `GET /v1/approvals/{id}/execution`. Manual (`agent`/`user`) calls
        // omit it — the caller already received the response in-band on
        // their `POST /v1/approvals/{id}/call`. Apply the same
        // `truncate_json_value` cap used by `ExecutionSummary::from` so a
        // multi-megabyte upstream body can't blow past subscriber size
        // limits or stress the webhook dispatcher.
        if triggered_by == "auto"
            && succeeded
            && let Some(result) = finalised.result.clone()
        {
            payload
                .as_object_mut()
                .expect("payload is a json object")
                .insert("result".into(), truncate_json_value(result));
        }
        tokio::spawn(async move {
            crate::services::webhook_dispatcher::dispatch(
                &db,
                &client,
                org_id,
                webhook_event,
                payload,
            )
            .await;
        });
    }

    Ok((finalised, succeeded, cascaded_approval_ids))
}

async fn cancel_approval_execution(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: OrgAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<ApprovalResponse>> {
    let approval = scope
        .get_approval(id)
        .await?
        .ok_or_else(|| AppError::NotFound("approval not found".into()))?;

    // Requesters may cancel their own pending execution (self-cancel).
    // Third parties need resolver-level access (Write ACL).
    use overslash_core::permissions::AccessLevel;
    if let Some(caller_identity) = auth.identity_id {
        let is_requester = caller_identity == approval.identity_id;
        let is_admin = auth.access_level >= AccessLevel::Admin;
        if !is_requester {
            if auth.access_level < AccessLevel::Write {
                return Err(AppError::Forbidden("write access required".into()));
            }
            if !is_admin {
                let allowed = crate::services::permission_chain::is_self_or_ancestor(
                    &scope,
                    caller_identity,
                    approval.current_resolver_identity_id,
                )
                .await?;
                if !allowed {
                    return Err(AppError::Forbidden(
                        "caller is not authorized to cancel this execution".into(),
                    ));
                }
            }
        }
    }

    let cancelled = scope.cancel_pending_execution(id).await?;
    let Some(cancelled) = cancelled else {
        let current = scope.get_execution_by_approval(id).await?;
        return Err(execution_conflict_error(current));
    };
    let execution_id = cancelled.id;

    let _ = scope
        .log_audit(AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "approval.execution_cancelled",
            resource_type: Some("approval"),
            resource_id: Some(id),
            detail: serde_json::json!({
                "execution_id": execution_id,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    {
        let db = state.db_pool(&ext);
        let client = state.http_client.clone();
        let org_id = auth.org_id;
        let payload = serde_json::json!({
            "approval_id": id,
            "execution_id": execution_id,
            "status": "cancelled",
        });
        tokio::spawn(async move {
            crate::services::webhook_dispatcher::dispatch(
                &db,
                &client,
                org_id,
                "approval.execution_cancelled",
                payload,
            )
            .await;
        });
    }

    let (identity_path, identity_path_ids) =
        crate::services::identity_path::build_for_identity(&scope, approval.identity_id)
            .await
            .unwrap_or(None)
            .map(|(p, ids)| (Some(p), ids))
            .unwrap_or((None, Vec::new()));
    let mut resp = ApprovalResponse::from_row(
        approval,
        identity_path,
        identity_path_ids,
        Some(cancelled),
        &state.registry,
    );
    resp.decorate_relationship(&scope, auth.identity_id).await?;
    Ok(Json(resp))
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
            "executed" => AppError::Conflict("execution has already completed".into()),
            "failed" => AppError::Conflict("execution already attempted and failed".into()),
            "cancelled" => AppError::Conflict("execution was cancelled".into()),
            "expired" => AppError::Gone("pending execution has expired".into()),
            other => AppError::Conflict(format!("execution in unexpected state: {other}")),
        },
    }
}

#[cfg(test)]
mod risk_tests {
    use super::*;
    use overslash_core::permissions::DerivedKey;
    use overslash_core::types::service::{Runtime, ServiceAction, ServiceDefinition};
    use std::collections::HashMap;

    fn registry_with(key: &str, action: &str, risk: Risk) -> ServiceRegistry {
        let mut actions = HashMap::new();
        actions.insert(
            action.into(),
            ServiceAction {
                method: "GET".into(),
                path: "/".into(),
                description: String::new(),
                risk,
                response_type: None,
                params: HashMap::new(),
                scope_param: None,
                required_scopes: vec![],
                permission: None,
                disclose: vec![],
                redact: vec![],
                mcp_tool: None,
                output_schema: None,
                disabled: false,
            },
        );
        let mut registry = ServiceRegistry::default();
        registry.insert(ServiceDefinition {
            key: key.into(),
            display_name: key.into(),
            description: None,
            hosts: vec![],
            category: None,
            hidden: false,
            auth: vec![],
            actions,
            runtime: Runtime::Http,
            mcp: None,
        });
        registry
    }

    fn dk(service: &str, action: &str) -> DerivedKey {
        DerivedKey {
            key: format!("{service}:{action}:*"),
            service: service.into(),
            action: action.into(),
            arg: "*".into(),
        }
    }

    #[test]
    fn risk_read_maps_low() {
        let reg = registry_with("github", "list_repos", Risk::Read);
        let keys = vec![dk("github", "list_repos")];
        assert_eq!(derive_risk_class(&reg, &keys), "low");
    }

    #[test]
    fn risk_write_maps_med() {
        let reg = registry_with("github", "create_pr", Risk::Write);
        let keys = vec![dk("github", "create_pr")];
        assert_eq!(derive_risk_class(&reg, &keys), "med");
    }

    #[test]
    fn risk_delete_maps_high() {
        let reg = registry_with("postgres", "drop_database", Risk::Delete);
        let keys = vec![dk("postgres", "drop_database")];
        assert_eq!(derive_risk_class(&reg, &keys), "high");
    }

    #[test]
    fn missing_service_falls_back_to_med() {
        let reg = ServiceRegistry::default();
        let keys = vec![dk("ghost", "vanish")];
        assert_eq!(derive_risk_class(&reg, &keys), "med");
    }

    #[test]
    fn missing_action_falls_back_to_med() {
        let reg = registry_with("github", "list_repos", Risk::Read);
        let keys = vec![dk("github", "create_pr")];
        assert_eq!(derive_risk_class(&reg, &keys), "med");
    }

    #[test]
    fn empty_derived_keys_falls_back_to_med() {
        let reg = ServiceRegistry::default();
        assert_eq!(derive_risk_class(&reg, &[]), "med");
    }
}
