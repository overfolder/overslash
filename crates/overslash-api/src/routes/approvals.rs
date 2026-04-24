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

use overslash_core::permissions::{GroupCeilingResult, PermissionKey, parse_derived_key};
use overslash_core::types::service::Risk;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AuthContext, ClientIp, OrgAcl, WriteAcl},
    services::action_executor::{
        self, AuditSource, ExecuteContext, ExecuteOutcome, StoredExecuteRequest,
    },
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
        .route("/v1/approvals/{id}/execute", post(execute_approval))
        .route("/v1/approvals/{id}/cancel", post(cancel_approval_execution))
        .route("/v1/approvals/{id}/execution", get(get_execution))
}

#[derive(Serialize)]
struct ExecutionSummary {
    id: Uuid,
    /// One of: `pending`, `executing`, `executed`, `failed`, `cancelled`, `expired`.
    status: String,
    /// Populated when `status='executed'`. Truncated at `MAX_EXECUTION_RESULT_BYTES`.
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// `agent` | `user`. Omitted from JSON while the execution is still pending.
    #[serde(skip_serializing_if = "Option::is_none")]
    triggered_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_at: Option<String>,
    expires_at: String,
    created_at: String,
}

impl ExecutionSummary {
    fn from_row(r: ExecutionRow) -> Self {
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
        }
    }
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
        execution: Option<ExecutionRow>,
    ) -> Self {
        let derived_keys = overslash_core::permissions::derive_keys(&r.permission_keys);
        let suggested_tiers = overslash_core::permissions::suggest_tiers(&r.permission_keys);
        let (action_detail, action_detail_truncated, action_detail_size_bytes) = match r
            .action_detail
            .as_ref()
            .and_then(|v| serde_json::to_string_pretty(v).ok())
        {
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
        };
        Self {
            id: r.id,
            identity_id: r.identity_id,
            requesting_identity_id: r.identity_id,
            current_resolver_identity_id: r.current_resolver_identity_id,
            identity_path,
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
        }
    }
}

async fn build_response(
    scope: &OrgScope,
    row: overslash_db::repos::approval::ApprovalRow,
) -> Result<ApprovalResponse> {
    let identity_path = crate::services::identity_path::build_for_identity(scope, row.identity_id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("failed to build identity_path for approval {}: {e}", row.id);
            None
        });
    let execution = scope.get_execution_by_approval(row.id).await?;
    Ok(ApprovalResponse::from_row(row, identity_path, execution))
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
}

async fn list_approvals(
    State(_state): State<AppState>,
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
        return Ok(Json(batch_responses(&scope, rows).await?));
    }
    let rows = match q.scope.as_deref() {
        Some("mine") => {
            let identity_id = auth.identity_id.ok_or_else(|| {
                AppError::BadRequest("scope=mine requires an identity-bound api key".into())
            })?;
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
    Ok(Json(batch_responses(&scope, rows).await?))
}

/// Assemble `ApprovalResponse`s for a list of approvals, batching the
/// execution lookup with a single `WHERE approval_id = ANY(...)` to avoid
/// the N+1 that a per-row `build_response` would produce.
async fn batch_responses(
    scope: &OrgScope,
    rows: Vec<overslash_db::repos::approval::ApprovalRow>,
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
        let identity_path =
            crate::services::identity_path::build_for_identity(scope, row.identity_id)
                .await
                .unwrap_or_else(|e| {
                    tracing::warn!("failed to build identity_path for approval {}: {e}", row.id);
                    None
                });
        let execution = exec_map.remove(&row.id);
        out.push(ApprovalResponse::from_row(row, identity_path, execution));
    }
    Ok(out)
}

async fn get_approval(
    State(_state): State<AppState>,
    scope: OrgScope,
    Path(id): Path<Uuid>,
) -> Result<Json<ApprovalResponse>> {
    let row = scope
        .get_approval(id)
        .await?
        .ok_or_else(|| AppError::NotFound("approval not found".into()))?;
    Ok(Json(build_response(&scope, row).await?))
}

async fn get_execution(
    State(_state): State<AppState>,
    scope: OrgScope,
    Path(id): Path<Uuid>,
) -> Result<Json<ExecutionSummary>> {
    // Require the approval exists in this org (4xx-not-leaky).
    let _ = scope
        .get_approval(id)
        .await?
        .ok_or_else(|| AppError::NotFound("approval not found".into()))?;
    let exec = scope
        .get_execution_by_approval(id)
        .await?
        .ok_or_else(|| AppError::NotFound("no execution for this approval".into()))?;
    Ok(Json(ExecutionSummary::from_row(exec)))
}

#[derive(Deserialize)]
struct ResolveRequest {
    resolution: String, // "allow", "deny", "allow_remember", "bubble_up"
    remember_keys: Option<Vec<String>>,
    ttl: Option<String>,
}

async fn resolve_approval(
    State(state): State<AppState>,
    WriteAcl(acl): WriteAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<ResolveRequest>,
) -> Result<Json<ApprovalResponse>> {
    let auth = acl;

    // Load the approval through the org-scoped lookup. A foreign id returns
    // None at the SQL boundary — 404 (not 403) avoids leaking existence.
    let approval_pre = scope
        .get_approval(id)
        .await?
        .ok_or_else(|| AppError::NotFound("approval not found".into()))?;

    // ── Authorize the caller as the current resolver (or an ancestor of them).
    use overslash_core::permissions::AccessLevel;
    if let Some(caller_identity) = auth.identity_id {
        if caller_identity == approval_pre.identity_id {
            return Err(AppError::Forbidden(
                "agents cannot resolve their own approval requests".into(),
            ));
        }
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

        let _ = OrgScope::new(auth.org_id, state.db.clone())
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

        return Ok(Json(build_response(&scope, updated).await?));
    }

    let (status, remember) = match req.resolution.as_str() {
        "allow" => ("allowed", false),
        "deny" => ("denied", false),
        "allow_remember" => ("allowed", true),
        other => return Err(AppError::BadRequest(format!("invalid resolution: {other}"))),
    };

    // ── Validate + normalise remember_keys / ttl (actual rule creation moves
    // to /execute on success).
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

    // On allow/allow_remember, create the pending execution row. The actual
    // replay is triggered later by POST /v1/approvals/{id}/execute.
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
        Some(row)
    } else {
        None
    };

    let _ = OrgScope::new(auth.org_id, state.db.clone())
        .log_audit(AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "approval.resolved",
            resource_type: Some("approval"),
            resource_id: Some(id),
            detail: serde_json::json!({
                "resolution": &req.resolution,
                "status": &row.status,
                "action_summary": &row.action_summary,
                "execution_id": execution.as_ref().map(|e| e.id),
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    // Dispatch webhook (fire-and-forget)
    {
        let db = state.db.clone();
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

    let identity_path = crate::services::identity_path::build_for_identity(&scope, row.identity_id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("failed to build identity_path for approval {}: {e}", row.id);
            None
        });
    Ok(Json(ApprovalResponse::from_row(
        row,
        identity_path,
        execution,
    )))
}

async fn execute_approval(
    State(state): State<AppState>,
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

    // Auth: the requesting agent may execute directly (even without write
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
                    "caller is not authorized to execute this approval".into(),
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
    let execution_id = claimed.id;

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
    // ActionRequest plus `filter`/`prefer_stream`, unaffected by
    // x-overslash-redact which only reshapes the UI-facing `action_detail`.
    // Fall back to `action_detail` for legacy / pre-feature approvals.
    let replay_value = match approval
        .replay_payload
        .clone()
        .or_else(|| approval.action_detail.clone())
    {
        Some(v) => v,
        None => {
            return fail_and_return(
                &scope,
                execution_id,
                "no_replay_payload",
                AppError::Internal("approval has no stored replay payload — cannot replay".into()),
            )
            .await;
        }
    };
    // MCP-runtime approvals have a different shape (runtime, tool,
    // arguments) that this HTTP-replay path can't execute. Clean 409 until
    // a dedicated MCP-replay path lands.
    if replay_value.get("runtime").and_then(|v| v.as_str()) == Some("mcp") {
        return fail_and_return(
            &scope,
            execution_id,
            "mcp_replay_not_supported",
            AppError::Conflict("replay of MCP-runtime approvals is not yet supported".into()),
        )
        .await;
    }
    let stored = match StoredExecuteRequest::from_stored_detail(&replay_value) {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("replay payload parse error: {e}");
            return fail_and_return(
                &scope,
                execution_id,
                &msg,
                AppError::Internal(format!(
                    "approval replay payload is not a valid ExecuteRequest: {e}"
                )),
            )
            .await;
        }
    };

    // ── Replay with timeout. Streaming is forced off — the reviewer's
    // connection isn't the original caller's.
    let exec_ctx = ExecuteContext {
        state: &state,
        scope: &scope,
        identity_id: approval.identity_id, // requester identity for audit/rate-limit
        ip: ip.0.as_deref(),
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

    let replay_timeout = std::time::Duration::from_secs(state.config.execution_replay_timeout_secs);
    let outcome = tokio::time::timeout(
        replay_timeout,
        action_executor::execute_action_request(exec_ctx, &stored.action),
    )
    .await;

    let (finalised, succeeded, result_summary) = match outcome {
        Ok(Ok(ExecuteOutcome::Buffered { result, .. })) => {
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
            let finalised = scope
                .finalize_execution_executed(execution_id, &result_json)
                .await?
                .unwrap_or(claimed);
            (finalised, true, Some(summary))
        }
        Ok(Ok(ExecuteOutcome::Streamed(_))) => {
            // Defensive: replay forces prefer_stream=false so this variant is
            // unreachable in practice. Record as failed rather than silently
            // dropping the response.
            let msg = "replay unexpectedly produced a streaming response";
            let finalised = scope
                .finalize_execution_failed(execution_id, msg)
                .await?
                .unwrap_or(claimed);
            (finalised, false, None)
        }
        Ok(Err(app_err)) => {
            let msg = app_err.to_string();
            let finalised = scope
                .finalize_execution_failed(execution_id, &msg)
                .await?
                .unwrap_or(claimed);
            (finalised, false, None)
        }
        Err(_elapsed) => {
            let msg = "replay_timeout";
            let finalised = scope
                .finalize_execution_failed(execution_id, msg)
                .await?
                .unwrap_or(claimed);
            (finalised, false, None)
        }
    };

    // ── Rule creation for Allow & Remember. Only on successful replay —
    // a failed replay leaves no rule so the reviewer can retry after fixing
    // the underlying issue.
    if succeeded && finalised.remember {
        let placement_id =
            crate::services::permission_chain::rule_placement_for(&scope, approval.identity_id)
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
    }

    // ── Audit + webhook.
    let audit_action = if succeeded {
        "approval.executed"
    } else {
        "approval.execution_failed"
    };
    let _ = OrgScope::new(auth.org_id, state.db.clone())
        .log_audit(AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: audit_action,
            resource_type: Some("approval"),
            resource_id: Some(id),
            detail: serde_json::json!({
                "execution_id": execution_id,
                "triggered_by": triggered_by,
                "status": finalised.status,
                "error": finalised.error,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    {
        let db = state.db.clone();
        let client = state.http_client.clone();
        let org_id = auth.org_id;
        let webhook_event = if succeeded {
            "approval.executed"
        } else {
            "approval.execution_failed"
        };
        let payload = serde_json::json!({
            "approval_id": id,
            "execution_id": execution_id,
            "status": finalised.status,
            "triggered_by": triggered_by,
            "error": finalised.error,
            "summary": result_summary,
        });
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

    let identity_path =
        crate::services::identity_path::build_for_identity(&scope, approval.identity_id)
            .await
            .unwrap_or(None);
    Ok(Json(ApprovalResponse::from_row(
        approval,
        identity_path,
        Some(finalised),
    )))
}

async fn cancel_approval_execution(
    State(state): State<AppState>,
    WriteAcl(acl): WriteAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<ApprovalResponse>> {
    let auth = acl;
    let approval = scope
        .get_approval(id)
        .await?
        .ok_or_else(|| AppError::NotFound("approval not found".into()))?;

    // Cancellation is resolver-only. Agents cannot cancel their own pending
    // executions — the agent's fallback is to let the 15-minute window expire.
    use overslash_core::permissions::AccessLevel;
    if let Some(caller_identity) = auth.identity_id {
        if caller_identity == approval.identity_id {
            return Err(AppError::Forbidden(
                "agents cannot cancel their own pending executions".into(),
            ));
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
                    "caller is not authorized to cancel this execution".into(),
                ));
            }
        }
    }

    let cancelled = scope.cancel_pending_execution(id).await?;
    let Some(cancelled) = cancelled else {
        let current = scope.get_execution_by_approval(id).await?;
        return Err(execution_conflict_error(current));
    };
    let execution_id = cancelled.id;

    let _ = OrgScope::new(auth.org_id, state.db.clone())
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
        let db = state.db.clone();
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

    let identity_path =
        crate::services::identity_path::build_for_identity(&scope, approval.identity_id)
            .await
            .unwrap_or(None);
    Ok(Json(ApprovalResponse::from_row(
        approval,
        identity_path,
        Some(cancelled),
    )))
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
