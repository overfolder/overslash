use std::collections::HashMap;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::util::fmt_time;

use overslash_db::repos::audit::AuditEntry;
use overslash_db::scopes::OrgScope;

use crate::{
    AppState,
    error::AppError,
    extractors::{AuthContext, ClientIp},
    services::{
        action_caller::{StoredCallRequest, StoredMcpCall},
        disclosure, group_ceiling, http_caller, mcp_caller,
        oauth::OAuthError,
        platform_connections,
        response_filter::{self, ResponseFilter},
    },
};
use overslash_core::{
    crypto, disclosure as core_disclosure,
    permissions::{AccessLevel, GroupCeilingResult, PermissionKey},
    secret_injection::inject_secrets,
    types::{
        ActionRequest, ActionResult, DisclosureField, FilteredBody, InjectAs, McpAuth, Runtime,
        SecretRef, service::Risk,
    },
};

/// Cap on the number of instance names we surface in `ServiceResolution`
/// error payloads. Agents only need a handful to disambiguate; the full
/// list lives in `overslash_search`.
const ERROR_INSTANCE_HINT_CAP: usize = 10;

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/actions/call", post(call_action))
}

/// `/v1/actions/validate` is a dry-run probe: it runs `validate_args` and
/// the permission chain, but never executes the upstream call, never
/// writes an approval, never logs audit, and is exempt from rate limits.
/// Mounted on its own router so callers can pre-flight bad params without
/// burning their rate budget.
pub fn validate_router() -> Router<AppState> {
    Router::new().route("/v1/actions/validate", post(validate_action))
}

/// Top-level handler that times the request and emits the
/// `overslash_action_executions_total` / `_duration_seconds` metrics.
/// Granular outcomes (approval_required vs called vs filtered) are encoded in
/// the success-body status tag and would require threading an outcome out of
/// the inner function — for now we classify by HTTP status only.
async fn call_action(
    State(state): State<AppState>,
    auth: AuthContext,
    scope: OrgScope,
    ip: ClientIp,
    Json(req): Json<CallRequest>,
) -> Result<Response, AppError> {
    let start = std::time::Instant::now();
    // Mode resolution mirrors `resolve_request` exactly: `connection` wins
    // over `service+action` when both are present, so the metric label
    // matches the execution path that actually runs downstream.
    let mode = if req.connection.is_some() {
        "b"
    } else if req.service.is_some() {
        "c"
    } else {
        "a"
    };
    // Bound the `template_key` label to keys that actually exist in the
    // registry. A client could otherwise submit `service: "<arbitrary>"`
    // and explode Prometheus cardinality even on requests that fail
    // validation inside the inner handler. When `connection` wins (mode b),
    // any `service` field is ignored downstream — emit `_raw` so labels
    // don't lie about which template was used.
    let template_key = if req.connection.is_some() {
        "_raw".to_string()
    } else {
        match req.service.as_deref() {
            Some(key) if state.registry.get(key).is_some() => key.to_string(),
            Some(_) => "_unknown".to_string(),
            None => "_raw".to_string(),
        }
    };

    let result = call_action_impl(State(state), auth, scope, ip, Json(req)).await;

    // Resolve the outcome to its eventual HTTP status so 4xx user-input errors
    // (BadRequest, NotFound, Forbidden, RateLimited) don't count as `failed`.
    let status_code = match &result {
        Ok(resp) => resp.status().as_u16(),
        Err(err) => err.status_code().as_u16(),
    };
    let status_label = if status_code >= 500 {
        "failed"
    } else if status_code == 403 {
        "denied"
    } else if status_code >= 400 {
        "rejected"
    } else {
        "called"
    };
    overslash_metrics::actions::record_execution(
        &template_key,
        mode,
        status_label,
        start.elapsed(),
    );
    result
}

/// `POST /v1/actions/validate` — dry-run probe for `/v1/actions/call`.
///
/// Runs the same body shape, the same identity / risk / argument checks,
/// and the same Layer 1 (group ceiling) + Layer 2 (permission chain)
/// gates that `/call` runs — but stops short of executing the upstream
/// request, writing an approval row, logging audit, or dispatching
/// webhooks. Returns 200 `{ok: true, permission: {status, ...}}` on
/// success, or 400 with the structured `invalid_action_args` body when
/// the caller's params don't match the action's input contract.
///
/// Exempt from rate limits (mounted on its own router) so an agent can
/// pre-validate without burning quota on a request it isn't sure of yet.
async fn validate_action(
    State(state): State<AppState>,
    auth: AuthContext,
    scope: OrgScope,
    _ip: ClientIp,
    Json(req): Json<CallRequest>,
) -> Result<Response, AppError> {
    let start = std::time::Instant::now();
    let mode = if req.connection.is_some() {
        "b"
    } else if req.service.is_some() {
        "c"
    } else {
        "a"
    };
    let template_key = if req.connection.is_some() {
        "_raw".to_string()
    } else {
        match req.service.as_deref() {
            Some(key) if state.registry.get(key).is_some() => key.to_string(),
            Some(_) => "_unknown".to_string(),
            None => "_raw".to_string(),
        }
    };

    let result = validate_action_impl(State(state), auth, scope, Json(req)).await;

    let outcome = match &result {
        Ok((_, label)) => *label,
        // Only the `InvalidActionArgs` 400 counts as `invalid_args`;
        // Mode B rejection, filter-syntax errors, and require_risk
        // mismatches are all 400s but unrelated to the schema check, so
        // they fall into `rejected` — keeps the dashboard panel for
        // schema misses honest.
        Err(AppError::InvalidActionArgs { .. }) => "invalid_args",
        Err(err) => {
            let code = err.status_code().as_u16();
            if code >= 500 {
                "failed"
            } else if code == 403 {
                "denied"
            } else {
                "rejected"
            }
        }
    };
    overslash_metrics::actions::record_validation(&template_key, mode, outcome, start.elapsed());

    result.map(|(resp, _)| resp)
}

/// Outcome label tracked alongside the response so the metrics wrapper
/// can distinguish e.g. `validated` vs `would_require_approval` without
/// re-parsing the response body.
async fn validate_action_impl(
    State(state): State<AppState>,
    auth: AuthContext,
    scope: OrgScope,
    Json(req): Json<CallRequest>,
) -> Result<(Response, &'static str), AppError> {
    // Mode B (raw connection) has no schema to validate against, and
    // resolving the connection would require a real OAuth token refresh
    // — not appropriate for a dry-run probe. The caller can hit
    // `/v1/actions/call` directly to test that path.
    if req.connection.is_some() {
        return Err(AppError::BadRequest(
            "validate does not support raw connection mode; \
             use /v1/actions/call to test connection-based requests"
                .into(),
        ));
    }

    // Filter syntax — same gate as `/call`. A malformed expression is a
    // 400, not a wasted upstream burn.
    if let Some(filter) = req.filter.as_ref() {
        response_filter::validate_syntax(filter).map_err(AppError::FilterSyntax)?;
    }

    let identity_id = auth
        .identity_id
        .ok_or_else(|| AppError::BadRequest("api key must be bound to an identity".into()))?;
    let identity = scope
        .get_identity(identity_id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
    let ceiling_user_id = group_ceiling::ceiling_user_id_from_identity(&identity)?;

    // Cheap resolution — loads the action template (Mode C) without
    // running OAuth, param resolvers, or scope checks. The resolved
    // template/instance ride along but the validate path doesn't
    // forward them anywhere; they're dropped at the end of this scope.
    let (meta, _resolved_mode_c) =
        resolve_action_metadata(&state, &auth, &scope, ceiling_user_id, &req).await?;

    // Argument validation runs before the risk gate so a request with
    // both bad params and a wrong-risk assertion produces the same
    // `invalid_action_args` 400 it would on `/call` — the byte-identical
    // 400 contract is meaningful only when the gates fire in the same
    // order in both endpoints.
    if let Err(errors) =
        overslash_core::openapi::validate_input::validate_args(&meta.validation_params, &req.params)
    {
        return Err(invalid_action_args_error(&meta.validation_params, errors));
    }

    // Caller-asserted risk gate — mirrors `/call` (which runs it inside
    // `resolve_request` after `validate_args` has already gated bad args).
    if let Some(required) = req.require_risk {
        let effective = meta
            .risk
            .unwrap_or_else(|| Risk::from_http_method(&meta.raw_method));
        if required == Risk::Read && effective.is_mutating() {
            let action_label = req
                .action
                .as_deref()
                .or(req.service.as_deref())
                .unwrap_or(&meta.raw_url);
            return Err(AppError::BadRequest(format!(
                "action '{action_label}' is risk={effective}; this entry point only permits risk=read actions. Use overslash_call instead."
            )));
        }
    }

    // Permission key derivation — same logic as `/call` runs after
    // `resolve_request` returns, using the resolved scope and method.
    let perm_keys = if let Some(ref svc) = meta.service_scope {
        PermissionKey::from_service_action(
            &svc.service_key,
            &svc.action_key,
            svc.scope_param.as_deref(),
            &req.params,
        )
    } else {
        PermissionKey::from_http(&meta.raw_method, &meta.raw_url)
    };

    // Layer 1: group ceiling. Surfaced as a permission status, not a
    // 403 — validate always returns 200 on a well-formed call so the
    // caller has a single decode path.
    let ceiling_service = meta
        .service_scope
        .as_ref()
        .map(|s| s.service_key.clone())
        .unwrap_or_else(|| "http".to_string());
    let ceiling_risk = meta
        .risk
        .unwrap_or_else(|| Risk::from_http_method(&meta.raw_method));
    let ceiling = group_ceiling::load_ceiling(&scope, ceiling_user_id).await?;
    let mut skip_layer2 = false;
    if ceiling.has_groups {
        match group_ceiling::check_ceiling(&ceiling, &ceiling_service, ceiling_risk) {
            GroupCeilingResult::ExceedsCeiling(reason) => {
                let body = serde_json::json!({
                    "ok": true,
                    "permission": {
                        "status": "exceeds_ceiling",
                        "reason": reason,
                    },
                });
                return Ok((
                    (StatusCode::OK, Json(body)).into_response(),
                    "exceeds_ceiling",
                ));
            }
            GroupCeilingResult::WithinCeiling { read_bypass } => {
                if read_bypass && identity.kind != "user" {
                    skip_layer2 = true;
                }
            }
            GroupCeilingResult::NoGroups => {}
        }
    }

    // Layer 2: permission chain. Users are gated by groups only, so
    // they get an immediate `allowed`. Agents walk the chain — first
    // gap reports `would_require_approval` without writing an approval
    // row or firing a webhook.
    if identity.kind == "user" || !meta.needs_gate || skip_layer2 {
        let body = serde_json::json!({
            "ok": true,
            "permission": { "status": "allowed" },
        });
        return Ok(((StatusCode::OK, Json(body)).into_response(), "validated"));
    }

    let bubble_secs =
        overslash_db::repos::org::get_approval_auto_bubble_secs(&state.db, auth.org_id)
            .await?
            .unwrap_or(300);
    let force_user_resolver = bubble_secs == 0;

    let outcome = crate::services::permission_chain::walk(
        &scope,
        identity_id,
        &perm_keys,
        force_user_resolver,
    )
    .await?;

    let (body, label) = match outcome {
        crate::services::permission_chain::ChainWalkResult::Allowed => (
            serde_json::json!({
                "ok": true,
                "permission": { "status": "allowed" },
            }),
            "validated",
        ),
        crate::services::permission_chain::ChainWalkResult::Gap {
            uncovered_keys,
            gap_identity_id,
            initial_resolver_id,
            rule_placement_id: _,
        } => {
            let keys: Vec<String> = uncovered_keys.iter().map(|k| k.0.clone()).collect();
            (
                serde_json::json!({
                    "ok": true,
                    "permission": {
                        "status": "would_require_approval",
                        "uncovered_keys": keys,
                        "gap_identity_id": gap_identity_id,
                        "initial_resolver_id": initial_resolver_id,
                    },
                }),
                "would_require_approval",
            )
        }
        crate::services::permission_chain::ChainWalkResult::Denied(reason) => (
            serde_json::json!({
                "ok": true,
                "permission": { "status": "denied", "reason": reason },
            }),
            "denied",
        ),
    };
    Ok(((StatusCode::OK, Json(body)).into_response(), label))
}

/// Unified call request: supports Mode A (raw HTTP) and Mode C (service + action).
#[derive(Debug, Deserialize)]
struct CallRequest {
    // Mode A fields
    method: Option<String>,
    url: Option<String>,
    #[serde(default)]
    headers: HashMap<String, String>,
    body: Option<String>,
    #[serde(default)]
    secrets: Vec<SecretRef>,

    // Mode C fields
    service: Option<String>,
    action: Option<String>,
    #[serde(default)]
    params: HashMap<String, serde_json::Value>,

    // Mode B: explicit connection
    connection: Option<Uuid>,

    // Large file handling
    #[serde(default)]
    prefer_stream: Option<bool>,

    // Optional server-side filter applied to the upstream response body
    // (e.g., jq). Output is attached to `result.filtered_body`; the
    // original `body` is always preserved.
    #[serde(default)]
    filter: Option<ResponseFilter>,

    // Caller-asserted risk class. Today only `read` is meaningful: when set
    // to `read`, the resolved action's risk must be `Read` or the call is
    // rejected with 400. `write` / `delete` are accepted by the parser but
    // do not gate anything (no caller currently asks for them). Set by the
    // MCP `overslash_read` tool to enforce its readOnlyHint.
    #[serde(default)]
    require_risk: Option<Risk>,
}

#[derive(Serialize)]
#[serde(tag = "status")]
enum CallResponse {
    #[serde(rename = "called")]
    Called {
        result: ActionResult,
        action_description: Option<String>,
    },
    #[serde(rename = "pending_approval")]
    PendingApproval {
        approval_id: Uuid,
        approval_url: String,
        action_description: String,
        expires_at: String,
    },
    #[serde(rename = "denied")]
    Denied { reason: String },
}

/// Metadata from request resolution, used to derive the correct permission key type.
struct ResolvedMeta {
    description: Option<String>,
    auth_injected: bool,
    /// Present only for Mode C — carries info needed to derive service-action permission keys.
    service_scope: Option<ServiceScope>,
    /// Risk level of the action (Mode C only, from the action definition).
    risk: Option<Risk>,
    /// Disclosure declarations from the action template (Mode C only, empty
    /// for Mode A/B). Runs at approval-create and audit-write time.
    disclose: Vec<DisclosureField>,
    /// Redact paths from the action template (Mode C only, empty for Mode
    /// A/B). Applied to the request projection before it's persisted as
    /// `approvals.action_detail`.
    redact: Vec<String>,
    /// Original resolved params (before url/body assembly), retained for the
    /// disclosure `.params.*` projection. Empty for Mode A/B where no
    /// disclosure runs.
    params: HashMap<String, serde_json::Value>,
    /// When the resolved service has `runtime: Mcp`, dispatch skips the HTTP
    /// executor and goes through `mcp_caller::invoke` with this payload.
    mcp_target: Option<McpTarget>,
    /// When the resolved service has `runtime: Platform`, dispatch calls the
    /// in-process handler registry instead of making any outgoing call.
    platform_target: Option<PlatformTarget>,
}

struct McpTarget {
    /// Resolved MCP server URL (instance.url ?? template mcp.url).
    url: String,
    /// Resolved auth — for Bearer, secret_name is always Some at this point.
    auth: McpAuth,
    tool: String,
    arguments: serde_json::Value,
}

struct PlatformTarget {
    action_key: String,
    params: serde_json::Map<String, serde_json::Value>,
}

struct ServiceScope {
    service_key: String,
    action_key: String,
    scope_param: Option<String>,
}

async fn call_action_impl(
    State(state): State<AppState>,
    auth: AuthContext,
    scope: OrgScope,
    ip: ClientIp,
    Json(req): Json<CallRequest>,
) -> Result<Response, AppError> {
    // Reject filter + streaming up front — silently dropping the filter
    // could let an agent think it's getting a small slice and instead
    // pipe a multi-MB stream into its context window.
    if req.prefer_stream.unwrap_or(false) && req.filter.is_some() {
        return Err(AppError::BadRequest(
            "filter cannot be combined with prefer_stream".into(),
        ));
    }

    // Validate filter syntax before any upstream call so a malformed
    // expression is a clean 400 — not a wasted upstream quota burn.
    if let Some(filter) = req.filter.as_ref() {
        response_filter::validate_syntax(filter).map_err(AppError::FilterSyntax)?;
    }

    let identity_id = auth
        .identity_id
        .ok_or_else(|| AppError::BadRequest("api key must be bound to an identity".into()))?;

    // Resolve the identity to determine kind and owner for ceiling check
    let identity = scope
        .get_identity(identity_id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;

    let ceiling_user_id = group_ceiling::ceiling_user_id_from_identity(&identity)?;

    // ── Argument validation gate ────────────────────────────────────
    //
    // Pre-resolve the action's metadata (cheap; no OAuth, no upstream
    // calls) and reject malformed args **before** any permission or
    // approval work. Sitting at the top of the handler — above the
    // ceiling check, above the permission walk, above the approval
    // branch — is what guarantees the ordering structurally: a future
    // refactor of `resolve_request` can't reintroduce the bug where a
    // user clicks "Allow" on a request that then fails validation.
    // Mode A/B carry an empty schema so the call is a no-op for them.
    //
    // The Mode C branch threads the resolved `(svc, instance)` into
    // `resolve_request` below so the call hot path doesn't re-fetch
    // the template / instance from the DB.
    let (pre_meta, pre_resolved_mode_c) =
        resolve_action_metadata(&state, &auth, &scope, ceiling_user_id, &req).await?;
    if let Err(errors) = overslash_core::openapi::validate_input::validate_args(
        &pre_meta.validation_params,
        &req.params,
    ) {
        return Err(invalid_action_args_error(
            &pre_meta.validation_params,
            errors,
        ));
    }

    // Resolve the request to a concrete ActionRequest. Passing `ceiling_user_id` reuses
    // the identity lookup above so Mode C name resolution doesn't re-fetch it.
    let (action_req, meta) = resolve_request(
        &state,
        &auth,
        &scope,
        identity_id,
        ceiling_user_id,
        &req,
        pre_resolved_mode_c,
    )
    .await?;

    // Caller-asserted risk gate (MCP `overslash_read`): reject before any
    // permission/approval work if the resolved action mutates. We use the
    // template-declared `risk` for Mode C and fall back to the HTTP-method
    // inference for Mode A/B — same logic as the ceiling check below.
    if let Some(required) = req.require_risk {
        let effective = meta
            .risk
            .unwrap_or_else(|| Risk::from_http_method(&action_req.method));
        if required == Risk::Read && effective.is_mutating() {
            let action_label = req
                .action
                .as_deref()
                .or(req.service.as_deref())
                .unwrap_or(&action_req.url);
            return Err(AppError::BadRequest(format!(
                "action '{action_label}' is risk={effective}; this entry point only permits risk=read actions. Use overslash_call instead."
            )));
        }
    }

    let perm_keys = if let Some(ref scope) = meta.service_scope {
        PermissionKey::from_service_action(
            &scope.service_key,
            &scope.action_key,
            scope.scope_param.as_deref(),
            &req.params,
        )
    } else {
        PermissionKey::from_http(&action_req.method, &action_req.url)
    };

    // ── Layer 1: Group ceiling check ─────────────────────────────────
    //
    // Owner access to a service flows through the user's auto-managed Myself
    // group grant (admin + auto_approve_reads = true by default), so every
    // call runs through this same ceiling — including ones targeting a
    // service owned by the caller's ceiling user.

    // Determine service name and risk for ceiling check
    let ceiling_service = if let Some(ref scope) = meta.service_scope {
        scope.service_key.clone()
    } else {
        "http".to_string()
    };
    let ceiling_risk = if let Some(risk) = meta.risk {
        risk
    } else {
        Risk::from_http_method(&action_req.method)
    };

    let ceiling = group_ceiling::load_ceiling(&scope, ceiling_user_id).await?;

    // `read_bypass = true` means the matching grant has `auto_approve_reads`
    // and the action is non-mutating — Layer 2 is skipped entirely (no
    // permission rule is written, no approval is filed).
    let mut skip_layer2 = false;

    if ceiling.has_groups {
        match group_ceiling::check_ceiling(&ceiling, &ceiling_service, ceiling_risk) {
            GroupCeilingResult::ExceedsCeiling(reason) => {
                return Ok(
                    (StatusCode::FORBIDDEN, Json(CallResponse::Denied { reason })).into_response(),
                );
            }
            GroupCeilingResult::WithinCeiling { read_bypass } => {
                if read_bypass && identity.kind != "user" {
                    skip_layer2 = true;
                }
            }
            GroupCeilingResult::NoGroups => {}
        }
    }
    // has_groups == false → NoGroups → permissive (no ceiling enforced)

    // ── Layer 2: Hierarchical permission check (agents/sub-agents only) ──
    let needs_gate =
        !action_req.secrets.is_empty() || req.connection.is_some() || meta.auth_injected;

    // Users are gated by groups only — they are their own approvers.
    // Agents walk the ancestor chain; first gap → approval at gap level.
    // Read bypass on a Myself / auto-approve-reads grant skips Layer 2 for
    // non-mutating actions without writing a permission rule.
    if identity.kind != "user" && needs_gate && !skip_layer2 {
        let bubble_secs =
            overslash_db::repos::org::get_approval_auto_bubble_secs(&state.db, auth.org_id)
                .await?
                .unwrap_or(300);
        let force_user_resolver = bubble_secs == 0;

        match crate::services::permission_chain::walk(
            &scope,
            identity_id,
            &perm_keys,
            force_user_resolver,
        )
        .await?
        {
            crate::services::permission_chain::ChainWalkResult::Allowed => {}
            crate::services::permission_chain::ChainWalkResult::Gap {
                uncovered_keys,
                gap_identity_id,
                initial_resolver_id,
                rule_placement_id: _,
            } => {
                let token = generate_token();
                let expires_at = time::OffsetDateTime::now_utc()
                    + time::Duration::seconds(state.config.approval_expiry_secs as i64);
                let summary = meta
                    .description
                    .clone()
                    .unwrap_or_else(|| format!("{} {}", action_req.method, action_req.url));
                let keys: Vec<String> = uncovered_keys.iter().map(|k| k.0.clone()).collect();

                // Configurable detail disclosure (SPEC §N): run the template's
                // jq filters against the resolved request projection, then
                // redact sensitive paths from the blob we persist as
                // action_detail. Falls back to the legacy raw ActionRequest
                // serialization when the template declares neither extension.
                let filter_timeout =
                    std::time::Duration::from_millis(state.config.filter_timeout_ms);
                let (disclosed_fields, redacted_detail) =
                    compute_approval_detail(&meta, &action_req, filter_timeout).await;

                // Raw replay payload (full ActionRequest + side-channel fields)
                // stored separately from action_detail so the replay at
                // POST /v1/approvals/{id}/call reproduces the agent's
                // original request faithfully — including jq `filter` and
                // `prefer_stream` — even when `action_detail` has been
                // redacted via x-overslash-redact for reviewer display.
                //
                // MCP-runtime approvals get a different shape (StoredMcpCall)
                // disambiguated at parse time by the top-level `tool` key.
                // Platform-runtime is still None (no replay path).
                let replay_payload = if meta.platform_target.is_some() {
                    None
                } else if let Some(target) = meta.mcp_target.as_ref() {
                    serde_json::to_value(StoredMcpCall {
                        url: target.url.clone(),
                        auth: target.auth.clone(),
                        tool: target.tool.clone(),
                        arguments: target.arguments.clone(),
                    })
                    .ok()
                } else {
                    serde_json::to_value(StoredCallRequest::new(
                        action_req.clone(),
                        req.filter.clone(),
                        req.prefer_stream.unwrap_or(false),
                    ))
                    .ok()
                };

                let approval = scope
                    .create_approval(
                        identity_id,
                        initial_resolver_id,
                        &summary,
                        redacted_detail,
                        if disclosed_fields.is_empty() {
                            None
                        } else {
                            serde_json::to_value(&disclosed_fields).ok()
                        },
                        replay_payload,
                        &keys,
                        &token,
                        expires_at,
                    )
                    .await?;

                let mut approval_audit_detail = serde_json::json!({
                    "summary": summary,
                    "current_resolver_identity_id": initial_resolver_id,
                });
                if !disclosed_fields.is_empty() {
                    approval_audit_detail
                        .as_object_mut()
                        .expect("audit detail is a json object")
                        .insert(
                            "disclosed".into(),
                            serde_json::to_value(&disclosed_fields).unwrap_or_default(),
                        );
                }

                let _ = OrgScope::new(auth.org_id, state.db.clone())
                    .log_audit(AuditEntry {
                        org_id: auth.org_id,
                        identity_id: Some(identity_id),
                        action: "approval.created",
                        resource_type: Some("approval"),
                        resource_id: Some(approval.id),
                        detail: approval_audit_detail,
                        description: Some(&summary),
                        ip_address: ip.0.as_deref(),
                    })
                    .await;

                // ── approval.created webhook (SPEC §5) ───────────────────
                // can_be_handled_by lists every identity in the resolver chain
                // who can act on this approval right now: the current resolver
                // and its strict ancestors (excluding the requester, who can
                // never self-resolve). Computed once here so subscribers don't
                // have to walk the tree themselves.
                let resolver_chain = scope
                    .get_identity_ancestor_chain(initial_resolver_id)
                    .await
                    .unwrap_or_default();
                let can_be_handled_by: Vec<serde_json::Value> = resolver_chain
                    .iter()
                    .filter(|i| i.id != identity_id)
                    .map(|i| {
                        serde_json::json!({
                            "identity_id": i.id,
                            "kind": i.kind,
                            "name": i.name,
                        })
                    })
                    .collect();
                let webhook_payload = serde_json::json!({
                    "approval_id": approval.id,
                    "identity_id": identity_id,
                    "gap_identity_id": gap_identity_id,
                    "current_resolver_identity_id": initial_resolver_id,
                    "action_summary": summary,
                    "permission_keys": keys,
                    "can_be_handled_by": can_be_handled_by,
                });
                {
                    let db = state.db.clone();
                    let client = state.http_client.clone();
                    let org_id = auth.org_id;
                    tokio::spawn(async move {
                        crate::services::webhook_dispatcher::dispatch(
                            &db,
                            &client,
                            org_id,
                            "approval.created",
                            webhook_payload,
                        )
                        .await;
                    });
                }

                let approval_url = state
                    .config
                    .dashboard_url_for(&format!("/approvals/{}", approval.id));
                let approval_url =
                    crate::services::short_url::mint(&state, &approval_url, expires_at)
                        .await
                        .unwrap_or(approval_url);

                return Ok((
                    StatusCode::ACCEPTED,
                    Json(CallResponse::PendingApproval {
                        approval_id: approval.id,
                        approval_url,
                        action_description: summary,
                        expires_at: fmt_time(expires_at),
                    }),
                )
                    .into_response());
            }
            crate::services::permission_chain::ChainWalkResult::Denied(reason) => {
                return Ok(
                    (StatusCode::FORBIDDEN, Json(CallResponse::Denied { reason })).into_response(),
                );
            }
        }
    }

    // ── MCP dispatch fork ────────────────────────────────────────────
    // Mcp-runtime services skip the HTTP executor: no URL templating, no
    // secret injection into headers, no streaming path. The executor owns
    // header resolution through mcp_auth::resolve_headers.
    if let Some(mcp_target) = meta.mcp_target.as_ref() {
        let result = mcp_caller::invoke(
            &state,
            &scope,
            &mcp_target.url,
            &mcp_target.auth,
            &mcp_target.tool,
            &mcp_target.arguments,
        )
        .await?;

        // Build the shared MCP audit shape, then layer on inline-only
        // fields (service/action/disclosed). Replay uses the same helper
        // from approvals.rs to keep the two surfaces from drifting.
        let (_is_error, mut audit_detail) = mcp_caller::build_audit_detail(
            &result,
            &mcp_target.tool,
            &mcp_target.url,
            &mcp_target.arguments,
        );
        {
            let obj = audit_detail
                .as_object_mut()
                .expect("audit_detail is a json object");
            obj.insert("service".into(), serde_json::json!(req.service));
            obj.insert("action".into(), serde_json::json!(req.action));
        }

        // Disclosure + redaction: MCP actions can declare the same
        // `disclose` / `redact` blocks HTTP actions do. compute_approval_detail
        // has an MCP branch that builds a tool/arguments projection; we
        // reuse it here so both audit and approval surfaces stay consistent.
        let filter_timeout = std::time::Duration::from_millis(state.config.filter_timeout_ms);
        let (disclosed_fields, _redacted_detail) =
            compute_approval_detail(&meta, &action_req, filter_timeout).await;

        if !disclosed_fields.is_empty() {
            audit_detail
                .as_object_mut()
                .expect("audit detail is a json object")
                .insert(
                    "disclosed".into(),
                    serde_json::to_value(&disclosed_fields).unwrap_or_default(),
                );
        }

        let _ = OrgScope::new(auth.org_id, state.db.clone())
            .log_audit(AuditEntry {
                org_id: auth.org_id,
                identity_id: Some(identity_id),
                action: "action.executed",
                resource_type: req.service.as_deref(),
                resource_id: None,
                detail: audit_detail,
                description: meta.description.as_deref(),
                ip_address: ip.0.as_deref(),
            })
            .await;

        return Ok((
            StatusCode::OK,
            Json(CallResponse::Called {
                result,
                action_description: meta.description,
            }),
        )
            .into_response());
    }

    // ── Platform dispatch fork ───────────────────────────────────────
    // Platform-runtime services are dispatched in-process to the handler
    // registry. No HTTP call, no secret injection, no streaming path.
    if let Some(pt) = meta.platform_target.as_ref() {
        let handler = state.platform_registry.get(&pt.action_key).ok_or_else(|| {
            AppError::Internal(format!(
                "platform handler '{}' not registered",
                pt.action_key
            ))
        })?;

        let platform_access_level = {
            let ceiling = scope.get_ceiling_for_user(ceiling_user_id).await?;
            ceiling
                .grants
                .iter()
                .filter(|g| g.template_key == "overslash")
                .filter_map(|g| AccessLevel::parse(&g.access_level))
                .max()
                .unwrap_or(AccessLevel::Read)
        };
        let ctx = crate::services::platform_caller::PlatformCallContext {
            org_id: auth.org_id,
            // The action gateway already requires an identity-bound key
            // (see `BadRequest("api key must be bound to an identity")`
            // earlier in this function), so `Some(identity_id)` here is
            // always populated.
            identity_id: Some(identity_id),
            access_level: platform_access_level,
            db: state.db.clone(),
            registry: std::sync::Arc::clone(&state.registry),
            config: state.config.clone(),
            http_client: state.http_client.clone(),
        };
        let params: std::collections::HashMap<String, serde_json::Value> =
            pt.params.clone().into_iter().collect();

        let value = handler.call(ctx, params).await?;

        let audit_detail = serde_json::json!({
            "runtime": "platform",
            "action": req.action,
            "service": req.service,
        });
        let _ = OrgScope::new(auth.org_id, state.db.clone())
            .log_audit(AuditEntry {
                org_id: auth.org_id,
                identity_id: Some(identity_id),
                action: "action.executed",
                resource_type: req.service.as_deref(),
                resource_id: None,
                detail: audit_detail,
                description: meta.description.as_deref(),
                ip_address: None,
            })
            .await;

        let result = overslash_core::types::ActionResult {
            status_code: 200,
            body: serde_json::to_string(&value).unwrap_or_default(),
            headers: std::collections::HashMap::new(),
            duration_ms: 0,
            filtered_body: None,
        };
        return Ok((
            StatusCode::OK,
            Json(CallResponse::Called {
                result,
                action_description: meta.description,
            }),
        )
            .into_response());
    }

    // Resolve secrets and inject
    let enc_key = crypto::parse_hex_key(&state.config.secrets_encryption_key)?;
    let mut secret_values = HashMap::new();
    for secret_ref in &action_req.secrets {
        let version = scope
            .get_current_secret_value(&secret_ref.name)
            .await?
            .ok_or_else(|| {
                // TODO(slice-4): replace with structured JSON-RPC `data` payload.
                AppError::BadRequest(format!(
                    "credential_missing: secret '{name}' not found. \
                     Hint: call overslash.request_secret with \
                     {{\"secret_name\":\"{name}\"}} to ask the user to provide a value.",
                    name = secret_ref.name,
                ))
            })?;
        let decrypted = crypto::decrypt(&enc_key, &version.encrypted_value)?;
        let value = String::from_utf8(decrypted)
            .map_err(|_| AppError::Internal("secret is not valid utf-8".into()))?;
        secret_values.insert(secret_ref.name.clone(), value);
    }

    let (resolved_url, resolved_headers) = inject_secrets(&action_req, &secret_values)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;
    let resolved_url = state.config.apply_base_overrides(&resolved_url);

    // Streaming proxy path
    if req.prefer_stream.unwrap_or(false) {
        let upstream = http_caller::call_streaming(
            &state.http_client,
            &action_req.method,
            &resolved_url,
            &resolved_headers,
            action_req.body.as_deref(),
        )
        .await?;

        let upstream_status = upstream.status();
        let upstream_headers = upstream.headers().clone();
        let content_length = upstream
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let mut streamed_detail = serde_json::json!({
            "method": action_req.method,
            "url": action_req.url,
            "status_code": upstream_status.as_u16(),
            "content_length": content_length,
            "service": req.service,
            "action": req.action,
        });
        let streamed_disclosed = compute_disclosure(
            &meta,
            &action_req,
            std::time::Duration::from_millis(state.config.filter_timeout_ms),
        )
        .await;
        if !streamed_disclosed.is_empty() {
            streamed_detail
                .as_object_mut()
                .expect("audit detail is a json object")
                .insert(
                    "disclosed".into(),
                    serde_json::to_value(&streamed_disclosed).unwrap_or_default(),
                );
        }

        let _ = OrgScope::new(auth.org_id, state.db.clone())
            .log_audit(AuditEntry {
                org_id: auth.org_id,
                identity_id: Some(identity_id),
                action: "action.streamed",
                resource_type: req.service.as_deref(),
                resource_id: None,
                detail: streamed_detail,
                description: meta.description.as_deref(),
                ip_address: ip.0.as_deref(),
            })
            .await;

        // Build streaming response — pipe upstream bytes through to caller
        let stream = upstream.bytes_stream();
        let body = axum::body::Body::from_stream(stream);

        let mut response = Response::builder().status(upstream_status.as_u16());
        // Forward safe upstream headers (content-type, content-length, content-disposition)
        for (name, value) in upstream_headers.iter() {
            let name_str = name.as_str();
            match name_str {
                "content-type"
                | "content-length"
                | "content-disposition"
                | "etag"
                | "last-modified"
                | "cache-control" => {
                    response = response.header(name, value);
                }
                _ => {}
            }
        }

        return Ok(response.body(body).unwrap());
    }

    // Buffered call path (default)
    let mut result = http_caller::call(
        &state.http_client,
        &action_req.method,
        &resolved_url,
        &resolved_headers,
        action_req.body.as_deref(),
        state.config.max_response_body_bytes,
    )
    .await
    .map_err(|e| match e {
        http_caller::CallError::ResponseTooLarge {
            content_length,
            content_type,
            limit_bytes,
        } => AppError::ResponseTooLarge {
            content_length,
            content_type,
            limit_bytes,
        },
        http_caller::CallError::Request(e) => AppError::Request(e),
    })?;

    // Apply the optional response filter (jq today). The original body is
    // preserved on `result.body` either way; the filtered output goes on
    // `result.filtered_body` (Some on both ok and error envelopes).
    let filter_audit = if let Some(filter) = req.filter.clone() {
        let lang = filter.lang().to_string();
        let expr = filter.expr().to_string();
        let timeout = std::time::Duration::from_millis(state.config.filter_timeout_ms);
        let filtered = response_filter::apply(filter, result.body.clone(), timeout).await;
        let audit = filter_audit_entry(&lang, &expr, &filtered);
        result.filtered_body = Some(filtered);
        Some(audit)
    } else {
        None
    };

    let mut audit_detail = serde_json::json!({
        "method": action_req.method,
        "url": action_req.url,
        "status_code": result.status_code,
        "duration_ms": result.duration_ms,
        "service": req.service,
        "action": req.action,
    });
    if let Some(filter_audit) = filter_audit {
        audit_detail
            .as_object_mut()
            .expect("audit_detail is a json object")
            .insert("filter".to_string(), filter_audit);
    }
    let called_disclosed = compute_disclosure(
        &meta,
        &action_req,
        std::time::Duration::from_millis(state.config.filter_timeout_ms),
    )
    .await;
    if !called_disclosed.is_empty() {
        audit_detail
            .as_object_mut()
            .expect("audit_detail is a json object")
            .insert(
                "disclosed".into(),
                serde_json::to_value(&called_disclosed).unwrap_or_default(),
            );
    }

    let _ = OrgScope::new(auth.org_id, state.db.clone())
        .log_audit(AuditEntry {
            org_id: auth.org_id,
            identity_id: Some(identity_id),
            action: "action.executed",
            resource_type: req.service.as_deref(),
            resource_id: None,
            detail: audit_detail,
            description: meta.description.as_deref(),
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok((
        StatusCode::OK,
        Json(CallResponse::Called {
            result,
            action_description: meta.description,
        }),
    )
        .into_response())
}

/// Compute the set of org-level service ids the caller's ceiling user can
/// see — mirrors the visibility filter applied by `routes/search.rs` and
/// `routes/services.rs::list_services`. Returning `None` (when the call
/// has no identity) preserves the existing org-key-bypasses-groups
/// behavior. The error helpers must apply this filter so we never leak
/// instance names the caller couldn't otherwise see.
async fn caller_visible_instance_ids(
    scope: &OrgScope,
    ceiling_user_id: Option<Uuid>,
) -> Result<Option<Vec<Uuid>>, AppError> {
    Ok(match ceiling_user_id {
        Some(c) => Some(scope.get_visible_service_ids(c).await?),
        None => None,
    })
}

/// List up to `ERROR_INSTANCE_HINT_CAP` active instance names that share the
/// given template key and are visible to the caller (group ceiling
/// applied). Used to populate the `available_instances` field on
/// `ServiceResolution` errors so the agent can pick a callable name
/// without re-running search.
async fn instance_names_for_template(
    scope: &OrgScope,
    identity_id: Option<Uuid>,
    ceiling_user_id: Option<Uuid>,
    template_key: &str,
) -> Result<Vec<String>, AppError> {
    let visible_ids = caller_visible_instance_ids(scope, ceiling_user_id).await?;
    let rows = scope
        .list_available_service_instances_with_groups(
            identity_id,
            ceiling_user_id,
            visible_ids.as_deref(),
        )
        .await?;
    Ok(rows
        .into_iter()
        .filter(|r| r.status == "active" && r.template_key == template_key)
        .map(|r| r.name)
        .take(ERROR_INSTANCE_HINT_CAP)
        .collect())
}

/// List up to `ERROR_INSTANCE_HINT_CAP` active instance names visible to the
/// caller (group ceiling applied), regardless of template. Used when the
/// supplied service name matches no template at all — gives the agent a
/// starting point.
async fn caller_visible_instance_names(
    scope: &OrgScope,
    identity_id: Option<Uuid>,
    ceiling_user_id: Option<Uuid>,
) -> Result<Vec<String>, AppError> {
    let visible_ids = caller_visible_instance_ids(scope, ceiling_user_id).await?;
    let rows = scope
        .list_available_service_instances_with_groups(
            identity_id,
            ceiling_user_id,
            visible_ids.as_deref(),
        )
        .await?;
    Ok(rows
        .into_iter()
        .filter(|r| r.status == "active")
        .map(|r| r.name)
        .take(ERROR_INSTANCE_HINT_CAP)
        .collect())
}

/// Resolve the right `ServiceResolution` error for an MCP runtime that
/// couldn't find a `url` or `secret_name`. Two distinct cases:
///
/// 1. **Instance found but misconfigured.** The caller passed a real
///    instance name; that instance just lacks the field. Tell the caller
///    to fix the instance — don't pretend they confused a template for an
///    instance.
/// 2. **No instance, template requires per-instance config.** This is the
///    common case the user complained about: agent passed `whatsapp`
///    instead of `whatsapp_angel`. Surface the template's instances so
///    the agent can pick one.
async fn mcp_missing_config_error(
    scope: &OrgScope,
    identity_id: Option<Uuid>,
    ceiling_user_id: Option<Uuid>,
    service_key: &str,
    instance: Option<&overslash_db::repos::service_instance::ServiceInstanceRow>,
    missing_field: &'static str,
) -> AppError {
    if let Some(inst) = instance {
        // Look up siblings under the same template so the hint can suggest
        // a different instance if this one is broken.
        let siblings = match instance_names_for_template(
            scope,
            identity_id,
            ceiling_user_id,
            &inst.template_key,
        )
        .await
        {
            Ok(names) => names.into_iter().filter(|n| n != &inst.name).collect(),
            Err(_) => Vec::new(),
        };
        let extra = if siblings.is_empty() {
            String::new()
        } else {
            format!(
                " Other instances of template '{}': {}.",
                inst.template_key,
                siblings.join(", ")
            )
        };
        return AppError::ServiceResolution {
            status: StatusCode::BAD_REQUEST,
            message: format!(
                "instance '{}' is missing `{missing_field}` configuration. \
                 Set `{missing_field}` on the instance, or pick a different instance.{extra}",
                inst.name
            ),
            matched_template: Some(inst.template_key.clone()),
            available_instances: siblings,
            hint: Some(format!(
                "Each MCP instance must carry its own `{missing_field}`; the template doesn't supply one."
            )),
        };
    }

    let available = instance_names_for_template(scope, identity_id, ceiling_user_id, service_key)
        .await
        .unwrap_or_default();
    template_without_instance_error(service_key, available)
}

fn template_without_instance_error(template_key: &str, available: Vec<String>) -> AppError {
    let message = if available.is_empty() {
        format!(
            "'{template_key}' is a service template, not a configured instance, \
             and no instances are configured for this caller. Use \
             overslash_auth.create_service_from_template to set one up."
        )
    } else {
        format!(
            "'{template_key}' is a service template, not a configured instance. \
             Pass an instance name as `service` (e.g. one of: {}). Run \
             overslash_search to discover instances.",
            available.join(", ")
        )
    };
    AppError::ServiceResolution {
        status: StatusCode::BAD_REQUEST,
        message,
        matched_template: Some(template_key.to_string()),
        available_instances: available,
        hint: Some(
            "The `service` argument must be an instance name (e.g. 'gmail_work'), not a template key.".to_string(),
        ),
    }
}

fn unknown_service_error(service_key: &str, available: Vec<String>) -> AppError {
    let message = if available.is_empty() {
        format!(
            "no service or instance named '{service_key}', and no instances are \
             configured for this caller. Use overslash_search to discover \
             services or overslash_auth.create_service_from_template to set one up."
        )
    } else {
        format!(
            "no service or instance named '{service_key}'. Available instances \
             include: {}. Run overslash_search to discover more.",
            available.join(", ")
        )
    };
    AppError::ServiceResolution {
        status: StatusCode::NOT_FOUND,
        message,
        matched_template: None,
        available_instances: available,
        hint: Some(
            "The `service` argument must match an instance name visible to the caller.".to_string(),
        ),
    }
}

/// Cheap, side-effect-free pre-resolution of a `CallRequest`.
///
/// Returns enough information for the top-level handler to:
///   1. Validate caller-supplied args against the action's schema
///      (Mode C only; A/B carry an empty schema).
///   2. Derive permission keys.
///   3. Run the caller-asserted risk gate.
///
/// Mode A / Mode B don't touch the DB. Mode C loads the service template
/// and looks up the action — no OAuth refresh, no `param_resolver` HTTP,
/// no scope checks, no audit. Used by both `/v1/actions/call` (so
/// `validate_args` can sit at the top of the handler, structurally before
/// any approval-creation work) and `/v1/actions/validate` (which only
/// runs the cheap path and never builds a real request).
///
/// For Mode C, the resolved template + instance ride along in the
/// returned tuple so `resolve_request` can reuse them and avoid the
/// duplicate DB lookup that a separate metadata pre-resolve would
/// otherwise force on the call hot path.
struct ActionMetadata {
    /// Schema for `validate_args`. Empty for Mode A/B (no contract to enforce).
    validation_params: HashMap<String, overslash_core::types::ActionParam>,
    /// Service/action keys for permission key derivation (Mode C only).
    service_scope: Option<ServiceScope>,
    /// Risk class — Mode C reads it from the template; A/B leave it
    /// `None` and the caller infers from the HTTP method.
    risk: Option<Risk>,
    /// Caller-supplied raw HTTP fields used for Mode A/B permission key
    /// derivation. Mode C ignores these (uses `service_scope`).
    raw_method: String,
    raw_url: String,
    /// Whether this request needs Layer 2 (permission-chain) gating.
    /// Mode C is always gated (templates ship with auth or are
    /// platform/MCP). Mode A is gated only when secrets are injected.
    /// Mode B is always gated.
    needs_gate: bool,
}

/// Mode-C pre-resolution: the looked-up template + instance, threaded
/// from `resolve_action_metadata` into `resolve_request` so the call
/// path doesn't re-fetch them.
struct ResolvedModeC {
    svc: overslash_core::types::ServiceDefinition,
    instance: Option<overslash_db::repos::service_instance::ServiceInstanceRow>,
}

async fn resolve_action_metadata(
    state: &AppState,
    auth: &AuthContext,
    scope: &OrgScope,
    ceiling_user_id: Uuid,
    req: &CallRequest,
) -> Result<(ActionMetadata, Option<ResolvedModeC>), AppError> {
    // Mode B: no schema, no template lookup. Permission keys are derived
    // from the caller's url/method.
    if req.connection.is_some() {
        let raw_method = req.method.clone().unwrap_or_else(|| "GET".into());
        let raw_url = req.url.clone().unwrap_or_default();
        return Ok((
            ActionMetadata {
                validation_params: HashMap::new(),
                service_scope: None,
                risk: None,
                raw_method,
                raw_url,
                needs_gate: true,
            },
            None,
        ));
    }

    // Mode C: service + action. Load template, look up action, expose
    // schema + scope for validation and permission derivation.
    if let (Some(service_key), Some(action_key)) = (&req.service, &req.action) {
        let instance = scope
            .resolve_service_instance_by_name(auth.identity_id, Some(ceiling_user_id), service_key)
            .await?;

        let svc = if let Some(ref inst) = instance {
            super::templates::resolve_template_definition(
                state,
                auth.org_id,
                auth.identity_id,
                &inst.template_key,
            )
            .await?
        } else {
            let from_template = super::templates::resolve_template_definition(
                state,
                auth.org_id,
                auth.identity_id,
                service_key,
            )
            .await
            .ok();
            match from_template.or_else(|| state.registry.get(service_key).cloned()) {
                Some(s) => s,
                None => {
                    let available = caller_visible_instance_names(
                        scope,
                        auth.identity_id,
                        Some(ceiling_user_id),
                    )
                    .await?;
                    return Err(unknown_service_error(service_key, available));
                }
            }
        };

        let action = svc.actions.get(action_key).ok_or_else(|| {
            AppError::NotFound(format!(
                "action '{action_key}' not found in service '{service_key}'"
            ))
        })?;

        // MCP-runtime templates hide disabled tools from agents — mirror
        // the check `resolve_request` makes inside the MCP fork so
        // `/validate` doesn't green-light an action that `/call` would
        // refuse with 404.
        if svc.runtime == Runtime::Mcp && action.disabled {
            return Err(AppError::NotFound(format!(
                "action '{action_key}' is disabled on service '{service_key}'"
            )));
        }

        // Platform actions use the `permission` field as the action_key
        // for permission scoping (mirrors `resolve_request`).
        let perm_action_key = if svc.runtime == Runtime::Platform {
            action
                .permission
                .as_deref()
                .unwrap_or(action_key)
                .to_string()
        } else {
            action_key.clone()
        };

        // `needs_gate` is a *conservative estimate* of `/call`'s
        // post-resolve `meta.auth_injected`. MCP and Platform always
        // inject auth (gate=true). HTTP estimates from cheap signals:
        // a template auth method or an instance binding (connection or
        // secret). The estimate can over-gate vs. `/call` in one
        // direction only — when an HTTP service has auth declared but
        // OAuth token resolution at `/call` time fails, `/call` sets
        // `auth_injected=false` and skips Layer 2, while `/validate`
        // (which never resolves tokens, by design) keeps the gate on
        // and reports `would_require_approval`. That's a worse-case
        // surface for the dry-run, not a silent allow, so it's worth
        // the runtime savings of skipping the OAuth round-trip.
        let auth_injected_estimate = match svc.runtime {
            Runtime::Mcp | Runtime::Platform => true,
            Runtime::Http => {
                !svc.auth.is_empty()
                    || instance
                        .as_ref()
                        .map(|i| i.connection_id.is_some() || i.secret_name.is_some())
                        .unwrap_or(false)
            }
        };

        let metadata = ActionMetadata {
            validation_params: action.params.clone(),
            service_scope: Some(ServiceScope {
                service_key: service_key.clone(),
                action_key: perm_action_key,
                scope_param: action.scope_param.clone(),
            }),
            risk: Some(action.risk),
            raw_method: String::new(),
            raw_url: String::new(),
            needs_gate: !req.secrets.is_empty() || auth_injected_estimate,
        };
        return Ok((metadata, Some(ResolvedModeC { svc, instance })));
    }

    // Mode A: raw HTTP. No schema. Permission keys from caller's url/method.
    let raw_method = req.method.clone().ok_or_else(|| {
        AppError::BadRequest("either 'method'+'url' or 'service'+'action' required".into())
    })?;
    let raw_url = req
        .url
        .clone()
        .ok_or_else(|| AppError::BadRequest("'url' required for raw HTTP mode".into()))?;
    Ok((
        ActionMetadata {
            validation_params: HashMap::new(),
            service_scope: None,
            risk: None,
            raw_method,
            raw_url,
            needs_gate: !req.secrets.is_empty(),
        },
        None,
    ))
}

/// Build the structured 400 returned when caller args don't match an
/// action's declared input contract. Surfaces the full `required` /
/// `allowed` schema so an agent runner can hand a clean shape to the LLM
/// instead of grepping a sentence.
fn invalid_action_args_error(
    params: &HashMap<String, overslash_core::types::ActionParam>,
    errors: Vec<overslash_core::openapi::validate_input::ArgError>,
) -> AppError {
    let mut required: Vec<String> = params
        .iter()
        .filter(|(_, p)| p.required)
        .map(|(k, _)| k.clone())
        .collect();
    required.sort();
    let mut allowed: Vec<String> = params.keys().cloned().collect();
    allowed.sort();
    let detail = overslash_core::openapi::validate_input::format_errors(&errors);
    let errors = errors.into_iter().map(Into::into).collect();
    AppError::InvalidActionArgs {
        required,
        allowed,
        errors,
        detail,
    }
}

/// Resolve a CallRequest into a concrete ActionRequest + metadata.
/// Handles Mode A (raw HTTP), Mode B (connection-based), and Mode C (service+action).
///
/// `pre_resolved_mode_c` lets the caller hand in the template+instance
/// already looked up by `resolve_action_metadata`, so Mode C doesn't
/// pay for a duplicate DB lookup. `None` is fine for the validate path
/// or for callers that don't share that work.
async fn resolve_request(
    state: &AppState,
    auth: &AuthContext,
    scope: &OrgScope,
    identity_id: Uuid,
    ceiling_user_id: Uuid,
    req: &CallRequest,
    pre_resolved_mode_c: Option<ResolvedModeC>,
) -> Result<(ActionRequest, ResolvedMeta), AppError> {
    // Mode B: explicit connection — resolve OAuth token and inject as header
    if let Some(conn_id) = req.connection {
        let conn = scope.get_connection(conn_id).await?;
        let conn = crate::ownership::require_org_owned(conn, auth.org_id, "connection")?;

        let enc_key = crypto::parse_hex_key(&state.config.secrets_encryption_key)?;
        let provider_key = conn.provider_key.clone();

        let creds = crate::services::client_credentials::resolve(
            &state.db,
            &enc_key,
            auth.org_id,
            auth.identity_id,
            &provider_key,
            Some(&conn),
            None,
        )
        .await?;

        let access_token = match crate::services::oauth::resolve_access_token(
            scope,
            &state.http_client,
            &enc_key,
            &conn,
            &creds.client_id,
            &creds.client_secret,
        )
        .await
        {
            Ok(token) => token,
            Err(e) => {
                return Err(
                    oauth_error_to_app_error(state, scope.org_id(), identity_id, &conn, e).await,
                );
            }
        };

        let method = req.method.clone().unwrap_or_else(|| "GET".into());
        let url = req
            .url
            .clone()
            .ok_or_else(|| AppError::BadRequest("'url' required for connection mode".into()))?;

        let mut headers = req.headers.clone();
        headers.insert("Authorization".into(), format!("Bearer {access_token}"));

        return Ok((
            ActionRequest {
                method,
                url,
                headers,
                body: req.body.clone(),
                secrets: vec![],
            },
            ResolvedMeta {
                description: Some(format!("OAuth request via {provider_key} connection")),
                auth_injected: true,
                service_scope: None,
                risk: None,
                disclose: Vec::new(),
                redact: Vec::new(),
                params: HashMap::new(),
                mcp_target: None,
                platform_target: None,
            },
        ));
    }

    // Mode C: service + action
    if let (Some(service_key), Some(action_key)) = (&req.service, &req.action) {
        // Reuse the template/instance lookup performed by
        // `resolve_action_metadata` if the caller threaded it through.
        // Otherwise fall back to the same DB walk it would have run.
        let (instance, svc) = if let Some(pre) = pre_resolved_mode_c {
            (pre.instance, pre.svc)
        } else {
            let instance = scope
                .resolve_service_instance_by_name(
                    auth.identity_id,
                    Some(ceiling_user_id),
                    service_key,
                )
                .await?;

            let svc = if let Some(ref inst) = instance {
                // Instance exists — resolve its template; propagate errors (don't fall back
                // to global registry, which could match on the wrong key)
                super::templates::resolve_template_definition(
                    state,
                    auth.org_id,
                    auth.identity_id,
                    &inst.template_key,
                )
                .await?
            } else {
                // No instance — try unified resolution, then fall back to global registry.
                // When neither matches, surface a structured ServiceResolution
                // error that names a few instances the agent could call
                // instead, so the agent doesn't dead-end on "service not found".
                let from_template = super::templates::resolve_template_definition(
                    state,
                    auth.org_id,
                    auth.identity_id,
                    service_key,
                )
                .await
                .ok();
                match from_template.or_else(|| state.registry.get(service_key).cloned()) {
                    Some(s) => s,
                    None => {
                        let available = caller_visible_instance_names(
                            scope,
                            auth.identity_id,
                            Some(ceiling_user_id),
                        )
                        .await?;
                        return Err(unknown_service_error(service_key, available));
                    }
                }
            };
            (instance, svc)
        };

        let action = svc.actions.get(action_key).ok_or_else(|| {
            AppError::NotFound(format!(
                "action '{action_key}' not found in service '{service_key}'"
            ))
        })?;

        // Note: argument validation against `action.params` happens
        // upstream in `call_action_impl` via `resolve_action_metadata`,
        // before any permission/approval work. Keeping it out of here
        // means the validation gate is structurally guaranteed to run
        // before the approval-creation branch — a future refactor of
        // this function can't accidentally reorder past it.

        // ── MCP runtime fork ─────────────────────────────────────────
        // Disabled tools are invisible to agents even when they exist in
        // the compiled action map. Every MCP call force-gates (auth_injected)
        // so empty-auth MCP templates cannot bypass Layer 2 approvals.
        if svc.runtime == Runtime::Mcp {
            if action.disabled {
                return Err(AppError::NotFound(format!(
                    "action '{action_key}' is disabled on service '{service_key}'"
                )));
            }
            let mcp_spec = svc.mcp.clone().ok_or_else(|| {
                AppError::Internal(format!(
                    "service '{service_key}' has runtime=mcp but no mcp block"
                ))
            })?;

            // Resolve URL: instance wins, template is fallback.
            let resolved_url = match instance
                .as_ref()
                .and_then(|i| i.url.as_deref().map(str::to_string))
                .or(mcp_spec.url.clone())
            {
                Some(u) => u,
                None => {
                    return Err(mcp_missing_config_error(
                        scope,
                        auth.identity_id,
                        Some(ceiling_user_id),
                        service_key,
                        instance.as_ref(),
                        "url",
                    )
                    .await);
                }
            };

            // Resolve bearer secret_name: instance wins, template is fallback.
            let resolved_auth = match &mcp_spec.auth {
                McpAuth::None => McpAuth::None,
                McpAuth::Bearer {
                    secret_name: tpl_sn,
                } => {
                    let sn = match instance
                        .as_ref()
                        .and_then(|i| i.secret_name.as_deref())
                        .or(tpl_sn.as_deref())
                    {
                        Some(s) => s.to_string(),
                        None => {
                            return Err(mcp_missing_config_error(
                                scope,
                                auth.identity_id,
                                Some(ceiling_user_id),
                                service_key,
                                instance.as_ref(),
                                "secret_name",
                            )
                            .await);
                        }
                    };
                    McpAuth::Bearer {
                        secret_name: Some(sn),
                    }
                }
            };

            let tool = action
                .mcp_tool
                .clone()
                .unwrap_or_else(|| action_key.clone());
            let arguments = serde_json::to_value(&req.params).unwrap_or(serde_json::Value::Null);
            // Interpolate `{param}` placeholders in the action description
            // using the caller's supplied params. Mirrors the HTTP path so
            // approvals and audit rows name the actual target — e.g.
            // "Search issues in team ENG" instead of "Search issues in team
            // {team}". Resolvers don't apply (MCP has no HTTP parameter
            // schema), so we pass an empty resolved map.
            let interpolated = overslash_core::description::interpolate_description_with_resolved(
                &action.description,
                &req.params,
                &std::collections::HashMap::new(),
            );
            let description = format!("{interpolated} ({})", svc.display_name);
            return Ok((
                ActionRequest {
                    method: String::new(),
                    url: resolved_url.clone(),
                    headers: HashMap::new(),
                    body: None,
                    secrets: Vec::new(),
                },
                ResolvedMeta {
                    description: Some(description),
                    auth_injected: true,
                    service_scope: Some(ServiceScope {
                        service_key: service_key.clone(),
                        action_key: action_key.clone(),
                        scope_param: action.scope_param.clone(),
                    }),
                    risk: Some(action.risk),
                    disclose: action.disclose.clone(),
                    redact: action.redact.clone(),
                    params: req.params.clone(),
                    mcp_target: Some(McpTarget {
                        url: resolved_url,
                        auth: resolved_auth,
                        tool,
                        arguments,
                    }),
                    platform_target: None,
                },
            ));
        }

        // ── Platform runtime fork ─────────────────────────────────────
        // Platform-runtime services route to the in-process handler registry.
        // They have no HTTP method/path, no secret injection. `auth_injected`
        // is set to true so the permission chain is always evaluated.
        if svc.runtime == Runtime::Platform {
            // Use the permission field as the action_key for PermissionKey derivation
            // so `list_templates`/`get_template`/`create_template` all resolve to
            // the `overslash:manage_templates_own:*` permission anchor.
            let perm_action_key = action
                .permission
                .as_deref()
                .unwrap_or(action_key)
                .to_string();
            let description = format!("{} ({})", action.description, svc.display_name);
            let params_map: serde_json::Map<String, serde_json::Value> =
                req.params.clone().into_iter().collect();
            return Ok((
                ActionRequest {
                    method: String::new(),
                    url: String::new(),
                    headers: HashMap::new(),
                    body: None,
                    secrets: Vec::new(),
                },
                ResolvedMeta {
                    description: Some(description),
                    auth_injected: true,
                    service_scope: Some(ServiceScope {
                        service_key: service_key.clone(),
                        action_key: perm_action_key,
                        scope_param: action.scope_param.clone(),
                    }),
                    risk: Some(action.risk),
                    disclose: Vec::new(),
                    redact: Vec::new(),
                    params: HashMap::new(),
                    mcp_target: None,
                    platform_target: Some(PlatformTarget {
                        action_key: action_key.clone(),
                        params: params_map,
                    }),
                },
            ));
        }

        let host = svc
            .hosts
            .first()
            .ok_or_else(|| AppError::Internal(format!("service '{service_key}' has no hosts")))?;

        let mut path = action.path.clone();
        for (k, v) in &req.params {
            let placeholder = format!("{{{k}}}");
            if path.contains(&placeholder) {
                let val = v.as_str().unwrap_or(&v.to_string()).to_string();
                path = path.replace(&placeholder, &val);
            }
        }

        // Support hosts with explicit scheme (e.g. "http://localhost:1234" for tests)
        let base_url = if host.contains("://") {
            format!("{host}{path}")
        } else {
            format!("https://{host}{path}")
        };

        let non_path_params: HashMap<String, serde_json::Value> = req
            .params
            .iter()
            .filter(|(k, _)| !action.path.contains(&format!("{{{k}}}")))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let (url, body) = if action.method == "GET" || action.method == "HEAD" {
            // Append non-path params as query string
            let url = if non_path_params.is_empty() {
                base_url
            } else {
                let qs = non_path_params
                    .iter()
                    .map(|(k, v)| {
                        let val = v.as_str().unwrap_or(&v.to_string()).to_string();
                        format!("{k}={}", urlencoding::encode(&val))
                    })
                    .collect::<Vec<_>>()
                    .join("&");
                format!("{base_url}?{qs}")
            };
            (url, None)
        } else {
            // Non-path params become JSON body
            let body = if non_path_params.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&non_path_params).unwrap_or_default())
            };
            (base_url, body)
        };

        let mut headers = HashMap::new();
        if body.is_some() {
            headers.insert("Content-Type".to_string(), "application/json".to_string());
        }

        // Scope gate: if the action declares `required_scopes`, and the
        // connection we'd use to auth doesn't carry all of them, return
        // `missing_scopes` with the upgrade URL *before* the outgoing call
        // happens. This is the fail-fast path promised by SPEC §9 — we don't
        // want the provider's 403 to surface as a generic upstream error.
        check_required_scopes(state, scope, identity_id, instance.as_ref(), &svc, action).await?;

        // Auth resolution: if instance has a bound connection/secret, use that;
        // otherwise fall back to auto-resolve from the template's auth config.
        // RefreshFailed / NoRefreshToken from the resolver bubble up as
        // `ReauthRequired` (with a freshly-minted gated URL) instead of being
        // swallowed and surfaced as opaque upstream errors downstream.
        let (secrets, oauth_injected) = if let Some(ref inst) = instance {
            resolve_instance_auth(
                state,
                scope,
                identity_id,
                inst,
                &svc,
                &req.secrets,
                &mut headers,
            )
            .await?
        } else {
            resolve_service_auth(state, scope, identity_id, &svc, &req.secrets, &mut headers)
                .await?
        };

        // After resolution, if the template declares OAuth and *nothing*
        // was injected — no header, no secret, no connection — the
        // upstream call is going to fail with whatever the provider
        // returns when faced with an empty Authorization header. Catch
        // it here and hand the agent a freshly-minted gated URL it can
        // forward to the user. Same envelope shape as the RefreshFailed
        // path so MCP clients only need one branch.
        //
        // ApiKey-only templates aren't covered: there's no OAuth provider
        // to mint a URL for, and the existing secret-not-found errors
        // already give the operator a "set this secret" path. MCP-bearer
        // templates take a different fork (the runtime check above) and
        // never reach this branch.
        if !oauth_injected && secrets.is_empty() {
            if let Some(err) = needs_authentication_for_service(
                state,
                scope.org_id(),
                identity_id,
                &svc,
                action,
                instance.as_ref(),
                service_key,
            )
            .await?
            {
                return Err(err);
            }
        }

        let resolver_base = if host.contains("://") {
            host.to_string()
        } else {
            format!("https://{host}")
        };
        let resolved = crate::services::param_resolver::resolve_display_params(
            &state.http_client,
            &resolver_base,
            &headers,
            action,
            &req.params,
        )
        .await;

        let interpolated = overslash_core::description::interpolate_description_with_resolved(
            &action.description,
            &req.params,
            &resolved,
        );
        let description = format!("{interpolated} ({})", svc.display_name);

        let action_risk = action.risk;

        return Ok((
            ActionRequest {
                method: action.method.clone(),
                url,
                headers,
                body,
                secrets,
            },
            ResolvedMeta {
                description: Some(description),
                auth_injected: oauth_injected,
                service_scope: Some(ServiceScope {
                    service_key: service_key.clone(),
                    action_key: action_key.clone(),
                    scope_param: action.scope_param.clone(),
                }),
                risk: Some(action_risk),
                disclose: action.disclose.clone(),
                redact: action.redact.clone(),
                params: req.params.clone(),
                mcp_target: None,
                platform_target: None,
            },
        ));
    }

    // Mode A: raw HTTP
    let method = req.method.clone().ok_or_else(|| {
        AppError::BadRequest("either 'method'+'url' or 'service'+'action' required".into())
    })?;
    let url = req
        .url
        .clone()
        .ok_or_else(|| AppError::BadRequest("'url' required for raw HTTP mode".into()))?;

    let description = {
        let display_url = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(&url);
        format!("{method} {display_url}")
    };

    Ok((
        ActionRequest {
            method,
            url,
            headers: req.headers.clone(),
            body: req.body.clone(),
            secrets: req.secrets.clone(),
        },
        ResolvedMeta {
            description: Some(description),
            auth_injected: false,
            service_scope: None,
            risk: None,
            disclose: Vec::new(),
            redact: Vec::new(),
            params: HashMap::new(),
            mcp_target: None,
            platform_target: None,
        },
    ))
}

/// Classify an OAuth resolver error so the action handler can respond
/// with the right HTTP status. The split mirrors RFC 7231 semantics:
///   * `Reauth(reason)` → 401, the user can fix it by clicking a link.
///   * `Internal` → 500, server-side problem the user can't fix
///     (crypto, DB, parse, provider config missing from the DB).
///   * `Upstream` → 502, the *provider* is the broken party (transport
///     error, provider rejected the credentials with a non-refresh body).
enum OAuthOutcome {
    Reauth(&'static str),
    Internal,
    Upstream,
}

fn classify_oauth(err: &OAuthError) -> OAuthOutcome {
    match err {
        OAuthError::RefreshFailed(_) => OAuthOutcome::Reauth("refresh_token_failed"),
        OAuthError::NoRefreshToken => OAuthOutcome::Reauth("no_refresh_token"),
        OAuthError::CryptoError(_)
        | OAuthError::DbError(_)
        | OAuthError::ParseError(_)
        | OAuthError::ProviderNotFound(_) => OAuthOutcome::Internal,
        OAuthError::HttpError(_) | OAuthError::TokenExchangeFailed(_) => OAuthOutcome::Upstream,
    }
}

/// Map an `OAuthError` to the right `AppError` response shape, given a
/// connection that the user could potentially reauth against. Centralises
/// the Reauth-vs-Internal-vs-Upstream split so both auth resolvers
/// (instance- and service-level) make the same call.
///
/// Mode B and the instance-bound branch of Mode C call this directly:
/// they target a *specific* connection, so an upstream blip can't
/// recover by trying another provider — we surface BadGateway. The
/// Mode C provider loop calls a non-bailing variant: see
/// [`oauth_error_to_app_error_or_continue`].
async fn oauth_error_to_app_error(
    state: &AppState,
    org_id: Uuid,
    caller_identity_id: Uuid,
    conn: &overslash_db::repos::connection::ConnectionRow,
    err: OAuthError,
) -> AppError {
    match classify_oauth(&err) {
        OAuthOutcome::Reauth(reason) => {
            reauth_required_envelope(state, org_id, caller_identity_id, conn, reason, &err).await
        }
        OAuthOutcome::Internal => {
            tracing::error!("OAuth internal error on connection {}: {err}", conn.id);
            AppError::Internal(format!("OAuth token resolution failed: {err}"))
        }
        OAuthOutcome::Upstream => {
            AppError::BadGateway(format!("OAuth provider returned an error: {err}"))
        }
    }
}

/// Variant used inside the multi-provider loop in `resolve_service_auth`:
/// returns `Some(err)` for outcomes that should bail the whole loop
/// (Reauth — actionable for the user; Internal — won't recover by
/// trying another provider), and `None` for Upstream errors — those
/// log + `continue` so a transient blip on provider A doesn't break
/// authentication via provider B.
async fn oauth_error_to_app_error_or_continue(
    state: &AppState,
    org_id: Uuid,
    caller_identity_id: Uuid,
    conn: &overslash_db::repos::connection::ConnectionRow,
    err: OAuthError,
) -> Option<AppError> {
    match classify_oauth(&err) {
        OAuthOutcome::Reauth(reason) => Some(
            reauth_required_envelope(state, org_id, caller_identity_id, conn, reason, &err).await,
        ),
        OAuthOutcome::Internal => {
            tracing::error!("OAuth internal error on connection {}: {err}", conn.id);
            Some(AppError::Internal(format!(
                "OAuth token resolution failed: {err}"
            )))
        }
        OAuthOutcome::Upstream => {
            tracing::warn!(
                "upstream OAuth error on provider '{}'; trying next provider: {err}",
                conn.provider_key
            );
            None
        }
    }
}

/// Build the structured `ReauthRequired` envelope: mint a gated upgrade URL
/// pointing at the existing connection (so the OAuth callback updates the
/// row in place), pack it together with the caller-supplied `reason` tag,
/// and fall back to `Internal` if the URL mint itself fails — at that
/// point we genuinely can't help the user from this response and the
/// operator needs to investigate.
async fn reauth_required_envelope(
    state: &AppState,
    org_id: Uuid,
    caller_identity_id: Uuid,
    conn: &overslash_db::repos::connection::ConnectionRow,
    reason: &'static str,
    underlying: &OAuthError,
) -> AppError {
    match platform_connections::mint_upgrade_auth_url(state, org_id, caller_identity_id, conn, &[])
        .await
    {
        Ok(auth_url) => AppError::ReauthRequired {
            connection_id: conn.id,
            auth_url,
            reason: reason.to_string(),
        },
        Err(mint_err) => {
            tracing::error!(
                "failed to mint reauth url for connection {}: {mint_err}",
                conn.id
            );
            AppError::Internal(format!("OAuth token resolution failed: {underlying}"))
        }
    }
}

/// Mode C: when auth resolution returned no header / no secret on a service
/// whose template requires auth, the upstream call is going to fail with
/// whatever shape the provider returns to an empty Authorization header.
/// Detect that *here* and hand the agent a structured `NeedsAuthentication`
/// envelope with a freshly-minted gated URL, so they can forward it to the
/// user instead of forwarding an opaque 401-from-Google.
///
/// Returns:
/// - `Ok(Some(err))` — the template declares OAuth and the URL mint
///   succeeded; caller should `Err(err)` out of `resolve_request`.
/// - `Ok(None)` — the template has no OAuth provider declared (the
///   no-op happy path for free templates and ApiKey-only templates).
/// - `Err(_)` — an internal failure during URL mint (DB, crypto).
///   Surfaced so the caller can decide whether to wrap or bail.
async fn needs_authentication_for_service(
    state: &AppState,
    org_id: Uuid,
    caller_identity_id: Uuid,
    svc: &overslash_core::types::ServiceDefinition,
    action: &overslash_core::types::ServiceAction,
    instance: Option<&overslash_db::repos::service_instance::ServiceInstanceRow>,
    service_key: &str,
) -> Result<Option<AppError>, AppError> {
    // First OAuth provider declared by the template. If the template has
    // multiple OAuth providers (rare), we pick the first — that mirrors
    // what `resolve_service_auth` already does.
    let provider = svc.auth.iter().find_map(|a| match a {
        overslash_core::types::ServiceAuth::OAuth { provider, .. } => Some(provider.clone()),
        _ => None,
    });

    // Templates that don't declare OAuth: nothing to mint a URL for. The
    // template might require an API key, but we don't have a click-to-fix
    // recovery shape for that today — the existing
    // `secret-not-found`-style errors handle it. Future: emit a different
    // typed envelope with a "go to dashboard / set this secret" hint.
    let Some(provider) = provider else {
        return Ok(None);
    };

    // Request the action's declared `required_scopes` up-front so the user
    // only sees one consent screen instead of two (consenting to nothing,
    // then being bounced through `missing_scopes` for the real set). When
    // the action declares no scopes, the empty vec is what we want anyway.
    //
    // If the URL mint fails (most commonly: provider row is missing from
    // the DB so the `oauth_provider::get_by_key` lookup 404s, but also
    // crypto/DB hiccups), don't propagate the raw NotFound — the client
    // would see a 404 on `/v1/actions/call` and think the *action* is
    // missing. Surface as Internal so operators can spot the misconfig,
    // and stop trying to mint a URL the user can't act on anyway.
    let auth_url = match platform_connections::mint_initial_auth_url(
        state,
        org_id,
        caller_identity_id,
        &provider,
        &action.required_scopes,
        None,
    )
    .await
    {
        Ok(url) => url,
        Err(mint_err) => {
            tracing::error!(
                "needs_authentication: failed to mint initial auth url for provider '{provider}': {mint_err}"
            );
            return Err(AppError::Internal(format!(
                "OAuth provider '{provider}' is not configured for this org: {mint_err}"
            )));
        }
    };

    Ok(Some(AppError::NeedsAuthentication {
        service: Some(service_key.to_string()),
        service_instance_id: instance.map(|i| i.id),
        connection_id: None,
        auth_url,
    }))
}

/// Auto-resolve auth for a service. Uses the identity's OAuth connection when the
/// template declares OAuth auth. Returns (secret_refs, oauth_was_injected).
/// If an OAuth token is resolved, it's injected directly into headers (not via SecretRef).
///
/// `RefreshFailed` / `NoRefreshToken` from the OAuth resolver bubble up as
/// `AppError::ReauthRequired` (with a freshly-minted gated URL) so the
/// caller doesn't see the upstream call fail with an opaque 5xx. Other
/// resolver errors (crypto/db/provider lookup) keep the legacy
/// fall-through behavior — they don't have a clean "click here to fix"
/// recovery shape.
async fn resolve_service_auth(
    state: &AppState,
    scope: &OrgScope,
    identity_id: Uuid,
    svc: &overslash_core::types::ServiceDefinition,
    explicit_secrets: &[SecretRef],
    headers: &mut HashMap<String, String>,
) -> Result<(Vec<SecretRef>, bool), AppError> {
    if !explicit_secrets.is_empty() {
        return Ok((explicit_secrets.to_vec(), false));
    }

    let org_id = scope.org_id();
    // The auto-resolve path is per-identity: build a UserScope so the
    // connection lookup is bounded by `(org_id, user_id)`.
    let user_scope = overslash_db::scopes::UserScope::new(org_id, identity_id, scope.db().clone());

    // Try OAuth first: check if identity has a connection for this service's OAuth provider
    // The encryption key is process-global, so a parse error here can't be
    // recovered by trying the next provider — propagate Internal once,
    // outside the loop.
    let enc_key = crypto::parse_hex_key(&state.config.secrets_encryption_key)
        .map_err(|e| AppError::Internal(format!("encryption key invalid: {e}")))?;

    // Track the first transient upstream error we hit while iterating
    // providers. If no provider succeeds AND at least one had a
    // connection that failed transiently, return BadGateway instead of
    // falling through to `needs_authentication` — otherwise the caller
    // would prompt the user to create a *duplicate* connection on a
    // template they're already authenticated against, just because the
    // provider had a hiccup.
    let mut first_upstream_blip: Option<String> = None;

    for service_auth in &svc.auth {
        if let overslash_core::types::ServiceAuth::OAuth {
            provider,
            token_injection,
            ..
        } = service_auth
        {
            // Per-provider lookup. `Ok(None)` is the legitimate "no
            // connection yet" case — try the next provider. A DB blip
            // (Err) we log and continue too, so a transient issue on
            // provider A doesn't break a multi-provider template that
            // could authenticate via provider B.
            let conn = match user_scope.find_my_connection_by_provider(provider).await {
                Ok(Some(conn)) => conn,
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(
                        "connection lookup for provider '{provider}' failed; trying next provider: {e}"
                    );
                    continue;
                }
            };
            // Per-provider credentials resolution. Failures here are
            // typically "no BYOC for provider X and no env fallback" — a
            // legitimate "try the next provider" signal. Log and continue
            // instead of bailing the whole loop.
            let creds = match crate::services::client_credentials::resolve(
                &state.db,
                &enc_key,
                org_id,
                Some(identity_id),
                provider,
                Some(&conn),
                None,
            )
            .await
            {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(
                        "OAuth client credentials resolution for '{provider}' failed; trying next provider: {e}"
                    );
                    continue;
                }
            };

            match crate::services::oauth::resolve_access_token(
                scope,
                &state.http_client,
                &enc_key,
                &conn,
                &creds.client_id,
                &creds.client_secret,
            )
            .await
            {
                Ok(access_token) => {
                    // Inject directly into headers
                    let value = match &token_injection.prefix {
                        Some(p) => format!("{p}{access_token}"),
                        None => access_token,
                    };
                    if let Some(header_name) = &token_injection.header_name {
                        headers.insert(header_name.clone(), value);
                    }
                    return Ok((vec![], true));
                }
                Err(e) => {
                    let err_str = e.to_string();
                    if let Some(err) =
                        oauth_error_to_app_error_or_continue(state, org_id, identity_id, &conn, e)
                            .await
                    {
                        return Err(err);
                    }
                    // Upstream blip — keep trying the next OAuth provider
                    // in the template, but remember it so we can surface
                    // BadGateway after the loop instead of misleading the
                    // user into a duplicate-connection prompt.
                    if first_upstream_blip.is_none() {
                        first_upstream_blip =
                            Some(format!("provider '{}': {err_str}", conn.provider_key));
                    }
                    continue;
                }
            }
        }
    }

    if let Some(detail) = first_upstream_blip {
        return Err(AppError::BadGateway(format!(
            "OAuth provider returned an error: {detail}"
        )));
    }
    Ok((Vec::new(), false))
}

/// Fail-fast scope gate: before the outgoing request is built, compare the
/// connection's granted scopes against what this action declares. When a
/// template doesn't declare `required_scopes`, returns `Ok(())` — preserves
/// today's behavior for templates that haven't adopted the field.
///
/// Returns `AppError::Forbidden` with a body carrying `missing_scopes` and an
/// `upgrade_url` the caller can `POST` to kick off an incremental-auth flow.
async fn check_required_scopes(
    state: &AppState,
    scope: &OrgScope,
    identity_id: Uuid,
    instance: Option<&overslash_db::repos::service_instance::ServiceInstanceRow>,
    svc: &overslash_core::types::ServiceDefinition,
    action: &overslash_core::types::ServiceAction,
) -> Result<(), AppError> {
    if action.required_scopes.is_empty() {
        return Ok(());
    }

    // Find the OAuth service-auth entry; a template without OAuth can't have
    // its scopes checked here.
    let provider = svc.auth.iter().find_map(|a| match a {
        overslash_core::types::ServiceAuth::OAuth { provider, .. } => Some(provider.clone()),
        _ => None,
    });
    let Some(provider) = provider else {
        return Ok(());
    };

    let org_id = scope.org_id();
    let user_scope = overslash_db::scopes::UserScope::new(org_id, identity_id, scope.db().clone());

    // Resolve the connection the exec path would actually use — instance's
    // explicit binding takes precedence, else `find_my_connection_by_provider`.
    let connection = if let Some(inst) = instance {
        if let Some(conn_id) = inst.connection_id {
            scope.get_connection(conn_id).await?
        } else {
            user_scope.find_my_connection_by_provider(&provider).await?
        }
    } else {
        user_scope.find_my_connection_by_provider(&provider).await?
    };

    let Some(connection) = connection else {
        // Fall through — auth resolution will report the missing connection
        // in its own way. The scope gate is only meaningful when a
        // connection exists.
        return Ok(());
    };

    let granted: std::collections::HashSet<&str> =
        connection.scopes.iter().map(String::as_str).collect();
    let missing: Vec<String> = action
        .required_scopes
        .iter()
        .filter(|s| !granted.contains(s.as_str()))
        .cloned()
        .collect();

    if missing.is_empty() {
        return Ok(());
    }

    // Mint a chat-deliverable gated `/connect-authorize` URL that, when
    // consumed, runs an incremental-scope OAuth flow against the existing
    // connection (segment 7 of the OAuth state carries `connection.id`).
    // The legacy `upgrade_url` field — pointing at the raw REST endpoint
    // `/v1/connections/{id}/upgrade_scopes` — is preserved alongside for
    // white-label callers that drive the API directly. Agents should use
    // `auth_url`.
    //
    // If the mint fails (DB hiccup, provider-key lookup), don't break the
    // missing_scopes contract by surfacing the mint error: log it and omit
    // `auth_url` from the body. The dashboard / REST clients will fall
    // back to `upgrade_url`, and the client still gets the correct 403
    // missing_scopes shape.
    let auth_url = match platform_connections::mint_upgrade_auth_url(
        state,
        scope.org_id(),
        identity_id,
        &connection,
        &missing,
    )
    .await
    {
        Ok(url) => Some(url),
        Err(e) => {
            tracing::error!(
                "missing_scopes: failed to mint upgrade auth url for connection {}: {e}",
                connection.id
            );
            None
        }
    };
    let upgrade_url = format!(
        "{}/v1/connections/{}/upgrade_scopes",
        state.config.public_url.trim_end_matches('/'),
        connection.id
    );
    let mut body = serde_json::json!({
        "error": "missing_scopes",
        "missing": missing,
        "connection_id": connection.id,
        "upgrade_url": upgrade_url,
    });
    if let Some(url) = auth_url {
        body["auth_url"] = serde_json::Value::String(url);
    }
    Err(AppError::Forbidden(body.to_string()))
}

/// Resolve auth for a service instance. If the instance has a bound connection_id or secret_name,
/// use that directly. Otherwise fall back to auto-resolve from the template's auth config.
async fn resolve_instance_auth(
    state: &AppState,
    scope: &OrgScope,
    identity_id: Uuid,
    instance: &overslash_db::repos::service_instance::ServiceInstanceRow,
    svc: &overslash_core::types::ServiceDefinition,
    explicit_secrets: &[SecretRef],
    headers: &mut HashMap<String, String>,
) -> Result<(Vec<SecretRef>, bool), AppError> {
    if !explicit_secrets.is_empty() {
        return Ok((explicit_secrets.to_vec(), false));
    }

    let org_id = scope.org_id();
    // If instance has a bound connection, use it directly. Errors here
    // (encryption-key parse, client-credentials resolve) are server-side
    // problems on the *specific* connection the instance is bound to —
    // falling back to template-level resolve_service_auth would either
    // re-trigger the same crypto error or pick an unrelated connection
    // that the operator never asked us to use. Propagate Internal so the
    // operator can see the real cause; mirror what resolve_service_auth
    // does for its access_token errors.
    if let Some(conn_id) = instance.connection_id {
        // Explicit `match` (rather than `if let Ok(Some(...))`) so a DB
        // error doesn't get silently treated as "no connection bound" and
        // misrouted to a `needs_authentication` 401. Ok(None) — the
        // connection was deleted out from under the instance — *does*
        // fall through to the template-auto-resolve / API-key path, which
        // will pick up any newly-minted connection on the calling
        // identity (e.g. one the user just created via the gated link
        // returned by `needs_authentication_for_service`). So a
        // disconnected instance recovers on the next call after reauth
        // without us needing to touch the binding here.
        let conn = match scope.get_connection(conn_id).await {
            Ok(Some(c)) => Some(c),
            Ok(None) => None,
            Err(e) => {
                return Err(AppError::Internal(format!(
                    "lookup of instance-bound connection {conn_id} failed: {e}"
                )));
            }
        };
        if let Some(conn) = conn {
            let enc_key = crypto::parse_hex_key(&state.config.secrets_encryption_key)
                .map_err(|e| AppError::Internal(format!("encryption key invalid: {e}")))?;
            let creds = crate::services::client_credentials::resolve(
                &state.db,
                &enc_key,
                org_id,
                Some(identity_id),
                &conn.provider_key,
                Some(&conn),
                None,
            )
            .await
            .map_err(|e| {
                AppError::Internal(format!(
                    "OAuth client credentials resolution for instance-bound connection {} failed: {e}",
                    conn.id
                ))
            })?;

            match crate::services::oauth::resolve_access_token(
                scope,
                &state.http_client,
                &enc_key,
                &conn,
                &creds.client_id,
                &creds.client_secret,
            )
            .await
            {
                Ok(access_token) => {
                    // Find the matching token_injection from the template's auth config
                    for service_auth in &svc.auth {
                        if let overslash_core::types::ServiceAuth::OAuth {
                            provider,
                            token_injection,
                            ..
                        } = service_auth
                        {
                            if *provider == conn.provider_key {
                                let value = match &token_injection.prefix {
                                    Some(p) => format!("{p}{access_token}"),
                                    None => access_token,
                                };
                                if let Some(header_name) = &token_injection.header_name {
                                    headers.insert(header_name.clone(), value);
                                }
                                return Ok((vec![], true));
                            }
                        }
                    }
                    // No matching auth config found, inject as Bearer by default
                    headers.insert("Authorization".into(), format!("Bearer {access_token}"));
                    return Ok((vec![], true));
                }
                Err(e) => {
                    // Surface the typed AppError up the call stack — the
                    // caller (resolve_request) maps each variant to the
                    // right HTTP status. Falling back to API-key /
                    // resolve_service_auth on a transient OAuth error
                    // would hide the real failure behind a misleading
                    // `needs_authentication` 401.
                    return Err(
                        oauth_error_to_app_error(state, org_id, identity_id, &conn, e).await,
                    );
                }
            }
        }
    }

    // If instance has a bound secret_name AND the template declares ApiKey auth, use it.
    // OAuth-only templates never reach the ApiKey branch; `secret_name` would be either
    // already NULL (migration 037) or blocked at create/update by the services API.
    if let Some(ref secret_name) = instance.secret_name {
        for service_auth in &svc.auth {
            if let overslash_core::types::ServiceAuth::ApiKey { injection, .. } = service_auth {
                return Ok((
                    vec![SecretRef {
                        name: secret_name.clone(),
                        inject_as: if injection.inject_as == "query" {
                            InjectAs::Query
                        } else {
                            InjectAs::Header
                        },
                        header_name: injection.header_name.clone(),
                        query_param: injection.query_param.clone(),
                        prefix: injection.prefix.clone(),
                    }],
                    false,
                ));
            }
        }
    }

    // No bound credentials on instance — fall back to auto-resolve
    resolve_service_auth(state, scope, identity_id, svc, explicit_secrets, headers).await
}

fn generate_token() -> String {
    use rand::RngExt;
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

/// Build the audit-log `filter` block. Truncates the expression for
/// log readability and includes a sha256 so identical filters can be
/// grouped across calls. Filter output values are never logged — same
/// reasoning that already keeps response bodies out of audit logs.
fn filter_audit_entry(lang: &str, expr: &str, outcome: &FilteredBody) -> serde_json::Value {
    use sha2::{Digest, Sha256};
    const EXPR_LOG_MAX: usize = 256;

    let expr_truncated: String = expr.chars().take(EXPR_LOG_MAX).collect();
    let expr_sha256 = hex::encode(Sha256::digest(expr.as_bytes()));

    let (result, original_bytes, filtered_bytes) = match outcome {
        FilteredBody::Ok {
            original_bytes,
            filtered_bytes,
            ..
        } => ("ok", *original_bytes, Some(*filtered_bytes)),
        FilteredBody::Error {
            kind,
            original_bytes,
            ..
        } => {
            let r = match kind {
                overslash_core::types::FilterErrorKind::BodyNotJson => "body_not_json",
                overslash_core::types::FilterErrorKind::RuntimeError => "runtime_error",
                overslash_core::types::FilterErrorKind::Timeout => "timeout",
                overslash_core::types::FilterErrorKind::OutputOverflow => "output_overflow",
            };
            (r, *original_bytes, None)
        }
    };

    let mut entry = serde_json::json!({
        "lang": lang,
        "expr_truncated": expr_truncated,
        "expr_sha256": expr_sha256,
        "result": result,
        "original_bytes": original_bytes,
    });
    if let Some(fb) = filtered_bytes {
        entry
            .as_object_mut()
            .expect("entry is a json object")
            .insert("filtered_bytes".to_string(), serde_json::json!(fb));
    }
    entry
}

/// Run the template's disclose filters against the resolved request and
/// return the labeled result list for audit rows. Empty vec when no filters
/// are declared or the batch timed out (failure is non-fatal — execution
/// continues without a summary rather than aborting the whole request).
async fn compute_disclosure(
    meta: &ResolvedMeta,
    req: &ActionRequest,
    filter_timeout: std::time::Duration,
) -> Vec<disclosure::DisclosedField> {
    if meta.disclose.is_empty() {
        return Vec::new();
    }
    let input = core_disclosure::build_jq_input(req, &meta.params);
    match disclosure::run_disclosures(&meta.disclose, &input, filter_timeout).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("disclosure batch failed: {e}");
            Vec::new()
        }
    }
}

/// Approval-create variant: returns the disclosed field list AND the
/// redacted JSON blob to persist as `approvals.action_detail`. Falls back
/// to the legacy raw `ActionRequest` serialization when the template
/// declares neither `x-overslash-disclose` nor `x-overslash-redact`, so
/// pre-feature templates are unaffected.
async fn compute_approval_detail(
    meta: &ResolvedMeta,
    req: &ActionRequest,
    filter_timeout: std::time::Duration,
) -> (Vec<disclosure::DisclosedField>, Option<serde_json::Value>) {
    // MCP-runtime actions use a different projection: the resolved
    // ActionRequest has no url/method/body to inspect, so reviewers need
    // the tool name and arguments to see what the agent actually called.
    // Disclosure jq filters are still applied when declared — they operate
    // on the MCP projection ({runtime, tool, arguments, service, action}).
    if let Some(target) = meta.mcp_target.as_ref() {
        let projection = serde_json::json!({
            "runtime": "mcp",
            "tool": &target.tool,
            "arguments": &target.arguments,
            "service": meta.service_scope.as_ref().map(|s| &s.service_key),
            "action": meta.service_scope.as_ref().map(|s| &s.action_key),
        });
        let disclosed = if meta.disclose.is_empty() {
            Vec::new()
        } else {
            match disclosure::run_disclosures(&meta.disclose, &projection, filter_timeout).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("mcp disclosure batch failed: {e}");
                    Vec::new()
                }
            }
        };
        let mut redacted = projection;
        if !meta.redact.is_empty() {
            core_disclosure::apply_redactions(&mut redacted, &meta.redact);
        }
        return (disclosed, Some(redacted));
    }

    if let Some(pt) = meta.platform_target.as_ref() {
        let projection = serde_json::json!({
            "runtime": "platform",
            "action": &pt.action_key,
            "params": &pt.params,
            "service": meta.service_scope.as_ref().map(|s| &s.service_key),
        });
        return (Vec::new(), Some(projection));
    }

    if meta.disclose.is_empty() && meta.redact.is_empty() {
        return (Vec::new(), serde_json::to_value(req).ok());
    }
    let projection = core_disclosure::build_jq_input(req, &meta.params);
    let disclosed = if meta.disclose.is_empty() {
        Vec::new()
    } else {
        match disclosure::run_disclosures(&meta.disclose, &projection, filter_timeout).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("disclosure batch failed: {e}");
                Vec::new()
            }
        }
    };
    let mut redacted = projection;
    if !meta.redact.is_empty() {
        core_disclosure::apply_redactions(&mut redacted, &meta.redact);
    }
    (disclosed, Some(redacted))
}
