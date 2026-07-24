//! `POST /v1/actions/call` execution handler.

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::routes::util::fmt_time;

use overslash_db::repos::audit::AuditEntry;
use overslash_db::scopes::OrgScope;

use crate::{
    AppState,
    error::AppError,
    extractors::{AuthContext, ClientIp, ReqExt},
    services::{
        action_caller::{StoredCallRequest, StoredMcpCall, StoredPlatformCall},
        audit_capture::{self, AuditResponseBodyMode},
        group_ceiling, http_caller, mcp_caller,
        response_filter::{self},
    },
};
use overslash_core::{
    permissions::{GroupCeilingResult, PermissionKey, suggest_tiers},
    secret_injection::inject_secrets,
    types::{ResolvedActionRequest, service::Risk},
};

use super::*;
use super::{approval_detail::*, resolve::*, service_resolve::*, validate::*};

/// Marker inserted into the Response's extensions when the transport
/// succeeded but the *upstream* reported failure — an MCP tool's in-band
/// `is_error: true`, or an upstream HTTP 5xx (buffered and streamed).
/// `call_action` reads it to record the execution as `"upstream_error"`
/// instead of `"called"` (or, for streamed 5xx passthrough, `"failed"`),
/// keeping upstream outages distinguishable from Overslash's own errors.
/// Zero-sized and in-process only: it never serializes, it just rides the
/// Response from the inner handler to the metrics wrapper.
#[derive(Clone, Copy)]
pub(crate) struct UpstreamErrored;

/// The `sql` audit block for one evaluated policy outcome: the DB label,
/// the classification, and (for writes) which fail-closed rule fired. The
/// raw query itself travels via the template's `disclose` filters.
fn sql_audit_block(sp: &SqlPolicyOutcome) -> serde_json::Value {
    serde_json::json!({
        "db": sp.db_label,
        "classified": sp.floor.to_string(),
        "write_reason": sp.write_reason.as_ref().map(|r| r.tag()),
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn call_action_impl(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: AuthContext,
    scope: OrgScope,
    ip: ClientIp,
    Json(mut req): Json<CallRequest>,
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
    // NOTE: More expensive that ceiling perms check, might move after it
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
    // The verb / `http` shapes carry an empty schema so the call is a
    // no-op for them.
    //
    // The service shapes thread the resolved `(svc, instance)` into
    // `resolve_request` below so the call hot path doesn't re-fetch
    // the template / instance from the DB.
    let (pre_meta, pre_resolved_mode_c) =
        resolve_action_metadata(&state, &ext, &auth, &scope, ceiling_user_id, &req).await?;
    // Rewrite template-declared parameter aliases (e.g. `to` → `recipient`) to
    // their canonical names first, so defaults, coercion, validation, the
    // approval replay payload, and resolution all see canonical keys only.
    overslash_core::openapi::validate_input::apply_aliases(
        &pre_meta.validation_params,
        &mut req.params,
    );
    // Apply the pinned config (e.g. `X-Mailbox-Imap` on a self-hosted mailbox
    // gateway) *after* aliases so it lands on canonical keys, and *before*
    // defaults so a pin beats the template default while an explicit caller arg
    // still beats the pin. Precedence, high to low: caller arg > instance config
    // > org-layer default > template default.
    apply_instance_config(
        &pre_meta.validation_params,
        pre_resolved_mode_c.as_ref(),
        &mut req.params,
    );
    // Fill in template-declared defaults (e.g. `calendarId: primary`) before
    // validation so a `required` param with a default isn't rejected as
    // missing, and before resolution so the default flows into the outgoing
    // path/query/body like a caller-supplied value.
    overslash_core::openapi::validate_input::apply_defaults(
        &pre_meta.validation_params,
        &mut req.params,
    );
    // Repair fixable shape problems (int→string, enum case) in place before
    // validating — the coerced value is what gets approved and executed.
    overslash_core::openapi::validate_input::coerce_args(
        &pre_meta.validation_params,
        &mut req.params,
    );
    if let Err(errors) = overslash_core::openapi::validate_input::validate_args(
        &pre_meta.validation_params,
        &req.params,
    ) {
        return Err(invalid_action_args_error(
            &pre_meta.validation_params,
            errors,
        ));
    }

    // ── D42 SQL content policy ────────────────────────────────────────
    //
    // Params are fully canonical (aliases, pins, defaults, coercion,
    // validation) and the resolved instance is still on hand, so this is
    // the one point where the SQL param can be located, the target DB's
    // dialect/label resolved, and the statement classified. The outcome
    // feeds the `require_risk` gate, the group ceiling, and the permission
    // keys below — all fail-closed.
    let sql_policy = evaluate_sql_policy(
        std::time::Duration::from_millis(state.config.filter_timeout_ms),
        &pre_meta,
        pre_resolved_mode_c.as_ref(),
        &req.params,
    )
    .await;
    if let Some(sp) = &sql_policy {
        tracing::info!(
            db_label = %sp.db_label,
            floor = %sp.floor,
            write_reason = sp.write_reason.as_ref().map(|r| r.tag()),
            tables = sp.table_keys.len(),
            "sql policy evaluated"
        );
    }

    // ── Admin-as-owner impersonation ──────────────────────────────────
    //
    // When the resolved instance is owned by a different user than the
    // caller's ceiling, only org admins are allowed to invoke it. The
    // effective identity is rebound to the owner so OAuth/secrets, the
    // group ceiling, and the permission chain all anchor on the user
    // the service actually belongs to — the only credentials that make
    // the upstream call succeed. The admin identity is preserved on the
    // audit trail via `OrgScope::with_impersonator`.
    let (identity, identity_id, ceiling_user_id, scope) = apply_owner_impersonation(
        &scope,
        identity,
        identity_id,
        ceiling_user_id,
        pre_resolved_mode_c
            .as_ref()
            .and_then(|m| m.instance.as_ref()),
        req.service_id.is_some(),
    )
    .await?;

    // Resolve the request to a concrete ActionRequest. Passing `ceiling_user_id` reuses
    // the identity lookup above so service-name resolution doesn't re-fetch it.
    // The live OAuth credential (when one resolved) rides separately on
    // `auth_header` — `action_req` itself is credential-free and therefore
    // safe to serialize into approval/audit/replay surfaces.
    let (resolved, meta) = resolve_request(
        &state,
        &ext,
        &auth,
        &scope,
        ceiling_user_id,
        &req,
        pre_resolved_mode_c,
    )
    .await?;
    let ResolvedActionRequest {
        request: action_req,
        auth_header,
    } = resolved;

    // Caller-asserted risk gate (MCP `overslash_read`): reject before any
    // permission/approval work if the resolved action mutates. The declared
    // risk (falling back to HTTP-method inference for verb / `http` shapes)
    // is merged with the SQL classification — a `dynamic` action carrying a
    // SELECT-only query passes as read here; a write-classified (or
    // unclassifiable) one is rejected. Same value as the ceiling check below.
    let effective = effective_risk(meta.risk, sql_policy.as_ref(), &action_req.method);
    if let Some(required) = req.require_risk {
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

    // After the no-`service` rejection in `resolve_action_metadata`,
    // `meta.service_scope` is always `Some` — both the action shape and
    // the verb shape (including `service: "http"`) populate it.
    let scope_meta = meta
        .service_scope
        .as_ref()
        .expect("resolve_request always sets service_scope after the no-service-rejection gate");
    let perm_keys = if let Some(ref verb) = scope_meta.http_verb {
        PermissionKey::from_service_http(&scope_meta.service_key, &verb.method, &verb.path)
    } else {
        PermissionKey::from_service_action(
            &scope_meta.service_key,
            &scope_meta.action_key,
            &scope_meta.scope_param,
            &req.params,
        )
    };
    // D42: per-table keys join (or, for the bare `:*` fallback, replace)
    // the scope_param keys; column keys ride separately as deny-screen.
    let perm_keys = merge_sql_keys(perm_keys, scope_meta, sql_policy.as_ref());
    let deny_screen_keys: Vec<PermissionKey> = sql_policy
        .as_ref()
        .map(|sp| sp.column_keys.clone())
        .unwrap_or_default();

    // ── Layer 1: Group ceiling check ─────────────────────────────────
    //
    // Owner access to a service flows through the user's auto-managed Myself
    // group grant (admin + auto_approve_reads = true by default), so every
    // call runs through this same ceiling — including ones targeting a
    // service owned by the caller's ceiling user.
    let ceiling_service = scope_meta.service_key.clone();
    // Same merged value as the `require_risk` gate: a write-classified SQL
    // statement exceeds a read-only ceiling and forfeits `read_bypass`.
    let ceiling_risk = effective;

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

    // D42: a deny rule overrides every allow mechanism — including the
    // `auto_approve_reads` read bypass and the users-are-their-own-approvers
    // rule, both of which skip the chain walk below. A SQL-classified call
    // therefore runs a deny-only sweep whenever the full walk won't: a
    // `column=…/ssn` or `column_star=…` deny (or a table deny) is a hard 403
    // no matter which fast path the call took.
    let walk_will_run = identity.kind != "user" && pre_meta.needs_gate && !skip_layer2;
    if sql_policy.is_some() && !walk_will_run {
        let mut screen: Vec<PermissionKey> = perm_keys.clone();
        screen.extend(deny_screen_keys.iter().cloned());
        if let Some(reason) =
            crate::services::permission_chain::denied_anywhere(&scope, identity_id, &screen).await?
        {
            return Ok(
                (StatusCode::FORBIDDEN, Json(CallResponse::Denied { reason })).into_response(),
            );
        }
    }

    // ── Layer 2: Hierarchical permission check (agents/sub-agents only) ──
    //
    // Use the conservative pre-resolution estimate (`pre_meta.needs_gate`)
    // rather than the post-resolution `meta.auth_injected`. If OAuth token
    // resolution fails silently (provider down, expired refresh, etc.),
    // `meta.auth_injected` would be `false` and the gate would silently
    // disengage — bypassing Layer 2 on a request that `/validate` would
    // have flagged as `would_require_approval`. The estimate stays `true`
    // whenever the instance has a binding or the template declares auth,
    // so the two endpoints agree even when OAuth resolution fails.
    let needs_gate = pre_meta.needs_gate;

    // Users are gated by groups only — they are their own approvers.
    // Agents walk the ancestor chain; first gap → approval at gap level.
    // Read bypass on a Myself / auto-approve-reads grant skips Layer 2 for
    // non-mutating actions without writing a permission rule.
    if identity.kind != "user" && needs_gate && !skip_layer2 {
        let bubble_secs =
            overslash_db::repos::org::get_approval_auto_bubble_secs(state.db(&ext), auth.org_id)
                .await?
                .unwrap_or(300);
        let force_user_resolver = bubble_secs == 0;

        match crate::services::permission_chain::walk(
            &scope,
            identity_id,
            &perm_keys,
            &deny_screen_keys,
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

                // Render the redacted payload for the inline envelope using the
                // exact pretty-print + truncation rules the GET read path uses,
                // before `redacted_detail` is moved into `create_approval`.
                let (response_action_detail, action_detail_truncated, action_detail_size_bytes) =
                    crate::routes::approvals::render_action_detail(redacted_detail.as_ref());

                // Raw replay payload (full ActionRequest + side-channel fields)
                // stored separately from action_detail so the replay at
                // POST /v1/approvals/{id}/call reproduces the agent's
                // original request faithfully — including jq `filter` and
                // `prefer_stream` — even when `action_detail` has been
                // redacted via x-overslash-redact for reviewer display.
                //
                // MCP-runtime approvals get a different shape (StoredMcpCall)
                // disambiguated at parse time by the top-level `tool` key.
                // Platform-runtime gets StoredPlatformCall, disambiguated by
                // an explicit top-level `runtime: "platform"` marker.
                let replay_payload = if let Some(pt) = meta.platform_target.as_ref() {
                    serde_json::to_value(StoredPlatformCall {
                        runtime: "platform".into(),
                        service: meta.service_scope.as_ref().map(|s| s.service_key.clone()),
                        action: pt.action_key.clone(),
                        params: pt.params.clone(),
                    })
                    .ok()
                } else if let Some(target) = meta.mcp_target.as_ref() {
                    serde_json::to_value(StoredMcpCall {
                        url: target.url.clone(),
                        auth: target.auth.clone(),
                        tool: target.tool.clone(),
                        arguments: target.arguments.clone(),
                    })
                    .ok()
                } else {
                    // `action_req` is credential-free (the live OAuth header
                    // rides on `auth_header`, which has no Serialize impl).
                    // Record the service/instance the credential resolved
                    // from — exactly when one resolved — so the replay path
                    // re-mints a fresh token instead of persisting this one.
                    let (replay_service_key, replay_instance_id) = if auth_header.is_some() {
                        (
                            meta.service_scope.as_ref().map(|s| s.service_key.clone()),
                            meta.instance_id,
                        )
                    } else {
                        (None, None)
                    };
                    serde_json::to_value(StoredCallRequest::new(
                        action_req.clone(),
                        req.filter.clone(),
                        req.prefer_stream.unwrap_or(false),
                        replay_service_key,
                        replay_instance_id,
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
                if let Some(sp) = &sql_policy {
                    approval_audit_detail
                        .as_object_mut()
                        .expect("audit detail is a json object")
                        .insert("sql".into(), sql_audit_block(sp));
                }
                if !disclosed_fields.is_empty() {
                    approval_audit_detail
                        .as_object_mut()
                        .expect("audit detail is a json object")
                        .insert(
                            "disclosed".into(),
                            serde_json::to_value(&disclosed_fields).unwrap_or_default(),
                        );
                }

                let _ = scope
                    .clone()
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
                    let db = state.db_pool(&ext);
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

                // Carry the approval's org in the deep-link so the dashboard can
                // switch the recipient's session into that org before loading the
                // approval. Without it, a recipient whose active session is a
                // different org (e.g. their personal org after a root login) gets
                // an org-scoped 404 that reads as "approval deleted".
                let approval_url = state.config.dashboard_url_for(&format!(
                    "/approvals/{}?org={}",
                    approval.id, approval.org_id
                ));
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
                        // Caller of `overslash_call` is the requester of the
                        // approval just created — by definition `self`. The
                        // field earns its keep when this payload is rendered
                        // for an ancestor in `list_pending` (`downstream`).
                        relationship: "self".into(),
                        suggested_tiers: suggest_tiers(&keys),
                        auto_call_on_approve: identity.auto_call_on_approve,
                        // The merged (SQL-classified) risk when the shape
                        // declares one; verb/http shapes keep the "med"
                        // default risk_class(None) has always produced.
                        risk: crate::routes::approvals::risk_class(meta.risk.map(|_| effective)),
                        permission_keys: keys.clone(),
                        action_detail: response_action_detail,
                        action_detail_truncated,
                        action_detail_size_bytes,
                        disclosed_fields,
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

    // Registry-bounded `template_key` for the upstream-response counter,
    // shared by the MCP and HTTP dispatch forks below. Same bounding the
    // metrics wrapper in `mod.rs` applies to `record_execution`.
    let upstream_tpl = super::bounded_template_key(&state.registry, req.service.as_deref());

    // Org-level response-body capture mode for audit rows. One extra PK
    // lookup on the hot path — the org row isn't otherwise fetched here.
    // Capture is best-effort observability (the audit write itself is
    // fire-and-forget), so any failure to resolve the mode — missing org
    // (can't happen post-auth) or a transient DB error — degrades to Off
    // rather than failing the caller's action.
    let audit_body_mode = match overslash_db::repos::org::get_audit_response_body_mode(
        state.db(&ext),
        auth.org_id,
    )
    .await
    {
        Ok(mode) => mode
            .map(|m| AuditResponseBodyMode::parse_or_off(&m))
            .unwrap_or(AuditResponseBodyMode::Off),
        Err(e) => {
            tracing::warn!(error = %e, "audit_response_body_mode read failed; response capture disabled for this call");
            AuditResponseBodyMode::Off
        }
    };

    // ── MCP dispatch fork ────────────────────────────────────────────
    // Mcp-runtime services skip the HTTP executor: no URL templating, no
    // secret injection into headers, no streaming path. The executor owns
    // header resolution through mcp_auth::resolve_headers.
    if let Some(mcp_target) = meta.mcp_target.as_ref() {
        let result = match mcp_caller::invoke(
            &state,
            &scope,
            &mcp_target.url,
            &mcp_target.auth,
            &mcp_target.tool,
            &mcp_target.arguments,
            mcp_target.auth_header.as_ref(),
        )
        .await
        {
            Ok(result) => result,
            Err(invoke_err) => {
                // Transport / JSON-RPC failures used to bubble out with no
                // audit trail at all. Record the attempt with a secret-safe
                // error summary before propagating; pre-flight failures
                // (header resolution, SSRF guard) carry no summary and keep
                // the old no-row behavior.
                if let Some(error_detail) = invoke_err.audit {
                    let _ = scope
                        .clone()
                        .log_audit(AuditEntry {
                            org_id: auth.org_id,
                            identity_id: Some(identity_id),
                            action: "action.executed",
                            resource_type: req.service.as_deref(),
                            resource_id: None,
                            detail: serde_json::json!({
                                "runtime": "mcp",
                                "tool": mcp_target.tool,
                                "arguments": mcp_target.arguments,
                                "url": mcp_target.url,
                                "is_error": true,
                                "error": error_detail,
                                "service": req.service,
                                "action": req.action,
                            }),
                            description: meta.description.as_deref(),
                            ip_address: ip.0.as_deref(),
                        })
                        .await;
                }
                return Err(invoke_err.app);
            }
        };

        // Build the shared MCP audit shape, then layer on inline-only
        // fields (service/action/disclosed). Replay uses the same helper
        // from approvals.rs to keep the two surfaces from drifting.
        let (is_error, mut audit_detail) = mcp_caller::build_audit_detail(
            &result,
            &mcp_target.tool,
            &mcp_target.url,
            &mcp_target.arguments,
        );
        // Transport + JSON-RPC succeeded (failures short-circuit above via
        // AppError::BadGateway and record nothing here); the tool's in-band
        // error flag is the only "upstream status" MCP has.
        overslash_metrics::actions::record_upstream_response(
            &upstream_tpl,
            "mcp",
            if is_error { "error" } else { "2xx" },
        );
        {
            let obj = audit_detail
                .as_object_mut()
                .expect("audit_detail is a json object");
            obj.insert("service".into(), serde_json::json!(req.service));
            obj.insert("action".into(), serde_json::json!(req.action));
            // Org-gated response capture: for MCP the "body" is the stable
            // result envelope (runtime/tool/structured/content/is_error).
            if audit_capture::should_capture(audit_body_mode, is_error) {
                obj.insert(
                    "response".into(),
                    audit_capture::capture_body(
                        &result.body,
                        Some("application/json"),
                        state.config.audit_response_body_max_bytes,
                    ),
                );
            }
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

        let _ = scope
            .clone()
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

        let mut resp = (
            StatusCode::OK,
            Json(CallResponse::Called {
                result: render_action_result(&result, req.verbose),
                action_description: meta.description,
                is_error,
            }),
        )
            .into_response();
        if is_error {
            resp.extensions_mut().insert(UpstreamErrored);
        }
        return Ok(resp);
    }

    // ── Platform dispatch fork ───────────────────────────────────────
    // Platform-runtime services are dispatched in-process to the handler
    // registry. No HTTP call, no secret injection, no streaming path.
    // The dispatch itself (handler lookup, access-level computation, ctx
    // construction) is shared with the approval-replay path at
    // `POST /v1/approvals/{id}/call` via `platform_caller::invoke`.
    if let Some(pt) = meta.platform_target.as_ref() {
        let params: std::collections::HashMap<String, serde_json::Value> =
            pt.params.clone().into_iter().collect();

        let value = crate::services::platform_caller::invoke(
            &state,
            &ext,
            &scope,
            identity_id,
            ceiling_user_id,
            &pt.action_key,
            params,
        )
        .await?;

        let audit_detail = serde_json::json!({
            "runtime": "platform",
            "action": req.action,
            "service": req.service,
        });
        let _ = scope
            .clone()
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
                result: render_action_result(&result, req.verbose),
                action_description: meta.description,
                // Platform handlers run in-process: failures surface as
                // `AppError`, so a Called envelope is always a success.
                is_error: false,
            }),
        )
            .into_response());
    }

    // Resolve secrets and inject
    let secret_values = crate::services::action_caller::resolve_credential_values(
        &state,
        &scope,
        req.service.as_deref(),
        &action_req,
    )
    .await?;

    let (resolved_url, mut resolved_headers) = inject_secrets(&action_req, &secret_values)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;
    // Send-time merge of the live OAuth credential — the only point where
    // the token and the outgoing request meet.
    if let Some(ah) = &auth_header {
        resolved_headers.insert(ah.name.clone(), ah.value.clone());
    }
    let resolved_url = state.config.apply_base_overrides(&resolved_url);

    // Streaming proxy path
    if req.prefer_stream.unwrap_or(false) {
        let upstream = match http_caller::call_streaming(
            &state.http_client,
            &action_req.method,
            &resolved_url,
            &resolved_headers,
            action_req.body.as_deref(),
        )
        .await
        {
            Ok(upstream) => upstream,
            Err(e) => {
                let e = http_caller::CallError::Request(e);
                log_transport_error_audit(
                    &scope,
                    auth.org_id,
                    identity_id,
                    &action_req,
                    req.service.as_deref(),
                    req.action.as_deref(),
                    audit_capture::scrub_transport_error(&e),
                    meta.description.as_deref(),
                    ip.0.as_deref(),
                )
                .await;
                return Err(map_call_error(e));
            }
        };

        let upstream_status = upstream.status();
        // A transport failure above propagates via `?` and records nothing
        // here — this counter only counts responses that actually arrived.
        overslash_metrics::actions::record_upstream_response(
            &upstream_tpl,
            "http",
            overslash_metrics::actions::status_class(upstream_status.as_u16()),
        );
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
            // Normalized upstream-failure flag, same field MCP audit details
            // carry — lets the dashboard flag failed executions across
            // runtimes without re-deriving from status_code.
            "is_error": upstream_status.as_u16() >= 400,
            "content_length": content_length,
            "service": req.service,
            "action": req.action,
        });
        // The streamed body is never buffered, so it can't be captured. A
        // small marker keeps "streamed, body unavailable" distinguishable
        // from "capture off" on rows where capture would have applied.
        if audit_capture::should_capture(audit_body_mode, upstream_status.as_u16() >= 400) {
            streamed_detail
                .as_object_mut()
                .expect("audit detail is a json object")
                .insert(
                    "response".into(),
                    serde_json::json!({ "skipped": "streamed" }),
                );
        }
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

        let _ = scope
            .clone()
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

        let mut response = response.body(body).unwrap();
        // Streamed 5xx passes the upstream status straight through, where
        // the metrics wrapper would otherwise classify it as Overslash's
        // own "failed". The marker keeps it attributed to the upstream.
        if upstream_status.as_u16() >= 500 {
            response.extensions_mut().insert(UpstreamErrored);
        }
        return Ok(response);
    }

    // Buffered call path (default)
    let mut result = match http_caller::call(
        &state.http_client,
        &action_req.method,
        &resolved_url,
        &resolved_headers,
        action_req.body.as_deref(),
        state.config.max_response_body_bytes,
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            // Transport failures / oversized bodies used to bail with no
            // audit trail at all — only metrics saw them. Record the
            // attempt with a secret-safe error summary before propagating.
            log_transport_error_audit(
                &scope,
                auth.org_id,
                identity_id,
                &action_req,
                req.service.as_deref(),
                req.action.as_deref(),
                audit_capture::scrub_transport_error(&e),
                meta.description.as_deref(),
                ip.0.as_deref(),
            )
            .await;
            return Err(map_call_error(e));
        }
    };
    // Transport failures / oversized bodies bail above (with an error audit
    // row but no upstream-response sample) —
    // this counter only counts responses that actually arrived upstream.
    overslash_metrics::actions::record_upstream_response(
        &upstream_tpl,
        "http",
        overslash_metrics::actions::status_class(result.status_code),
    );

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

    let upstream_error = result.status_code >= 400;
    let mut audit_detail = serde_json::json!({
        "method": action_req.method,
        "url": action_req.url,
        "status_code": result.status_code,
        // Normalized upstream-failure flag, same field MCP audit details
        // carry — lets the dashboard flag failed executions across
        // runtimes without re-deriving from status_code.
        "is_error": upstream_error,
        "duration_ms": result.duration_ms,
        "service": req.service,
        "action": req.action,
    });
    if let Some(sp) = &sql_policy {
        audit_detail
            .as_object_mut()
            .expect("audit_detail is a json object")
            .insert("sql".into(), sql_audit_block(sp));
    }
    // Org-gated response capture (off / errors_only / all), truncated at
    // AUDIT_RESPONSE_BODY_MAX_BYTES.
    if audit_capture::should_capture(audit_body_mode, upstream_error) {
        audit_detail
            .as_object_mut()
            .expect("audit_detail is a json object")
            .insert(
                "response".to_string(),
                audit_capture::capture_body(
                    &result.body,
                    result.headers.get("content-type").map(String::as_str),
                    state.config.audit_response_body_max_bytes,
                ),
            );
    }
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

    let _ = scope
        .clone()
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

    // Google's metadata-scope denial (403 `"Metadata scope does not support…"`)
    // means the injected access token is metadata-only even though the
    // connection's recorded scopes claim a broader grant (connection
    // `85844f1a`). Returning the upstream 403 inside a 200 `Called` envelope
    // makes the partner's agent loop forever — the recorded scopes pass the
    // scope-gate so it keeps retrying. Surface a typed `reauth_required`
    // instead so the loop breaks and the partner re-consents.
    if super::auth::is_metadata_scope_denial(result.status_code, &result.body) {
        if let Some(service_key) = req.service.as_deref() {
            if let Some(err) = super::auth::metadata_scope_reauth_envelope(
                &state,
                &ext,
                &scope,
                ceiling_user_id,
                service_key,
            )
            .await
            {
                return Err(err);
            }
        }
    }

    let mut resp = (
        StatusCode::OK,
        Json(CallResponse::Called {
            result: render_action_result(&result, req.verbose),
            action_description: meta.description,
            is_error: upstream_error,
        }),
    )
        .into_response();
    // Upstream 5xx rides inside this 200 envelope — same in-band shape as
    // an MCP tool error, same marker, so the metrics wrapper records it as
    // `upstream_error` rather than a plain `called`. Mirrors the replay
    // path's `status_code >= 500` classification.
    if result.status_code >= 500 {
        resp.extensions_mut().insert(UpstreamErrored);
    }
    Ok(resp)
}

/// Map a transport-level `CallError` to the client-facing `AppError`.
/// Shared by the streamed and buffered forks so the error contract stays
/// what it was before transport failures gained audit rows.
fn map_call_error(e: http_caller::CallError) -> AppError {
    match e {
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
    }
}

/// Write the `action.executed` audit row for an HTTP call whose upstream
/// never produced a response (DNS/connect/timeout, or a body over the
/// buffering limit). No `status_code` — nothing arrived. `error_detail`
/// comes from `audit_capture::scrub_transport_error`, so it never carries
/// the resolved URL or injected secrets; `action_req.url` is the same
/// secret-free template URL the success rows store.
#[allow(clippy::too_many_arguments)]
async fn log_transport_error_audit(
    scope: &OrgScope,
    org_id: Uuid,
    identity_id: Uuid,
    action_req: &overslash_core::types::ActionRequest,
    service: Option<&str>,
    action: Option<&str>,
    error_detail: serde_json::Value,
    description: Option<&str>,
    ip: Option<&str>,
) {
    let _ = scope
        .clone()
        .log_audit(AuditEntry {
            org_id,
            identity_id: Some(identity_id),
            action: "action.executed",
            resource_type: service,
            resource_id: None,
            detail: serde_json::json!({
                "method": action_req.method,
                "url": action_req.url,
                "is_error": true,
                "error": error_detail,
                "service": service,
                "action": action,
            }),
            description,
            ip_address: ip,
        })
        .await;
}
