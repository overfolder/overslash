//! `POST /v1/actions/call` execution handler.

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use overslash_db::repos::audit::AuditEntry;
use overslash_db::scopes::OrgScope;

use crate::{
    AppState,
    error::AppError,
    extractors::{AuthContext, CallerTransport, ClientIp, ReqExt},
    services::{
        audit_capture::{self, AuditResponseBodyMode},
        call_timeout, group_ceiling, http_caller, mcp_caller,
        response_filter::{self},
    },
};
use overslash_core::{
    permissions::{GroupCeilingResult, PermissionKey},
    secret_injection::inject_secrets,
    types::{ResolvedActionRequest, service::Risk},
};

use super::upstream_error::{log_transport_error_audit, map_call_error};
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

#[allow(clippy::too_many_arguments)]
pub(super) async fn call_action_impl(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: AuthContext,
    scope: OrgScope,
    ip: ClientIp,
    transport: CallerTransport,
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

    let deliver_url = deferred::validate_flags(&req)?;

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
            write_reason = sp.analysis.write_reason.as_ref().map(|r| r.tag()),
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
    if let Some(required) = req.require_risk
        && required == Risk::Read
        && effective.is_mutating()
    {
        let action_label = req
            .action
            .as_deref()
            .or(req.service.as_deref())
            .unwrap_or(&action_req.url);
        return Err(AppError::BadRequest(format!(
            "action '{action_label}' is risk={effective}; this entry point only permits risk=read actions. Use overslash_call instead."
        )));
    }

    // System-derived metadata tags for this call. Minted from the *resolved*
    // request but the *pre-injection* URL — `action_req.url` still carries
    // `{secret}` placeholders, so a `host:` tag can never leak an injected
    // credential the way the post-injection `resolved_url` might.
    //
    // `enforce_permission_chain` mints the identical set for the approval it
    // may create; both go through `tags::call_tags` so the two cannot drift.
    let call_tags = tags::call_tags(
        &meta,
        sql_policy.as_ref(),
        effective,
        tags::Transport::of(&meta, req.prefer_stream.unwrap_or(false)),
        &action_req.url,
    );

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
            &canonical_scope_params(&req.params, &meta.canonical),
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
    // group grant (admin access, read-level auto-approval by default), so
    // every call runs through this same ceiling — including ones targeting a
    // service owned by the caller's ceiling user.
    let ceiling_service = scope_meta.service_key.clone();
    // Same merged value as the `require_risk` gate: a write-classified SQL
    // statement is measured against the write rung of both ladders, so it
    // can exceed a read-only ceiling and forfeit a read-only auto-approval.
    let ceiling_risk = effective;

    let ceiling = group_ceiling::load_ceiling(&scope, ceiling_user_id).await?;

    // `auto_approved = true` means a matching grant's `auto_approve_level`
    // covers this action's risk — Layer 2 is skipped entirely (no permission
    // rule is written, no approval is filed).
    let mut skip_layer2 = false;

    if ceiling.has_groups {
        match group_ceiling::check_ceiling(&ceiling, &ceiling_service, ceiling_risk) {
            GroupCeilingResult::ExceedsCeiling(reason) => {
                return Ok(
                    (StatusCode::FORBIDDEN, Json(CallResponse::Denied { reason })).into_response(),
                );
            }
            GroupCeilingResult::WithinCeiling { auto_approved } => {
                if auto_approved && identity.kind != "user" {
                    skip_layer2 = true;
                }
            }
            GroupCeilingResult::NoGroups => {}
        }
    }
    // has_groups == false → NoGroups → permissive (no ceiling enforced)

    // D42/D53: a deny rule overrides every allow mechanism — including the
    // `auto_approve_level` bypass and the users-are-their-own-approvers
    // rule, both of which skip the chain walk below. A SQL-classified call
    // therefore runs a deny-only sweep whenever the full walk won't: a
    // `column=…/ssn` or `column_star=…` deny (or a table deny) is a hard 403
    // no matter which fast path the call took.
    //
    // D53 widens the sweep to *any* mutating call that took the auto-approve
    // bypass, SQL-classified or not. Before write-level auto-approval existed
    // the bypass could only ever free reads, so the blast radius of skipping
    // deny rules along with the rest of Layer 2 was small enough to live with
    // outside the SQL tier. A grant that auto-approves writes changes that: a
    // deny is often the *only* thing standing between an agent and a mutation
    // an admin explicitly carved out. Reads keep the old zero-query fast path
    // — that behaviour is unchanged and a read bypass was never intended to
    // consult the chain.
    let walk_will_run = identity.kind != "user" && pre_meta.needs_gate && !skip_layer2;
    let auto_approved_mutation = skip_layer2 && ceiling_risk.is_mutating();
    if (sql_policy.is_some() || auto_approved_mutation) && !walk_will_run {
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

    // Org-level call settings: audit capture mode plus the D56 timeout rungs.
    // One PK lookup on the hot path — the org row isn't otherwise fetched
    // here, and folding both consumers into one query keeps it at one.
    //
    // Both halves degrade rather than fail, for different reasons. Capture is
    // best-effort observability (the audit write is itself fire-and-forget),
    // so it falls back to Off. The timeouts fall back to *no org opinion*,
    // which lands on the deployment default — never on "unbounded", which is
    // the one outcome a failed read must not be able to produce.
    let org_call_settings = match overslash_db::repos::org::get_call_settings(
        state.db(&ext),
        auth.org_id,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "org call settings read failed; using deployment defaults");
            None
        }
    };
    let audit_body_mode = org_call_settings
        .as_ref()
        .map(|s| AuditResponseBodyMode::parse_or_off(&s.audit_response_body_mode))
        .unwrap_or(AuditResponseBodyMode::Off);

    // Resolved once, here, before the MCP / HTTP / deferred forks — so every
    // runtime gets the same number and the cascade lives in exactly one place.
    let call_timeout = call_timeout::resolve(
        call_timeout::TimeoutLayers {
            per_call_ms: req.timeout_ms,
            action_ms: meta.action_timeout_ms,
            service_ms: meta.service_timeout_ms,
            org_default_ms: org_call_settings
                .as_ref()
                .and_then(|s| s.call_timeout_ms)
                .map(|v| v as u64),
            org_max_ms: org_call_settings
                .as_ref()
                .and_then(|s| s.max_call_timeout_ms)
                .map(|v| v as u64),
        },
        state.config.call_timeout_ms,
        state.config.call_timeout_max_ms,
    )
    .map_err(|e| AppError::BadRequest(e.to_string()))?;

    // Resolved *before* the gate on purpose: a call that gets gated stores
    // this budget on the approval, so the eventual replay honours what the
    // caller asked for instead of falling back to a deployment default.

    // Layer 2 (agents/sub-agents only): walk the ancestor chain and file an
    // approval at the first gap. `permission_gate` documents why the gate
    // keys off the pre-resolution estimate.
    if let Some(resp) = permission_gate::enforce_permission_chain(
        &state,
        &ext,
        &auth,
        &scope,
        &ip,
        &req,
        &identity,
        identity_id,
        &meta,
        &action_req,
        auth_header.is_some(),
        &perm_keys,
        &deny_screen_keys,
        sql_policy.as_ref(),
        effective,
        pre_meta.needs_gate,
        skip_layer2,
        call_timeout,
    )
    .await?
    {
        return Ok(resp);
    }

    // Registry-bounded `template_key` for the upstream-response counter,
    // shared by the MCP and HTTP dispatch forks below. Same bounding the
    // metrics wrapper in `mod.rs` applies to `record_execution`.
    let upstream_tpl = super::bounded_template_key(&state.registry, req.service.as_deref());

    // ── MCP dispatch fork ────────────────────────────────────────────
    // Mcp-runtime services skip the HTTP executor: no URL templating, no
    // secret injection into headers, no streaming path. The executor owns
    // header resolution through mcp_auth::resolve_headers.
    if let Some(mcp_target) = meta.mcp_target.as_ref() {
        let mut result = match mcp_caller::invoke(
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
                        .log_audit_tagged(
                            AuditEntry {
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
                            },
                            &tags::with_outcome(call_tags.clone(), true),
                        )
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
        // An MCP tool has no upstream size cap to dodge, but it has the same
        // context budget as an HTTP one — a `list` tool returning 500 rows is
        // the same problem. Applied after the audit shape is built so the
        // org-gated `response` capture still records what the tool returned,
        // not what the caller chose to look at.
        let filter_audit = filter_apply::apply_to(&state, &req, &mut result).await;
        filter_apply::record(&mut audit_detail, filter_audit);
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
            .log_audit_tagged(
                AuditEntry {
                    org_id: auth.org_id,
                    identity_id: Some(identity_id),
                    action: "action.executed",
                    resource_type: req.service.as_deref(),
                    resource_id: None,
                    detail: audit_detail,
                    description: meta.description.as_deref(),
                    ip_address: ip.0.as_deref(),
                },
                &tags::with_outcome(call_tags.clone(), is_error),
            )
            .await;

        // Deferred delivery. See `deferred::swap_in_mcp_download` for why a
        // failed tool result is never minted from.
        if deliver_url && !is_error {
            deferred::swap_in_mcp_download(
                &state,
                &ext,
                &mut result,
                auth.org_id,
                identity_id,
                mcp_target,
                &meta,
                &req,
            )
            .await?;
        }

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

        let mut result = overslash_core::types::ActionResult {
            status_code: 200,
            body: serde_json::to_string(&value).unwrap_or_default(),
            headers: std::collections::HashMap::new(),
            duration_ms: 0,
            filtered_body: None,
        };
        let mut audit_detail = serde_json::json!({
            "runtime": "platform",
            "action": req.action,
            "service": req.service,
        });
        // Platform handlers answer from our own database, so there is no cap
        // to dodge here either — but `list_pending` on a busy org is exactly
        // the kind of response a caller wants to project down before reading.
        let filter_audit = filter_apply::apply_to(&state, &req, &mut result).await;
        filter_apply::record(&mut audit_detail, filter_audit);
        let _ = scope
            .clone()
            .log_audit_tagged(
                AuditEntry {
                    org_id: auth.org_id,
                    identity_id: Some(identity_id),
                    action: "action.executed",
                    resource_type: req.service.as_deref(),
                    resource_id: None,
                    detail: audit_detail,
                    description: meta.description.as_deref(),
                    ip_address: None,
                },
                &tags::with_outcome(call_tags.clone(), false),
            )
            .await;

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

    // ── Deferred delivery (HTTP runtime) ─────────────────────────────
    //

    // Deferred delivery (HTTP runtime). See `deferred::mint_http_download`.
    if deliver_url {
        let d = deferred::HttpDeferred {
            auth: &auth,
            req: &req,
            meta: &meta,
            identity_id,
            ip: ip.0.as_deref(),
            tags: &call_tags,
        };
        return deferred::mint_http_download(&state, &ext, &scope, &action_req, d).await;
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
        // Header phase only — see `http_caller`'s module docs on why a total
        // deadline must not reach a streamed body.
        let upstream = match http_caller::call_streaming(
            &state.http_client,
            &action_req.method,
            &resolved_url,
            &resolved_headers,
            action_req.body.as_deref(),
            call_timeout.duration(),
        )
        .await
        {
            Ok(upstream) => upstream,
            Err(e) => {
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
                    &tags::with_outcome(call_tags.clone(), true),
                )
                .await;
                // Streamed fork: never buffers, so never oversized — there is
                // nothing to mint from.
                return Err(map_call_error(
                    e,
                    call_timeout,
                    transport.offers_prefer_stream(),
                    None,
                ));
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
            .log_audit_tagged(
                AuditEntry {
                    org_id: auth.org_id,
                    identity_id: Some(identity_id),
                    action: "action.streamed",
                    resource_type: req.service.as_deref(),
                    resource_id: None,
                    detail: streamed_detail,
                    description: meta.description.as_deref(),
                    ip_address: ip.0.as_deref(),
                },
                // Same predicate `streamed_detail.is_error` uses, so the tag
                // and the detail block can never disagree.
                &tags::with_outcome(call_tags.clone(), upstream_status.as_u16() >= 400),
            )
            .await;

        // Build streaming response — pipe upstream bytes through to caller.
        // Shared with `GET /v1/downloads/{token}` so the forwarded-header
        // allowlist can't drift between the inline and deferred paths.
        let mut response = crate::services::deferred_download::stream_through(
            upstream,
            std::time::Duration::from_millis(state.config.call_stream_idle_timeout_ms),
        );
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
        call_timeout.duration(),
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
                &tags::with_outcome(call_tags.clone(), true),
            )
            .await;
            // Mint the retry the hint would otherwise only name. This is
            // best-effort by construction: `mint_http_descriptor` refuses
            // OAuth-injected services and inline raw-HTTP credentials, and a
            // mint that fails for any other reason must not replace the error
            // the caller actually hit — so every failure collapses to `None`
            // and the 502 goes out exactly as it did before.
            let download = if matches!(e, http_caller::CallError::ResponseTooLarge { .. }) {
                deferred::mint_http_descriptor(
                    &state,
                    &ext,
                    &scope,
                    &action_req,
                    &deferred::HttpDeferred {
                        auth: &auth,
                        req: &req,
                        meta: &meta,
                        identity_id,
                        ip: ip.0.as_deref(),
                        tags: &call_tags,
                    },
                    deferred::MintCause::ResponseTooLarge,
                )
                .await
                .ok()
            } else {
                None
            };
            return Err(map_call_error(
                e,
                call_timeout,
                transport.offers_prefer_stream(),
                download,
            ));
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

    let filter_audit = filter_apply::apply_to(&state, &req, &mut result).await;

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
            .insert("sql".into(), tags::sql_audit_block(sp));
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
    filter_apply::record(&mut audit_detail, filter_audit);
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
        .log_audit_tagged(
            AuditEntry {
                org_id: auth.org_id,
                identity_id: Some(identity_id),
                action: "action.executed",
                resource_type: req.service.as_deref(),
                resource_id: None,
                detail: audit_detail,
                description: meta.description.as_deref(),
                ip_address: ip.0.as_deref(),
            },
            &tags::with_outcome(call_tags.clone(), upstream_error),
        )
        .await;

    // Google's metadata-scope denial (403 `"Metadata scope does not support…"`)
    // means the injected access token is metadata-only even though the
    // connection's recorded scopes claim a broader grant (connection
    // `85844f1a`). Returning the upstream 403 inside a 200 `Called` envelope
    // makes the partner's agent loop forever — the recorded scopes pass the
    // scope-gate so it keeps retrying. Surface a typed `reauth_required`
    // instead so the loop breaks and the partner re-consents.
    if super::auth::is_metadata_scope_denial(result.status_code, &result.body)
        && let Some(service_key) = req.service.as_deref()
        && let Some(err) = super::auth::metadata_scope_reauth_envelope(
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
