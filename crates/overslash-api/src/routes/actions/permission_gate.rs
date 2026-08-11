//! Layer 2 of the permission model: the hierarchical chain walk, and the
//! approval it files when that walk finds a gap.
//!
//! Split out of `call.rs` for size. The block is a self-contained sink:
//! every local it reads is dead by the time it returns, and it defines
//! nothing the dispatch forks below it consume — its whole contract is
//! the `Option<Response>` it hands back.

use overslash_db::repos::audit::AuditEntry;
use overslash_db::scopes::OrgScope;

use crate::routes::util::fmt_time;

use crate::{
    AppState,
    error::AppError,
    extractors::{AuthContext, ClientIp},
    services::{
        action_caller::{StoredCallRequest, StoredMcpCall, StoredPlatformCall},
        call_timeout::CallTimeout,
    },
};
use overslash_core::{
    permissions::{PermissionKey, suggest_tiers},
    types::{ActionRequest, service::Risk},
};

use super::*;
use super::{approval_detail::*, tags::sql_audit_block};

/// Walk the ancestor chain and, at the first gap, file an approval.
///
/// The caller passes the conservative pre-resolution estimate
/// (`pre_meta.needs_gate`) as `needs_gate`, rather than the
/// post-resolution `meta.auth_injected`. If OAuth token resolution fails
/// silently (provider down, expired refresh, etc.), `meta.auth_injected`
/// would be `false` and the gate would silently disengage — bypassing
/// Layer 2 on a request that `/validate` would have flagged as
/// `would_require_approval`. The estimate stays `true` whenever the
/// instance has a binding or the template declares auth, so the two
/// endpoints agree even when OAuth resolution fails.
///
/// `Ok(None)` means the walk allowed the call (or the gate does not
/// apply) and the caller should proceed to dispatch. `Ok(Some(resp))`
/// means the call terminates here — 202 with a pending approval, or 403.
///
/// Takes `auth_header_present` rather than the header itself: the gate
/// only needs to know whether a live OAuth credential resolved, while the
/// value stays in `call.rs` for the send-time header merge.
#[allow(clippy::too_many_arguments)]
pub(super) async fn enforce_permission_chain(
    state: &AppState,
    ext: &axum::http::Extensions,
    auth: &AuthContext,
    scope: &OrgScope,
    ip: &ClientIp,
    req: &CallRequest,
    identity: &overslash_db::repos::identity::IdentityRow,
    identity_id: uuid::Uuid,
    meta: &ResolvedMeta,
    action_req: &ActionRequest,
    auth_header_present: bool,
    perm_keys: &[PermissionKey],
    deny_screen_keys: &[PermissionKey],
    sql_policy: Option<&SqlPolicyOutcome>,
    effective: Risk,
    needs_gate: bool,
    skip_layer2: bool,
    // The D56-resolved timeout for this call, stored on the approval so a
    // later replay reproduces the budget the caller actually asked for.
    call_timeout: CallTimeout,
) -> Result<Option<Response>, AppError> {
    // Users are gated by groups only — they are their own approvers.
    // Agents walk the ancestor chain; first gap → approval at gap level.
    // Read bypass on a Myself / auto-approve-reads grant skips Layer 2 for
    // non-mutating actions without writing a permission rule.
    if identity.kind != "user" && needs_gate && !skip_layer2 {
        let bubble_secs =
            overslash_db::repos::org::get_approval_auto_bubble_secs(state.db(ext), auth.org_id)
                .await?
                .unwrap_or(300);
        let force_user_resolver = bubble_secs == 0;

        match crate::services::permission_chain::walk(
            scope,
            identity_id,
            perm_keys,
            deny_screen_keys,
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
                    compute_approval_detail(meta, action_req, filter_timeout).await;

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
                    let (replay_service_key, replay_instance_id) = if auth_header_present {
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
                        Some(call_timeout.ms()),
                    ))
                    .ok()
                };

                // The same tag set the execution will inherit and the audit
                // rows will carry — minted once, here, so an approval can
                // never disagree with what it later becomes.
                let tags = super::tags::call_tags(
                    meta,
                    sql_policy,
                    effective,
                    super::tags::Transport::of(meta, req.prefer_stream.unwrap_or(false)),
                    &action_req.url,
                );

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
                        &tags,
                    )
                    .await?;

                let mut approval_audit_detail = serde_json::json!({
                    "summary": summary,
                    "current_resolver_identity_id": initial_resolver_id,
                });
                if let Some(sp) = sql_policy {
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
                    .log_audit_tagged(
                        AuditEntry {
                            org_id: auth.org_id,
                            identity_id: Some(identity_id),
                            action: "approval.created",
                            resource_type: Some("approval"),
                            resource_id: Some(approval.id),
                            detail: approval_audit_detail,
                            description: Some(&summary),
                            ip_address: ip.0.as_deref(),
                        },
                        &tags,
                    )
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
                let audience = crate::services::events::audience::for_approval_with_resolver_chain(
                    scope,
                    identity_id,
                    resolver_chain.iter().map(|i| i.id),
                )
                .await;
                // `created` states the fact; `pending` says who it is now
                // waiting on. Emitted as one ordered unit so a subscriber
                // never sees the derived signal before its cause.
                crate::services::events::emit_all(
                    state.db_pool(ext),
                    state.http_client.clone(),
                    vec![
                        crate::services::events::EventDraft {
                            org_id: auth.org_id,
                            event_type: crate::services::events::EventType::ApprovalCreated,
                            payload: webhook_payload,
                            audience,
                        },
                        crate::services::events::approvals::pending(
                            scope,
                            approval.id,
                            identity_id,
                            initial_resolver_id,
                            &summary,
                            crate::services::events::approvals::PendingReason::Created,
                        )
                        .await,
                    ],
                );

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
                    crate::services::short_url::mint(state, &approval_url, expires_at)
                        .await
                        .unwrap_or(approval_url);

                return Ok(Some(
                    (
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
                            risk: crate::routes::approvals::risk_class(
                                meta.risk.map(|_| effective),
                            ),
                            permission_keys: keys.clone(),
                            action_detail: response_action_detail,
                            action_detail_truncated,
                            action_detail_size_bytes,
                            disclosed_fields,
                        }),
                    )
                        .into_response(),
                ));
            }
            crate::services::permission_chain::ChainWalkResult::Denied(reason) => {
                return Ok(Some(
                    (StatusCode::FORBIDDEN, Json(CallResponse::Denied { reason })).into_response(),
                ));
            }
        }
    }

    Ok(None)
}
