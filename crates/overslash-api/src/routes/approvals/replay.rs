//! Replay lifecycle: `POST /v1/approvals/{id}/call`, the shared
//! `execute_claimed_approval` driver, and `POST /v1/approvals/{id}/cancel`.
//!
//! The three per-runtime branches of `execute_claimed_approval` live in the
//! `replay_http` / `replay_mcp` / `replay_platform` siblings.

use super::*;

use axum::http::StatusCode;

use crate::services::call_timeout;

use super::replay_http::replay_http;
use super::replay_mcp::replay_mcp;
use super::replay_platform::replay_platform;

pub(super) async fn call_approval(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: OrgAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<ApprovalResponse>)> {
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

    // ── Async fork: the call asked to run off the request path, so triggering
    // it means handing the row to the worker rather than dialling here. The
    // response is the ordinary approval envelope under a 202, not a second body
    // shape — the dashboard, MCP and the CLI all already parse this one.
    //
    // The flag is re-read rather than trusted from stamp time: an approval
    // marked `async` on a deployment that has since turned the worker off must
    // run inline rather than queue a row nothing will ever claim.
    if approval.is_async() && state.config.async_execution.enabled {
        if let Some(queued) = scope
            .enqueue_approval_execution(
                id,
                triggered_by,
                ip.0.as_deref(),
                state.config.execution_pending_ttl_secs as i64,
            )
            .await?
        {
            // Deliberately no `mark_execution_viewed` here. The stamp on the
            // synchronous path is justified by the result riding back in this
            // response; nothing rides back on a queued call, and stamping would
            // suppress the `result_unread` signal the agent polls for.
            let mut response =
                build_queued_response(&scope, &state.registry, approval, queued).await?;
            response
                .decorate_relationship(&scope, auth.identity_id)
                .await?;
            return Ok((StatusCode::ACCEPTED, Json(response)));
        }
        // Nothing was queued. Either someone got there first — in which case
        // this is a conflict, not an invitation to dial a second time — or the
        // approval predates `replay_payload` and has nothing to hand the worker,
        // which is the one case that falls through to the inline replay below.
        if let Some(current) = scope.get_execution_by_approval(id).await?
            && (current.has_request || current.status != "pending")
        {
            return Err(execution_conflict_error(Some(current)));
        }
    }

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

    // A manual dispatch hands the result straight back in this response, so
    // the requester has already seen it — stamp it read. Without this the
    // execution would sit in the agent's inbox as a permanently unread
    // `result_unread` event (see `services::inbox`), clearable only by
    // re-fetching a body the caller already holds. Resolver-triggered calls
    // deliberately don't stamp: the requesting agent still hasn't seen it.
    let finalised = if auth.identity_id == Some(approval.identity_id) {
        match scope.mark_execution_viewed(finalised.id).await {
            Ok(true) => scope
                .get_execution_by_approval(id)
                .await?
                .unwrap_or(finalised),
            _ => finalised,
        }
    } else {
        finalised
    };

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
    Ok((StatusCode::OK, Json(response)))
}

/// Render the 202 for a replay that was just handed to the worker.
///
/// The embedded `execution` is the queued row itself, so the caller gets the id
/// to poll (`GET /v1/executions/{id}`) and `queued: true` to tell "waiting on a
/// worker" from "waiting on you to trigger it".
async fn build_queued_response(
    scope: &OrgScope,
    registry: &ServiceRegistry,
    approval: overslash_db::repos::approval::ApprovalRow,
    queued: ExecutionRow,
) -> Result<ApprovalResponse> {
    let (identity_path, identity_path_ids) =
        crate::services::identity_path::build_for_identity(scope, approval.identity_id)
            .await
            .unwrap_or(None)
            .map(|(p, ids)| (Some(p), ids))
            .unwrap_or((None, Vec::new()));
    let mut response = ApprovalResponse::from_row(
        approval,
        identity_path,
        identity_path_ids,
        Some(queued),
        registry,
    );
    response.poll_after_ms = Some(POLL_AFTER_MS);
    Ok(response)
}

// Validator: if any step fails, finalize the row and surface the error.
// We own the row (unique claim) so this is race-free.
pub(super) async fn fail_and_return<T>(
    scope: &OrgScope,
    execution_id: Uuid,
    msg: &str,
    err: AppError,
) -> Result<T> {
    let _ = scope.finalize_execution_failed(execution_id, msg).await;
    Err(err)
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
pub(super) async fn execute_claimed_approval(
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

    // The outer wall, not the timeout the caller asked for — that one is
    // resolved per call and applied inside `call_action_request`. This bounds
    // the whole replay future (upstream call *plus* filtering and
    // finalisation) so a wedged replay can never hold the row in `executing`
    // forever. Derived from `call_timeout_max_ms`, so it is always wide enough
    // to let a legitimate max-length call finish.
    let replay_timeout = state.config.replay_wall_clock();

    // Org-level call settings for this replay: audit capture mode plus the
    // ceiling to re-clamp the stored timeout against. Resolved once so the
    // call pipeline stays query-free.
    //
    // A failed read degrades rather than erroring — the execution row is
    // already claimed as `executing` here, and a `?` would skip finalization
    // and wedge it in that state forever. Capture degrades to Off; the
    // ceiling degrades to "no org opinion", leaving the deployment maximum.
    let org_call_settings = match overslash_db::repos::org::get_call_settings(
        state.db(ext),
        approval.org_id,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "org call settings read failed; replaying with deployment defaults");
            None
        }
    };
    let audit_body_mode = org_call_settings
        .as_ref()
        .map(|s| audit_capture::AuditResponseBodyMode::parse_or_off(&s.audit_response_body_mode))
        .unwrap_or(audit_capture::AuditResponseBodyMode::Off);

    // The budget the caller was granted when the approval was created,
    // re-clamped against today's ceiling — so an org that tightened its
    // maximum in the meantime binds retroactively rather than being
    // outranked by a stale approval.
    let call_timeout = call_timeout::reclamp_stored(
        payload.stored_timeout_ms(),
        org_call_settings
            .as_ref()
            .and_then(|s| s.max_call_timeout_ms)
            .map(|v| v as u64),
        state.config.call_timeout_ms,
        state.config.call_timeout_max_ms,
    );

    // Replays count toward the same execution/upstream metrics inline calls
    // record (they were invisible there before). The original call shape
    // isn't stored, so `mode = "replay"`; the template key is recovered from
    // the approval's permission keys.
    let replay_tpl = tail::replay_template_key(&state.registry, &approval.permission_keys);
    let replay_start = std::time::Instant::now();

    // Each branch produces (finalised, succeeded, upstream_errored,
    // result_summary) for the shared metrics + audit + webhook +
    // rule-creation tail below. `upstream_errored` is true when the upstream
    // responded but reported failure (HTTP 5xx, MCP in-band `is_error`) —
    // a success from the approval's perspective, an outage from the
    // operator's.
    let (finalised, succeeded, upstream_errored, result_summary) = match payload {
        ReplayPayload::Http(stored) => {
            replay_http(
                state,
                ext,
                scope,
                approval,
                claimed,
                stored,
                id,
                execution_id,
                ip,
                audit_body_mode,
                call_timeout,
                replay_timeout,
                &replay_tpl,
            )
            .await?
        }
        ReplayPayload::Mcp(call) => {
            replay_mcp(
                state,
                ext,
                scope,
                approval,
                claimed,
                call,
                id,
                execution_id,
                ip,
                audit_org_id,
                audit_body_mode,
                replay_timeout,
                &replay_tpl,
            )
            .await?
        }
        ReplayPayload::Platform(call) => {
            replay_platform(
                state,
                ext,
                scope,
                approval,
                claimed,
                call,
                id,
                execution_id,
                ip,
                audit_org_id,
                replay_timeout,
            )
            .await?
        }
    };

    let cascaded_approval_ids = super::tail::run(super::tail::ApprovalTail {
        state,
        ext,
        scope,
        approval,
        finalised: &finalised,
        succeeded,
        upstream_errored,
        result_summary,
        triggered_by,
        ip,
        audit_org_id,
        audit_identity_id,
        metrics_tpl: &replay_tpl,
        elapsed: replay_start.elapsed(),
    })
    .await?;

    Ok((finalised, succeeded, cascaded_approval_ids))
}

pub(super) async fn cancel_approval_execution(
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

    // Two shapes of cancel. A row still waiting — for a trigger, or for a worker
    // to claim it — flips to `cancelled` here and now. A row a worker is already
    // running can only be *asked* to stop: the flag is observed on the next
    // heartbeat, and the worker emits the terminal event when it does. Without
    // this fall-through the button would stop working exactly when a background
    // job is running, which is when a user most wants it.
    let (cancelled, cooperative) = match scope.cancel_pending_execution(id).await? {
        Some(row) => (row, false),
        None => match scope.get_execution_by_approval(id).await? {
            Some(current) if current.has_request && current.status == "executing" => {
                let requested = scope
                    .request_execution_cancel(current.id)
                    .await?
                    .ok_or_else(|| execution_conflict_error(Some(current)))?;
                (requested, true)
            }
            other => return Err(execution_conflict_error(other)),
        },
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
                "cooperative": cooperative,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    // Only the immediate branch announces a terminal state. On the cooperative
    // one the row is still `executing`; the worker emits `execution.cancelled`
    // when it actually stops, and emitting both here would show a cancelled row
    // that keeps running for another heartbeat.
    if !cooperative {
        let audience = crate::services::events::audience::for_approval(
            &scope,
            approval.identity_id,
            Some(approval.current_resolver_identity_id),
        )
        .await;
        crate::services::events::emit(
            state.db_pool(&ext),
            state.http_client.clone(),
            crate::services::events::EventDraft {
                org_id: auth.org_id,
                event_type: crate::services::events::EventType::ApprovalExecutionCancelled,
                payload: serde_json::json!({
                    "approval_id": id,
                    "execution_id": execution_id,
                    "status": "cancelled",
                }),
                audience,
            },
        );
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
