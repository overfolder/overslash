//! `POST /v1/approvals/{id}/resolve` — allow / deny / allow_remember /
//! bubble_up, plus the pending-execution + auto-call handoff.

use super::*;

#[derive(Deserialize)]
pub(super) struct ResolveRequest {
    resolution: String, // "allow", "deny", "allow_remember", "bubble_up"
    remember_keys: Option<Vec<String>>,
    ttl: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn resolve_approval(
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

        // The item just moved between inboxes. Without these two the identity
        // that gained it would not learn so until its next poll.
        crate::services::events::emit_all(
            state.db_pool(&ext),
            state.http_client.clone(),
            vec![
                crate::services::events::approvals::bubbled(
                    &scope,
                    id,
                    approval_pre.identity_id,
                    approval_pre.current_resolver_identity_id,
                    next,
                    crate::services::events::approvals::BubbleVia::User,
                )
                .await,
                crate::services::events::approvals::pending(
                    &scope,
                    id,
                    approval_pre.identity_id,
                    next,
                    &approval_pre.action_summary,
                    crate::services::events::approvals::PendingReason::Bubbled,
                )
                .await,
            ],
        );

        return Ok(Json(
            build_response(&scope, &state.registry, updated, &auth).await?,
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

            // A remember key must be *about this request*: either it is one of
            // the suggested tiers verbatim, or it covers at least one of the
            // keys the approval was raised for. The second arm is what makes
            // the dashboard's "Custom… (advanced)" field usable — a hand-typed
            // key that genuinely relates to the request no longer 400s just
            // for not appearing verbatim in a tier. The first arm still
            // matters: a broadening rung like `http:ANY:{host}/**` is offered
            // as a tier even though `ANY` is not a glob for the concrete verb,
            // so coverage alone would reject a tier the UI put in front of the
            // approver. Unrelated grants are still refused, and the
            // group-ceiling check below applies either way.
            let tiers = overslash_core::permissions::suggest_tiers(&approval.permission_keys);
            let tier_keys: std::collections::HashSet<&str> = tiers
                .iter()
                .flat_map(|t| t.keys.iter().map(|k| k.as_str()))
                .collect();

            for key in keys {
                let relates = tier_keys.contains(key.as_str())
                    || approval
                        .permission_keys
                        .iter()
                        .any(|requested| overslash_core::permissions::key_covers(key, requested));
                if !relates {
                    return Err(AppError::BadRequest(format!(
                        "remember_key '{key}' does not cover any permission key this approval requested"
                    )));
                }
            }

            // Duplicates would each write their own identical rule below.
            let mut seen = std::collections::HashSet::new();
            keys.iter()
                .filter(|k| seen.insert(k.as_str()))
                .cloned()
                .collect()
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
    if let Some(resolver) = auth.identity_id
        && let Some(obj) = audit_detail.as_object_mut()
    {
        obj.insert(
            "resolved_by_identity_id".into(),
            serde_json::json!(resolver),
        );
    }
    if let ApprovalRelationship::SelfApproval =
        relationship.unwrap_or(ApprovalRelationship::NotInYourChain)
        && let Some(obj) = audit_detail.as_object_mut()
    {
        obj.insert(
            "mcp_client_id".into(),
            serde_json::Value::String(auth_ctx.mcp_client_id.clone().unwrap_or_default()),
        );
        if let Some(b) = self_approve_binding_id {
            obj.insert("binding_id".into(), serde_json::json!(b));
        }
    }
    let _ = scope
        .log_audit_tagged(
            AuditEntry {
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
            },
            &approval_pre.tags,
        )
        .await;

    // Notify subscribers (fire-and-forget)
    {
        let mut payload = serde_json::json!({
            "approval_id": row.id,
            "status": row.status,
            "action_summary": row.action_summary,
        });
        if let Some(exec) = execution.as_ref() {
            payload
                .as_object_mut()
                .expect("payload is a json object")
                .insert(
                    "execution".into(),
                    serde_json::json!({
                        "id": exec.id,
                        "status": exec.status,
                        "expires_at": fmt_time(exec.expires_at),
                    }),
                );
        }
        // Audience comes from the pre-resolution row so everyone who could see
        // the approval while it was pending also sees how it ended.
        let audience = crate::services::events::audience::for_approval(
            &scope,
            approval_pre.identity_id,
            Some(approval_pre.current_resolver_identity_id),
        )
        .await;
        crate::services::events::emit(
            state.db_pool(&ext),
            state.http_client.clone(),
            crate::services::events::EventDraft {
                org_id: auth.org_id,
                event_type: crate::services::events::EventType::ApprovalResolved,
                payload,
                audience,
            },
        );
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
