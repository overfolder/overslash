//! The shared post-execution tail of an approved call.
//!
//! Everything here happens *after* the upstream has answered and the
//! `executions` row has reached a terminal state: the execution metric, the
//! "Allow & Remember" rules, the cascade those rules unblock, the
//! `approval.executed` audit row, and the approval webhook.
//!
//! It is a module of its own because two very different callers reach it. The
//! inline replay in [`super::replay::execute_claimed_approval`] runs on the
//! connection that triggered it; the async worker in
//! [`crate::services::async_executor::job`] runs on a leased row minutes later.
//! An approved call must produce the same rules, the same cascade, the same
//! audit row and the same event whichever one dialled it — and the only way to
//! make that a fact rather than an intention is to have one copy.
//!
//! It stays under `routes::approvals` rather than moving to `services` so that
//! the `tail → spawn_auto_call → execute_claimed_approval → tail` cycle stays
//! inside one module and `spawn_auto_call` stays private. `services` already
//! calls into `routes` in the other direction (`stored_call` reaches
//! `routes::actions::resolve_replay_auth_header`), so the worker's edge into
//! here is not a new kind of dependency.

use super::*;

/// Everything the tail needs, assembled by whichever path owned the dial.
///
/// A struct rather than fourteen positional arguments, and borrowed throughout:
/// the caller still owns the approval and the finalised row, and both are read
/// again after this returns (the inline path renders them into its response).
pub(crate) struct ApprovalTail<'a> {
    pub(crate) state: &'a AppState,
    pub(crate) ext: &'a axum::http::Extensions,
    pub(crate) scope: &'a OrgScope,
    pub(crate) approval: &'a overslash_db::repos::approval::ApprovalRow,
    /// The *finalised* row, not the claim: `remember`, `remember_keys` and
    /// `remember_rule_ttl` are read off it, and its id is the execution id.
    pub(crate) finalised: &'a ExecutionRow,
    pub(crate) succeeded: bool,
    /// The upstream answered but reported failure (HTTP 5xx, MCP in-band
    /// `is_error`) — a success from the approval's perspective, an outage from
    /// the operator's.
    pub(crate) upstream_errored: bool,
    /// Per-runtime digest for the approval event payload.
    pub(crate) result_summary: Option<serde_json::Value>,
    /// `agent` | `user` | `auto`. Stamped on the row when the replay was
    /// triggered; restated here because the worker reads it back off the row
    /// while the inline path still has it as a literal.
    pub(crate) triggered_by: &'a str,
    pub(crate) ip: Option<&'a str>,
    pub(crate) audit_org_id: Uuid,
    pub(crate) audit_identity_id: Option<Uuid>,
    /// Registry-bounded template key for the execution metric.
    pub(crate) metrics_tpl: &'a str,
    /// How long the dial took. Passed in because only the caller knows when it
    /// started.
    pub(crate) elapsed: std::time::Duration,
}

/// Run the tail. Returns the approvals the cascade resolved, which the inline
/// path echoes back in its response.
pub(crate) async fn run(t: ApprovalTail<'_>) -> Result<Vec<Uuid>> {
    let ApprovalTail {
        state,
        ext,
        scope,
        approval,
        finalised,
        succeeded,
        upstream_errored,
        result_summary,
        triggered_by,
        ip,
        audit_org_id,
        audit_identity_id,
        metrics_tpl,
        elapsed,
    } = t;
    let id = approval.id;
    let execution_id = finalised.id;

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
    overslash_metrics::actions::record_execution(metrics_tpl, "replay", replay_status, elapsed);

    // ── Rule creation for Allow & Remember. Only on successful replay —
    // a failed replay leaves no rule so the reviewer can retry after fixing
    // the underlying issue.
    let mut cascaded_approval_ids: Vec<Uuid> = Vec::new();
    if succeeded && finalised.remember {
        let placement_id =
            crate::services::permission_chain::rule_placement_for(scope, approval.identity_id)
                .await?;
        // Dedupe defensively: a broad tier used to arrive with the same key
        // once per originating permission key (an N-recipient send collapsing
        // to one `svc:send:*`), and rows stored before that fix — or a direct
        // API caller — can still carry repeats. One key, one rule.
        let keys_owned: Vec<String> = {
            let mut seen = std::collections::HashSet::new();
            finalised
                .remember_keys
                .clone()
                .unwrap_or_else(|| approval.permission_keys.clone())
                .into_iter()
                .filter(|k| seen.insert(k.clone()))
                .collect()
        };
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
        .log_audit_tagged(
            AuditEntry {
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
            },
            &replay_tags(approval, !succeeded),
        )
        .await;

    {
        let event_type = if succeeded {
            crate::services::events::EventType::ApprovalExecuted
        } else {
            crate::services::events::EventType::ApprovalExecutionFailed
        };
        let mut payload = serde_json::json!({
            "approval_id": id,
            "execution_id": execution_id,
            "status": finalised.status,
            "triggered_by": triggered_by,
            "error": finalised.error,
            "summary": result_summary,
        });
        // The webhook ships the result body exactly when nobody received it
        // in-band, so a white-label platform can render the outcome without a
        // follow-up `GET /v1/approvals/{id}/execution`. That is every auto-fired
        // execution, and — since D66 — every worker-run one: a manual `/call` on
        // an async approval answers 202 with no body, so `triggered_by` alone is
        // no longer the right test. A manual *synchronous* call still omits it,
        // because that caller already holds the response. Apply the same
        // `truncate_json_value` cap used by `ExecutionSummary::from` so a
        // multi-megabyte upstream body can't blow past subscriber size
        // limits or stress the webhook dispatcher.
        let answered_in_band = triggered_by != "auto" && !finalised.has_request;
        if !answered_in_band
            && succeeded
            && let Some(result) = finalised.result.clone()
        {
            payload
                .as_object_mut()
                .expect("payload is a json object")
                .insert("result".into(), truncate_json_value(result));
        }
        let audience = crate::services::events::audience::for_approval(
            scope,
            approval.identity_id,
            Some(approval.current_resolver_identity_id),
        )
        .await;
        crate::services::events::emit(
            state.db_pool(ext),
            state.http_client.clone(),
            crate::services::events::EventDraft {
                org_id: audit_org_id,
                event_type,
                payload,
                audience,
            },
        );
    }
    Ok(cascaded_approval_ids)
}

/// Recover a registry-bounded `template_key` for replay metrics from the
/// approval's permission keys. Keys derive as `{service}:{action}:{arg}` or
/// `{service}:{METHOD}:{path}` (SPEC §8), so the prefix before the first
/// `:` is the service key. Anything that doesn't resolve to a registry
/// entry collapses to `"_unknown"` — same cardinality bound the inline
/// path applies via `bounded_template_key`.
///
/// Derived from the live registry rather than stored when the call was gated:
/// a key frozen at approval time goes stale the moment a service is renamed or
/// dropped, and the whole point of this function is to bound cardinality
/// against what the registry holds *now*.
pub(crate) fn replay_template_key(
    registry: &ServiceRegistry,
    permission_keys: &[String],
) -> String {
    let service = permission_keys
        .first()
        .and_then(|k| k.split(':').next())
        .filter(|s| !s.is_empty());
    match service {
        Some(s) if registry.get(s).is_some() => s.to_string(),
        _ => "_unknown".to_string(),
    }
}

/// The approval's tags plus the replay's outcome.
///
/// Replay never re-classifies — it re-executes a stored payload — so the
/// approval's tag set is authoritative and only the outcome is new
/// information. Shared by all three runtime branches (the HTTP path, plus
/// `replay_mcp` and `replay_platform`) so a replayed MCP call and a replayed
/// HTTP call can never end up tagged by different rules.
pub(crate) fn replay_tags(
    approval: &overslash_db::repos::approval::ApprovalRow,
    is_error: bool,
) -> Vec<String> {
    overslash_core::tags::with_outcome(approval.tags.clone(), is_error)
}
