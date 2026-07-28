//! MCP-runtime replay — the `ReplayPayload::Mcp` branch of
//! `execute_claimed_approval`.

use super::*;

use super::replay::{fail_and_return, replay_tags};

/// Replay a stored MCP call (`ReplayPayload::Mcp`). Returns the same
/// `(finalised, succeeded, upstream_errored, result_summary)` tuple as the
/// other runtime branches.
#[allow(clippy::too_many_arguments)]
pub(super) async fn replay_mcp(
    state: &AppState,
    ext: &axum::http::Extensions,
    scope: &OrgScope,
    approval: &overslash_db::repos::approval::ApprovalRow,
    claimed: ExecutionRow,
    call: action_caller::StoredMcpCall,
    id: Uuid,
    execution_id: Uuid,
    ip: Option<&str>,
    audit_org_id: Uuid,
    audit_body_mode: audit_capture::AuditResponseBodyMode,
    replay_timeout: std::time::Duration,
    replay_tpl: &str,
) -> Result<(ExecutionRow, bool, bool, Option<serde_json::Value>)> {
    // MCP replays go through mcp_caller::invoke, which returns the
    // same ActionResult envelope a fresh MCP call produces — keeping
    // the dashboard's execution-result rendering identical to inline
    // calls. Tool-level errors (`is_error: true`) live inside the
    // envelope and still count as successful execution from the
    // approval's perspective: the agent's call ran, the policy
    // decision was honored. Rule creation should still happen.
    // Re-resolve OAuth fresh at replay time. Like the HTTP replay path,
    // the stored payload is credential-free (only the provider survives
    // in `call.auth`), so the token — which may have expired while the
    // approval sat pending — is minted anew against the requester's
    // owner identity here.
    let mcp_oauth_header = match &call.auth {
        overslash_core::types::McpAuth::OAuth { provider, .. } => {
            let owner = match crate::services::group_ceiling::resolve_ceiling_user_id(
                scope,
                approval.identity_id,
            )
            .await
            {
                Ok(o) => o,
                Err(e) => {
                    return fail_and_return(
                        scope,
                        execution_id,
                        &format!("replay auth re-resolution failed: {e}"),
                        e,
                    )
                    .await;
                }
            };
            match crate::routes::actions::resolve_mcp_oauth_bearer(
                state, ext, scope, owner, None, provider, None,
            )
            .await
            {
                Ok(Some(h)) => Some(h),
                Ok(None) => {
                    let msg = "cannot replay: no OAuth connection for the MCP provider \
                               (it may have been removed since the approval was created)";
                    return fail_and_return(
                        scope,
                        execution_id,
                        msg,
                        AppError::Conflict(msg.into()),
                    )
                    .await;
                }
                Err(e) => {
                    return fail_and_return(
                        scope,
                        execution_id,
                        &format!("replay auth re-resolution failed: {e}"),
                        e,
                    )
                    .await;
                }
            }
        }
        _ => None,
    };
    let outcome = tokio::time::timeout(
        replay_timeout,
        mcp_caller::invoke(
            state,
            scope,
            &call.url,
            &call.auth,
            &call.tool,
            &call.arguments,
            mcp_oauth_header.as_ref(),
        ),
    )
    .await;
    Ok(match outcome {
        Ok(Ok(result)) => {
            let result_json = serde_json::to_value(&result)
                .unwrap_or_else(|_| serde_json::json!({"note": "result not serializable"}));
            // Mirror the inline MCP call's `action.executed` audit
            // shape so reviewers see runtime/tool/arguments/is_error
            // for replays too. The HTTP replay path emits its own
            // `action.executed` from action_caller; we do the
            // equivalent here. `build_audit_detail` is shared with
            // the inline executor so the two paths can't drift.
            let (is_error, mut audit_detail) =
                mcp_caller::build_audit_detail(&result, &call.tool, &call.url, &call.arguments);
            // Same in-band mapping as the inline MCP branch:
            // transport succeeded, the tool's is_error flag is the
            // upstream status. Transport failures land in
            // Ok(Err(..)) below and record nothing here.
            overslash_metrics::actions::record_upstream_response(
                replay_tpl,
                "mcp",
                if is_error { "error" } else { "2xx" },
            );
            {
                let obj = audit_detail
                    .as_object_mut()
                    .expect("audit_detail is a json object");
                obj.insert("replayed_from_approval".into(), serde_json::json!(id));
                obj.insert("execution_id".into(), serde_json::json!(execution_id));
                // Org-gated response capture — same envelope-as-body
                // shape the inline MCP branch stores.
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
            let _ = scope
                .log_audit_tagged(
                    AuditEntry {
                        org_id: audit_org_id,
                        identity_id: Some(approval.identity_id),
                        action: "action.executed",
                        resource_type: Some("mcp"),
                        resource_id: None,
                        detail: audit_detail,
                        description: Some(approval.action_summary.as_str()),
                        ip_address: ip,
                    },
                    &replay_tags(approval, is_error),
                )
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
        Ok(Err(invoke_err)) => {
            // Transport / JSON-RPC failures used to record nothing in
            // the audit log. Mirror the inline MCP fork: a secret-safe
            // error summary, plus the replay cross-references.
            if let Some(error_detail) = invoke_err.audit {
                let _ = scope
                    .log_audit_tagged(
                        AuditEntry {
                            org_id: audit_org_id,
                            identity_id: Some(approval.identity_id),
                            action: "action.executed",
                            resource_type: Some("mcp"),
                            resource_id: None,
                            detail: serde_json::json!({
                                "runtime": "mcp",
                                "tool": call.tool,
                                "arguments": call.arguments,
                                "url": call.url,
                                "is_error": true,
                                "error": error_detail,
                                "replayed_from_approval": id,
                                "execution_id": execution_id,
                            }),
                            description: Some(approval.action_summary.as_str()),
                            ip_address: ip,
                        },
                        &replay_tags(approval, true),
                    )
                    .await;
            }
            let msg = invoke_err.app.to_string();
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
    })
}
