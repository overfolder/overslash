//! Platform-runtime replay — the `ReplayPayload::Platform` branch of
//! `execute_claimed_approval`.

use super::*;

/// Replay a stored platform call (`ReplayPayload::Platform`). Returns the same
/// `(finalised, succeeded, upstream_errored, result_summary)` tuple as the other
/// runtime branches; `upstream_errored` is always false because platform
/// dispatch is in-process.
#[allow(clippy::too_many_arguments)]
pub(super) async fn replay_platform(
    state: &AppState,
    ext: &axum::http::Extensions,
    scope: &OrgScope,
    approval: &overslash_db::repos::approval::ApprovalRow,
    claimed: ExecutionRow,
    call: action_caller::StoredPlatformCall,
    id: Uuid,
    execution_id: Uuid,
    ip: Option<&str>,
    audit_org_id: Uuid,
    replay_timeout: std::time::Duration,
) -> Result<(ExecutionRow, bool, bool, Option<serde_json::Value>)> {
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
    let ceiling_outcome = group_ceiling::resolve_ceiling_user_id(scope, approval.identity_id).await;
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
    Ok(match outcome {
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
                .log_audit_tagged(
                    AuditEntry {
                        org_id: audit_org_id,
                        identity_id: Some(approval.identity_id),
                        action: "action.executed",
                        resource_type: call.service.as_deref(),
                        resource_id: None,
                        detail: audit_detail,
                        description: Some(approval.action_summary.as_str()),
                        ip_address: ip,
                    },
                    // Platform handlers surface failures as AppError, so a
                    // row written here is always a success.
                    &replay_tags(approval, false),
                )
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
    })
}

/// The approval's tags plus the replay's outcome. Replay does not
/// re-classify — it re-executes a stored payload — so the approval's tag set
/// is the authoritative one; only the outcome is new information.
fn replay_tags(
    approval: &overslash_db::repos::approval::ApprovalRow,
    is_error: bool,
) -> Vec<String> {
    overslash_core::tags::with_outcome(approval.tags.clone(), is_error)
}
