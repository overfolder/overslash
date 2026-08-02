//! HTTP-runtime replay — the `ReplayPayload::Http` branch of
//! `execute_claimed_approval`.

use super::*;

use super::replay::fail_and_return;

/// Replay a stored HTTP call (`ReplayPayload::Http`). Returns the
/// `(finalised, succeeded, upstream_errored, result_summary)` tuple the shared
/// metrics / audit / webhook tail in `execute_claimed_approval` consumes.
#[allow(clippy::too_many_arguments)]
pub(super) async fn replay_http(
    state: &AppState,
    ext: &axum::http::Extensions,
    scope: &OrgScope,
    approval: &overslash_db::repos::approval::ApprovalRow,
    claimed: ExecutionRow,
    stored: action_caller::StoredCallRequest,
    id: Uuid,
    execution_id: Uuid,
    ip: Option<&str>,
    audit_body_mode: audit_capture::AuditResponseBodyMode,
    replay_timeout: std::time::Duration,
    replay_tpl: &str,
) -> Result<(ExecutionRow, bool, bool, Option<serde_json::Value>)> {
    // Replay payloads are credential-free: when the original call
    // carried an OAuth header, only the service/instance it resolved
    // from was stored. Re-resolve a fresh token against the
    // requester's identity now — the stored request never holds one,
    // and the original token could have expired while the approval
    // sat pending. Pre-fix rows have no `service_key` and replay
    // their baked-in headers as-is.
    let auth_header = match stored.service_key.as_deref() {
        Some(service_key) => {
            match crate::routes::actions::resolve_replay_auth_header(
                state,
                ext,
                scope,
                approval.identity_id,
                service_key,
                stored.instance_id,
            )
            .await
            {
                Ok(h) => Some(h),
                Err(e) => {
                    let msg = format!("replay auth re-resolution failed: {e}");
                    return fail_and_return(scope, execution_id, &msg, e).await;
                }
            }
        }
        None => None,
    };

    // ── Replay with timeout. Streaming is forced off — the reviewer's
    // connection isn't the original caller's.
    let call_ctx = CallContext {
        state,
        scope,
        identity_id: approval.identity_id, // requester identity for audit/rate-limit
        ip,
        description: Some(approval.action_summary.as_str()),
        service_key: None,
        action_key: None,
        filter: stored.filter.clone(),
        prefer_stream: false,
        audit_source: AuditSource::Replay {
            approval_id: id,
            execution_id,
        },
        audit_body_mode,
    };

    let outcome = tokio::time::timeout(
        replay_timeout,
        action_caller::call_action_request(call_ctx, &stored.action, auth_header.as_ref()),
    )
    .await;

    Ok(match outcome {
        Ok(Ok(CallOutcome::Buffered { result, .. })) => {
            // Upstream actually responded — count it, same as the
            // inline buffered path. Transport failures land in the
            // Ok(Err(..)) arm below and record nothing here.
            overslash_metrics::actions::record_upstream_response(
                replay_tpl,
                "http",
                overslash_metrics::actions::status_class(result.status_code),
            );
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
            let upstream_errored = result.status_code >= 500;
            let finalised = scope
                .finalize_execution_executed(execution_id, &result_json)
                .await?
                .unwrap_or(claimed);
            (finalised, true, upstream_errored, Some(summary))
        }
        Ok(Ok(CallOutcome::Streamed(_))) => {
            // Defensive: replay forces prefer_stream=false so this variant is
            // unreachable in practice. Record as failed rather than silently
            // dropping the response.
            let msg = "replay unexpectedly produced a streaming response";
            let finalised = scope
                .finalize_execution_failed(execution_id, msg)
                .await?
                .unwrap_or(claimed);
            (finalised, false, false, None)
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
            let msg = "replay_timeout";
            let finalised = scope
                .finalize_execution_failed(execution_id, msg)
                .await?
                .unwrap_or(claimed);
            (finalised, false, false, None)
        }
    })
}
