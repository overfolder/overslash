//! Running a stored call payload, independent of what stored it.
//!
//! A stored payload ([`ReplayPayload`]) is a credential-free description of a
//! call that was resolved once and has to be dialled later — either because it
//! sat behind an approval, or because the caller asked for it to run off the
//! request path. Both cases need exactly the same three things: re-mint the
//! credential (the stored payload never holds one, and the original may have
//! expired in the meantime), dial the right runtime, and write the
//! `action.executed` audit row.
//!
//! What they do *not* share is the row. Approval replay owns an `executions`
//! row reached through its approval; the async worker owns one reached through
//! its lease. So this module deliberately writes **no execution rows at all**
//! and returns a [`StoredOutcome`] the caller finalizes however it must. That
//! split is the whole point: it is what lets an approval-free call reuse the
//! credential re-resolution and audit shape rather than growing a second,
//! subtly divergent copy of them — which is how a security bug gets written.

use std::time::Duration;

use uuid::Uuid;

use overslash_db::repos::audit::AuditEntry;
use overslash_db::scopes::OrgScope;

use crate::AppState;
use crate::error::AppError;
use crate::services::action_caller::{
    self, AuditSource, CallContext, CallOutcome, ReplayPayload, StoredCallRequest, StoredMcpCall,
    StoredPlatformCall,
};
use crate::services::audit_capture::{self, AuditResponseBodyMode};
use crate::services::call_timeout::CallTimeout;
use crate::services::{group_ceiling, mcp_caller, platform_caller};

/// Everything running a stored payload needs that the payload itself does not
/// carry. Assembled by the caller because every field here needs a row the
/// caller already has in hand — this pipeline stays query-free.
pub struct StoredCallCtx<'a> {
    pub state: &'a AppState,
    pub ext: &'a axum::http::Extensions,
    pub scope: &'a OrgScope,
    pub org_id: Uuid,
    /// The *requester's* identity. Credentials are re-minted against it, the
    /// audit row is attributed to it, and rate limits are charged to it — not
    /// to whoever triggered the run.
    pub identity_id: Uuid,
    pub ip: Option<&'a str>,
    pub description: Option<&'a str>,
    /// Tag set minted when the call was first made. The outcome tag is
    /// appended here, so callers pass the tags *without* it.
    pub tags: &'a [String],
    pub audit_source: AuditSource,
    pub audit_body_mode: AuditResponseBodyMode,
    /// Inner budget, bounding the upstream request itself.
    ///
    /// `None` for the MCP and platform runtimes: neither resolves a D56
    /// budget, because `mcp_caller` carries its own and platform actions run
    /// in-process. Only the outer `wall` applies to those.
    pub timeout: Option<CallTimeout>,
    /// Outer wall: bounds this whole future, including the work after the
    /// upstream answers, so a wedged run cannot hold its row forever. Always
    /// wider than `timeout`.
    pub wall: Duration,
    /// Registry-bounded template key for metrics cardinality.
    pub metrics_tpl: &'a str,
}

impl StoredCallCtx<'_> {
    fn outcome_tags(&self, is_error: bool) -> Vec<String> {
        overslash_core::tags::with_outcome(self.tags.to_vec(), is_error)
    }
}

/// Terminal outcome of running a stored payload.
///
/// Says nothing about execution rows on purpose — see the module doc.
pub enum StoredOutcome {
    Executed {
        result: serde_json::Value,
        /// The upstream itself reported a failure (5xx, or an MCP tool
        /// `is_error`). The *call* still ran, so this is not `Failed`.
        upstream_errored: bool,
        summary: serde_json::Value,
    },
    /// The call did not complete: transport failure, timeout, or an executor
    /// error. The message is safe to store on the row.
    Failed { message: String },
    /// The call never started because its credential could not be re-minted.
    /// Kept distinct from `Failed` because the replay path surfaces this to
    /// its HTTP caller as an error response, while a worker just fails the row.
    Rejected { message: String, error: AppError },
}

/// Dial a stored payload and return its outcome. Writes the `action.executed`
/// audit row; writes no execution row.
pub async fn run_stored(ctx: StoredCallCtx<'_>, payload: ReplayPayload) -> StoredOutcome {
    match payload {
        ReplayPayload::Http(stored) => run_http(ctx, stored).await,
        ReplayPayload::Mcp(call) => run_mcp(ctx, call).await,
        ReplayPayload::Platform(call) => run_platform(ctx, call).await,
    }
}

async fn run_http(ctx: StoredCallCtx<'_>, stored: StoredCallRequest) -> StoredOutcome {
    // The HTTP runtime is the only one that resolves a D56 budget, so it is
    // the only one that can be missing it. Fail the row rather than panicking:
    // a caller that forgot is a bug, but not one worth taking the process down.
    let Some(timeout) = ctx.timeout else {
        return StoredOutcome::Failed {
            message: "internal: stored HTTP call has no resolved timeout".into(),
        };
    };

    // Stored payloads are credential-free: when the original call carried an
    // OAuth header, only the service/instance it resolved from was stored.
    // Re-resolve a fresh token now — the original could have expired while the
    // call was waiting. Pre-fix rows have no `service_key` and replay their
    // baked-in headers as-is.
    let auth_header = match stored.service_key.as_deref() {
        Some(service_key) => match crate::routes::actions::resolve_replay_auth_header(
            ctx.state,
            ctx.ext,
            ctx.scope,
            ctx.identity_id,
            service_key,
            stored.instance_id,
        )
        .await
        {
            Ok(h) => Some(h),
            Err(e) => {
                return StoredOutcome::Rejected {
                    message: format!("replay auth re-resolution failed: {e}"),
                    error: e,
                };
            }
        },
        None => None,
    };

    // Streaming is forced off: whoever is watching now is not the original
    // caller's connection, and for an async run there is no connection at all.
    let call_ctx = CallContext {
        state: ctx.state,
        scope: ctx.scope,
        identity_id: ctx.identity_id,
        ip: ctx.ip,
        description: ctx.description,
        service_key: None,
        action_key: None,
        filter: stored.filter.clone(),
        prefer_stream: false,
        audit_source: ctx.audit_source,
        audit_body_mode: ctx.audit_body_mode,
        timeout,
    };

    let outcome = tokio::time::timeout(
        ctx.wall,
        action_caller::call_action_request(call_ctx, &stored.action, auth_header.as_ref()),
    )
    .await;

    match outcome {
        Ok(Ok(CallOutcome::Buffered { result, .. })) => {
            // Upstream actually responded — count it, same as the inline
            // buffered path. Transport failures land in the Ok(Err(..)) arm
            // below and record nothing here.
            overslash_metrics::actions::record_upstream_response(
                ctx.metrics_tpl,
                "http",
                overslash_metrics::actions::status_class(result.status_code),
            );
            let mut result_json = serde_json::to_value(&result)
                .unwrap_or_else(|_| serde_json::json!({"note": "result not serializable"}));
            if stored.prefer_stream
                && let Some(obj) = result_json.as_object_mut()
            {
                obj.insert("streamed_originally".into(), serde_json::Value::Bool(true));
            }
            StoredOutcome::Executed {
                upstream_errored: result.status_code >= 500,
                summary: serde_json::json!({
                    "status_code": result.status_code,
                    "duration_ms": result.duration_ms,
                }),
                result: result_json,
            }
        }
        Ok(Ok(CallOutcome::Streamed(_))) => {
            // Defensive: this path forces prefer_stream=false, so the variant
            // is unreachable in practice. Record as failed rather than
            // silently dropping the response.
            StoredOutcome::Failed {
                message: "replay unexpectedly produced a streaming response".into(),
            }
        }
        Ok(Err(app_err)) => StoredOutcome::Failed {
            message: app_err.to_string(),
        },
        Err(_elapsed) => StoredOutcome::Failed {
            message: "replay_timeout".into(),
        },
    }
}

async fn run_mcp(ctx: StoredCallCtx<'_>, call: StoredMcpCall) -> StoredOutcome {
    // Re-resolve OAuth fresh, for the same reason as the HTTP path: the stored
    // payload is credential-free (only the provider survives in `call.auth`),
    // so the token — which may have expired while the call waited — is minted
    // anew against the requester's owner identity here.
    let mcp_oauth_header = match &call.auth {
        overslash_core::types::McpAuth::OAuth { provider, .. } => {
            let owner =
                match group_ceiling::resolve_ceiling_user_id(ctx.scope, ctx.identity_id).await {
                    Ok(o) => o,
                    Err(e) => {
                        return StoredOutcome::Rejected {
                            message: format!("replay auth re-resolution failed: {e}"),
                            error: e,
                        };
                    }
                };
            match crate::routes::actions::resolve_mcp_oauth_bearer(
                ctx.state, ctx.ext, ctx.scope, owner, None, provider, None,
            )
            .await
            {
                Ok(Some(h)) => Some(h),
                Ok(None) => {
                    let msg = "cannot replay: no OAuth connection for the MCP provider \
                               (it may have been removed since the approval was created)";
                    return StoredOutcome::Rejected {
                        message: msg.into(),
                        error: AppError::Conflict(msg.into()),
                    };
                }
                Err(e) => {
                    return StoredOutcome::Rejected {
                        message: format!("replay auth re-resolution failed: {e}"),
                        error: e,
                    };
                }
            }
        }
        _ => None,
    };

    let outcome = tokio::time::timeout(
        ctx.wall,
        mcp_caller::invoke(
            ctx.state,
            ctx.scope,
            &call.url,
            &call.auth,
            &call.tool,
            &call.arguments,
            mcp_oauth_header.as_ref(),
        ),
    )
    .await;

    match outcome {
        Ok(Ok(result)) => {
            let result_json = serde_json::to_value(&result)
                .unwrap_or_else(|_| serde_json::json!({"note": "result not serializable"}));
            // Mirror the inline MCP call's `action.executed` audit shape so
            // reviewers see runtime/tool/arguments/is_error here too. The HTTP
            // path emits its own from action_caller; this is the equivalent.
            // `build_audit_detail` is shared with the inline executor so the
            // two cannot drift.
            let (is_error, mut audit_detail) =
                mcp_caller::build_audit_detail(&result, &call.tool, &call.url, &call.arguments);
            // Same in-band mapping as the inline MCP branch: transport
            // succeeded, the tool's is_error flag is the upstream status.
            // Transport failures land in Ok(Err(..)) below and record nothing.
            overslash_metrics::actions::record_upstream_response(
                ctx.metrics_tpl,
                "mcp",
                if is_error { "error" } else { "2xx" },
            );
            {
                ctx.audit_source.stamp_refs(&mut audit_detail);
                let obj = audit_detail
                    .as_object_mut()
                    .expect("audit_detail is a json object");
                // Org-gated response capture — same envelope-as-body shape the
                // inline MCP branch stores.
                if audit_capture::should_capture(ctx.audit_body_mode, is_error) {
                    obj.insert(
                        "response".into(),
                        audit_capture::capture_body(
                            &result.body,
                            Some("application/json"),
                            ctx.state.config.audit_response_body_max_bytes,
                        ),
                    );
                }
            }
            let _ = ctx
                .scope
                .log_audit_tagged(
                    AuditEntry {
                        org_id: ctx.org_id,
                        identity_id: Some(ctx.identity_id),
                        action: "action.executed",
                        resource_type: Some("mcp"),
                        resource_id: None,
                        detail: audit_detail,
                        description: ctx.description,
                        ip_address: ctx.ip,
                    },
                    &ctx.outcome_tags(is_error),
                )
                .await;
            StoredOutcome::Executed {
                result: result_json,
                upstream_errored: is_error,
                summary: serde_json::json!({
                    "runtime": "mcp",
                    "tool": call.tool,
                    "duration_ms": result.duration_ms,
                }),
            }
        }
        Ok(Err(invoke_err)) => {
            // Transport / JSON-RPC failures used to record nothing in the
            // audit log. Mirror the inline MCP fork: a secret-safe error
            // summary, plus the cross-references.
            if let Some(error_detail) = invoke_err.audit {
                let mut detail = serde_json::json!({
                    "runtime": "mcp",
                    "tool": call.tool,
                    "arguments": call.arguments,
                    "url": call.url,
                    "is_error": true,
                    "error": error_detail,
                });
                ctx.audit_source.stamp_refs(&mut detail);
                let _ = ctx
                    .scope
                    .log_audit_tagged(
                        AuditEntry {
                            org_id: ctx.org_id,
                            identity_id: Some(ctx.identity_id),
                            action: "action.executed",
                            resource_type: Some("mcp"),
                            resource_id: None,
                            detail,
                            description: ctx.description,
                            ip_address: ctx.ip,
                        },
                        &ctx.outcome_tags(true),
                    )
                    .await;
            }
            StoredOutcome::Failed {
                message: invoke_err.app.to_string(),
            }
        }
        Err(_elapsed) => StoredOutcome::Failed {
            message: "replay_timeout".into(),
        },
    }
}

async fn run_platform(ctx: StoredCallCtx<'_>, call: StoredPlatformCall) -> StoredOutcome {
    // Platform runs re-dispatch via the shared `platform_caller::invoke`
    // helper, mirroring the direct `/v1/actions/call` happy path. The
    // requester's ceiling user (and thus their access level) is recomputed
    // against current state — if they were demoted since the call was stored,
    // the new ceiling applies.
    let ceiling_outcome = group_ceiling::resolve_ceiling_user_id(ctx.scope, ctx.identity_id).await;
    let outcome = match ceiling_outcome {
        Ok(ceiling_user_id) => {
            let params: std::collections::HashMap<String, serde_json::Value> =
                call.params.clone().into_iter().collect();
            tokio::time::timeout(
                ctx.wall,
                platform_caller::invoke(
                    ctx.state,
                    ctx.ext,
                    ctx.scope,
                    ctx.identity_id,
                    ceiling_user_id,
                    &call.action,
                    params,
                ),
            )
            .await
        }
        Err(e) => Ok(Err(e)),
    };

    match outcome {
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
            // Stamp a top-level `runtime` so `extract_runtime` (which probes
            // the stored result for the `ExecutionSummary` payload) classifies
            // platform executions correctly instead of falling through the
            // `status_code` check and misreporting them as HTTP.
            if let Some(obj) = result_json.as_object_mut() {
                obj.insert("runtime".into(), serde_json::json!("platform"));
            }
            let mut audit_detail = serde_json::json!({
                "runtime": "platform",
                "action": &call.action,
                "service": &call.service,
            });
            ctx.audit_source.stamp_refs(&mut audit_detail);
            let _ = ctx
                .scope
                .log_audit_tagged(
                    AuditEntry {
                        org_id: ctx.org_id,
                        identity_id: Some(ctx.identity_id),
                        action: "action.executed",
                        resource_type: call.service.as_deref(),
                        resource_id: None,
                        detail: audit_detail,
                        description: ctx.description,
                        ip_address: ctx.ip,
                    },
                    // Platform handlers surface failures as AppError, so a row
                    // written here is always a success.
                    &ctx.outcome_tags(false),
                )
                .await;
            StoredOutcome::Executed {
                result: result_json,
                // Platform dispatch is in-process — there is no upstream to
                // report on.
                upstream_errored: false,
                summary: serde_json::json!({
                    "runtime": "platform",
                    "action": &call.action,
                }),
            }
        }
        Ok(Err(app_err)) => StoredOutcome::Failed {
            message: app_err.to_string(),
        },
        Err(_elapsed) => StoredOutcome::Failed {
            message: "replay_timeout".into(),
        },
    }
}
