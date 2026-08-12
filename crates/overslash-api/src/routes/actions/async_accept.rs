//! Accepting an async call: persist the resolved request, audit the accept,
//! and hand back the 202.
//!
//! Split out of `call` because that file is at the repo's 1000-line ceiling,
//! and this is the natural seam: everything here happens *after* the call has
//! been fully validated and authorised, and none of it dials anything.

use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use overslash_db::scopes::OrgScope;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::AuthContext,
};

use super::dto::{CallRequest, CallResponse, ResolvedMeta};

/// Accept an async call: persist the resolved request and hand back a 202.
///
/// Everything the worker needs is captured here, at accept time, because none
/// of it can be recovered later — the request `Extensions`, the client IP, the
/// resolved description and template key all belong to a connection that will
/// be gone. The payload itself is built by the same
/// [`super::replay_payload::build`] the permission gate uses, so a direct async
/// call and a gated-then-async one provably store the same thing.
#[allow(clippy::too_many_arguments)]
pub(super) async fn accept(
    state: &AppState,
    ext: &axum::http::Extensions,
    scope: &OrgScope,
    auth: &AuthContext,
    identity_id: Uuid,
    req: &CallRequest,
    meta: &ResolvedMeta,
    action_req: &overslash_core::types::ActionRequest,
    auth_header_present: bool,
    call_timeout: crate::services::call_timeout::CallTimeout,
    call_tags: &[String],
    ip: Option<&str>,
    upstream_tpl: &str,
) -> Result<Response> {
    if !state.config.async_execution.enabled {
        return Err(AppError::BadRequest(
            "execution: \"async\" is not enabled on this deployment".into(),
        ));
    }

    let payload =
        super::replay_payload::build(meta, req, action_req, auth_header_present, call_timeout)
            .ok_or_else(|| AppError::Internal("could not serialize async call payload".into()))?;

    // Bounded so an unclaimed row cannot sit forever: the existing
    // `expire_stale` sweep already reaps `pending AND expires_at < now()`, and
    // reusing that TTL keeps one knob instead of two with identical meaning.
    let expires_at = time::OffsetDateTime::now_utc()
        + time::Duration::seconds(state.config.execution_pending_ttl_secs as i64);

    let (service_key, instance_id) = if auth_header_present {
        (
            meta.service_scope.as_ref().map(|s| s.service_key.as_str()),
            meta.instance_id,
        )
    } else {
        (None, None)
    };

    let exec = scope
        .create_async_execution(overslash_db::repos::execution::AsyncExecutionInput {
            org_id: auth.org_id,
            identity_id,
            request: &payload,
            service_key,
            service_instance_id: instance_id,
            tags: call_tags,
            render_verbose: req.verbose,
            template_key: Some(upstream_tpl),
            description: meta.description.as_deref(),
            client_ip: ip,
            expires_at,
        })
        .await?;

    // Audit at *accept* time, not only at completion. An agent that launches a
    // thousand background calls and never polls must still be visible in the
    // trail; waiting for the worker would make that invisible until it drained.
    let _ = scope
        .clone()
        .log_audit_tagged(
            overslash_db::repos::audit::AuditEntry {
                org_id: auth.org_id,
                identity_id: Some(identity_id),
                action: "action.accepted",
                resource_type: req.service.as_deref(),
                resource_id: Some(exec.id),
                detail: serde_json::json!({
                    "execution_id": exec.id,
                    "service": req.service,
                    "action": req.action,
                    "timeout_ms": call_timeout.ms(),
                }),
                description: meta.description.as_deref(),
                ip_address: ip,
            },
            call_tags,
        )
        .await;

    let _ = ext; // resolution already consumed it; kept for signature symmetry

    let execution_url = state
        .config
        .dashboard_url_for(&format!("/executions/{}", exec.id));

    Ok((
        axum::http::StatusCode::ACCEPTED,
        axum::Json(CallResponse::Accepted {
            execution_id: exec.id,
            execution_url,
            action_description: meta.description.clone(),
            expires_at: crate::routes::util::fmt_time(exec.expires_at),
            timeout_ms: call_timeout.ms(),
            // One worker tick plus a little: polling sooner than the worker can
            // possibly have claimed the row just burns a request.
            poll_after_ms: 2_500,
        }),
    )
        .into_response())
}
