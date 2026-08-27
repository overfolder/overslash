//! The MCP dispatch fork of `POST /v1/actions/call`.
//!
//! Split out of `call` to keep that file under the repo's 1000-line ceiling.
//! The seam is the one the gate asks for: this is a whole runtime branch that
//! returns its own response and shares nothing with the HTTP path below it —
//! no URL templating, no secret injection into headers, no streaming. The
//! executor owns header resolution through `mcp_auth::resolve_headers`.

use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use overslash_db::repos::audit::AuditEntry;
use overslash_db::scopes::OrgScope;

// The same globs `call` uses, so the moved block keeps resolving the helpers
// it always did instead of growing a bespoke import list that would drift.
use super::call::UpstreamErrored;
use super::*;
use super::{approval_detail::*, dto::CallRequest, dto::ResolvedMeta};
use crate::{AppState, extractors::AuthContext, services::audit_capture, services::mcp_caller};

/// Dispatch an MCP-runtime action and build its response.
#[allow(clippy::too_many_arguments)]
pub(super) async fn dispatch(
    state: &AppState,
    ext: &axum::http::Extensions,
    scope: &OrgScope,
    auth: &AuthContext,
    identity_id: Uuid,
    req: &CallRequest,
    meta: &ResolvedMeta,
    mcp_target: &super::dto::McpTarget,
    action_req: &overslash_core::types::ActionRequest,
    ip: Option<&str>,
    call_tags: Vec<String>,
    upstream_tpl: &str,
    audit_body_mode: audit_capture::AuditResponseBodyMode,
    deliver_url: bool,
) -> Result<Response, AppError> {
    let mut result = match mcp_caller::invoke(
        state,
        scope,
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
                            ip_address: ip,
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
    let filter_audit = filter_apply::apply_to(state, req, &mut result).await;
    filter_apply::record(&mut audit_detail, filter_audit);
    // Transport + JSON-RPC succeeded (failures short-circuit above via
    // AppError::BadGateway and record nothing here); the tool's in-band
    // error flag is the only "upstream status" MCP has.
    overslash_metrics::actions::record_upstream_response(
        upstream_tpl,
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
        compute_approval_detail(meta, action_req, filter_timeout).await;

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
                ip_address: ip,
            },
            &tags::with_outcome(call_tags.clone(), is_error),
        )
        .await;

    // Deferred delivery. See `deferred::swap_in_mcp_download` for why a
    // failed tool result is never minted from.
    if deliver_url && !is_error {
        deferred::swap_in_mcp_download(
            state,
            ext,
            &mut result,
            auth.org_id,
            identity_id,
            mcp_target,
            meta,
            req,
        )
        .await?;
    }

    // Dev's #547 routes every rendered result through `render_stored` so an
    // oversized compact body gets a re-fetchable URL. The MCP fork moved out
    // of `call` after that landed, so it has to carry the same call.
    let rendered =
        super::render_stored(state, ext, &result, req, meta, auth.org_id, identity_id).await;
    let mut resp = (
        StatusCode::OK,
        Json(CallResponse::Called {
            result: rendered,
            action_description: meta.description.clone(),
            is_error,
            execution_id: None,
        }),
    )
        .into_response();
    if is_error {
        resp.extensions_mut().insert(UpstreamErrored);
    }
    Ok(resp)
}
