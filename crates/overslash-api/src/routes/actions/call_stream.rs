//! The inline streaming-proxy fork of `POST /v1/actions/call`
//! (`prefer_stream: true` on the HTTP runtime).
//!
//! Split out of `call.rs` because it is self-contained: dial with a header-phase
//! deadline only, write the `action.streamed` row, then pipe the upstream body
//! through unbuffered. The bytes that actually flowed are counted on the way
//! out and recorded on an `action.stream_completed` row when the transfer ends
//! — see [`crate::services::response_size`].

use std::collections::HashMap;

use axum::response::Response;
use overslash_core::types::ActionRequest;
use overslash_db::repos::audit::AuditEntry;
use overslash_db::scopes::OrgScope;

use crate::{
    AppState,
    error::AppError,
    services::{
        audit_capture::{self, AuditResponseBodyMode},
        call_timeout::CallTimeout,
        http_caller,
        response_size::{CompletionAudit, ResponseSize},
    },
};

use super::call::UpstreamErrored;
use super::deferred::HttpDeferred;
use super::upstream_error::{log_transport_error_audit, map_call_error};
use super::*;
use super::{approval_detail::compute_disclosure, tags};

/// Where the request goes and what governs it, beyond the caller context that
/// [`HttpDeferred`] already bundles.
pub(super) struct InlineStream<'a> {
    pub(super) url: &'a str,
    pub(super) headers: &'a HashMap<String, String>,
    pub(super) body: Option<http_caller::Payload<'a>>,
    pub(super) timeout: CallTimeout,
    pub(super) offer_prefer_stream: bool,
    pub(super) audit_body_mode: AuditResponseBodyMode,
    pub(super) upstream_tpl: &'a str,
}

pub(super) async fn stream_inline(
    state: &AppState,
    scope: &OrgScope,
    action_req: &ActionRequest,
    d: &HttpDeferred<'_>,
    s: InlineStream<'_>,
) -> Result<Response, AppError> {
    let (auth, req, meta, identity_id, ip, call_tags) =
        (d.auth, d.req, d.meta, d.identity_id, d.ip, d.tags);
    // Header phase only — see `http_caller`'s module docs on why a total
    // deadline must not reach a streamed body.
    let upstream = match http_caller::call_streaming(
        &action_req.method,
        s.url,
        s.headers,
        s.body,
        s.timeout.duration(),
    )
    .await
    {
        Ok(upstream) => upstream,
        Err(e) => {
            log_transport_error_audit(
                scope,
                auth.org_id,
                identity_id,
                action_req,
                req.service.as_deref(),
                req.action.as_deref(),
                &e,
                meta.description.as_deref(),
                ip,
                &tags::with_outcome(call_tags.to_vec(), true),
            )
            .await;
            // Streamed fork: never buffers, so never oversized — there is
            // nothing to mint from.
            return Err(map_call_error(
                e,
                s.timeout,
                s.offer_prefer_stream,
                None,
                page_size_param(meta),
            ));
        }
    };

    let upstream_status = upstream.status();
    // A transport failure above propagates via `?` and records nothing
    // here — this counter only counts responses that actually arrived.
    overslash_metrics::actions::record_upstream_response(
        s.upstream_tpl,
        "http",
        overslash_metrics::actions::status_class(upstream_status.as_u16()),
    );
    let content_length = upstream
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());

    let mut streamed_detail = serde_json::json!({
        "method": action_req.method,
        "url": action_req.url,
        "status_code": upstream_status.as_u16(),
        // Normalized upstream-failure flag, same field MCP audit details
        // carry — lets the dashboard flag failed executions across
        // runtimes without re-deriving from status_code.
        "is_error": upstream_status.as_u16() >= 400,
        "content_length": content_length,
        "service": req.service,
        "action": req.action,
    });
    ResponseSize::streamed(content_length).stamp(&mut streamed_detail);
    // The streamed body is never buffered, so it can't be captured. A
    // small marker keeps "streamed, body unavailable" distinguishable
    // from "capture off" on rows where capture would have applied.
    if audit_capture::should_capture(s.audit_body_mode, upstream_status.as_u16() >= 400) {
        streamed_detail
            .as_object_mut()
            .expect("audit detail is a json object")
            .insert(
                "response".into(),
                serde_json::json!({ "skipped": "streamed" }),
            );
    }
    let streamed_disclosed = compute_disclosure(
        meta,
        action_req,
        std::time::Duration::from_millis(state.config.filter_timeout_ms),
    )
    .await;
    if !streamed_disclosed.is_empty() {
        streamed_detail
            .as_object_mut()
            .expect("audit detail is a json object")
            .insert(
                "disclosed".into(),
                serde_json::to_value(&streamed_disclosed).unwrap_or_default(),
            );
    }

    let _ = scope
        .clone()
        .log_audit_tagged(
            AuditEntry {
                org_id: auth.org_id,
                identity_id: Some(identity_id),
                action: "action.streamed",
                resource_type: req.service.as_deref(),
                resource_id: None,
                detail: streamed_detail,
                description: meta.description.as_deref(),
                ip_address: ip,
            },
            // Same predicate `streamed_detail.is_error` uses, so the tag
            // and the detail block can never disagree.
            &tags::with_outcome(call_tags.to_vec(), upstream_status.as_u16() >= 400),
        )
        .await;

    // Build streaming response — pipe upstream bytes through to caller.
    // Shared with `GET /v1/downloads/{token}` so the forwarded-header
    // allowlist can't drift between the inline and deferred paths.
    let completion = CompletionAudit {
        scope: scope.clone(),
        identity_id,
        service: req.service.clone(),
        action: req.action.clone(),
        template_key: s.upstream_tpl.to_string(),
        via: "prefer_stream",
        token_id: None,
        ip: ip.map(str::to_string),
    };
    let mut response = crate::services::deferred_download::stream_through(
        upstream,
        std::time::Duration::from_millis(state.config.call_stream_idle_timeout_ms),
        completion.into_callback(),
    );
    // Streamed 5xx passes the upstream status straight through, where
    // the metrics wrapper would otherwise classify it as Overslash's
    // own "failed". The marker keeps it attributed to the upstream.
    if upstream_status.as_u16() >= 500 {
        response.extensions_mut().insert(UpstreamErrored);
    }
    Ok(response)
}
