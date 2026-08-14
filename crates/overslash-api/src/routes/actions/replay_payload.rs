//! Building the credential-free stored payload for a call that will be dialled
//! later.
//!
//! Two callers need byte-identical output: `permission_gate`, which stores it
//! on an approval so the replay at `POST /v1/approvals/{id}/call` reproduces
//! the agent's original request, and the async fork in `call`, which stores it
//! on an execution so the worker can. Sharing one builder is what makes "a
//! gated async call replays the identical request a direct async call would
//! have run" a compile-time fact rather than two hand-synced blocks that drift.
//!
//! The three shapes are disambiguated at parse time by JSON shape, not a serde
//! tag, because HTTP rows predate the other two and have no marker field:
//! platform carries an explicit `runtime: "platform"`, MCP carries `tool`, and
//! anything else is HTTP.

use crate::services::action_caller::{StoredCallRequest, StoredMcpCall, StoredPlatformCall};
use crate::services::call_timeout::CallTimeout;

use super::dto::{CallRequest, ResolvedMeta};

/// Serialize the stored payload for `meta`'s runtime.
///
/// `auth_header_present` must be true exactly when the resolve produced a live
/// OAuth header. It is what decides whether the service/instance the credential
/// came from is recorded — the header itself never is, so the later dial
/// re-mints a fresh token rather than replaying an expired one.
///
/// Returns `None` only if serialization fails, which the callers treat as a
/// non-replayable call rather than panicking.
pub(super) fn build(
    meta: &ResolvedMeta,
    req: &CallRequest,
    action_req: &overslash_core::types::ActionRequest,
    auth_header_present: bool,
    call_timeout: CallTimeout,
) -> Option<serde_json::Value> {
    if let Some(pt) = meta.platform_target.as_ref() {
        return serde_json::to_value(StoredPlatformCall {
            runtime: "platform".into(),
            service: meta.service_scope.as_ref().map(|s| s.service_key.clone()),
            action: pt.action_key.clone(),
            params: pt.params.clone(),
        })
        .ok();
    }
    if let Some(target) = meta.mcp_target.as_ref() {
        return serde_json::to_value(StoredMcpCall {
            url: target.url.clone(),
            auth: target.auth.clone(),
            tool: target.tool.clone(),
            arguments: target.arguments.clone(),
        })
        .ok();
    }
    // `action_req` is credential-free: the live OAuth header rides on
    // `auth_header`, which has no Serialize impl.
    let (service_key, instance_id) = if auth_header_present {
        (
            meta.service_scope.as_ref().map(|s| s.service_key.clone()),
            meta.instance_id,
        )
    } else {
        (None, None)
    };
    serde_json::to_value(StoredCallRequest::new(
        action_req.clone(),
        req.filter.clone(),
        req.prefer_stream.unwrap_or(false),
        service_key,
        instance_id,
        Some(call_timeout.ms()),
    ))
    .ok()
}
