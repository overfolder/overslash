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
            pagination: stored_pagination(meta, req),
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
        stored_pagination(meta, req),
    ))
    .ok()
}

/// Carry the pagination declaration and the arguments this call went out with
/// onto the stored payload.
///
/// Replay resolves nothing: it has a URL, not an action key, so it cannot look
/// the declaration back up — the same reason `timeout_ms` is stored resolved
/// (D56). Without this an async or gated call to a paged action comes back with
/// no `next`, which an agent cannot distinguish from the last page.
fn stored_pagination(
    meta: &ResolvedMeta,
    req: &CallRequest,
) -> Option<crate::services::pagination::StoredPagination> {
    Some(crate::services::pagination::StoredPagination {
        spec: meta.action_pagination.clone()?,
        service: req.service.clone(),
        action: req.action.clone(),
        params: req.params.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::action_caller::StoredCallRequest;
    use overslash_core::types::{NextSpec, NextStyle, PageSize, PaginationSpec};

    /// Same literal `tags.rs` writes for the same reason: `ResolvedMeta` is a
    /// projection with no `Default`, and spelling it out is cheaper than
    /// deriving one on a production type for a test's sake.
    fn meta(pagination: Option<PaginationSpec>) -> ResolvedMeta {
        ResolvedMeta {
            action_timeout_ms: None,
            action_wait_mode: None,
            action_handoff_after_ms: None,
            action_pagination: pagination,
            service_timeout_ms: None,
            description: None,
            service_scope: None,
            risk: None,
            disclose: Vec::new(),
            redact: Vec::new(),
            oauth_injected: false,
            download: None,
            params: Default::default(),
            resolved: Default::default(),
            canonical: Default::default(),
            mcp_target: None,
            platform_target: None,
            instance_id: None,
            binding: Default::default(),
        }
    }

    fn req(service: &str, action: &str, params: &[(&str, serde_json::Value)]) -> CallRequest {
        serde_json::from_value(serde_json::json!({
            "service": service,
            "action": action,
            "params": params.iter().cloned().map(|(k, v)| (k.to_string(), v)).collect::<serde_json::Map<_, _>>(),
        }))
        .expect("CallRequest fixture")
    }

    fn spec() -> PaginationSpec {
        PaginationSpec {
            page_size: Some(PageSize {
                param: "maxResults".into(),
                default: Some(100),
                max: None,
            }),
            next: NextSpec {
                style: NextStyle::Cursor,
                param: Some("pageToken".into()),
                from: Some("nextPageToken".into()),
            },
            items: None,
            has_more: None,
        }
    }

    /// The whole point of storing it. A stored payload is a *resolved* request
    /// — a URL, headers, a body — so by replay time the action key and the
    /// argument map the marker is computed from are gone. D56 hit the same wall
    /// with the timeout cascade and answered it the same way.
    #[test]
    fn a_paged_action_carries_its_declaration_onto_the_stored_payload() {
        let stored = stored_pagination(
            &meta(Some(spec())),
            &req(
                "gmail",
                "list_messages",
                &[("maxResults", serde_json::json!(10))],
            ),
        )
        .expect("declaration carried");
        assert_eq!(stored.spec, spec());
        assert_eq!(stored.service.as_deref(), Some("gmail"));
        assert_eq!(stored.action.as_deref(), Some("list_messages"));
        assert_eq!(stored.params["maxResults"], serde_json::json!(10));
    }

    /// An action that declares nothing writes nothing, and a payload with no
    /// pagination key parses back to `None` — which is every row written before
    /// the field existed.
    #[test]
    fn an_unannotated_action_stores_nothing_and_old_rows_still_parse() {
        assert!(stored_pagination(&meta(None), &req("gmail", "list_labels", &[])).is_none());

        let legacy = serde_json::json!({
            "action": {"method": "GET", "url": "https://x.test/y", "headers": {}},
            "prefer_stream": false
        });
        let parsed: StoredCallRequest = serde_json::from_value(legacy).unwrap();
        assert!(parsed.pagination.is_none());
    }
}
