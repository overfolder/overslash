//! Approval disclosure, redaction, and audit-entry construction.

use crate::services::disclosure;
use overslash_core::{
    disclosure as core_disclosure,
    types::{ActionRequest, FilteredBody},
};

use super::*;

pub(super) fn generate_token() -> String {
    use rand::RngExt;
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

/// Build the audit-log `filter` block. Truncates the expression for
/// log readability and includes a sha256 so identical filters can be
/// grouped across calls. Filter output values are never logged — same
/// reasoning that already keeps response bodies out of audit logs.
pub(super) fn filter_audit_entry(
    lang: &str,
    expr: &str,
    outcome: &FilteredBody,
) -> serde_json::Value {
    use sha2::{Digest, Sha256};
    const EXPR_LOG_MAX: usize = 256;

    let expr_truncated: String = expr.chars().take(EXPR_LOG_MAX).collect();
    let expr_sha256 = hex::encode(Sha256::digest(expr.as_bytes()));

    let (result, original_bytes, filtered_bytes) = match outcome {
        FilteredBody::Ok {
            original_bytes,
            filtered_bytes,
            ..
        } => ("ok", *original_bytes, Some(*filtered_bytes)),
        FilteredBody::Error {
            kind,
            original_bytes,
            ..
        } => {
            let r = match kind {
                overslash_core::types::FilterErrorKind::BodyNotJson => "body_not_json",
                overslash_core::types::FilterErrorKind::RuntimeError => "runtime_error",
                overslash_core::types::FilterErrorKind::Timeout => "timeout",
                overslash_core::types::FilterErrorKind::OutputOverflow => "output_overflow",
            };
            (r, *original_bytes, None)
        }
    };

    let mut entry = serde_json::json!({
        "lang": lang,
        "expr_truncated": expr_truncated,
        "expr_sha256": expr_sha256,
        "result": result,
        "original_bytes": original_bytes,
    });
    if let Some(fb) = filtered_bytes {
        entry
            .as_object_mut()
            .expect("entry is a json object")
            .insert("filtered_bytes".to_string(), serde_json::json!(fb));
    }
    entry
}

/// Run the template's disclose filters against the resolved request and
/// return the labeled result list for audit rows. Empty vec when no filters
/// are declared or the batch timed out (failure is non-fatal — execution
/// continues without a summary rather than aborting the whole request).
pub(super) async fn compute_disclosure(
    meta: &ResolvedMeta,
    req: &ActionRequest,
    filter_timeout: std::time::Duration,
) -> Vec<disclosure::DisclosedField> {
    if meta.disclose.is_empty() {
        return Vec::new();
    }
    let input = core_disclosure::build_jq_input(req, &meta.params, &meta.resolved);
    match disclosure::run_disclosures(&meta.disclose, &input, filter_timeout).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("disclosure batch failed: {e}");
            Vec::new()
        }
    }
}

/// Approval-create variant: returns the disclosed field list AND the
/// redacted JSON blob to persist as `approvals.action_detail`.
///
/// Every branch — including the no-declaration fallback — goes through the
/// header-free `build_jq_input` projection
/// (`{method, url, params, body, resolved}`).
/// Headers are never part of `action_detail`: the projection is what gets
/// persisted, returned inline in the `pending_approval` envelope (REST and
/// MCP), and served from `GET /v1/approvals` — all agent-reachable
/// surfaces. See the projection-shape rationale in
/// `overslash_core::disclosure::apply_redactions`.
pub(super) async fn compute_approval_detail(
    meta: &ResolvedMeta,
    req: &ActionRequest,
    filter_timeout: std::time::Duration,
) -> (Vec<disclosure::DisclosedField>, Option<serde_json::Value>) {
    // MCP-runtime actions use a different projection: the resolved
    // ActionRequest has no url/method/body to inspect, so reviewers need
    // the tool name and arguments to see what the agent actually called.
    // Disclosure jq filters are still applied when declared — they operate
    // on the MCP projection ({runtime, tool, arguments, service, action}).
    // No `resolved` key here (or on the platform projection below): display
    // param resolvers are HTTP-action-only, so `meta.resolved` is always
    // empty for these shapes and the projections stay unchanged.
    if let Some(target) = meta.mcp_target.as_ref() {
        let projection = serde_json::json!({
            "runtime": "mcp",
            "tool": &target.tool,
            "arguments": &target.arguments,
            "service": meta.service_scope.as_ref().map(|s| &s.service_key),
            "action": meta.service_scope.as_ref().map(|s| &s.action_key),
        });
        let disclosed = if meta.disclose.is_empty() {
            Vec::new()
        } else {
            match disclosure::run_disclosures(&meta.disclose, &projection, filter_timeout).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("mcp disclosure batch failed: {e}");
                    Vec::new()
                }
            }
        };
        let mut redacted = projection;
        if !meta.redact.is_empty() {
            core_disclosure::apply_redactions(&mut redacted, &meta.redact);
        }
        return (disclosed, Some(redacted));
    }

    if let Some(pt) = meta.platform_target.as_ref() {
        let projection = serde_json::json!({
            "runtime": "platform",
            "action": &pt.action_key,
            "params": &pt.params,
            "service": meta.service_scope.as_ref().map(|s| &s.service_key),
        });
        return (Vec::new(), Some(projection));
    }

    if meta.disclose.is_empty() && meta.redact.is_empty() {
        return (
            Vec::new(),
            Some(core_disclosure::build_jq_input(
                req,
                &meta.params,
                &meta.resolved,
            )),
        );
    }
    let projection = core_disclosure::build_jq_input(req, &meta.params, &meta.resolved);
    let disclosed = if meta.disclose.is_empty() {
        Vec::new()
    } else {
        match disclosure::run_disclosures(&meta.disclose, &projection, filter_timeout).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("disclosure batch failed: {e}");
                Vec::new()
            }
        }
    };
    let mut redacted = projection;
    if !meta.redact.is_empty() {
        core_disclosure::apply_redactions(&mut redacted, &meta.redact);
    }
    (disclosed, Some(redacted))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn http_meta() -> ResolvedMeta {
        ResolvedMeta {
            description: None,
            service_scope: Some(ServiceScope {
                service_key: "github".into(),
                action_key: "create_issue".into(),
                scope_param: Default::default(),
                http_verb: None,
            }),
            risk: None,
            disclose: Vec::new(),
            redact: Vec::new(),
            oauth_injected: false,
            download: None,
            params: HashMap::new(),
            resolved: HashMap::new(),
            mcp_target: None,
            platform_target: None,
            instance_id: None,
            binding: Default::default(),
        }
    }

    /// Regression guard for the OAuth-token leak: a template that declares
    /// neither `x-overslash-disclose` nor `x-overslash-redact` must still
    /// get the header-free projection — never a raw `ActionRequest`
    /// serialization that would expose `headers` on every approval surface.
    #[tokio::test]
    async fn no_declaration_fallback_uses_headerless_projection() {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert(
            "X-Custom-Auth".to_string(),
            "Bearer leaked-token-123".to_string(),
        );
        let req = ActionRequest {
            method: "POST".into(),
            url: "https://api.github.com/repos/o/r/issues".into(),
            headers,
            body: Some(r#"{"title":"hi"}"#.into()),
            secrets: Vec::new(),
        };
        let meta = http_meta();

        let (disclosed, detail) =
            compute_approval_detail(&meta, &req, std::time::Duration::from_millis(100)).await;

        assert!(disclosed.is_empty());
        let detail = detail.expect("fallback always produces a detail blob");
        assert_eq!(
            detail,
            overslash_core::disclosure::build_jq_input(&req, &meta.params, &meta.resolved),
            "fallback must equal the canonical header-free projection"
        );
        assert!(detail.get("headers").is_none(), "headers must never appear");
        let rendered = serde_json::to_string(&detail).expect("detail serializes");
        assert!(
            !rendered.contains("leaked-token-123"),
            "credential values must never appear in action_detail"
        );
    }
}
