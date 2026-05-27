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
    let input = core_disclosure::build_jq_input(req, &meta.params);
    match disclosure::run_disclosures(&meta.disclose, &input, filter_timeout).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("disclosure batch failed: {e}");
            Vec::new()
        }
    }
}

/// Approval-create variant: returns the disclosed field list AND the
/// redacted JSON blob to persist as `approvals.action_detail`. Falls back
/// to the legacy raw `ActionRequest` serialization when the template
/// declares neither `x-overslash-disclose` nor `x-overslash-redact`, so
/// pre-feature templates are unaffected.
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
        return (Vec::new(), serde_json::to_value(req).ok());
    }
    let projection = core_disclosure::build_jq_input(req, &meta.params);
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
