//! Applying the caller's response filter, wherever the result came from.
//!
//! The jq `filter` on a `CallRequest` used to be handled inline in the
//! buffered HTTP fork and nowhere else, so an MCP-runtime or platform-runtime
//! action accepted a filter, validated its syntax, and then silently returned
//! the whole body — the caller had no way to tell a filter that matched
//! nothing from one that was never run. Those runtimes have no upstream size
//! cap to dodge, but they have the same context budget, which is the reason
//! the filter exists.
//!
//! Lives in its own module rather than in `call.rs` because it now has three
//! call sites there and `call.rs` is against the 1000-line gate.

use overslash_core::types::ActionResult;

use crate::AppState;
use crate::services::response_filter;

use super::approval_detail::filter_audit_entry;
use super::dto::CallRequest;

/// Apply `req.filter` to `result` in place, returning the audit block for it.
///
/// The original body is preserved on `result.body` either way; the filtered
/// output goes on `result.filtered_body`, which is `Some` on both the ok and
/// the error envelope so a filter that failed is visible rather than absent.
/// Returns `None` when the caller supplied no filter — there is then nothing
/// to record, and an empty `filter` key in the audit detail would read as "a
/// filter ran and did nothing".
pub(super) async fn apply_to(
    state: &AppState,
    req: &CallRequest,
    result: &mut ActionResult,
) -> Option<serde_json::Value> {
    let filter = req.filter.clone()?;
    let lang = filter.lang().to_string();
    let expr = filter.expr().to_string();
    let timeout = std::time::Duration::from_millis(state.config.filter_timeout_ms);
    let filtered = response_filter::apply(filter, result.body.clone(), timeout).await;
    let audit = filter_audit_entry(&lang, &expr, &filtered);
    result.filtered_body = Some(filtered);
    Some(audit)
}

/// Insert a filter audit block into an action's audit detail, if there is one.
///
/// Every call site builds `detail` as a JSON object, so the `expect` is a
/// type-level fact rather than a runtime assumption.
pub(super) fn record(detail: &mut serde_json::Value, audit: Option<serde_json::Value>) {
    if let Some(audit) = audit {
        detail
            .as_object_mut()
            .expect("audit detail is a json object")
            .insert("filter".to_string(), audit);
    }
}
