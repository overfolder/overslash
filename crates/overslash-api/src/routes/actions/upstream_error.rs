//! What the HTTP call path does when the upstream fails us.
//!
//! Split out of `call.rs` along the one seam that is genuinely a different
//! concern from building and dispatching a request: turning a transport-level
//! failure into a client-facing error and a durable audit row. Both halves are
//! shared by the streamed and buffered forks, which is why neither lives
//! inside either.

use overslash_db::repos::audit::AuditEntry;
use overslash_db::scopes::OrgScope;
use uuid::Uuid;

use crate::error::AppError;
use crate::services::{call_timeout::CallTimeout, http_caller};

/// Map a transport-level `CallError` to the client-facing `AppError`.
/// Shared by the streamed and buffered forks so the error contract stays
/// what it was before transport failures gained audit rows.
pub(super) fn map_call_error(e: http_caller::CallError, timeout: CallTimeout) -> AppError {
    match e {
        http_caller::CallError::ResponseTooLarge {
            content_length,
            content_type,
            limit_bytes,
        } => AppError::ResponseTooLarge {
            content_length,
            content_type,
            limit_bytes,
        },
        // `timeout_ms` comes from the transport (what was actually applied),
        // the rest from the resolver (who set it, and what the caller would
        // have to clear to ask for more).
        http_caller::CallError::Timeout { timeout_ms } => AppError::UpstreamTimeout {
            timeout_ms,
            timeout_source: timeout.source(),
            max_ms: timeout.max_ms(),
        },
        http_caller::CallError::Request(e) => AppError::Request(e),
    }
}

/// Write the `action.executed` audit row for an HTTP call whose upstream
/// never produced a response (DNS/connect/timeout, or a body over the
/// buffering limit). No `status_code` — nothing arrived. `error_detail`
/// comes from `audit_capture::scrub_transport_error`, so it never carries
/// the resolved URL or injected secrets; `action_req.url` is the same
/// secret-free template URL the success rows store.
#[allow(clippy::too_many_arguments)]
pub(super) async fn log_transport_error_audit(
    scope: &OrgScope,
    org_id: Uuid,
    identity_id: Uuid,
    action_req: &overslash_core::types::ActionRequest,
    service: Option<&str>,
    action: Option<&str>,
    error_detail: serde_json::Value,
    description: Option<&str>,
    ip: Option<&str>,
    tags: &[String],
) {
    let _ = scope
        .clone()
        .log_audit_tagged(
            AuditEntry {
                org_id,
                identity_id: Some(identity_id),
                action: "action.executed",
                resource_type: service,
                resource_id: None,
                detail: serde_json::json!({
                    "method": action_req.method,
                    "url": action_req.url,
                    "is_error": true,
                    "error": error_detail,
                    "service": service,
                    "action": action,
                }),
                description,
                ip_address: ip,
            },
            tags,
        )
        .await;
}
