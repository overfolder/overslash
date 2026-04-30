//! Mode-C MCP dispatch: resolve auth headers via the secret vault, call the
//! external server's JSON-RPC `tools/call`, and pack the result into the
//! same `ActionResult` shape HTTP actions produce.
//!
//! The envelope placed in `ActionResult.body` is stable:
//!
//! ```json
//! {
//!   "runtime": "mcp",
//!   "tool": "<name>",
//!   "structured": <structuredContent or null>,
//!   "content": [...content blocks, or Null],
//!   "is_error": false
//! }
//! ```
//!
//! Tool-level errors (`isError: true`) are returned inside the envelope, not
//! as an `AppError` — MCP models them as in-band. Transport errors (4xx/5xx,
//! broken JSON, protocol errors) short-circuit with `AppError::BadGateway`
//! and write nothing to the audit body.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use overslash_core::types::{ActionResult, McpAuth};
use overslash_db::scopes::OrgScope;
use serde_json::{Value, json};

use crate::AppState;
use crate::error::AppError;
use crate::services::{
    mcp_auth,
    mcp_client::{DEFAULT_MAX_BODY_BYTES, McpClient},
    ssrf_guard,
};

/// Total read/connect timeout for every outbound MCP call. Matches the
/// `fetch_openapi_url` import path so admins see consistent latency-bound
/// behavior across the two user-URL code paths.
const MCP_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn invoke(
    state: &AppState,
    scope: &OrgScope,
    url: &str,
    auth: &McpAuth,
    tool: &str,
    arguments: &Value,
) -> Result<ActionResult, AppError> {
    let headers = mcp_auth::resolve_headers(state, scope, auth).await?;

    // Apply OVERSLASH_SSRF_ALLOW_PRIVATE-gated host overrides so e2e tests
    // can route MCP calls at a local fake. Same semantics as the HTTP path
    // in `action_caller::call_action_request`.
    let resolved_url = state.config.apply_base_overrides(url);
    let url = resolved_url.as_str();

    // SSRF guard: validate url's host resolves to a public IP and pin
    // the reqwest client to that IP so a compromised resolver cannot rebind
    // to an internal target between validation and connect. Timeouts live
    // on this client too — state.http_client has no per-request deadline.
    let (http, base) = ssrf_guard::build_pinned_client(url, MCP_TIMEOUT).await?;
    let client = McpClient::with_client_and_base(http, base, DEFAULT_MAX_BODY_BYTES);

    let start = Instant::now();
    let result = client
        .tools_call(&headers, tool, arguments)
        .await
        .map_err(map_client_error)?;
    let duration_ms = start.elapsed().as_millis() as u64;

    let envelope = json!({
        "runtime": "mcp",
        "tool": tool,
        "structured": result.structured,
        "content": result.content,
        "is_error": result.is_error,
    });

    Ok(ActionResult {
        // 200 when the transport and JSON-RPC both succeeded, even if
        // is_error == true. Tool-level errors are in-band per the MCP spec.
        status_code: 200,
        headers: HashMap::new(),
        body: envelope.to_string(),
        duration_ms,
        filtered_body: None,
    })
}

/// Build the canonical `action.executed` audit detail for an MCP call,
/// shared between the inline executor (`routes/actions.rs`) and the
/// approval-replay path (`routes/approvals.rs`). Returns the in-band
/// `is_error` flag so callers can branch on it (e.g. for response
/// metadata) without parsing the envelope twice. Callers may then merge
/// their own keys into the returned object (`service`/`action`/
/// `disclosed` inline; `replayed_from_approval`/`execution_id` on replay).
pub fn build_audit_detail(
    result: &ActionResult,
    tool: &str,
    url: &str,
    arguments: &Value,
) -> (bool, Value) {
    let envelope: Option<Value> = serde_json::from_str(&result.body).ok();
    let is_error = envelope
        .as_ref()
        .and_then(|e| e.get("is_error"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let detail = json!({
        "runtime": "mcp",
        "tool": tool,
        "arguments": arguments,
        "url": url,
        "duration_ms": result.duration_ms,
        "is_error": is_error,
    });
    (is_error, detail)
}

fn map_client_error(err: crate::services::mcp_client::McpClientError) -> AppError {
    use crate::services::mcp_client::McpClientError::*;
    match err {
        InvalidUrl(m) => AppError::BadRequest(format!("invalid mcp.url: {m}")),
        Transport(e) => AppError::BadGateway(format!("mcp transport error: {e}")),
        BadJson(m) => AppError::BadGateway(format!("mcp server returned invalid JSON: {m}")),
        Http { status, body } => {
            AppError::BadGateway(format!("mcp server returned HTTP {status}: {body}"))
        }
        Rpc { code, message } => {
            AppError::BadGateway(format!("mcp JSON-RPC error {code}: {message}"))
        }
        UnexpectedShape(m) => AppError::BadGateway(format!("mcp unexpected response: {m}")),
        ResponseTooLarge { limit_bytes } => {
            AppError::BadGateway(format!("mcp response exceeded {limit_bytes} bytes"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::map_client_error;
    use crate::error::AppError;
    use crate::services::mcp_client::McpClientError;

    fn is_bad_gateway(e: &AppError) -> bool {
        matches!(e, AppError::BadGateway(_))
    }
    fn is_bad_request(e: &AppError) -> bool {
        matches!(e, AppError::BadRequest(_))
    }

    #[test]
    fn map_invalid_url_is_bad_request() {
        let e = map_client_error(McpClientError::InvalidUrl("nope".into()));
        assert!(is_bad_request(&e));
    }

    #[test]
    fn map_bad_json_is_bad_gateway() {
        let e = map_client_error(McpClientError::BadJson("garbage".into()));
        assert!(is_bad_gateway(&e));
    }

    #[test]
    fn map_http_error_is_bad_gateway() {
        let e = map_client_error(McpClientError::Http {
            status: 502,
            body: "upstream down".into(),
        });
        assert!(is_bad_gateway(&e));
    }

    #[test]
    fn map_rpc_error_is_bad_gateway() {
        let e = map_client_error(McpClientError::Rpc {
            code: -32601,
            message: "Method not found".into(),
        });
        assert!(is_bad_gateway(&e));
    }

    #[test]
    fn map_unexpected_shape_is_bad_gateway() {
        let e = map_client_error(McpClientError::UnexpectedShape("no result".into()));
        assert!(is_bad_gateway(&e));
    }
}
