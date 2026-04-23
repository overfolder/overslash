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
use std::time::Instant;

use overslash_core::types::{ActionResult, McpSpec};
use overslash_db::scopes::OrgScope;
use serde_json::{Value, json};

use crate::AppState;
use crate::error::AppError;
use crate::services::{mcp_auth, mcp_client::McpClient};

pub async fn invoke(
    state: &AppState,
    scope: &OrgScope,
    mcp: &McpSpec,
    tool: &str,
    arguments: &Value,
) -> Result<ActionResult, AppError> {
    let headers = mcp_auth::resolve_headers(state, scope, &mcp.auth).await?;

    let client = McpClient::new(state.http_client.clone(), &mcp.url)
        .map_err(|e| AppError::BadRequest(format!("invalid mcp.url: {e}")))?;

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
    }
}
