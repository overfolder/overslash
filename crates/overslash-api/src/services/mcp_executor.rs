//! Dispatches a resolved MCP tool call to the overslash-mcp-runtime service.
//! Called from `routes/actions.rs` after secret/OAuth env resolution and
//! permission/approval gating — same position in the pipeline where
//! `http_executor::execute` runs for HTTP-runtime services.
//!
//! The MCP result is packed into the existing [`ActionResult`] shape:
//! `body` carries the tool-result JSON (stringified), `status_code=200`,
//! `headers={}`. That keeps the `ExecuteResponse::Executed` wire shape
//! unchanged and lets dashboards/clients render MCP outputs the same way
//! they render an HTTP API's JSON body.

use std::collections::HashMap;

use serde::Serialize;
use uuid::Uuid;

use overslash_core::types::McpSpec;

use crate::error::AppError;
use crate::services::mcp_runtime_client::{InvokeRequest, InvokeResponse, RuntimeClient};

/// Body wrapper for MCP results serialized into `ActionResult.body`. Keeps
/// the envelope tiny and obvious so the dashboard can detect MCP responses
/// by shape if needed.
#[derive(Serialize)]
struct McpResultEnvelope<'a> {
    runtime: &'static str,
    tool: &'a str,
    result: &'a serde_json::Value,
}

/// Dispatch an MCP tool call. Returns the raw [`InvokeResponse`] so the
/// caller can keep `duration_ms` and `warm` for audit detail, plus pack
/// `result` into whatever response envelope fits.
#[allow(clippy::too_many_arguments)]
pub async fn invoke(
    client: &RuntimeClient,
    service_instance_id: Uuid,
    mcp: &McpSpec,
    tool: &str,
    arguments: &serde_json::Value,
    env: &HashMap<String, String>,
    env_hash: &str,
    request_id: Option<&str>,
) -> Result<InvokeResponse, AppError> {
    let package = (!mcp.package.is_empty()).then_some(mcp.package.as_str());
    let version = (!mcp.version.is_empty()).then_some(mcp.version.as_str());
    let command = mcp.command.as_deref();
    let limits = (!mcp.limits.is_empty()).then_some(&mcp.limits);

    let req = InvokeRequest {
        service_instance_id,
        tool,
        arguments,
        env,
        env_hash,
        package,
        version,
        command,
        limits,
        request_id,
    };
    client.invoke(&req).await
}

/// Pack an [`InvokeResponse`] into the `ActionResult.body` JSON envelope.
pub fn pack_body(tool: &str, resp: &InvokeResponse) -> String {
    let env = McpResultEnvelope {
        runtime: "mcp",
        tool,
        result: &resp.result,
    };
    serde_json::to_string(&env).unwrap_or_else(|_| "{}".to_string())
}
