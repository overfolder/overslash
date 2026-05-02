//! Minimal MCP server fake.
//!
//! Speaks Streamable HTTP (`POST /mcp`) JSON-RPC 2.0 with a fixed tool list.
//! This is sufficient for testing Overslash's *MCP client* code path
//! (`overslash_call`-style remote tool execution); it is intentionally
//! unrelated to Overslash's *own* `POST /mcp` server endpoint.
//!
//! Capability shape is selected by [`crate::scenarios::McpVariant`] — see
//! that module for the variants used in e2e scenarios.

use axum::{Json, Router, extract::State, routing::post};
use serde_json::{Value, json};

use crate::{Handle, bind, scenarios::McpVariant, serve};

pub async fn start() -> Handle {
    start_on("127.0.0.1:0").await
}

pub async fn start_on(bind_addr: &str) -> Handle {
    start_on_with(bind_addr, McpVariant::default()).await
}

pub async fn start_on_with(bind_addr: &str, variant: McpVariant) -> Handle {
    let (listener, addr, url) = bind(bind_addr).await.expect("bind mcp fake");
    let app = router(variant);
    serve(listener, addr, url, app)
}

pub fn router(variant: McpVariant) -> Router {
    Router::new().route("/mcp", post(rpc)).with_state(variant)
}

async fn rpc(State(variant): State<McpVariant>, Json(req): Json<Value>) -> Json<Value> {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");

    let result = match method {
        "initialize" => json!({
            "protocolVersion": "2025-03-26",
            "serverInfo": { "name": "overslash-fakes-mcp", "version": "0.1.0" },
            "capabilities": variant.capabilities(),
        }),
        "tools/list" => variant.tools(),
        "resources/list" => variant.resources(),
        "tools/call" => {
            let args = req
                .get("params")
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or(Value::Null);
            let message = args
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("(no message)");
            let elicited = variant.elicits_on_call();
            let text = if elicited {
                format!("elicited+echo: {message}")
            } else {
                format!("echo: {message}")
            };
            json!({
                "content": [{ "type": "text", "text": text }],
                "isError": false,
                "_overslash_fakes": { "elicited": elicited },
            })
        }
        _ => {
            return Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": format!("method not found: {method}") },
            }));
        }
    };

    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}
