//! Minimal MCP server fake.
//!
//! Speaks Streamable HTTP (`POST /mcp`) JSON-RPC 2.0 with a fixed tool list.
//! This is sufficient for testing Overslash's *MCP client* code path
//! (`overslash_call`-style remote tool execution); it is intentionally
//! unrelated to Overslash's *own* `POST /mcp` server endpoint.

use axum::{Json, Router, routing::post};
use serde_json::{Value, json};

use crate::{Handle, bind, serve};

pub async fn start() -> Handle {
    start_on("127.0.0.1:0").await
}

pub async fn start_on(bind_addr: &str) -> Handle {
    let (listener, addr, url) = bind(bind_addr).await.expect("bind mcp fake");
    let app = router();
    serve(listener, addr, url, app)
}

pub fn router() -> Router {
    Router::new().route("/mcp", post(rpc))
}

async fn rpc(Json(req): Json<Value>) -> Json<Value> {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");

    let result = match method {
        "initialize" => json!({
            "protocolVersion": "2025-03-26",
            "serverInfo": { "name": "overslash-fakes-mcp", "version": "0.1.0" },
            "capabilities": { "tools": {} },
        }),
        "tools/list" => json!({
            "tools": [
                {
                    "name": "echo",
                    "description": "Echoes back its `message` argument.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "message": { "type": "string" } },
                        "required": ["message"],
                    },
                },
            ],
        }),
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
            json!({
                "content": [{ "type": "text", "text": format!("echo: {message}") }],
                "isError": false,
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
