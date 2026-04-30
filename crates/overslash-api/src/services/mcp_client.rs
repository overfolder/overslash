//! Thin JSON-RPC 2.0 client for MCP Streamable HTTP transport
//! (spec revision 2025-06-18).
//!
//! Scope: v1 speaks only the minimum Overslash needs to proxy a tool call:
//!
//! - `initialize` — advertises client capabilities, receives server info.
//! - `tools/list` — enumerates available tools with `inputSchema` /
//!   `outputSchema`. Used by the template save + resync flows to populate
//!   `discovered_tools`.
//! - `tools/call` — invokes a tool and returns the raw JSON-RPC result
//!   (caller interprets `content` / `structuredContent` / `isError`).
//!
//! Each public method runs a single HTTP POST round-trip. Sessions
//! (`Mcp-Session-Id`) are not pooled across requests — v1 is stateless.
//! `text/event-stream` responses are tolerated (first event delivers the
//! payload, we do not aggregate further SSE frames).

use futures_util::StreamExt;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;

const JSONRPC_VERSION: &str = "2.0";
const PROTOCOL_VERSION: &str = "2025-06-18";

/// Default cap on upstream response bytes. The MCP spec places no ceiling
/// on tool results; a cooperative-but-buggy server could stream megabytes
/// into our buffer. The 5 MB cap matches `max_response_body_bytes` used by
/// the HTTP executor.
pub const DEFAULT_MAX_BODY_BYTES: usize = 5 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum McpClientError {
    #[error("invalid MCP server URL: {0}")]
    InvalidUrl(String),

    #[error(transparent)]
    Transport(#[from] reqwest::Error),

    #[error("response was not valid JSON: {0}")]
    BadJson(String),

    #[error("server returned HTTP {status} {body}")]
    Http { status: u16, body: String },

    /// Upstream MCP server returned `401 Unauthorized` with a
    /// `WWW-Authenticate: Bearer resource_metadata="..."` header (RFC 9728).
    /// The caller should look up an existing token, attempt refresh, and
    /// otherwise mint a nested-OAuth flow at `resource_metadata_url`.
    #[error("upstream requires OAuth (resource_metadata={resource_metadata_url})")]
    AuthRequired { resource_metadata_url: String },

    #[error("JSON-RPC error {code}: {message}")]
    Rpc { code: i64, message: String },

    #[error("unexpected response shape: {0}")]
    UnexpectedShape(String),

    #[error("response exceeded {limit_bytes} bytes")]
    ResponseTooLarge { limit_bytes: usize },
}

/// A tool description as returned by `tools/list`. We only keep the fields
/// Overslash needs to render a UI, persist into the template, and merge with
/// the admin-authored YAML overrides.
#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveredTool {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default, rename = "inputSchema")]
    pub input_schema: Option<Value>,
    #[serde(default, rename = "outputSchema")]
    pub output_schema: Option<Value>,
}

/// Raw `tools/call` result. Callers interpret the MCP-level semantics
/// (`structuredContent` wins over `content`, `is_error` is in-band).
#[derive(Debug, Clone)]
pub struct ToolCallResult {
    pub content: Value,
    pub structured: Option<Value>,
    pub is_error: bool,
}

#[derive(Debug, Clone)]
pub struct McpClient {
    http: reqwest::Client,
    base: Url,
    max_body_bytes: usize,
}

impl McpClient {
    pub fn new(http: reqwest::Client, url: &str) -> Result<Self, McpClientError> {
        let base = Url::parse(url).map_err(|e| McpClientError::InvalidUrl(e.to_string()))?;
        Ok(Self {
            http,
            base,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        })
    }

    /// Construct with a caller-provided base URL (already validated) and a
    /// pre-built reqwest client (usually SSRF-pinned with timeouts). Used
    /// on the hot path so SSRF resolution happens once per request.
    pub fn with_client_and_base(http: reqwest::Client, base: Url, max_body_bytes: usize) -> Self {
        Self {
            http,
            base,
            max_body_bytes,
        }
    }

    /// Send `initialize` and return the server info payload. Callers that
    /// only need a one-shot tool call (the common Overslash path) can skip
    /// this and rely on the server accepting a `tools/call` without a
    /// preceding `initialize` — most public MCP servers do. We still expose
    /// this so the resync flow can validate reachability cheaply.
    pub async fn initialize(&self, auth_headers: &HeaderMap) -> Result<Value, McpClientError> {
        let req = json!({
            "jsonrpc": JSONRPC_VERSION,
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "overslash", "version": env!("CARGO_PKG_VERSION") }
            }
        });
        self.rpc(auth_headers, &req).await
    }

    pub async fn tools_list(
        &self,
        auth_headers: &HeaderMap,
    ) -> Result<Vec<DiscoveredTool>, McpClientError> {
        let req = json!({
            "jsonrpc": JSONRPC_VERSION,
            "id": 2,
            "method": "tools/list",
        });
        let result = self.rpc(auth_headers, &req).await?;
        let arr = result
            .get("tools")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                McpClientError::UnexpectedShape("tools/list result missing `tools`".into())
            })?;
        arr.iter()
            .map(|v| {
                serde_json::from_value::<DiscoveredTool>(v.clone())
                    .map_err(|e| McpClientError::UnexpectedShape(format!("tool entry: {e}")))
            })
            .collect()
    }

    pub async fn tools_call(
        &self,
        auth_headers: &HeaderMap,
        name: &str,
        arguments: &Value,
    ) -> Result<ToolCallResult, McpClientError> {
        let req = json!({
            "jsonrpc": JSONRPC_VERSION,
            "id": 3,
            "method": "tools/call",
            "params": { "name": name, "arguments": arguments }
        });
        let result = self.rpc(auth_headers, &req).await?;
        Ok(ToolCallResult {
            content: result.get("content").cloned().unwrap_or(Value::Null),
            structured: result.get("structuredContent").cloned(),
            is_error: result
                .get("isError")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        })
    }

    async fn rpc(&self, auth_headers: &HeaderMap, body: &Value) -> Result<Value, McpClientError> {
        let response = self
            .http
            .post(self.base.clone())
            .headers(auth_headers.clone())
            .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
            // MCP Streamable HTTP clients advertise acceptance of both JSON
            // and SSE; servers pick one. We only parse JSON; an SSE reply is
            // still accepted because the first event carries the full frame.
            .header(
                ACCEPT,
                HeaderValue::from_static("application/json, text/event-stream"),
            )
            .json(body)
            .send()
            .await?;

        let status = response.status();
        let ctype = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        // RFC 9728 §3 — 401 + `WWW-Authenticate: Bearer resource_metadata="..."`
        // signals that the resource server expects a bearer token issued by
        // its associated authorization server. Surface this as a structured
        // error so callers can mint a nested-OAuth flow rather than treating
        // it as a generic transport failure.
        if status == reqwest::StatusCode::UNAUTHORIZED {
            if let Some(www) = response
                .headers()
                .get(reqwest::header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok())
            {
                if let Some(url) = parse_resource_metadata(www) {
                    return Err(McpClientError::AuthRequired {
                        resource_metadata_url: url,
                    });
                }
            }
        }

        // Short-circuit if Content-Length is already oversized. This stops us
        // buffering anything when a server advertises a huge payload upfront.
        if let Some(len) = response.content_length() {
            if len as usize > self.max_body_bytes {
                return Err(McpClientError::ResponseTooLarge {
                    limit_bytes: self.max_body_bytes,
                });
            }
        }

        // Stream + cap: the MCP spec places no ceiling on tool results, and
        // `response.text()` would buffer without bound. A misbehaving or
        // compromised upstream could pipe megabytes into our process.
        let mut collected: Vec<u8> = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if collected.len() + chunk.len() > self.max_body_bytes {
                return Err(McpClientError::ResponseTooLarge {
                    limit_bytes: self.max_body_bytes,
                });
            }
            collected.extend_from_slice(&chunk);
        }
        let text = String::from_utf8_lossy(&collected).into_owned();

        if !status.is_success() {
            return Err(McpClientError::Http {
                status: status.as_u16(),
                body: text,
            });
        }

        let payload = parse_rpc_payload(&text, &ctype)?;

        if let Some(err) = payload.get("error") {
            let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
            let message = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            return Err(McpClientError::Rpc { code, message });
        }

        payload
            .get("result")
            .cloned()
            .ok_or_else(|| McpClientError::UnexpectedShape("missing `result` field".into()))
    }
}

/// Extract `resource_metadata="..."` from a `WWW-Authenticate: Bearer …`
/// header per RFC 9728 §5.1. Tolerates both quoted and unquoted forms; the
/// MCP spec mandates the parameter when an MCP server expects auth.
fn parse_resource_metadata(www_authenticate: &str) -> Option<String> {
    // Skip the auth scheme prefix ("Bearer", "DPoP", etc.).
    let rest = www_authenticate
        .split_once(' ')
        .map(|(_, r)| r)
        .unwrap_or(www_authenticate);
    for param in rest.split(',') {
        let param = param.trim();
        let (k, v) = param.split_once('=')?;
        if k.trim().eq_ignore_ascii_case("resource_metadata") {
            let v = v.trim();
            let v = v.trim_start_matches('"').trim_end_matches('"');
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Parse a Streamable HTTP response into the JSON-RPC envelope.
///
/// If the server replied with `text/event-stream`, we take the first
/// `data:` frame. Full SSE aggregation (multiple events, heartbeat pings)
/// is deliberately out of scope for v1 — real servers always emit the
/// complete envelope in the first data frame for a `tools/call`.
fn parse_rpc_payload(text: &str, content_type: &str) -> Result<Value, McpClientError> {
    if content_type.starts_with("text/event-stream") {
        let frame = text
            .lines()
            .find_map(|l| l.strip_prefix("data:").map(str::trim))
            .ok_or_else(|| {
                McpClientError::UnexpectedShape("SSE response had no data frame".into())
            })?;
        serde_json::from_str(frame).map_err(|e| McpClientError::BadJson(e.to_string()))
    } else {
        serde_json::from_str(text).map_err(|e| McpClientError::BadJson(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_url_rejected() {
        let err = McpClient::new(reqwest::Client::new(), "not a url").unwrap_err();
        assert!(matches!(err, McpClientError::InvalidUrl(_)));
    }

    #[test]
    fn parse_resource_metadata_quoted() {
        assert_eq!(
            parse_resource_metadata(
                "Bearer resource_metadata=\"https://x.example/.well-known/oauth-protected-resource\""
            ),
            Some("https://x.example/.well-known/oauth-protected-resource".to_string())
        );
    }

    #[test]
    fn parse_resource_metadata_with_other_params() {
        assert_eq!(
            parse_resource_metadata(
                "Bearer realm=\"x\", resource_metadata=\"https://x/foo\", scope=\"read write\""
            ),
            Some("https://x/foo".to_string())
        );
    }

    #[test]
    fn parse_resource_metadata_missing() {
        assert_eq!(parse_resource_metadata("Bearer realm=\"x\""), None);
    }

    #[test]
    fn parse_resource_metadata_unquoted() {
        // RFC 7235 allows token68 unquoted forms; tolerate both.
        assert_eq!(
            parse_resource_metadata("Bearer resource_metadata=https://x/foo"),
            Some("https://x/foo".to_string())
        );
    }

    #[test]
    fn parse_rpc_payload_json() {
        let v = parse_rpc_payload(
            r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
            "application/json",
        )
        .unwrap();
        assert_eq!(v["result"]["ok"], true);
    }

    #[test]
    fn parse_rpc_payload_sse_first_frame() {
        let sse = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":42}\n\n";
        let v = parse_rpc_payload(sse, "text/event-stream").unwrap();
        assert_eq!(v["result"], 42);
    }

    #[test]
    fn parse_rpc_payload_sse_missing_data() {
        let sse = "event: ping\n\n";
        let err = parse_rpc_payload(sse, "text/event-stream").unwrap_err();
        assert!(matches!(err, McpClientError::UnexpectedShape(_)));
    }

    #[test]
    fn parse_rpc_payload_bad_json() {
        let err = parse_rpc_payload("not json", "application/json").unwrap_err();
        assert!(matches!(err, McpClientError::BadJson(_)));
    }

    // ── Live round-trips against an in-process axum stub ────────────────
    //
    // These tests exercise the full HTTP path — serialization, Accept
    // handshake, header forwarding, JSON-RPC envelope, SSE fallback, error
    // mapping — without a real MCP server.

    use axum::{Json, Router, extract::State, http::HeaderMap as AxumHeaders, routing::post};
    use reqwest::header::AUTHORIZATION;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::Mutex;
    use tokio::net::TcpListener;

    #[derive(Default, Clone)]
    struct StubState {
        last_auth: Arc<Mutex<Option<String>>>,
        sse: bool,
        error: Option<(i64, String)>,
    }

    async fn stub_handler(
        State(state): State<StubState>,
        headers: AxumHeaders,
        Json(req): Json<Value>,
    ) -> axum::response::Response {
        use axum::response::IntoResponse;
        *state.last_auth.lock().unwrap() = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");

        if let Some((code, msg)) = &state.error {
            return Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": code, "message": msg }
            }))
            .into_response();
        }

        let result = match method {
            "initialize" => json!({
                "protocolVersion": PROTOCOL_VERSION,
                "serverInfo": { "name": "stub", "version": "0" },
                "capabilities": {}
            }),
            "tools/list" => json!({
                "tools": [
                    {
                        "name": "echo",
                        "description": "Echo input",
                        "inputSchema": {
                            "type": "object",
                            "properties": { "x": { "type": "string" } },
                            "required": ["x"]
                        }
                    }
                ]
            }),
            "tools/call" => {
                let args = req
                    .get("params")
                    .and_then(|p| p.get("arguments"))
                    .cloned()
                    .unwrap_or(Value::Null);
                json!({
                    "content": [{ "type": "text", "text": "ok" }],
                    "structuredContent": { "echo": args },
                    "isError": false
                })
            }
            _ => json!({}),
        };

        let envelope = json!({ "jsonrpc": "2.0", "id": id, "result": result });

        if state.sse {
            let body = format!("event: message\ndata: {}\n\n", envelope);
            axum::http::Response::builder()
                .header("content-type", "text/event-stream")
                .body(axum::body::Body::from(body))
                .unwrap()
                .into_response()
        } else {
            Json(envelope).into_response()
        }
    }

    async fn start_stub(state: StubState) -> SocketAddr {
        let app = Router::new()
            .route("/mcp", post(stub_handler))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        addr
    }

    fn bearer(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {v}")).unwrap(),
        );
        h
    }

    #[tokio::test]
    async fn initialize_roundtrip_and_forwards_auth() {
        let state = StubState::default();
        let addr = start_stub(state.clone()).await;
        let client = McpClient::new(reqwest::Client::new(), &format!("http://{addr}/mcp")).unwrap();
        let res = client.initialize(&bearer("abc")).await.unwrap();
        assert_eq!(res["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(
            state.last_auth.lock().unwrap().as_deref(),
            Some("Bearer abc")
        );
    }

    #[tokio::test]
    async fn tools_list_parses_into_discovered_tools() {
        let addr = start_stub(StubState::default()).await;
        let client = McpClient::new(reqwest::Client::new(), &format!("http://{addr}/mcp")).unwrap();
        let tools = client.tools_list(&HeaderMap::new()).await.unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "echo");
        assert_eq!(tools[0].description.as_deref(), Some("Echo input"));
        assert!(tools[0].input_schema.is_some());
    }

    #[tokio::test]
    async fn tools_call_returns_structured_content() {
        let addr = start_stub(StubState::default()).await;
        let client = McpClient::new(reqwest::Client::new(), &format!("http://{addr}/mcp")).unwrap();
        let res = client
            .tools_call(&HeaderMap::new(), "echo", &json!({ "x": "hi" }))
            .await
            .unwrap();
        assert!(!res.is_error);
        assert_eq!(res.structured.unwrap()["echo"]["x"], "hi");
    }

    #[tokio::test]
    async fn sse_response_is_accepted() {
        let state = StubState {
            sse: true,
            ..Default::default()
        };
        let addr = start_stub(state).await;
        let client = McpClient::new(reqwest::Client::new(), &format!("http://{addr}/mcp")).unwrap();
        let res = client
            .tools_call(&HeaderMap::new(), "echo", &json!({ "x": "sse" }))
            .await
            .unwrap();
        assert_eq!(res.structured.unwrap()["echo"]["x"], "sse");
    }

    #[tokio::test]
    async fn oversized_response_is_rejected_before_buffering_everything() {
        // Serve a response that's well over the configured cap. The client
        // must return ResponseTooLarge, not buffer everything and OOM.
        let app = Router::new().route(
            "/mcp",
            post(|| async {
                // 2 MiB payload — dwarfs the 64 KiB cap we pass in this test.
                let big = "x".repeat(2 * 1024 * 1024);
                Json(json!({ "jsonrpc": "2.0", "id": 1, "result": { "blob": big } }))
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let base = Url::parse(&format!("http://{addr}/mcp")).unwrap();
        let client = McpClient::with_client_and_base(reqwest::Client::new(), base, 64 * 1024);
        let err = client
            .tools_call(&HeaderMap::new(), "echo", &json!({}))
            .await
            .unwrap_err();
        match err {
            McpClientError::ResponseTooLarge { limit_bytes } => {
                assert_eq!(limit_bytes, 64 * 1024)
            }
            other => panic!("wrong err: {other:?}"),
        }
    }

    #[tokio::test]
    async fn jsonrpc_error_surfaces_as_rpc_error() {
        let state = StubState {
            error: Some((-32601, "Method not found".into())),
            ..Default::default()
        };
        let addr = start_stub(state).await;
        let client = McpClient::new(reqwest::Client::new(), &format!("http://{addr}/mcp")).unwrap();
        let err = client
            .tools_call(&HeaderMap::new(), "ghost", &json!({}))
            .await
            .unwrap_err();
        match err {
            McpClientError::Rpc { code, .. } => assert_eq!(code, -32601),
            other => panic!("wrong err: {other:?}"),
        }
    }
}
