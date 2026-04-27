//! `POST /mcp` — MCP Streamable HTTP transport.
//!
//! This is the server-side of the design described in
//! `docs/design/mcp-oauth-transport.md`. An MCP client sends a JSON-RPC
//! request in the body; this handler dispatches it and returns the JSON-RPC
//! response.
//!
//! Dispatch is intentionally small: the three tools (`overslash_search`,
//! `overslash_call`, `overslash_auth`) are the whole catalog. The MCP
//! surface is call-only — it lets an agent discover and run already-
//! configured services, plus introspect its own identity. Self-management
//! (creating services, minting subagents, resolving approvals, listing
//! secrets) lives in the dashboard; see
//! `docs/design/agent-self-management.md` for the roadmap to bring those
//! capabilities back under Overslash + Claude Code permission gates.
//!
//! Each tool call is forwarded to the corresponding REST endpoint over
//! loopback reqwest so we get the same rate-limiting, audit, and ACL
//! plumbing the REST callers go through. Forwarded bearer tokens carry the
//! caller's credential (either the same `aud=mcp` JWT presented on `/mcp`,
//! or an `osk_` agent key).
//!
//! `GET /mcp` returns a 405 for v1 — the protocol allows servers to opt out
//! of server-initiated streams, and none of our tools require them yet.
//! The route shape is reserved so we can turn it on without a client config
//! change when needed.

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use reqwest::Method;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    AppState,
    extractors::AuthContext,
    services::{jwt, oauth_as, session},
};

pub fn router() -> Router<AppState> {
    Router::new().route("/mcp", post(post_mcp).get(get_mcp))
}

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 error codes used here.
// ---------------------------------------------------------------------------

const PARSE_ERROR: i32 = -32700;
const INVALID_REQUEST: i32 = -32600;
const METHOD_NOT_FOUND: i32 = -32601;
const INVALID_PARAMS: i32 = -32602;
const INTERNAL_ERROR: i32 = -32603;

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    #[serde(default)]
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

// ---------------------------------------------------------------------------
// Auth challenge (401 + WWW-Authenticate)
// ---------------------------------------------------------------------------

fn challenge(state: &AppState) -> Response {
    let public_url = state.config.public_url.trim_end_matches('/');
    let header_val =
        format!(r#"Bearer resource_metadata="{public_url}/.well-known/oauth-protected-resource""#,);
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, header_val)],
        Json(json!({ "error": "unauthorized" })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// GET /mcp
// ---------------------------------------------------------------------------

async fn get_mcp(
    State(state): State<AppState>,
    auth: Result<AuthContext, crate::error::AppError>,
) -> Response {
    if auth.is_err() {
        return challenge(&state);
    }
    // No server-initiated streams for v1.
    (StatusCode::METHOD_NOT_ALLOWED, "method not allowed").into_response()
}

// ---------------------------------------------------------------------------
// POST /mcp
// ---------------------------------------------------------------------------

async fn post_mcp(
    State(state): State<AppState>,
    auth: Result<AuthContext, crate::error::AppError>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let auth = match auth {
        Ok(a) => a,
        Err(_) => return challenge(&state),
    };

    // Prefer the explicit Bearer header. When the caller authenticated via
    // a session cookie (no Authorization header), mint a short-lived MCP
    // JWT on the fly so the loopback REST calls carry a valid Bearer.
    let bearer: Option<String> = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_string)
        .or_else(|| {
            let signing_key = hex::decode(&state.config.signing_key)
                .unwrap_or_else(|_| state.config.signing_key.as_bytes().to_vec());
            let email = session::extract_session(&state, &headers)
                .map(|c| c.email)
                .unwrap_or_default();
            jwt::mint_mcp(
                &signing_key,
                auth.identity_id.unwrap_or_default(),
                auth.org_id,
                email,
                oauth_as::ACCESS_TOKEN_TTL_SECS,
            )
            .ok()
        });

    let req: JsonRpcRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => {
            return rpc_error_response(Value::Null, PARSE_ERROR, format!("parse error: {e}"));
        }
    };
    if req.jsonrpc != "2.0" {
        return rpc_error_response(req.id, INVALID_REQUEST, "jsonrpc must be \"2.0\"");
    }

    match req.method.as_str() {
        "initialize" => initialize_response(req.id),
        "tools/list" => tools_list_response(req.id),
        "tools/call" => tools_call(&state, req, bearer.as_deref()).await,
        "notifications/initialized" => {
            // Notifications don't expect a response; return 204.
            (StatusCode::NO_CONTENT, "").into_response()
        }
        other => rpc_error_response(
            req.id,
            METHOD_NOT_FOUND,
            format!("unknown method `{other}`"),
        ),
    }
}

fn rpc_error_response(id: Value, code: i32, message: impl Into<String>) -> Response {
    let body = json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message.into() }
    });
    (StatusCode::OK, Json(body)).into_response()
}

fn rpc_ok_response(id: Value, result: Value) -> Response {
    let body = json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    });
    (StatusCode::OK, Json(body)).into_response()
}

fn initialize_response(id: Value) -> Response {
    rpc_ok_response(
        id,
        json!({
            "protocolVersion": "2025-06-18",
            "capabilities": { "tools": {} },
            "serverInfo": {
                "name": "overslash",
                "version": env!("CARGO_PKG_VERSION"),
            },
            "instructions": "Overslash MCP server. Use overslash_search to discover \
        services, overslash_call to run actions, and overslash_auth for \
        identity introspection (whoami, service_status).",
        }),
    )
}

fn tools_list_response(id: Value) -> Response {
    rpc_ok_response(
        id,
        json!({
            "tools": [
                {
                    "name": "overslash_search",
                    "description": "Discover Overslash services and actions available to the caller.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": { "type": "string", "description": "Free-text query" }
                        },
                        "additionalProperties": false
                    }
                },
                {
                    "name": "overslash_call",
                    "description": "Call an Overslash action. May return pending_approval if the user must approve — once approved, call this tool again with `approval_id` (and no service/action/params) to trigger the stored request and receive the result. A pending approval expires 15 minutes after the user allows it.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "service":     { "type": "string" },
                            "action":      { "type": "string" },
                            "params":      {},
                            "approval_id": {
                                "type": "string",
                                "description": "Trigger the replay of a previously-approved action. Mutually exclusive with service/action/params."
                            }
                        },
                        "additionalProperties": false
                    }
                },
                {
                    "name": "overslash_auth",
                    "description": "Identity introspection sub-actions: whoami, service_status.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "action": { "type": "string" },
                            "params": {}
                        },
                        "required": ["action"],
                        "additionalProperties": false
                    }
                }
            ]
        }),
    )
}

// ---------------------------------------------------------------------------
// tools/call dispatch
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ToolCallParams {
    name: String,
    #[serde(default)]
    arguments: Value,
}

async fn tools_call(state: &AppState, req: JsonRpcRequest, bearer: Option<&str>) -> Response {
    let params: ToolCallParams = match serde_json::from_value(req.params.clone()) {
        Ok(p) => p,
        Err(e) => {
            return rpc_error_response(req.id, INVALID_PARAMS, format!("bad params: {e}"));
        }
    };
    let bearer = match bearer {
        Some(b) => b,
        None => {
            return rpc_error_response(req.id, INTERNAL_ERROR, "bearer missing after auth");
        }
    };

    let outcome = match params.name.as_str() {
        "overslash_search" => dispatch_search(state, bearer, &params.arguments).await,
        "overslash_call" => dispatch_call(state, bearer, &params.arguments).await,
        "overslash_auth" => dispatch_auth(state, bearer, &params.arguments).await,
        other => {
            return rpc_error_response(req.id, METHOD_NOT_FOUND, format!("unknown tool `{other}`"));
        }
    };

    match outcome {
        Ok(v) => rpc_ok_response(
            req.id,
            json!({
                "content": [{ "type": "text", "text": serde_json::to_string(&v).unwrap_or_default() }]
            }),
        ),
        Err(msg) => rpc_error_response(req.id, INTERNAL_ERROR, msg),
    }
}

async fn dispatch_search(state: &AppState, bearer: &str, args: &Value) -> Result<Value, String> {
    let q = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
    if q.is_empty() {
        return Err(
            "overslash_search requires a non-empty `query` — pass the natural-language string \
             describing what you want to do (e.g. \"send an email\")"
                .into(),
        );
    }
    let path = format!("/v1/search?q={}", urlencoding::encode(q));
    forward(state, bearer, Method::GET, &path, None).await
}

async fn dispatch_call(state: &AppState, bearer: &str, args: &Value) -> Result<Value, String> {
    // Resume-mode: caller is triggering the replay of a previously-approved
    // action. Forwards to POST /v1/approvals/{id}/call.
    if let Some(approval_id) = args.get("approval_id").and_then(|v| v.as_str()) {
        if args.get("service").is_some() || args.get("action").is_some() {
            return Err("approval_id is mutually exclusive with service/action/params".into());
        }
        let path = format!("/v1/approvals/{}/call", urlencoding::encode(approval_id));
        return forward(state, bearer, Method::POST, &path, None).await;
    }

    // Fresh-call mode: service + action required.
    let service = args
        .get("service")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            "service required (or pass approval_id to resume a pending approval)".to_string()
        })?;
    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "action required".to_string())?;

    // Overslash metaservice platform actions are handled in-process; they have
    // no upstream HTTP host to forward to.
    if service == "overslash" {
        return dispatch_overslash_platform(state, bearer, action, args).await;
    }

    let body = json!({
        "service": service,
        "action": action,
        "params": args.get("params").cloned().unwrap_or(Value::Null),
    });
    forward(state, bearer, Method::POST, "/v1/actions/call", Some(body)).await
}

async fn dispatch_overslash_platform(
    state: &AppState,
    bearer: &str,
    action: &str,
    args: &Value,
) -> Result<Value, String> {
    let params = args.get("params");
    match action {
        "list_pending" => {
            let mut result = forward(
                state,
                bearer,
                Method::GET,
                "/v1/approvals?scope=mine&status=allowed",
                None,
            )
            .await?;
            // An approval's status stays 'allowed' even after its execution
            // has been dispatched, failed, or expired. Only return entries
            // where the execution is still dispatchable.
            if let Some(arr) = result.as_array_mut() {
                arr.retain(|item| {
                    item.get("execution")
                        .and_then(|e| e.get("status"))
                        .and_then(Value::as_str)
                        == Some("pending")
                });
            }
            Ok(result)
        }
        "call_pending" => {
            let id = params
                .and_then(|p| p.get("approval_id"))
                .and_then(Value::as_str)
                .ok_or_else(|| "call_pending requires params.approval_id".to_string())?;
            let path = format!("/v1/approvals/{}/call", urlencoding::encode(id));
            forward(state, bearer, Method::POST, &path, None).await
        }
        "cancel_pending" => {
            let id = params
                .and_then(|p| p.get("approval_id"))
                .and_then(Value::as_str)
                .ok_or_else(|| "cancel_pending requires params.approval_id".to_string())?;
            let path = format!("/v1/approvals/{}/cancel", urlencoding::encode(id));
            forward(state, bearer, Method::POST, &path, None).await
        }
        other => Err(format!(
            "overslash platform action '{other}' is not callable via MCP"
        )),
    }
}

async fn dispatch_auth(state: &AppState, bearer: &str, args: &Value) -> Result<Value, String> {
    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "action required".to_string())?;
    let params = args.get("params").cloned().unwrap_or(Value::Null);

    // Self-management sub-actions (list_secrets, request_secret,
    // create_subagent, create_service_from_template) have been removed from
    // the MCP surface intentionally. Agents should use already-configured
    // services via overslash_call; creation and credential plumbing live
    // in the dashboard until the work in
    // docs/design/agent-self-management.md lands.
    let (method, path, body) = match action {
        "whoami" => (Method::GET, "/v1/whoami".to_string(), None),
        "service_status" => {
            let name = params
                .get("service")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "service_status requires `service`".to_string())?;
            (
                Method::GET,
                format!("/v1/services/{}", urlencoding::encode(name)),
                None,
            )
        }
        other => {
            return Err(format!(
                "unknown action `{other}` — supported: whoami, service_status"
            ));
        }
    };
    forward(state, bearer, method, &path, body).await
}

async fn forward(
    state: &AppState,
    bearer: &str,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value, String> {
    let url = format!("{}{}", state.config.public_url.trim_end_matches('/'), path);
    let mut req = state.http_client.request(method, &url).bearer_auth(bearer);
    if let Some(b) = body {
        req = req.json(&b);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("upstream error: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.map_err(|e| format!("body error: {e}"))?;
    if !status.is_success() {
        return Err(format!("API {status}: {text}"));
    }
    if text.is_empty() {
        return Ok(Value::Null);
    }
    Ok(serde_json::from_str(&text).unwrap_or(Value::String(text)))
}
