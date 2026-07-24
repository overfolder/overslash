//! `POST /mcp` — MCP Streamable HTTP transport.
//!
//! This is the server-side of the design described in
//! `docs/design/mcp-oauth-transport.md`. An MCP client sends a JSON-RPC
//! request in the body; this handler dispatches it and returns the JSON-RPC
//! response.
//!
//! Dispatch is intentionally small: the four tools (`overslash_search`,
//! `overslash_read`, `overslash_call`, `overslash_auth`) are the whole
//! catalog. `overslash_read` is the read-only fast-path — same shape as
//! `overslash_call`'s fresh-call mode but the action handler rejects the
//! request when the resolved action's risk is not `Read`, which lets MCP
//! clients honour `readOnlyHint: true` and skip the confirmation prompt.
//! The MCP surface is call-only — it lets an agent discover and run
//! already-configured services, plus introspect its own identity.
//! Self-management
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

use std::convert::Infallible;
use std::time::Duration;

use axum::{
    Json, Router,
    extract::{Extension, State},
    http::{HeaderMap, StatusCode, header},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::post,
};
use futures_util::stream::{self, Stream, StreamExt};
use overslash_core::build_info::build_info;
use reqwest::Method;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    AppState,
    extractors::{AuthContext, ReqExt},
    middleware::subdomain::RequestOrgContext,
    routes::oauth_as as oauth_as_routes,
    services::{inbox, jwt, mcp_session, oauth_as, session},
};

mod dispatch;
mod elicitation;
mod initialize;
mod tools_call;

use initialize::{initialize_response, tools_list_response};
use tools_call::tools_call;

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

fn challenge(state: &AppState, headers: &HeaderMap, ctx: &RequestOrgContext) -> Response {
    // The challenge URL must point at the same issuer the metadata
    // endpoint will return so the MCP client can complete the discovery
    // chain on a per-org subdomain. Reuse the issuer builder.
    let issuer = oauth_as_routes::issuer_for(state, headers, ctx);
    let header_val =
        format!(r#"Bearer resource_metadata="{issuer}/.well-known/oauth-protected-resource""#);
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
    ctx: Option<Extension<RequestOrgContext>>,
    headers: HeaderMap,
    auth: Result<AuthContext, crate::error::AppError>,
) -> Response {
    if auth.is_err() {
        let ctx = ctx.map(|Extension(c)| c).unwrap_or(RequestOrgContext::Root);
        return challenge(&state, &headers, &ctx);
    }
    // No server-initiated streams for v1.
    (StatusCode::METHOD_NOT_ALLOWED, "method not allowed").into_response()
}

// ---------------------------------------------------------------------------
// POST /mcp
// ---------------------------------------------------------------------------

async fn post_mcp(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    ctx: Option<Extension<RequestOrgContext>>,
    auth: Result<AuthContext, crate::error::AppError>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let ctx = ctx.map(|Extension(c)| c).unwrap_or(RequestOrgContext::Root);
    let auth = match auth {
        Ok(a) => a,
        Err(_) => return challenge(&state, &headers, &ctx),
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
                None,
            )
            .ok()
        });

    // Per Streamable HTTP, clients echo the `Mcp-Session-Id` they received
    // on `initialize` in subsequent requests. We trust this header over the
    // DB's `last_session_id` because the latter races between concurrent
    // initialize calls sharing one client_id.
    let req_session_id: Option<Uuid> = headers
        .get("Mcp-Session-Id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok());

    // First try to parse as a request (has `method`). If that fails, try to
    // parse as a response — clients deliver elicitation answers as bare
    // `{ id, result }` / `{ id, error }` objects on POST /mcp.
    if let Ok(req) = serde_json::from_str::<JsonRpcRequest>(&body) {
        if req.jsonrpc != "2.0" {
            return rpc_error_response(req.id, INVALID_REQUEST, "jsonrpc must be \"2.0\"");
        }
        return match req.method.as_str() {
            "initialize" => initialize_response(&state, &ext, &auth, &req).await,
            "tools/list" => tools_list_response(&state, &ext, &auth, req.id).await,
            "tools/call" => {
                tools_call(&state, &ext, &auth, req, bearer.as_deref(), req_session_id).await
            }
            "notifications/initialized" => (StatusCode::NO_CONTENT, "").into_response(),
            other => rpc_error_response(
                req.id,
                METHOD_NOT_FOUND,
                format!("unknown method `{other}`"),
            ),
        };
    }

    // Bare-response delivery (server-initiated elicitation answer). Schema:
    //   { jsonrpc: "2.0", id: "elicit_<uuid>", result|error: ... }
    if let Ok(resp) = serde_json::from_str::<Value>(&body) {
        if let Some(id) = resp.get("id").and_then(Value::as_str) {
            if id.starts_with("elicit_") {
                // Tenant-isolation guard: the elicit_id behaves like a
                // capability and can leak through logs / SSE payloads.
                // Only the agent that owns the elicitation row may answer
                // it — otherwise a caller in another tenant who learns the
                // id could drive the victim's resolve+call as the victim.
                let owner_ok =
                    match overslash_db::repos::mcp_elicitation::get(state.db(&ext), id).await {
                        Ok(Some(row)) => Some(row.agent_identity_id) == auth.identity_id,
                        Ok(None) => false,
                        Err(e) => {
                            tracing::error!("lookup elicitation failed: {e}");
                            false
                        }
                    };
                if !owner_ok {
                    return rpc_error_response(
                        Value::String(id.to_string()),
                        INVALID_REQUEST,
                        "elicitation not found or not addressable by this caller",
                    );
                }

                let result = resp.get("result").cloned().unwrap_or_else(
                    || json!({ "action": "cancel", "content": resp.get("error").cloned() }),
                );
                let st = state.clone();
                let ext_c = ext.clone();
                let db = state.db_pool(&ext);
                let id_owned = id.to_string();
                // Bound the background task: two loopback HTTP calls
                // (resolve + call) shouldn't take more than a minute even
                // under load. Without this an unresponsive upstream could
                // pin a tokio task slot indefinitely.
                tokio::spawn(async move {
                    let work =
                        mcp_session::complete_from_elicitation(&st, &ext_c, &id_owned, &result);
                    match tokio::time::timeout(Duration::from_secs(60), work).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            tracing::error!(
                                elicit_id = %id_owned,
                                "complete elicitation failed: {e}"
                            );
                        }
                        Err(_) => {
                            tracing::error!(
                                elicit_id = %id_owned,
                                "complete elicitation timed out after 60s; cancelling row"
                            );
                            let _ =
                                overslash_db::repos::mcp_elicitation::cancel(&db, &id_owned).await;
                        }
                    }
                });
                return (StatusCode::ACCEPTED, "").into_response();
            }
        }
    }

    rpc_error_response(
        Value::Null,
        PARSE_ERROR,
        "parse error: not a request or recognised response",
    )
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

/// Wrap a typed-error envelope (a JSON object whose top-level `error` field
/// names the typed code) as an MCP tool result with `isError: true`. Per
/// the MCP spec, tool execution failures live on the success path with the
/// error flag set so the LLM still sees the body — JSON-RPC errors are
/// reserved for protocol-level failures.
///
/// The body is stringified into `content[0].text` because the MCP `content`
/// array contract is `text | image | resource`, and `text` is what every
/// model-facing client (Claude.ai, Claude Code, Openclaw) actually surfaces
/// to the model.
fn rpc_tool_error_response(id: Value, envelope: &Value) -> Response {
    let body = json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{
                "type": "text",
                "text": serde_json::to_string(envelope).unwrap_or_default(),
            }],
            "isError": true,
        },
    });
    (StatusCode::OK, Json(body)).into_response()
}

/// Result of a `forward()` call. The split lets the MCP layer distinguish
/// "upstream returned a typed error envelope the agent can branch on" from
/// "upstream blew up in a way the agent can't act on" without losing the
/// structured body to a `format!()`.
///
/// Why this matters: the REST layer renders `needs_authentication`,
/// `reauth_required`, `missing_scopes`, `credential_missing`, and
/// `not_in_your_chain` as JSON objects with a top-level `"error"` string
/// field (see `crate::error::AppError::into_response`). Stringifying those
/// destroys the structure the agent needs to self-recover.
#[derive(Debug)]
enum ForwardOutcome {
    /// 2xx response — value is the parsed body (or `Value::Null` for empty).
    Ok(Value),
    /// Non-2xx response carrying a JSON object body with a top-level
    /// `"error": "<typed_code>"` string field. Forward as-is so the MCP
    /// wrapper can hand it back as a tool result with `isError: true`.
    TypedError(Value),
}

impl ForwardOutcome {
    /// Apply `f` to the inner value when this is a success outcome; pass
    /// typed errors through unchanged. Lets dispatchers manipulate happy-path
    /// payloads (e.g. filter an array) without accidentally rewriting an
    /// error envelope.
    fn map_ok<F: FnOnce(Value) -> Value>(self, f: F) -> Self {
        match self {
            ForwardOutcome::Ok(v) => ForwardOutcome::Ok(f(v)),
            ForwardOutcome::TypedError(v) => ForwardOutcome::TypedError(v),
        }
    }
}

async fn forward(
    state: &AppState,
    bearer: &str,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<ForwardOutcome, String> {
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
        // Whitelist the five SPEC §5 envelopes (`docs/design/agent-self-management.md`
        // §5) that an agent can branch on. Every `AppError::into_response`
        // arm renders a `{"error": "<msg>"}` object, so a generic "any JSON
        // with `error` field" check would silently reframe every NotFound /
        // BadRequest / Forbidden as a tool result with `isError: true`,
        // widening the contract beyond what the slice promises. The
        // whitelist keeps unrecognized errors flowing through JSON-RPC
        // `INTERNAL_ERROR (-32603)` until they're explicitly added here
        // alongside spec coverage.
        const TYPED_ERROR_CODES: &[&str] = &[
            "needs_authentication",
            "reauth_required",
            "missing_scopes",
            "credential_missing",
            "not_in_your_chain",
        ];
        // The typed OAuth envelopes no longer carry a raw upstream provider
        // URL (white-label partners import tokens instead of wrapping an
        // Overslash-built authorize URL), so there is nothing to strip before
        // relaying to a chat consumer.
        if let Ok(parsed) = serde_json::from_str::<Value>(&text) {
            if let Some(code) = parsed.get("error").and_then(Value::as_str) {
                if TYPED_ERROR_CODES.contains(&code) {
                    return Ok(ForwardOutcome::TypedError(parsed));
                }
            }
        }
        return Err(format!("API {status}: {text}"));
    }
    if text.is_empty() {
        return Ok(ForwardOutcome::Ok(Value::Null));
    }
    Ok(ForwardOutcome::Ok(
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    ))
}
