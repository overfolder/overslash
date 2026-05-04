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
use reqwest::Method;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    AppState,
    extractors::AuthContext,
    middleware::subdomain::RequestOrgContext,
    routes::oauth_as as oauth_as_routes,
    services::{jwt, mcp_session, oauth_as, session},
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
            "initialize" => initialize_response(&state, &auth, &req).await,
            "tools/list" => tools_list_response(req.id),
            "tools/call" => tools_call(&state, &auth, req, bearer.as_deref(), req_session_id).await,
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
                let owner_ok = match overslash_db::repos::mcp_elicitation::get(&state.db, id).await
                {
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
                let id_owned = id.to_string();
                // Bound the background task: two loopback HTTP calls
                // (resolve + call) shouldn't take more than a minute even
                // under load. Without this an unresponsive upstream could
                // pin a tokio task slot indefinitely.
                tokio::spawn(async move {
                    let work = mcp_session::complete_from_elicitation(&st, &id_owned, &result);
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
                            let _ = overslash_db::repos::mcp_elicitation::cancel(&st.db, &id_owned)
                                .await;
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

async fn initialize_response(
    state: &AppState,
    auth: &AuthContext,
    req: &JsonRpcRequest,
) -> Response {
    // Persist capabilities + clientInfo + protocolVersion declared by the
    // client so we can later decide whether elicitation is reachable for
    // that connection. Best-effort: a DB hiccup must not block the
    // handshake (initialize is synchronous from the client's POV).
    let session_id = Uuid::new_v4();
    if let Some(client_id) = auth.mcp_client_id.as_deref() {
        let capabilities = req
            .params
            .get("capabilities")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let client_info = req
            .params
            .get("clientInfo")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let protocol_version = req
            .params
            .get("protocolVersion")
            .and_then(Value::as_str)
            .unwrap_or("");
        if let Err(e) = overslash_db::repos::oauth_mcp_client::update_initialize_state(
            &state.db,
            client_id,
            &capabilities,
            &client_info,
            protocol_version,
            session_id,
        )
        .await
        {
            tracing::warn!(client_id, "failed to persist mcp initialize state: {e}");
        }
    }

    let body = json!({
        "jsonrpc": "2.0",
        "id": req.id,
        "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": { "tools": {} },
            "serverInfo": {
                "name": "overslash",
                "version": env!("CARGO_PKG_VERSION"),
            },
            "instructions": "Overslash MCP server. Use overslash_search to discover \
        services, overslash_read to invoke read-class actions (the server \
        rejects writes/deletes routed through it), overslash_call to invoke \
        any action or resume a pending approval, and overslash_auth for \
        identity introspection (whoami, service_status). Prefer overslash_read \
        when the action only reads data — clients can skip the confirmation \
        prompt.",
        }
    });
    (
        StatusCode::OK,
        [("Mcp-Session-Id", session_id.to_string())],
        Json(body),
    )
        .into_response()
}

fn tools_list_response(id: Value) -> Response {
    rpc_ok_response(
        id,
        json!({
            "tools": [
                {
                    "name": "overslash_search",
                    "title": "Search Overslash services",
                    "description": "Discover Overslash service instances and actions available to the caller. Each result's `service` field is the instance name to pass directly as `overslash_call.service` (e.g. `gmail_work`, `whatsapp_angel`) — never the `template` key. Templates with multiple connected instances fan out into one row per instance. Pass `include_catalog: true` to also surface un-connected templates; those rows are marked `setup_required: true` and have no `service` field — set them up with `overslash_auth.create_service_from_template` before calling. An empty `query` lists every callable instance without actions (browse mode).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Free-text query. Pass an empty string to list every callable instance (no actions)."
                            },
                            "include_catalog": {
                                "type": "boolean",
                                "default": false,
                                "description": "When true, also surface un-connected templates as `setup_required: true` rows. Default returns only configured instances the caller can call right now."
                            }
                        },
                        "additionalProperties": false
                    },
                    "annotations": {
                        "readOnlyHint": true,
                        "idempotentHint": true,
                        "openWorldHint": false
                    }
                },
                {
                    "name": "overslash_read",
                    "title": "Read via Overslash",
                    "description": "Call a read-class Overslash action on a configured service instance. The `service` argument must be an *instance name* (e.g. `gmail_work`), discoverable via overslash_search — not a template key like `gmail`. The server rejects this call if the resolved action's risk is not `read`. Use overslash_call for write/delete actions or to resume a pending approval.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "service": {
                                "type": "string",
                                "description": "Instance name (e.g. `gmail_work`). Pass the `service` field from an overslash_search result, not the `template` key."
                            },
                            "action":  { "type": "string" },
                            "params":  {}
                        },
                        "required": ["service", "action"],
                        "additionalProperties": false
                    },
                    "annotations": {
                        "readOnlyHint": true,
                        "idempotentHint": true,
                        "openWorldHint": true
                    }
                },
                {
                    "name": "overslash_call",
                    "title": "Call an Overslash action",
                    "description": "Call any Overslash action (read, write, or delete) on a configured service instance, or resume a pending approval. The `service` argument must be an *instance name* (e.g. `gmail_work`), discoverable via overslash_search — not a template key like `gmail`. May return pending_approval if the user must approve — once approved, call this tool again with `approval_id` (and no service/action/params) to trigger the stored request and receive the result. A pending approval expires 15 minutes after the user allows it. Prefer overslash_read for read-only actions so clients can skip the confirmation prompt.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "service": {
                                "type": "string",
                                "description": "Instance name (e.g. `gmail_work`). Pass the `service` field from an overslash_search result, not the `template` key."
                            },
                            "action":      { "type": "string" },
                            "params":      {},
                            "approval_id": {
                                "type": "string",
                                "description": "Trigger the replay of a previously-approved action. Mutually exclusive with service/action/params."
                            }
                        },
                        "additionalProperties": false
                    },
                    "annotations": {
                        "readOnlyHint": false,
                        "destructiveHint": true,
                        "idempotentHint": false,
                        "openWorldHint": true
                    }
                },
                {
                    "name": "overslash_auth",
                    "title": "Identity & service status",
                    "description": "Identity introspection sub-actions: whoami, service_status.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "action": { "type": "string" },
                            "params": {}
                        },
                        "required": ["action"],
                        "additionalProperties": false
                    },
                    "annotations": {
                        "readOnlyHint": true,
                        "idempotentHint": true,
                        "openWorldHint": false
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

async fn tools_call(
    state: &AppState,
    auth: &AuthContext,
    req: JsonRpcRequest,
    bearer: Option<&str>,
    req_session_id: Option<Uuid>,
) -> Response {
    let mut params: ToolCallParams = match serde_json::from_value(req.params.clone()) {
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

    normalize_stringified_params(&mut params.arguments);

    let outcome = match params.name.as_str() {
        "overslash_search" => dispatch_search(state, bearer, &params.arguments).await,
        "overslash_read" => dispatch_read(state, bearer, &params.arguments).await,
        "overslash_call" => {
            return tools_call_overslash_call(
                state,
                auth,
                &req,
                bearer,
                &params.arguments,
                req_session_id,
            )
            .await;
        }
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

/// Branch off `overslash_call` so we can upgrade to SSE on a permission gap.
///
/// Mirrors `dispatch_call` for happy-path (just calls it), then peeks for
/// `status: "pending_approval"` in the response. If elicitation is enabled
/// and the client supports it, the response is reframed as a server-initiated
/// `elicitation/create` request streamed back over SSE; the final tool
/// result lands once the user resolves through the dialog (or an out-of-band
/// dashboard click). Otherwise the original synchronous `pending_approval`
/// JSON is returned just like before.
async fn tools_call_overslash_call(
    state: &AppState,
    auth: &AuthContext,
    req: &JsonRpcRequest,
    bearer: &str,
    args: &Value,
    req_session_id: Option<Uuid>,
) -> Response {
    let outcome = match dispatch_call(state, bearer, args).await {
        Ok(v) => v,
        Err(msg) => return rpc_error_response(req.id.clone(), INTERNAL_ERROR, msg),
    };

    // Synchronous success or platform action: return as today.
    let is_pending = outcome.get("status").and_then(Value::as_str) == Some("pending_approval");
    if !is_pending {
        return rpc_ok_response(
            req.id.clone(),
            json!({
                "content": [{ "type": "text", "text": serde_json::to_string(&outcome).unwrap_or_default() }]
            }),
        );
    }

    // Pending approval — promote to elicitation if eligible.
    let promote = elicitation_eligible(state, auth).await;
    if !promote {
        return rpc_ok_response(
            req.id.clone(),
            json!({
                "content": [{ "type": "text", "text": serde_json::to_string(&outcome).unwrap_or_default() }]
            }),
        );
    }

    let approval_id = match outcome.get("approval_id").and_then(Value::as_str) {
        Some(s) => match Uuid::parse_str(s) {
            Ok(u) => u,
            Err(_) => return synchronous_pending_response(&req.id, &outcome),
        },
        None => return synchronous_pending_response(&req.id, &outcome),
    };
    let action_summary = outcome
        .get("action_description")
        .and_then(Value::as_str)
        .unwrap_or("an action")
        .to_string();
    let agent_identity_id = match auth.identity_id {
        Some(id) => id,
        None => return synchronous_pending_response(&req.id, &outcome),
    };

    let elicit_id = format!("elicit_{}", Uuid::new_v4());
    // Prefer the session id the client echoed in the `Mcp-Session-Id`
    // header (per Streamable HTTP) — it identifies *this* client even when
    // multiple clients share one DCR client_id. Fall back to the DB's
    // `last_session_id` for clients that don't echo the header, then to a
    // fresh UUID. The point of using an existing id is so disconnect's
    // `cancel_for_session(last_session_id)` can find and cancel this row.
    let session_id = match req_session_id {
        Some(s) => s,
        None => match auth.mcp_client_id.as_deref() {
            Some(client_id) => {
                match overslash_db::repos::oauth_mcp_client::get_by_client_id(&state.db, client_id)
                    .await
                {
                    Ok(Some(c)) => c.last_session_id.unwrap_or_else(Uuid::new_v4),
                    _ => Uuid::new_v4(),
                }
            }
            None => Uuid::new_v4(),
        },
    };
    if let Err(e) = mcp_session::open(
        state,
        &elicit_id,
        session_id,
        agent_identity_id,
        approval_id,
    )
    .await
    {
        tracing::error!("open mcp elicitation failed: {e}");
        return synchronous_pending_response(&req.id, &outcome);
    }

    sse_elicitation_response(
        state.clone(),
        req.id.clone(),
        elicit_id,
        approval_id,
        action_summary,
        outcome.clone(),
    )
}

fn synchronous_pending_response(id: &Value, outcome: &Value) -> Response {
    rpc_ok_response(
        id.clone(),
        json!({
            "content": [{ "type": "text", "text": serde_json::to_string(outcome).unwrap_or_default() }]
        }),
    )
}

/// Decide whether elicitation is reachable for the *calling* (agent, client)
/// pair. Both lookups are keyed on `auth.mcp_client_id` rather than the
/// most-recently-updated binding for the agent — otherwise, in a
/// multi-client-per-agent setup, an eligible client could be denied
/// because the most recent binding belongs to a different client whose
/// capabilities or toggle don't match.
async fn elicitation_eligible(state: &AppState, auth: &AuthContext) -> bool {
    let Some(agent_id) = auth.identity_id else {
        return false;
    };
    let Some(client_id) = auth.mcp_client_id.as_deref() else {
        return false;
    };
    let binding = match overslash_db::repos::mcp_client_agent_binding::get_for_agent_and_client(
        &state.db, agent_id, client_id,
    )
    .await
    {
        Ok(Some(b)) => b,
        _ => return false,
    };
    if !binding.elicitation_enabled {
        return false;
    }
    let client =
        match overslash_db::repos::oauth_mcp_client::get_by_client_id(&state.db, client_id).await {
            Ok(Some(c)) => c,
            _ => return false,
        };
    client
        .capabilities
        .as_ref()
        .and_then(|c| c.get("elicitation"))
        .is_some()
}

fn sse_elicitation_response(
    state: AppState,
    rpc_id: Value,
    elicit_id: String,
    approval_id: Uuid,
    action_summary: String,
    pending_outcome: Value,
) -> Response {
    let elicit_request = json!({
        "jsonrpc": "2.0",
        "id": elicit_id,
        "method": "elicitation/create",
        "params": elicitation_params(&action_summary, &pending_outcome),
    });

    let stream = elicitation_event_stream(state, rpc_id, elicit_id, approval_id, elicit_request);
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}

fn elicitation_event_stream(
    state: AppState,
    rpc_id: Value,
    elicit_id: String,
    approval_id: Uuid,
    elicit_request: Value,
) -> impl Stream<Item = Result<Event, Infallible>> {
    let first = stream::once(async move {
        Ok::<_, Infallible>(Event::default().json_data(elicit_request).unwrap())
    });

    let tail = stream::once(async move {
        let outcome = mcp_session::await_completion(&state, &elicit_id).await;
        let result_event = match outcome {
            mcp_session::ElicitOutcome::Completed(v) => json!({
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "content": [{ "type": "text", "text": serde_json::to_string(&v).unwrap_or_default() }],
                }
            }),
            mcp_session::ElicitOutcome::Failed(v) => json!({
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "isError": true,
                    "content": [{ "type": "text", "text": serde_json::to_string(&v).unwrap_or_default() }],
                }
            }),
            mcp_session::ElicitOutcome::Cancelled => json!({
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {
                    "code": INTERNAL_ERROR,
                    "message": "elicitation cancelled or timed out",
                    "data": { "approval_id": approval_id }
                }
            }),
        };
        Ok::<_, Infallible>(Event::default().json_data(result_event).unwrap())
    });

    first.chain(tail)
}

/// Build the elicitation/create params for a permission gap, mirroring the
/// dashboard `ApprovalResolver` choices: decision (allow/allow_remember/
/// deny/bubble_up), optional remember_keys (custom), optional ttl. The
/// client renders a flat form whose answers we translate in
/// `mcp_session::complete_from_elicitation`.
fn elicitation_params(action_summary: &str, pending_outcome: &Value) -> Value {
    // Pull suggested tiers off the pending_approval response so the form
    // can show the same scope choices the dashboard does.
    let suggested = pending_outcome
        .get("suggested_tiers")
        .cloned()
        .unwrap_or_else(|| Value::Array(vec![]));

    json!({
        "message": format!("Allow this agent to: {}?", action_summary),
        "requestedSchema": {
            "type": "object",
            "properties": {
                "decision": {
                    "type": "string",
                    "title": "Decision",
                    "oneOf": [
                        { "const": "allow",          "title": "Allow once" },
                        { "const": "allow_remember", "title": "Allow & remember" },
                        { "const": "deny",           "title": "Deny" },
                        { "const": "bubble_up",      "title": "Ask my parent" }
                    ],
                    "default": "allow"
                },
                "ttl": {
                    "type": "string",
                    "title": "If remembering, for how long",
                    "oneOf": [
                        { "const": "forever", "title": "Forever" },
                        { "const": "1h",      "title": "1 hour" },
                        { "const": "24h",     "title": "24 hours" },
                        { "const": "7d",      "title": "7 days" },
                        { "const": "30d",     "title": "30 days" }
                    ],
                    "default": "forever"
                }
            },
            "required": ["decision"]
        },
        "_meta": {
            "io.overslash/suggested_tiers": suggested
        }
    })
}

// Workaround for claude.ai / Claude Desktop connectors that stringify
// object-typed tool arguments (anthropics/claude-code#5504, #24599, #26094):
// if `params` arrives as a JSON-encoded string, decode it in place. Scoped to
// the top-level field — recursing would double-decode payloads that
// legitimately arrive as JSON strings (e.g. Mode A request bodies).
fn normalize_stringified_params(args: &mut Value) {
    let Some(obj) = args.as_object_mut() else {
        return;
    };
    let Some(p) = obj.get_mut("params") else {
        return;
    };
    let Some(s) = p.as_str() else {
        return;
    };

    if s.is_empty() {
        *p = Value::Null;
        tracing::warn!(
            client_quirk = "stringified_params",
            "rewrote empty-string params to null"
        );
        return;
    }

    match serde_json::from_str::<Value>(s) {
        Ok(parsed) if parsed.is_object() || parsed.is_null() => {
            *p = parsed;
            tracing::warn!(
                client_quirk = "stringified_params",
                "rewrote stringified JSON params to object"
            );
        }
        _ => {}
    }
}

async fn dispatch_search(state: &AppState, bearer: &str, args: &Value) -> Result<Value, String> {
    // Empty query is supported: it triggers browse mode in the REST handler,
    // returning every visible *connected* service (without actions) so an
    // agent can catalog what it can run right now before issuing a scoped
    // query. `include_catalog=true` surfaces the un-connected catalog too.
    let q = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
    let include_catalog = args
        .get("include_catalog")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let path = format!(
        "/v1/search?q={}&include_catalog={}",
        urlencoding::encode(q),
        include_catalog,
    );
    forward(state, bearer, Method::GET, &path, None).await
}

/// Read-only fast path: forwards to `/v1/actions/call` with `require_risk=read`
/// so the action handler rejects the call when the resolved action's risk is
/// not `Risk::Read`. The split lets MCP clients skip confirmation prompts on
/// the readonly tool while still routing through the same execution pipeline.
///
/// `approval_id` is rejected here: approval resume always replays a previously
/// permission-gated (i.e. write/delete) action, so it has no place on a tool
/// annotated `readOnlyHint: true`.
async fn dispatch_read(state: &AppState, bearer: &str, args: &Value) -> Result<Value, String> {
    if args.get("approval_id").is_some() {
        return Err(
            "approval_id is not allowed on overslash_read; use overslash_call to resume a pending approval".into(),
        );
    }
    let service = args
        .get("service")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "service required".to_string())?;
    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "action required".to_string())?;

    // The `overslash` meta-service exposes both read and write sub-actions
    // through the same `dispatch_overslash_platform` code path. Route the
    // read sub-actions through the appropriate path and reject the write
    // ones explicitly so the user gets a clear error rather than a 404 from
    // the actions handler:
    //   - `list_pending` is GET /v1/approvals?... and predates the bridged
    //     platform-action set, so it goes through the platform dispatcher
    //     directly.
    //   - `list_templates` / `get_template` are bridged read-class platform
    //     actions; fall through to the regular `/v1/actions/call` forwarding
    //     so `require_risk=read` is enforced at the action gateway.
    if service == "overslash" {
        return match action {
            // Pass `require_risk: "read"` so the actions handler enforces the
            // risk gate even though the caller is the read tool. Defense in
            // depth — if a write-class action ever sneaks into this arm by
            // mistake, the server-side check refuses it.
            "list_pending" | "list_services" | "get_service" | "list_templates"
            | "get_template" => {
                dispatch_overslash_platform(state, bearer, action, args, Some("read")).await
            }
            other => Err(format!(
                "overslash platform action '{other}' is not read-class; use overslash_call"
            )),
        };
    }

    let mut body = serde_json::Map::new();
    body.insert("service".into(), Value::String(service.into()));
    body.insert("action".into(), Value::String(action.into()));
    body.insert("require_risk".into(), Value::String("read".into()));
    // Forward `params` only when the caller actually supplied a map. The
    // receiving CallRequest's `params: HashMap<...>` deserializer rejects an
    // explicit `null` (it expects a map), even though `#[serde(default)]`
    // would happily fill in an empty map for an absent key.
    if let Some(p) = args.get("params").filter(|v| !v.is_null()) {
        body.insert("params".into(), p.clone());
    }
    forward(
        state,
        bearer,
        Method::POST,
        "/v1/actions/call",
        Some(Value::Object(body)),
    )
    .await
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
    // no upstream HTTP host to forward to. No `require_risk` here — the call
    // tool admits read/write/delete equally.
    if service == "overslash" {
        return dispatch_overslash_platform(state, bearer, action, args, None).await;
    }

    let mut body = serde_json::Map::new();
    body.insert("service".into(), Value::String(service.into()));
    body.insert("action".into(), Value::String(action.into()));
    // See `dispatch_read` — explicit `null` would 422 the action handler;
    // omit when the caller didn't supply a map.
    if let Some(p) = args.get("params").filter(|v| !v.is_null()) {
        body.insert("params".into(), p.clone());
    }
    forward(
        state,
        bearer,
        Method::POST,
        "/v1/actions/call",
        Some(Value::Object(body)),
    )
    .await
}

async fn dispatch_overslash_platform(
    state: &AppState,
    bearer: &str,
    action: &str,
    args: &Value,
    require_risk: Option<&str>,
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
        // Bridged platform kernels — forward through `/v1/actions/call` so the
        // platform_target dispatcher in `routes/actions.rs` runs the kernel via
        // `state.platform_registry`. Permission gating is handled by the
        // action's `permission:` anchor in `services/overslash.yaml` (the
        // `manage_services_own` / `manage_services_share` /
        // `manage_templates_own` / `manage_templates_publish` splits). When
        // the caller is the read tool, `require_risk` is forwarded so the
        // action handler enforces the risk gate.
        "list_services" | "get_service" | "create_service" | "update_service"
        | "list_templates" | "get_template" | "create_template" | "import_template"
        | "delete_template" => {
            forward_overslash_action(state, bearer, action, params, require_risk).await
        }
        other => Err(format!(
            "overslash platform action '{other}' is not callable via MCP"
        )),
    }
}

/// Forward an `overslash`-platform action through `/v1/actions/call` so the
/// existing platform_target dispatch in `routes/actions.rs` runs the kernel
/// via `state.platform_registry`. Returns whatever the actions endpoint
/// returned (which may be `pending_approval` if the agent lacks the
/// permission anchor declared on the action).
async fn forward_overslash_action(
    state: &AppState,
    bearer: &str,
    action: &str,
    params: Option<&Value>,
    require_risk: Option<&str>,
) -> Result<Value, String> {
    let mut body = serde_json::Map::new();
    body.insert("service".into(), Value::String("overslash".into()));
    body.insert("action".into(), Value::String(action.into()));
    if let Some(risk) = require_risk {
        body.insert("require_risk".into(), Value::String(risk.into()));
    }
    if let Some(p) = params.filter(|v| !v.is_null()) {
        body.insert("params".into(), p.clone());
    }
    forward(
        state,
        bearer,
        Method::POST,
        "/v1/actions/call",
        Some(Value::Object(body)),
    )
    .await
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stringified_empty_object_becomes_object() {
        let mut args = json!({"service": "x", "action": "y", "params": "{}"});
        normalize_stringified_params(&mut args);
        assert_eq!(args["params"], json!({}));
    }

    #[test]
    fn stringified_object_with_content_is_decoded() {
        let mut args = json!({
            "service": "x",
            "action": "y",
            "params": "{\"approval_id\":\"abc\",\"n\":3}"
        });
        normalize_stringified_params(&mut args);
        assert_eq!(args["params"], json!({"approval_id": "abc", "n": 3}));
    }

    #[test]
    fn empty_string_params_becomes_null() {
        let mut args = json!({"service": "x", "action": "y", "params": ""});
        normalize_stringified_params(&mut args);
        assert!(args["params"].is_null());
    }

    #[test]
    fn real_object_params_unchanged() {
        let original = json!({"service": "x", "action": "y", "params": {"k": "v"}});
        let mut args = original.clone();
        normalize_stringified_params(&mut args);
        assert_eq!(args, original);
    }

    #[test]
    fn missing_params_is_noop() {
        let original = json!({"service": "x", "action": "y"});
        let mut args = original.clone();
        normalize_stringified_params(&mut args);
        assert_eq!(args, original);
    }

    #[test]
    fn null_params_unchanged() {
        let original = json!({"service": "x", "action": "y", "params": null});
        let mut args = original.clone();
        normalize_stringified_params(&mut args);
        assert_eq!(args, original);
    }

    #[test]
    fn non_json_string_passes_through() {
        // We don't try to "rescue" arbitrary strings: leave them in place
        // so the downstream typed deserializer surfaces a clear error.
        let original = json!({"service": "x", "action": "y", "params": "not json"});
        let mut args = original.clone();
        normalize_stringified_params(&mut args);
        assert_eq!(args, original);
    }

    #[test]
    fn stringified_non_object_passes_through() {
        // A stringified array or number is not the bug we're fixing — leave it.
        let original = json!({"service": "x", "action": "y", "params": "[1,2,3]"});
        let mut args = original.clone();
        normalize_stringified_params(&mut args);
        assert_eq!(args, original);
    }

    #[test]
    fn non_object_args_is_noop() {
        let mut args = Value::Null;
        normalize_stringified_params(&mut args);
        assert_eq!(args, Value::Null);
    }
}
