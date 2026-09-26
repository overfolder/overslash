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
mod modern;
mod roster;
mod tools_call;

use initialize::{initialize_response, tools_list_response};
use tools_call::{Reply, tools_call};

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

/// Drive an elicitation answer to completion, and make sure the row ends
/// terminal whatever happens.
///
/// Extracted from `post_mcp`'s spawn so the retire-on-failure policy is one
/// named thing rather than two arms of an inline match. `pub` for the same
/// reason `router()` is: the integration suite drives it directly, because
/// forcing the unexpected-`Err` path through a live handler would mean
/// injecting a broken loopback into the running API's config.
///
/// Every exit leaves `pending_mcp_elicitations` in a terminal status. That is
/// the property the originator depends on: it polls this row and gives up only
/// at `mcp_session::DEFAULT_TIMEOUT` (300s), so a row stuck in `claimed` is a
/// five-minute hang on a live `tools/call` — where the caller could have had
/// the `pending_approval` envelope immediately.
///
/// `complete_from_elicitation` drives its *expected* failures to a terminal
/// status itself (`repo::fail` on a denial or a rejected resolve). An `Err` out
/// of it is the unexpected kind — a JWT mint, a loopback transport error, or
/// the terminal write itself failing — so this retires the row on its behalf.
///
/// Retiring can race a resolve that already landed, leaving the model reading
/// `pending_approval` for an approval that is really `allowed`. That is the
/// benign race `elicitation::elicit_result_event` documents: the model's
/// correct next move, `overslash_call` with the approval_id, is right for that
/// state anyway. A stuck row has no such recovery.
pub async fn complete_elicitation_and_retire(
    state: &AppState,
    ext: &axum::http::Extensions,
    db: &sqlx::PgPool,
    elicit_id: &str,
    result: &Value,
) {
    // Bound the work: two loopback HTTP calls (resolve + call) shouldn't take
    // more than a minute even under load. Without this an unresponsive
    // upstream could pin a tokio task slot indefinitely.
    let work = mcp_session::complete_from_elicitation(state, ext, elicit_id, result);
    match tokio::time::timeout(Duration::from_secs(60), work).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            tracing::error!(
                elicit_id,
                "complete elicitation failed; cancelling row: {e}"
            );
            let _ = overslash_db::repos::mcp_elicitation::cancel(db, elicit_id).await;
        }
        Err(_) => {
            tracing::error!(
                elicit_id,
                "complete elicitation timed out after 60s; cancelling row"
            );
            let _ = overslash_db::repos::mcp_elicitation::cancel(db, elicit_id).await;
        }
    }
}

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

    // A client that did not offer to read an event stream cannot be handed
    // one. Streamable HTTP has POST carry `Accept: application/json,
    // text/event-stream`; the absence of the stream type marks a
    // `tools/call`-only bridge, and upgrading it to SSE would hang the call
    // instead of answering it. Cheap to check, and it is the difference
    // between "elicitation is off for you" and "your tool call never
    // returns" — which matters now that elicitation is on by default.
    let accepts_sse = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("text/event-stream"));

    // First try to parse as a request (has `method`). If that fails, try to
    // parse as a response — clients deliver elicitation answers as bare
    // `{ id, result }` / `{ id, error }` objects on POST /mcp.
    if let Ok(req) = serde_json::from_str::<JsonRpcRequest>(&body) {
        if req.jsonrpc != "2.0" {
            return rpc_error_response(req.id, INVALID_REQUEST, "jsonrpc must be \"2.0\"");
        }
        // A 2026-07-28 request carries its protocol version in `_meta` and
        // has no session; it gets its own dispatcher. Everything else is the
        // `initialize`-era protocol, served exactly as before.
        let modern = match modern::classify(&headers, &req) {
            Ok(Some(m)) => m,
            Ok(None) => {
                return legacy_request(
                    &state,
                    &ext,
                    &auth,
                    req,
                    bearer.as_deref(),
                    req_session_id,
                    accepts_sse,
                )
                .await;
            }
            Err(rejection) => return rejection,
        };
        return modern::dispatch(&state, &ext, &auth, &req, bearer.as_deref(), &modern).await;
    }

    // Bare-response delivery (server-initiated elicitation answer). Schema:
    //   { jsonrpc: "2.0", id: "elicit_<uuid>", result|error: ... }
    //
    // Legacy-only by construction: a 2026-07-28 client never sends a bare
    // response, because that era has no server-to-client requests to answer.
    respond_to_elicitation(&state, &ext, &auth, &body).await
}

/// Serve one request on an `initialize`-era (`2025-06-18`) connection.
async fn legacy_request(
    state: &AppState,
    ext: &axum::http::Extensions,
    auth: &AuthContext,
    req: JsonRpcRequest,
    bearer: Option<&str>,
    req_session_id: Option<Uuid>,
    accepts_sse: bool,
) -> Response {
    match req.method.as_str() {
        "initialize" => initialize_response(state, ext, auth, &req).await,
        "tools/list" => tools_list_response(state, ext, auth, req.id).await,
        "tools/call" => {
            let reply = tools_call(
                state,
                ext,
                auth,
                &req,
                bearer,
                req_session_id,
                accepts_sse,
                None,
            )
            .await;
            match reply {
                Reply::Result(result) => rpc_ok_response(req.id, result),
                Reply::Error(code, message) => rpc_error_response(req.id, code, message),
                Reply::Stream(response) => response,
            }
        }
        "notifications/initialized" => (StatusCode::NO_CONTENT, "").into_response(),
        other => rpc_error_response(
            req.id,
            METHOD_NOT_FOUND,
            format!("unknown method `{other}`"),
        ),
    }
}

/// A client's answer to a server-initiated `elicitation/create` (legacy SSE
/// flow), delivered as a bare JSON-RPC response on `POST /mcp`.
async fn respond_to_elicitation(
    state: &AppState,
    ext: &axum::http::Extensions,
    auth: &AuthContext,
    body: &str,
) -> Response {
    if let Ok(resp) = serde_json::from_str::<Value>(body)
        && let Some(id) = resp.get("id").and_then(Value::as_str)
        && id.starts_with("elicit_")
    {
        // Tenant-isolation guard: the elicit_id behaves like a
        // capability and can leak through logs / SSE payloads.
        // Only the agent that owns the elicitation row may answer
        // it — otherwise a caller in another tenant who learns the
        // id could drive the victim's resolve+call as the victim.
        let owner_ok = match overslash_db::repos::mcp_elicitation::get(state.db(ext), id).await {
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
        let db = state.db_pool(ext);
        let id_owned = id.to_string();
        tokio::spawn(async move {
            complete_elicitation_and_retire(&st, &ext_c, &db, &id_owned, &result).await;
        });
        return (StatusCode::ACCEPTED, "").into_response();
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
fn tool_error_result(envelope: &Value) -> Value {
    json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string(envelope).unwrap_or_default(),
        }],
        "isError": true,
    })
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
    // Stamp the surface. This request is about to look exactly like a direct
    // REST call — same URL, same bearer — and the handler on the other end has
    // no other way to tell that an MCP client is waiting on the far side. Read
    // back by `extractors::CallerTransport`; see its doc comment for why an
    // advisory header is the right weight for what depends on it.
    let mut req = state
        .http_client
        .request(method, &url)
        .header(crate::extractors::TRANSPORT_HEADER, "mcp")
        .bearer_auth(bearer);
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
        if let Ok(parsed) = serde_json::from_str::<Value>(&text)
            && let Some(code) = parsed.get("error").and_then(Value::as_str)
            && TYPED_ERROR_CODES.contains(&code)
        {
            return Ok(ForwardOutcome::TypedError(collapse_link_pairs(parsed)));
        }
        return Err(format!("API {status}: {text}"));
    }
    if text.is_empty() {
        return Ok(ForwardOutcome::Ok(Value::Null));
    }
    Ok(ForwardOutcome::Ok(collapse_link_pairs(
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )))
}

/// Canonical-URL field → the field carrying its `oversla.sh` short form.
///
/// Only Overslash's own link pairs. Each entry is a contract with one REST
/// response shape, so a new pair belongs here and nowhere else.
const LINK_PAIRS: &[(&str, &str)] = &[
    // `AppError::{NeedsAuthentication, ReauthRequired, MissingScopes}`, and
    // `CreateConnectionResponse` / `InitiateConnectionResponse`.
    ("auth_url", "short"),
    // `AuthorizeUrls` on the upstream-OAuth boot flow. `raw` is untouched:
    // it's the opt-in upstream provider URL, a different thing entirely, and
    // shortening or dropping it would break the callers that ask for it.
    ("proxied", "short"),
    // `CreateSecretRequestResponse` (REST) and the platform `request_secret`
    // result (`provide_url`).
    ("url", "short_url"),
    ("provide_url", "short_url"),
    // `SetupBundle` on the `create_service` response, and each of its
    // `requests[]` entries — which is why the walk below recurses through
    // arrays as well as objects. A multi-slot template hands over one link per
    // entry, so every entry needs collapsing, not just the bundle's scalar.
    ("setup_url", "short_url"),
];

/// Collapse every canonical/short URL pair into the canonical field, for MCP
/// consumers only.
///
/// REST keeps both halves: partners host-allow-list the canonical URL, parse
/// the flow id out of it, or would rather not put a second service in their
/// OAuth path. An agent needs none of that — it hands the link to a human
/// verbatim — and a pair only makes it guess which half to paste. So the MCP
/// side, and only the MCP side, sees one field holding the short form.
///
/// Runs at the forwarding boundary because that is the one place every
/// MCP-facing response passes through: the REST handlers stay unaware there is
/// a second surface, and a response shape that grows a pair later is collapsed
/// here without touching its handler.
///
/// Recursive: the pairs sit at different depths (flat on the auth envelopes,
/// nested under `authorize_urls`, and inside the action-call result wrapper).
/// A short field with no value is dropped rather than relayed as `null`.
fn collapse_link_pairs(value: Value) -> Value {
    match value {
        Value::Object(mut map) => {
            for (canonical, short) in LINK_PAIRS {
                // Only when both keys are present: a lone `url` on some
                // unrelated payload is left exactly as it is.
                if !map.contains_key(*canonical) || !map.contains_key(*short) {
                    continue;
                }
                // A present-but-null/unusable short form is dropped; the
                // canonical URL it sat beside is always populated.
                if let Some(Value::String(s)) = map.remove(*short) {
                    map.insert((*canonical).to_string(), Value::String(s));
                }
            }
            Value::Object(
                map.into_iter()
                    .map(|(k, v)| (k, collapse_link_pairs(v)))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.into_iter().map(collapse_link_pairs).collect()),
        other => other,
    }
}

#[cfg(test)]
mod collapse_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_short_form_replaces_the_canonical_url_and_the_pair_field_goes() {
        let out = collapse_link_pairs(json!({
            "error": "needs_authentication",
            "auth_url": "https://api.overslash.com/connect-authorize?id=abc",
            "short": "https://oversla.sh/xy7",
            "provider": "google",
        }));
        assert_eq!(out["auth_url"], "https://oversla.sh/xy7");
        assert!(out.get("short").is_none(), "{out}");
        assert_eq!(out["provider"], "google", "untouched keys survive: {out}");
    }

    #[test]
    fn a_canonical_url_with_no_short_sibling_is_left_alone() {
        // Headless orgs, and every response minted while the shortener is
        // unconfigured — which is prod today.
        let body = json!({
            "error": "needs_authentication",
            "auth_url": "https://api.overslash.com/connect-authorize?id=abc",
        });
        assert_eq!(collapse_link_pairs(body.clone()), body);
    }

    #[test]
    fn a_null_short_never_replaces_a_usable_url() {
        let out = collapse_link_pairs(json!({
            "provide_url": "https://app.overslash.com/secrets/provide/r1?token=t",
            "short_url": Value::Null,
        }));
        assert_eq!(
            out["provide_url"],
            "https://app.overslash.com/secrets/provide/r1?token=t"
        );
        assert!(out.get("short_url").is_none(), "{out}");
    }

    #[test]
    fn nested_and_arrayed_pairs_collapse_too() {
        // `AuthorizeUrls` rides under `authorize_urls`, and action-call
        // results arrive inside a wrapper.
        let out = collapse_link_pairs(json!({
            "result": {
                "authorize_urls": {
                    "proxied": "https://api.overslash.com/gated-authorize?id=f1",
                    "short": "https://oversla.sh/zz1",
                    "raw": "https://accounts.google.com/o/oauth2/v2/auth?x=1",
                },
                "items": [{ "url": "https://long/one", "short_url": "https://oversla.sh/a" }],
            }
        }));
        let urls = &out["result"]["authorize_urls"];
        assert_eq!(urls["proxied"], "https://oversla.sh/zz1");
        assert!(urls.get("short").is_none());
        assert_eq!(
            urls["raw"], "https://accounts.google.com/o/oauth2/v2/auth?x=1",
            "raw is the opt-in upstream URL and must never be shortened or dropped: {out}"
        );
        assert_eq!(out["result"]["items"][0]["url"], "https://oversla.sh/a");
    }

    /// The `create_service` setup bundle: a scalar pair on the bundle itself
    /// and one per `requests[]` entry. A multi-slot template hands over one
    /// link per entry, so collapsing only the scalar would leave an agent
    /// picking between two URLs for every slot after the first — the exact
    /// trap this collapse exists to remove.
    #[test]
    fn every_setup_link_in_the_bundle_collapses() {
        let out = collapse_link_pairs(json!({
            "result": { "setup": {
                "setup_url": "https://app.overslash.com/services/setup/req_a?token=x",
                "short_url": "https://oversla.sh/a1",
                "requests": [
                    {
                        "credential_key": "acme_user",
                        "setup_url": "https://app.overslash.com/services/setup/req_a?token=x",
                        "short_url": "https://oversla.sh/a1",
                    },
                    {
                        "credential_key": "acme_pass",
                        "setup_url": "https://app.overslash.com/services/setup/req_b?token=y",
                        "short_url": "https://oversla.sh/b2",
                    },
                ],
            }}
        }));
        let setup = &out["result"]["setup"];
        assert_eq!(setup["setup_url"], "https://oversla.sh/a1");
        assert!(setup.get("short_url").is_none());
        assert_eq!(setup["requests"][0]["setup_url"], "https://oversla.sh/a1");
        assert_eq!(
            setup["requests"][1]["setup_url"], "https://oversla.sh/b2",
            "the second slot's link collapses too, not just the first: {out}"
        );
        assert!(setup["requests"][1].get("short_url").is_none());
        // Untouched.
        assert_eq!(setup["requests"][1]["credential_key"], "acme_pass");
    }

    /// With the shortener unconfigured every `short_url` is absent, so there
    /// is no pair and the long form has to survive.
    #[test]
    fn a_setup_link_with_no_short_form_is_left_alone() {
        let out = collapse_link_pairs(json!({
            "setup": {
                "setup_url": "https://app.overslash.com/services/setup/req_a?token=x",
                "requests": [{ "setup_url": "https://app.overslash.com/services/setup/req_a?token=x" }],
            }
        }));
        assert_eq!(
            out["setup"]["setup_url"],
            "https://app.overslash.com/services/setup/req_a?token=x"
        );
        assert_eq!(
            out["setup"]["requests"][0]["setup_url"],
            "https://app.overslash.com/services/setup/req_a?token=x"
        );
    }

    #[test]
    fn an_unrelated_url_field_is_not_touched() {
        // Plenty of payloads carry a `url` that is nothing to do with a link
        // pair. Without its partner key present, it stays exactly as it is.
        let body = json!({ "url": "https://example.com/webhook", "method": "POST" });
        assert_eq!(collapse_link_pairs(body.clone()), body);
    }
}
