//! The MCP `2026-07-28` ("modern") protocol, served alongside the
//! `initialize`-era one on the same `POST /mcp`.
//!
//! What changes for a modern request, and why this is its own dispatcher
//! rather than a version check sprinkled through the legacy one:
//!
//! - **No handshake, no session.** There is no `initialize`; every request
//!   carries its protocol version, client info and client capabilities in
//!   `params._meta`, and the HTTP headers mirror the version, method and tool
//!   name. `server/discover` replaces the handshake as the way a client learns
//!   what the server speaks. `Mcp-Session-Id` is ignored and never minted.
//! - **No server-to-client requests.** Elicitation is a multi round-trip
//!   request (MRTR): the server answers `tools/call` with
//!   `resultType: "input_required"`, the dialog inside `inputRequests` and an
//!   opaque `requestState`; the client asks the user, then retries the same
//!   call with `inputResponses` and the `requestState` echoed back.
//! - **Every result is typed.** `resultType` is required, and list results
//!   carry `ttlMs` / `cacheScope`.
//!
//! The approval dialogs themselves are the legacy flow's: the same forms, the
//! same `pending_mcp_elicitations` row, the same resolve + call in
//! `mcp_session::complete_from_elicitation`. Only the transport differs. The
//! row stays because it is what suppresses the approval's auto-call while a
//! dialog is open and what the post-cancel cooldown reads; the signed
//! `requestState` is what lets any replica pick the retry up.
//!
//! Claude Code only declares `elicitation: { form, url }` on this era, which
//! is why it exists; see `docs/design/mcp-elicitation-approvals.md`.

use base64::Engine as _;
use sha2::{Digest, Sha256};

use super::elicitation::{
    elicit_result, elicitation_eligible, elicitation_params, remember_params,
};
use super::initialize::{server_info, server_instructions, tools_list_result};
use super::tools_call::{Reply, pending_approval_result, tools_call};
use super::*;

/// The one modern revision this server speaks.
pub(super) const MODERN_PROTOCOL_VERSION: &str = "2026-07-28";
/// What `initialize` answers with; still the only legacy revision served.
pub(super) const LEGACY_PROTOCOL_VERSION: &str = "2025-06-18";

// Error codes the 2026-07-28 spec allocates from its reserved sub-range.
const HEADER_MISMATCH: i32 = -32020;
const UNSUPPORTED_PROTOCOL_VERSION: i32 = -32022;

const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
const META_CLIENT_INFO: &str = "io.modelcontextprotocol/clientInfo";
const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";

/// How long a client may reuse a `server/discover` or `tools/list` answer.
///
/// Both are per caller (the roster sentence, `overslash_approve_self`), so
/// `cacheScope` is always `private`. A legacy connection fetches them once
/// and never again — there is no `list_changed` — so any finite TTL is at
/// least as fresh as what legacy clients already get.
const LIST_TTL_MS: u64 = 5 * 60 * 1000;

/// How long a retry waits for its elicitation row to settle.
///
/// The row is driven synchronously by the retry itself, so this only binds
/// when a concurrent duplicate retry claimed it first. It clears the 60s
/// bound `complete_elicitation_and_retire` puts on the resolve + call.
const SETTLE_TIMEOUT: Duration = Duration::from_secs(65);

/// `inputRequests` key — and `requestState.step` — of the decision dialog.
const STEP_DECISION: &str = "decision";
/// `inputRequests` key — and `requestState.step` — of the "Allow & remember"
/// follow-up (scope + duration).
const STEP_REMEMBER: &str = "remember";

/// What a modern request's `_meta` declared.
pub(super) struct ModernRequest {
    pub(super) capabilities: Value,
    pub(super) client_info: Value,
}

/// Decide which era a request belongs to.
///
/// `Ok(None)` is the legacy protocol: no `_meta` protocol version and not
/// `server/discover`. That keeps every `initialize`-era client on exactly the
/// path it had, since none of them ever sends the `_meta` key.
///
/// `Ok(Some)` is a well-formed 2026-07-28 request. `Err` is a modern request
/// the spec says must be refused — an unsupported version, or headers that do
/// not mirror the body — already rendered as the `400` it requires.
pub(super) fn classify(
    headers: &HeaderMap,
    req: &JsonRpcRequest,
) -> Result<Option<ModernRequest>, Response> {
    if req.method == "initialize" {
        return Ok(None);
    }
    let meta = req.params.get("_meta");
    let version = meta
        .and_then(|m| m.get(META_PROTOCOL_VERSION))
        .and_then(Value::as_str);
    let Some(version) = version else {
        if req.method == "server/discover" {
            // A discover probe with no version cannot be served, and must not
            // be mistaken for a modern error either: a plain `-32602` sends a
            // dual-era client back to `initialize`, which is right for it.
            return Err(modern_error(
                StatusCode::BAD_REQUEST,
                &req.id,
                INVALID_PARAMS,
                format!("`_meta[\"{META_PROTOCOL_VERSION}\"]` is required"),
                None,
            ));
        }
        return Ok(None);
    };

    if version != MODERN_PROTOCOL_VERSION {
        return Err(modern_error(
            StatusCode::BAD_REQUEST,
            &req.id,
            UNSUPPORTED_PROTOCOL_VERSION,
            "Unsupported protocol version".into(),
            Some(json!({
                "supported": [MODERN_PROTOCOL_VERSION],
                "requested": version,
            })),
        ));
    }

    if let Err(why) = check_mirrored_headers(headers, req, version) {
        return Err(modern_error(
            StatusCode::BAD_REQUEST,
            &req.id,
            HEADER_MISMATCH,
            format!("Header mismatch: {why}"),
            None,
        ));
    }

    let capabilities = meta
        .and_then(|m| m.get(META_CLIENT_CAPABILITIES))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let client_info = meta
        .and_then(|m| m.get(META_CLIENT_INFO))
        .cloned()
        .unwrap_or_else(|| json!({}));
    Ok(Some(ModernRequest {
        capabilities,
        client_info,
    }))
}

/// The Streamable HTTP request-metadata rule: `MCP-Protocol-Version`,
/// `Mcp-Method` and (for `tools/call`) `Mcp-Name` are required and must equal
/// the body. Intermediaries may route on the headers while we execute the
/// body, so a disagreement between them is refused, not reconciled.
fn check_mirrored_headers(
    headers: &HeaderMap,
    req: &JsonRpcRequest,
    version: &str,
) -> Result<(), String> {
    let header = |name: &str| -> Result<&str, String> {
        headers
            .get(name)
            .ok_or_else(|| format!("missing {name} header"))?
            .to_str()
            .map_err(|_| format!("{name} header is not visible ASCII"))
    };

    let header_version = header("MCP-Protocol-Version")?;
    if header_version != version {
        return Err(format!(
            "MCP-Protocol-Version header '{header_version}' does not match body value '{version}'"
        ));
    }
    let method = header("Mcp-Method")?;
    if method != req.method {
        return Err(format!(
            "Mcp-Method header '{method}' does not match body value '{}'",
            req.method
        ));
    }
    if req.method == "tools/call" {
        let body_name = req.params.get("name").and_then(Value::as_str).unwrap_or("");
        let name = decode_header_value(header("Mcp-Name")?)
            .ok_or_else(|| "Mcp-Name header has an invalid base64 value".to_string())?;
        if name != body_name {
            return Err(format!(
                "Mcp-Name header '{name}' does not match body value '{body_name}'"
            ));
        }
    }
    Ok(())
}

/// Undo the `=?base64?…?=` sentinel a client uses for a header value that is
/// not plain ASCII. A value without the sentinel is returned as it is.
fn decode_header_value(raw: &str) -> Option<String> {
    match raw
        .strip_prefix("=?base64?")
        .and_then(|rest| rest.strip_suffix("?="))
    {
        Some(encoded) => base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok()),
        None => Some(raw.to_string()),
    }
}

/// Serve one 2026-07-28 request.
pub(super) async fn dispatch(
    state: &AppState,
    ext: &axum::http::Extensions,
    auth: &AuthContext,
    req: &JsonRpcRequest,
    bearer: Option<&str>,
    modern: &ModernRequest,
) -> Response {
    match req.method.as_str() {
        "server/discover" => {
            remember_client(state, ext, auth, modern).await;
            let result = json!({
                "supportedVersions": [MODERN_PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION],
                "capabilities": { "tools": {} },
                "instructions": server_instructions(state, ext, auth).await,
                "ttlMs": LIST_TTL_MS,
                "cacheScope": "private",
            });
            modern_result(&req.id, result)
        }
        "tools/list" => {
            // `server/discover` is optional and cacheable, so it cannot be
            // the only place the declared capabilities are recorded.
            remember_client(state, ext, auth, modern).await;
            let mut result = tools_list_result(state, ext, auth).await;
            result["ttlMs"] = json!(LIST_TTL_MS);
            result["cacheScope"] = json!("private");
            modern_result(&req.id, result)
        }
        "tools/call" => {
            let reply = tools_call(state, ext, auth, req, bearer, None, false, Some(modern)).await;
            match reply {
                Reply::Result(result) => modern_result(&req.id, result),
                Reply::Error(code, message) => {
                    modern_error(StatusCode::OK, &req.id, code, message, None)
                }
                // Only the legacy elicitation path streams; `Some(modern)`
                // never reaches it. Answer rather than hang if that changes.
                Reply::Stream(_) => modern_error(
                    StatusCode::OK,
                    &req.id,
                    INTERNAL_ERROR,
                    "unexpected stream on a 2026-07-28 request".into(),
                    None,
                ),
            }
        }
        other => modern_error(
            StatusCode::NOT_FOUND,
            &req.id,
            METHOD_NOT_FOUND,
            format!("unknown method `{other}`"),
            None,
        ),
    }
}

/// Record what this client declared on its client row — best-effort, like the
/// `initialize` path it replaces. The dashboard's `elicitation_supported`
/// reads it; request handling never does, since a modern request's own
/// `_meta` is the authority for that request.
async fn remember_client(
    state: &AppState,
    ext: &axum::http::Extensions,
    auth: &AuthContext,
    modern: &ModernRequest,
) {
    let Some(client_id) = auth.mcp_client_id.as_deref() else {
        return;
    };
    if let Err(e) = overslash_db::repos::oauth_mcp_client::update_modern_client_state(
        state.db(ext),
        client_id,
        &modern.capabilities,
        &modern.client_info,
        MODERN_PROTOCOL_VERSION,
    )
    .await
    {
        tracing::warn!(client_id, "failed to persist mcp client state: {e}");
    }
}

/// A modern JSON-RPC success: `result` gains the required `resultType`
/// (`complete` unless the caller already typed it) and the server's identity.
fn modern_result(id: &Value, mut result: Value) -> Response {
    if let Value::Object(map) = &mut result {
        map.entry("resultType")
            .or_insert_with(|| Value::String("complete".into()));
        let meta = map.entry("_meta").or_insert_with(|| json!({}));
        if let Value::Object(meta) = meta {
            meta.insert(META_SERVER_INFO.into(), server_info());
        }
    }
    let body = json!({ "jsonrpc": "2.0", "id": id, "result": result });
    (StatusCode::OK, Json(body)).into_response()
}

fn modern_error(
    status: StatusCode,
    id: &Value,
    code: i32,
    message: String,
    data: Option<Value>,
) -> Response {
    let mut error = json!({ "code": code, "message": message });
    if let Some(data) = data {
        error["data"] = data;
    }
    let body = json!({ "jsonrpc": "2.0", "id": id, "error": error });
    (status, Json(body)).into_response()
}

// ---------------------------------------------------------------------------
// Elicitation as a multi round-trip request
// ---------------------------------------------------------------------------

/// First leg: `overslash_call` hit a permission gap. Ask the decision dialog
/// as an `input_required` result, or — when the dialog is not reachable —
/// return the `pending_approval` envelope exactly as the legacy path would.
pub(super) async fn begin_elicitation(
    state: &AppState,
    ext: &axum::http::Extensions,
    auth: &AuthContext,
    modern: &ModernRequest,
    tool_name: &str,
    args: &Value,
    pending_outcome: &Value,
) -> Reply {
    let fallback = || Reply::Result(pending_approval_result(pending_outcome));

    if !elicitation_eligible(state, ext, auth, Some(&modern.capabilities)).await {
        return fallback();
    }
    let Some(approval_id) = pending_outcome
        .get("approval_id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
    else {
        return fallback();
    };
    let Some(agent_identity_id) = auth.identity_id else {
        return fallback();
    };

    let elicit_id = format!("elicit_{}", Uuid::new_v4());
    // There is no session in this era. The row's session id only has to be
    // unique: disconnect retires rows by agent, not by session.
    if let Err(e) = mcp_session::open(
        state,
        ext,
        &elicit_id,
        Uuid::new_v4(),
        agent_identity_id,
        approval_id,
    )
    .await
    {
        tracing::error!("open mcp elicitation failed: {e}");
        return fallback();
    }

    let digest = request_digest(tool_name, args);
    match mint_state(
        state,
        auth,
        agent_identity_id,
        &elicit_id,
        STEP_DECISION,
        &digest,
        pending_outcome,
    ) {
        Ok(request_state) => Reply::Result(input_required(
            STEP_DECISION,
            pending_outcome,
            &request_state,
        )),
        Err(e) => {
            tracing::error!(elicit_id, "mint mcp request state failed: {e}");
            let _ = overslash_db::repos::mcp_elicitation::cancel(state.db(ext), &elicit_id).await;
            fallback()
        }
    }
}

/// Retry leg: the client came back with the dialog's answer. Drive it through
/// the same resolve + call the legacy receiver runs, then turn the settled row
/// into this call's result — or into the next dialog, for "Allow & remember".
pub(super) async fn continue_elicitation(
    state: &AppState,
    ext: &axum::http::Extensions,
    auth: &AuthContext,
    tool_name: &str,
    args: &Value,
    request_state: &str,
    input_responses: Option<&Value>,
) -> Reply {
    let secret = jwt::signing_key_bytes(&state.config.signing_key);
    let Ok(claims) = jwt::verify_mcp_request_state(&secret, request_state) else {
        return Reply::Error(
            INVALID_PARAMS,
            "requestState is invalid or has expired; call the tool again without it".into(),
        );
    };
    // Bound to the principal and to the request it was minted for. A state
    // lifted from someone else's call, or pasted onto a different call of
    // one's own, must not answer that call's dialog.
    if Some(claims.agent) != auth.identity_id
        || claims.client.as_deref() != auth.mcp_client_id.as_deref()
        || claims.digest != request_digest(tool_name, args)
    {
        return Reply::Error(
            INVALID_PARAMS,
            "requestState does not belong to this request".into(),
        );
    }

    // Defence in depth over the signature: the row must still be this
    // agent's. A missing row was reaped; nobody can answer it now.
    let row = overslash_db::repos::mcp_elicitation::get(state.db(ext), &claims.elicit_id).await;
    match row {
        Ok(Some(row)) if row.agent_identity_id == claims.agent => {}
        _ => {
            return Reply::Result(elicit_result(
                mcp_session::ElicitOutcome::Abandoned,
                &claims.envelope,
            ));
        }
    }

    // The spec's answer to a retry that is missing the requested input is to
    // ask for it again, not to fail the call.
    let answer = input_responses
        .and_then(|r| r.get(claims.step.as_str()))
        .filter(|a| a.is_object());
    let Some(answer) = answer else {
        return Reply::Result(input_required(
            &claims.step,
            &claims.envelope,
            request_state,
        ));
    };

    let db = state.db_pool(ext);
    // A no-op when the row is no longer `pending` (a duplicate retry, or the
    // sweeper got there first); the read below reports whatever it settled as.
    complete_elicitation_and_retire(state, ext, &db, &claims.elicit_id, answer).await;
    let outcome =
        mcp_session::await_completion_with_timeout(state, ext, &claims.elicit_id, SETTLE_TIMEOUT)
            .await;

    match outcome {
        mcp_session::ElicitOutcome::FollowUp(next_id) if claims.step == STEP_DECISION => {
            match mint_state(
                state,
                auth,
                claims.agent,
                &next_id,
                STEP_REMEMBER,
                &claims.digest,
                &claims.envelope,
            ) {
                Ok(next_state) => {
                    Reply::Result(input_required(STEP_REMEMBER, &claims.envelope, &next_state))
                }
                Err(e) => {
                    tracing::error!(next_id, "mint mcp request state failed: {e}");
                    let _ =
                        overslash_db::repos::mcp_elicitation::cancel(state.db(ext), &next_id).await;
                    Reply::Result(pending_approval_result(&claims.envelope))
                }
            }
        }
        mcp_session::ElicitOutcome::FollowUp(next_id) => {
            // Only one follow-up is defined. Retire the extra row so it does
            // not keep suppressing auto-call on the approval — as the legacy
            // stream does.
            let _ = overslash_db::repos::mcp_elicitation::cancel(state.db(ext), &next_id).await;
            Reply::Result(pending_approval_result(&claims.envelope))
        }
        other => Reply::Result(elicit_result(other, &claims.envelope)),
    }
}

/// An `input_required` result asking one dialog, keyed by its step.
fn input_required(step: &str, pending_outcome: &Value, request_state: &str) -> Value {
    let mut params = if step == STEP_REMEMBER {
        remember_params(pending_outcome)
    } else {
        let action_summary = pending_outcome
            .get("action_description")
            .and_then(Value::as_str)
            .unwrap_or("an action");
        elicitation_params(action_summary, pending_outcome)
    };
    params["mode"] = json!("form");
    json!({
        "resultType": "input_required",
        "inputRequests": {
            step: { "method": "elicitation/create", "params": params },
        },
        "requestState": request_state,
    })
}

fn mint_state(
    state: &AppState,
    auth: &AuthContext,
    agent: Uuid,
    elicit_id: &str,
    step: &str,
    digest: &str,
    pending_outcome: &Value,
) -> Result<String, jwt::JwtError> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let claims = jwt::McpRequestStateClaims {
        kind: jwt::MCP_REQUEST_STATE_KIND.into(),
        agent,
        client: auth.mcp_client_id.clone(),
        elicit_id: elicit_id.to_string(),
        step: step.to_string(),
        digest: digest.to_string(),
        envelope: pending_outcome.clone(),
        iat: now,
        // No longer than a legacy originator would have waited: past this the
        // sweeper may already have retired the row.
        exp: now + mcp_session::DEFAULT_TIMEOUT.as_secs() as i64,
    };
    jwt::mint_mcp_request_state(&jwt::signing_key_bytes(&state.config.signing_key), &claims)
}

/// Identify the call a `requestState` belongs to: the tool name plus its
/// arguments, with object keys sorted so that a client re-serialising the
/// same arguments in another order still matches.
fn request_digest(tool_name: &str, args: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(tool_name.as_bytes());
    hasher.update([0]);
    hasher.update(
        serde_json::to_string(&canonical(args))
            .unwrap_or_default()
            .as_bytes(),
    );
    hex::encode(hasher.finalize())
}

fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(k, v)| (k.clone(), canonical(v)))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(method: &str, params: Value) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: json!(1),
            method: method.into(),
            params,
        }
    }

    fn modern_params(extra: Value) -> Value {
        let mut params = json!({
            "_meta": {
                META_PROTOCOL_VERSION: MODERN_PROTOCOL_VERSION,
                META_CLIENT_CAPABILITIES: { "elicitation": { "form": {}, "url": {} } },
                META_CLIENT_INFO: { "name": "claude-code", "version": "2.1.282" },
            }
        });
        if let (Value::Object(p), Value::Object(e)) = (&mut params, extra) {
            p.extend(e);
        }
        params
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, v.parse().unwrap());
        }
        h
    }

    async fn error_of(resp: Response) -> (StatusCode, Value) {
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[test]
    fn a_request_without_a_meta_version_is_legacy() {
        let req = request("tools/list", json!({}));
        assert!(matches!(classify(&HeaderMap::new(), &req), Ok(None)));
        // Legacy clients send the header too — only the `_meta` key decides.
        let h = headers(&[("MCP-Protocol-Version", "2025-06-18")]);
        assert!(matches!(classify(&h, &req), Ok(None)));
    }

    #[test]
    fn initialize_is_always_legacy() {
        let req = request("initialize", modern_params(json!({})));
        assert!(matches!(classify(&HeaderMap::new(), &req), Ok(None)));
    }

    #[test]
    fn a_well_formed_modern_request_carries_its_capabilities() {
        let req = request(
            "tools/call",
            modern_params(json!({ "name": "overslash_call", "arguments": {} })),
        );
        let h = headers(&[
            ("MCP-Protocol-Version", MODERN_PROTOCOL_VERSION),
            ("Mcp-Method", "tools/call"),
            ("Mcp-Name", "overslash_call"),
        ]);
        let Ok(Some(m)) = classify(&h, &req) else {
            panic!("expected modern")
        };
        assert!(m.capabilities["elicitation"]["url"].is_object());
        assert_eq!(m.client_info["name"], "claude-code");
    }

    #[tokio::test]
    async fn an_unknown_modern_version_is_refused_with_the_supported_list() {
        let mut params = modern_params(json!({}));
        params["_meta"][META_PROTOCOL_VERSION] = json!("2099-01-01");
        let Err(resp) = classify(&HeaderMap::new(), &request("tools/list", params)) else {
            panic!("expected rejection")
        };
        let (status, body) = error_of(resp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], UNSUPPORTED_PROTOCOL_VERSION);
        assert_eq!(
            body["error"]["data"]["supported"],
            json!([MODERN_PROTOCOL_VERSION])
        );
        assert_eq!(body["error"]["data"]["requested"], "2099-01-01");
    }

    #[tokio::test]
    async fn headers_that_disagree_with_the_body_are_refused() {
        let req = request(
            "tools/call",
            modern_params(json!({ "name": "overslash_call" })),
        );
        for h in [
            // Missing entirely.
            headers(&[]),
            headers(&[
                ("MCP-Protocol-Version", MODERN_PROTOCOL_VERSION),
                ("Mcp-Method", "tools/list"),
                ("Mcp-Name", "overslash_call"),
            ]),
            headers(&[
                ("MCP-Protocol-Version", MODERN_PROTOCOL_VERSION),
                ("Mcp-Method", "tools/call"),
                ("Mcp-Name", "overslash_read"),
            ]),
            headers(&[
                ("MCP-Protocol-Version", "2025-11-25"),
                ("Mcp-Method", "tools/call"),
                ("Mcp-Name", "overslash_call"),
            ]),
        ] {
            let Err(resp) = classify(&h, &req) else {
                panic!("expected rejection for {h:?}")
            };
            let (status, body) = error_of(resp).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{h:?}");
            assert_eq!(body["error"]["code"], HEADER_MISMATCH, "{h:?}");
        }
    }

    #[test]
    fn a_base64_encoded_tool_name_is_decoded_before_comparing() {
        let req = request(
            "tools/call",
            modern_params(json!({ "name": "overslash_call" })),
        );
        let encoded = format!(
            "=?base64?{}?=",
            base64::engine::general_purpose::STANDARD.encode("overslash_call")
        );
        let h = headers(&[
            ("MCP-Protocol-Version", MODERN_PROTOCOL_VERSION),
            ("Mcp-Method", "tools/call"),
            ("Mcp-Name", &encoded),
        ]);
        assert!(matches!(classify(&h, &req), Ok(Some(_))));
    }

    #[tokio::test]
    async fn a_discover_without_a_version_is_not_a_modern_error() {
        let Err(resp) = classify(&HeaderMap::new(), &request("server/discover", json!({}))) else {
            panic!("expected rejection")
        };
        let (status, body) = error_of(resp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body["error"]["code"], INVALID_PARAMS,
            "a dual-era client must read this as legacy and fall back: {body}"
        );
    }

    #[test]
    fn digest_ignores_key_order_but_not_values_or_tool() {
        let a = request_digest("overslash_call", &json!({ "service": "s", "action": "a" }));
        let b = request_digest("overslash_call", &json!({ "action": "a", "service": "s" }));
        assert_eq!(a, b);
        assert_ne!(
            a,
            request_digest("overslash_call", &json!({ "service": "s", "action": "b" }))
        );
        assert_ne!(
            a,
            request_digest("overslash_read", &json!({ "service": "s", "action": "a" }))
        );
    }

    #[test]
    fn input_required_names_the_dialog_by_its_step_and_marks_it_form() {
        let env = json!({ "action_description": "send an email", "suggested_tiers": [] });
        let r = input_required(STEP_DECISION, &env, "state");
        assert_eq!(r["resultType"], "input_required");
        assert_eq!(r["requestState"], "state");
        let ask = &r["inputRequests"][STEP_DECISION];
        assert_eq!(ask["method"], "elicitation/create");
        assert_eq!(ask["params"]["mode"], "form");
        assert_eq!(
            ask["params"]["message"],
            "Allow this agent to: send an email?"
        );

        let r = input_required(STEP_REMEMBER, &env, "state");
        assert!(
            r["inputRequests"][STEP_REMEMBER]["params"]["requestedSchema"]["properties"]["ttl"]
                .is_object()
        );
    }

    #[tokio::test]
    async fn modern_results_are_typed_and_signed_by_the_server() {
        let (_, body) = error_of(modern_result(&json!(3), json!({ "content": [] }))).await;
        assert_eq!(body["result"]["resultType"], "complete");
        assert_eq!(
            body["result"]["_meta"][META_SERVER_INFO]["name"],
            "overslash"
        );

        // An `input_required` result keeps its own type.
        let (_, body) = error_of(modern_result(
            &json!(4),
            json!({ "resultType": "input_required", "requestState": "s" }),
        ))
        .await;
        assert_eq!(body["result"]["resultType"], "input_required");
    }
}
