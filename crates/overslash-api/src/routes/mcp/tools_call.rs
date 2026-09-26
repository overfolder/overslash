//! `tools/call` entry point and the `overslash_call` elicitation fork.

use super::dispatch::{
    dispatch_approve, dispatch_auth, dispatch_call, dispatch_read, dispatch_search,
    normalize_stringified_params,
};
use super::elicitation::{elicitation_eligible, sse_elicitation_response};
use super::modern::{self, ModernRequest};
use super::*;

// ---------------------------------------------------------------------------
// tools/call dispatch
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ToolCallParams {
    name: String,
    #[serde(default)]
    arguments: Value,
    /// 2026-07-28 multi round-trip retry: the client's answers to the
    /// `inputRequests` of an earlier `input_required` result.
    #[serde(default, rename = "inputResponses")]
    input_responses: Option<Value>,
    /// 2026-07-28 multi round-trip retry: the opaque state the earlier
    /// `input_required` result carried, echoed back verbatim.
    #[serde(default, rename = "requestState")]
    request_state: Option<String>,
}

/// What a `tools/call` produced, before either protocol era frames it.
///
/// A legacy connection wraps it in a plain JSON-RPC response; a 2026-07-28
/// request additionally stamps `resultType` and `serverInfo` on the result.
/// `Stream` only ever comes out of the legacy elicitation path — the modern
/// era has no server-to-client requests to stream.
pub(super) enum Reply {
    /// The JSON-RPC `result` object.
    Result(Value),
    /// A JSON-RPC error: code and message.
    Error(i32, String),
    /// An already-built response (the legacy SSE elicitation stream).
    Stream(Response),
}

/// `modern` is `Some` for a 2026-07-28 request, carrying what its `_meta`
/// declared; `None` for a legacy (`initialize`-era) connection.
#[allow(clippy::too_many_arguments)]
pub(super) async fn tools_call(
    state: &AppState,
    ext: &axum::http::Extensions,
    auth: &AuthContext,
    req: &JsonRpcRequest,
    bearer: Option<&str>,
    req_session_id: Option<Uuid>,
    accepts_sse: bool,
    modern: Option<&ModernRequest>,
) -> Reply {
    let mut params: ToolCallParams = match serde_json::from_value(req.params.clone()) {
        Ok(p) => p,
        Err(e) => return Reply::Error(INVALID_PARAMS, format!("bad params: {e}")),
    };
    let bearer = match bearer {
        Some(b) => b,
        None => return Reply::Error(INTERNAL_ERROR, "bearer missing after auth".into()),
    };

    normalize_stringified_params(&mut params.arguments);

    // A 2026-07-28 retry of a call that was answered with `input_required`.
    // It continues that elicitation and must never dispatch the call again:
    // the first leg already did, and doing it twice would open a second
    // approval for the same action. Legacy connections have no such retry,
    // so a `requestState` from one is ignored like any unknown field.
    if modern.is_some()
        && let Some(request_state) = params.request_state.as_deref()
    {
        return modern::continue_elicitation(
            state,
            ext,
            auth,
            &params.name,
            &params.arguments,
            request_state,
            params.input_responses.as_ref(),
        )
        .await;
    }

    let outcome = match params.name.as_str() {
        "overslash_search" => dispatch_search(state, bearer, &params.arguments).await,
        "overslash_read" => dispatch_read(state, bearer, &params.arguments).await,
        "overslash_call" => {
            return tools_call_overslash_call(
                state,
                ext,
                auth,
                req,
                bearer,
                &params.arguments,
                req_session_id,
                accepts_sse,
                modern,
            )
            .await;
        }
        "overslash_auth" => dispatch_auth(state, bearer, &params.arguments).await,
        "overslash_approve" | "overslash_approve_self" => {
            dispatch_approve(state, bearer, &params.arguments).await
        }
        other => return Reply::Error(METHOD_NOT_FOUND, format!("unknown tool `{other}`")),
    };

    match outcome {
        Ok(ForwardOutcome::Ok(v)) => Reply::Result(text_result(&v)),
        Ok(ForwardOutcome::TypedError(envelope)) => Reply::Result(tool_error_result(&envelope)),
        Err(msg) => Reply::Error(INTERNAL_ERROR, msg),
    }
}

/// A successful tool result: `value` stringified into one text block.
fn text_result(value: &Value) -> Value {
    json!({
        "content": [{ "type": "text", "text": serde_json::to_string(value).unwrap_or_default() }]
    })
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
///
/// On a 2026-07-28 request the same promotion happens, but as an
/// `input_required` result the client answers by retrying the call — see
/// [`modern::begin_elicitation`].
#[allow(clippy::too_many_arguments)]
async fn tools_call_overslash_call(
    state: &AppState,
    ext: &axum::http::Extensions,
    auth: &AuthContext,
    req: &JsonRpcRequest,
    bearer: &str,
    args: &Value,
    req_session_id: Option<Uuid>,
    accepts_sse: bool,
    modern: Option<&ModernRequest>,
) -> Reply {
    let outcome = match dispatch_call(state, bearer, args).await {
        Ok(ForwardOutcome::Ok(v)) => v,
        Ok(ForwardOutcome::TypedError(envelope)) => {
            // Typed envelopes (needs_authentication, reauth_required,
            // missing_scopes, credential_missing, not_in_your_chain) bypass
            // the elicitation fork: the agent has structured branching info
            // already, no human-in-the-loop dialog applies.
            return Reply::Result(tool_error_result(&envelope));
        }
        Err(msg) => return Reply::Error(INTERNAL_ERROR, msg),
    };

    // Synchronous success or platform action: return as today.
    let is_pending = outcome.get("status").and_then(Value::as_str) == Some("pending_approval");
    if !is_pending {
        return Reply::Result(text_result(&outcome));
    }

    if let Some(modern) = modern {
        return modern::begin_elicitation(
            state,
            ext,
            auth,
            modern,
            "overslash_call",
            args,
            &outcome,
        )
        .await;
    }

    // Pending approval — promote to elicitation if eligible. The `Accept`
    // check comes first because it is free and because a caller that cannot
    // read the stream must never be upgraded onto one, whatever its binding
    // or declared capabilities say.
    if !accepts_sse {
        tracing::debug!("skipping elicitation upgrade: caller did not Accept text/event-stream");
        return Reply::Result(pending_approval_result(&outcome));
    }
    if !elicitation_eligible(state, ext, auth, None).await {
        return Reply::Result(pending_approval_result(&outcome));
    }

    let approval_id = match outcome.get("approval_id").and_then(Value::as_str) {
        Some(s) => match Uuid::parse_str(s) {
            Ok(u) => u,
            Err(_) => return Reply::Result(pending_approval_result(&outcome)),
        },
        None => return Reply::Result(pending_approval_result(&outcome)),
    };
    let action_summary = outcome
        .get("action_description")
        .and_then(Value::as_str)
        .unwrap_or("an action")
        .to_string();
    let agent_identity_id = match auth.identity_id {
        Some(id) => id,
        None => return Reply::Result(pending_approval_result(&outcome)),
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
                match overslash_db::repos::oauth_mcp_client::get_by_client_id(
                    state.db(ext),
                    client_id,
                )
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
        ext,
        &elicit_id,
        session_id,
        agent_identity_id,
        approval_id,
    )
    .await
    {
        tracing::error!("open mcp elicitation failed: {e}");
        return Reply::Result(pending_approval_result(&outcome));
    }

    Reply::Stream(sse_elicitation_response(
        state.clone(),
        ext.clone(),
        req.id.clone(),
        elicit_id,
        action_summary,
        outcome.clone(),
    ))
}

/// The tool result the no-elicitation path returns for a pending approval:
/// the `pending_approval` envelope in a single text content block.
///
/// Shared with the elicitation SSE tail so that what the model reads after an
/// unanswered dialog is byte-identical to what it would have read with
/// elicitation switched off. That identity is the property that makes the
/// fallback trustworthy, so resist adding an "elicitation was skipped" marker
/// here — it would only invite the two paths to drift.
pub(super) fn pending_approval_result(outcome: &Value) -> Value {
    json!({
        "content": [{ "type": "text", "text": serde_json::to_string(outcome).unwrap_or_default() }]
    })
}
