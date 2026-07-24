//! `tools/call` entry point and the `overslash_call` elicitation fork.

use super::dispatch::{
    dispatch_approve, dispatch_auth, dispatch_call, dispatch_read, dispatch_search,
    normalize_stringified_params,
};
use super::elicitation::{elicitation_eligible, sse_elicitation_response};
use super::*;

// ---------------------------------------------------------------------------
// tools/call dispatch
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ToolCallParams {
    name: String,
    #[serde(default)]
    arguments: Value,
}

pub(super) async fn tools_call(
    state: &AppState,
    ext: &axum::http::Extensions,
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
                ext,
                auth,
                &req,
                bearer,
                &params.arguments,
                req_session_id,
            )
            .await;
        }
        "overslash_auth" => dispatch_auth(state, bearer, &params.arguments).await,
        "overslash_approve" | "overslash_approve_self" => {
            dispatch_approve(state, bearer, &params.arguments).await
        }
        other => {
            return rpc_error_response(req.id, METHOD_NOT_FOUND, format!("unknown tool `{other}`"));
        }
    };

    match outcome {
        Ok(ForwardOutcome::Ok(v)) => rpc_ok_response(
            req.id,
            json!({
                "content": [{ "type": "text", "text": serde_json::to_string(&v).unwrap_or_default() }]
            }),
        ),
        Ok(ForwardOutcome::TypedError(envelope)) => rpc_tool_error_response(req.id, &envelope),
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
#[allow(clippy::too_many_arguments)]
async fn tools_call_overslash_call(
    state: &AppState,
    ext: &axum::http::Extensions,
    auth: &AuthContext,
    req: &JsonRpcRequest,
    bearer: &str,
    args: &Value,
    req_session_id: Option<Uuid>,
) -> Response {
    let outcome = match dispatch_call(state, bearer, args).await {
        Ok(ForwardOutcome::Ok(v)) => v,
        Ok(ForwardOutcome::TypedError(envelope)) => {
            // Typed envelopes (needs_authentication, reauth_required,
            // missing_scopes, credential_missing, not_in_your_chain) bypass
            // the elicitation fork: the agent has structured branching info
            // already, no human-in-the-loop dialog applies.
            return rpc_tool_error_response(req.id.clone(), &envelope);
        }
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
    let promote = elicitation_eligible(state, ext, auth).await;
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
        return synchronous_pending_response(&req.id, &outcome);
    }

    sse_elicitation_response(
        state.clone(),
        ext.clone(),
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
