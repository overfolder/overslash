//! Server-initiated elicitation: eligibility, the SSE response, and the
//! `elicitation/create` params.

use super::*;

/// Decide whether elicitation is reachable for the *calling* (agent, client)
/// pair. Both lookups are keyed on `auth.mcp_client_id` rather than the
/// most-recently-updated binding for the agent — otherwise, in a
/// multi-client-per-agent setup, an eligible client could be denied
/// because the most recent binding belongs to a different client whose
/// capabilities or toggle don't match.
pub(super) async fn elicitation_eligible(
    state: &AppState,
    ext: &axum::http::Extensions,
    auth: &AuthContext,
) -> bool {
    let Some(agent_id) = auth.identity_id else {
        return false;
    };
    let Some(client_id) = auth.mcp_client_id.as_deref() else {
        return false;
    };
    let binding = match overslash_db::repos::mcp_client_agent_binding::get_for_agent_and_client(
        state.db(ext),
        agent_id,
        client_id,
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
        match overslash_db::repos::oauth_mcp_client::get_by_client_id(state.db(ext), client_id)
            .await
        {
            Ok(Some(c)) => c,
            _ => return false,
        };
    client
        .capabilities
        .as_ref()
        .and_then(|c| c.get("elicitation"))
        .is_some()
}

#[allow(clippy::too_many_arguments)]
pub(super) fn sse_elicitation_response(
    state: AppState,
    ext: axum::http::Extensions,
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

    let stream =
        elicitation_event_stream(state, ext, rpc_id, elicit_id, approval_id, elicit_request);
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}

fn elicitation_event_stream(
    state: AppState,
    ext: axum::http::Extensions,
    rpc_id: Value,
    elicit_id: String,
    approval_id: Uuid,
    elicit_request: Value,
) -> impl Stream<Item = Result<Event, Infallible>> {
    let first = stream::once(async move {
        Ok::<_, Infallible>(Event::default().json_data(elicit_request).unwrap())
    });

    let tail = stream::once(async move {
        let outcome = mcp_session::await_completion(&state, &ext, &elicit_id).await;
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
/// dashboard `ApprovalDetail` choices: decision (allow/allow_remember/
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

    // Surface the descriptive render-form fields the envelope now carries so
    // the elicitation dialog can show *what* is being approved (the labeled
    // disclosure summary + risk class), mirroring the dashboard review card.
    // Both read straight off the in-hand outcome — no extra work.
    let disclosed_fields = pending_outcome
        .get("disclosed_fields")
        .cloned()
        .unwrap_or_else(|| Value::Array(vec![]));
    let risk = pending_outcome.get("risk").cloned().unwrap_or(Value::Null);

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
            "io.overslash/suggested_tiers": suggested,
            "io.overslash/disclosed_fields": disclosed_fields,
            "io.overslash/risk": risk
        }
    })
}
