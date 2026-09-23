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
    if binding.elicitation_opted_out {
        return false;
    }
    let client =
        match overslash_db::repos::oauth_mcp_client::get_by_client_id(state.db(ext), client_id)
            .await
        {
            Ok(Some(c)) => c,
            _ => return false,
        };
    if client
        .capabilities
        .as_ref()
        .and_then(|c| c.get("elicitation"))
        .is_none()
    {
        return false;
    }
    // Back off after an unanswered dialog (see `CANCEL_COOLDOWN`). Last check
    // of the four so it only costs a query for callers that would otherwise
    // be promoted, and fails closed: the fallback is the URL-reject envelope,
    // which is never *wrong*, only less convenient — whereas a wrong `true`
    // here can leave a headless call waiting on a dialog nobody will answer.
    matches!(
        overslash_db::repos::mcp_elicitation::cancelled_recently_for_agent(
            state.db(ext),
            agent_id,
            mcp_session::CANCEL_COOLDOWN.as_secs() as i64,
        )
        .await,
        Ok(false)
    )
}

pub(super) fn sse_elicitation_response(
    state: AppState,
    ext: axum::http::Extensions,
    rpc_id: Value,
    elicit_id: String,
    action_summary: String,
    pending_outcome: Value,
) -> Response {
    let elicit_request = json!({
        "jsonrpc": "2.0",
        "id": elicit_id,
        "method": "elicitation/create",
        "params": elicitation_params(&action_summary, &pending_outcome),
    });

    let stream = elicitation_event_stream(
        state,
        ext,
        rpc_id,
        elicit_id,
        elicit_request,
        pending_outcome,
    );
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}

fn elicitation_event_stream(
    state: AppState,
    ext: axum::http::Extensions,
    rpc_id: Value,
    elicit_id: String,
    elicit_request: Value,
    pending_outcome: Value,
) -> impl Stream<Item = Result<Event, Infallible>> {
    let first = stream::once(async move {
        Ok::<_, Infallible>(Event::default().json_data(elicit_request).unwrap())
    });

    let tail = stream::once(async move {
        let outcome = mcp_session::await_completion(&state, &ext, &elicit_id).await;
        Ok::<_, Infallible>(
            Event::default()
                .json_data(elicit_result_event(&rpc_id, outcome, &pending_outcome))
                .unwrap(),
        )
    });

    first.chain(tail)
}

/// Pure translation of a settled elicitation into the JSON-RPC frame that
/// closes the original `tools/call`. Split out from the stream so the three
/// outcomes can be pinned by unit test without a database or a live socket.
fn elicit_result_event(
    rpc_id: &Value,
    outcome: mcp_session::ElicitOutcome,
    pending_outcome: &Value,
) -> Value {
    match outcome {
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
        // Nobody answered. The approval is still pending, so close the call
        // with the very envelope the non-elicitation path would have returned
        // — same approval_id, approval_url, suggested_tiers,
        // auto_call_on_approve — and the model falls back to the URL. A
        // JSON-RPC error here would hand the model something it cannot act on
        // while the approval sits there, live and unmentioned.
        //
        // Benign race: the user may have resolved the approval from the
        // dashboard between the cancel and this frame, so the envelope can say
        // `pending_approval` for an approval that is already `allowed`. The
        // model's correct next move — `overslash_call` with the `approval_id`
        // — is right for that state anyway, so it self-heals.
        mcp_session::ElicitOutcome::Abandoned => json!({
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": super::tools_call::pending_approval_result(pending_outcome),
        }),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> Value {
        json!({
            "status": "pending_approval",
            "approval_id": "11111111-1111-1111-1111-111111111111",
            "approval_url": "https://example.test/approvals/1111",
            "action_description": "send an email",
            "suggested_tiers": [],
            "auto_call_on_approve": true,
        })
    }

    /// The whole point of the fallback: what the model reads after an
    /// unanswered dialog must be the same bytes it would have read with
    /// elicitation switched off. Not an error, not an annotated variant.
    #[test]
    fn abandoned_returns_the_pending_envelope_verbatim() {
        let outcome = envelope();
        let ev = elicit_result_event(&json!(7), mcp_session::ElicitOutcome::Abandoned, &outcome);

        assert_eq!(ev["id"], json!(7));
        assert!(
            ev.get("error").is_none(),
            "a JSON-RPC error would hand the model something it cannot act on \
             while the approval is still live: {ev}"
        );
        assert!(
            ev["result"].get("isError").is_none(),
            "an unanswered dialog is not a failed call: {ev}"
        );

        let text = ev["result"]["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(text).unwrap(),
            outcome,
            "the envelope must round-trip unchanged"
        );
        assert_eq!(
            ev["result"],
            super::super::tools_call::pending_approval_result(&outcome),
            "and be literally what the synchronous path builds"
        );
    }

    #[test]
    fn completed_is_a_plain_result_and_failed_carries_is_error() {
        let done = elicit_result_event(
            &json!(1),
            mcp_session::ElicitOutcome::Completed(json!({"ok": true})),
            &envelope(),
        );
        assert!(done["result"].get("isError").is_none());
        assert_eq!(
            done["result"]["content"][0]["text"].as_str().unwrap(),
            r#"{"ok":true}"#
        );

        // A `decline` lands here: the user really did say no, so the model
        // should see the call fail rather than a pending approval to chase.
        let failed = elicit_result_event(
            &json!(2),
            mcp_session::ElicitOutcome::Failed(json!({"resolution": "deny"})),
            &envelope(),
        );
        assert_eq!(failed["result"]["isError"], true);
    }
}
