//! Server-initiated elicitation: eligibility, the SSE response, and the
//! `elicitation/create` params.

use super::*;

/// Decide whether elicitation is reachable for the *calling* (agent, client)
/// pair. Both lookups are keyed on `auth.mcp_client_id` rather than the
/// most-recently-updated binding for the agent — otherwise, in a
/// multi-client-per-agent setup, an eligible client could be denied
/// because the most recent binding belongs to a different client whose
/// capabilities or toggle don't match.
///
/// `declared` is where the client's capabilities come from. A legacy
/// (`initialize`) connection declared them once, at handshake, and they were
/// persisted on the client row — pass `None` to read them from there. A
/// 2026-07-28 request carries its own in `_meta`, which is the only
/// authority for that request — pass them as `Some`.
pub(super) async fn elicitation_eligible(
    state: &AppState,
    ext: &axum::http::Extensions,
    auth: &AuthContext,
    declared: Option<&Value>,
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
    let form_supported = match declared {
        Some(caps) => supports_form_elicitation(caps),
        None => {
            match overslash_db::repos::oauth_mcp_client::get_by_client_id(state.db(ext), client_id)
                .await
            {
                Ok(Some(c)) => c
                    .capabilities
                    .as_ref()
                    .is_some_and(supports_form_elicitation),
                _ => false,
            }
        }
    };
    if !form_supported {
        return false;
    }
    // Back off after an unanswered dialog (see `CANCEL_COOLDOWN`). Last check
    // of the four so it only costs a query for callers that would otherwise
    // be promoted, and fails closed: the fallback is the URL-reject envelope,
    // which is never *wrong*, only less convenient — whereas a wrong `true`
    // here can leave a headless call waiting on a dialog nobody will answer.
    !in_cancel_cooldown(state, ext, agent_id).await
}

/// Did this agent leave a dialog unanswered within `CANCEL_COOLDOWN`? Also
/// holds off the URL-mode approval hand-off: a human who just dismissed one
/// prompt does not want the model's retry to raise another in a new form.
/// Fails closed (a lookup error reads as "in cooldown").
pub(super) async fn in_cancel_cooldown(
    state: &AppState,
    ext: &axum::http::Extensions,
    agent_id: Uuid,
) -> bool {
    !matches!(
        overslash_db::repos::mcp_elicitation::cancelled_recently_for_agent(
            state.db(ext),
            agent_id,
            mcp_session::CANCEL_COOLDOWN.as_secs() as i64,
        )
        .await,
        Ok(false)
    )
}

/// Does a declared `capabilities` object allow a form-mode dialog?
///
/// `elicitation: {}` is the pre-`2025-11-25` shape and means form only, per
/// both the 2025-11-25 and 2026-07-28 specs; a client that lists modes must
/// list `form` for one to be sent. A `{ url: {} }`-only client gets no form.
pub(super) fn supports_form_elicitation(capabilities: &Value) -> bool {
    match capabilities.get("elicitation") {
        Some(Value::Object(modes)) => modes.is_empty() || modes.contains_key("form"),
        _ => false,
    }
}

pub(super) fn sse_elicitation_response(
    state: AppState,
    ext: axum::http::Extensions,
    org_id: Uuid,
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
        org_id,
        rpc_id,
        elicit_id,
        elicit_request,
        pending_outcome,
    );
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}

/// Where the stream is between frames: polling one dialog's row (with how
/// many follow-up dialogs it may still raise), or finished.
enum StreamStep {
    Poll {
        elicit_id: String,
        follow_ups_left: u8,
    },
    Done,
}

fn elicitation_event_stream(
    state: AppState,
    ext: axum::http::Extensions,
    org_id: Uuid,
    rpc_id: Value,
    elicit_id: String,
    elicit_request: Value,
    pending_outcome: Value,
) -> impl Stream<Item = Result<Event, Infallible>> {
    let first = stream::once(async move {
        Ok::<_, Infallible>(Event::default().json_data(elicit_request).unwrap())
    });

    // Poll the current dialog's row. "Allow & remember" hands over to one
    // follow-up dialog (scope + duration), which this emits as a second
    // `elicitation/create` before polling *its* row; any other outcome
    // closes the original `tools/call`.
    let initial = StreamStep::Poll {
        elicit_id,
        follow_ups_left: 1,
    };
    let tail = stream::unfold(initial, move |step| {
        let state = state.clone();
        let ext = ext.clone();
        let rpc_id = rpc_id.clone();
        let pending_outcome = pending_outcome.clone();
        async move {
            let StreamStep::Poll {
                elicit_id,
                follow_ups_left,
            } = step
            else {
                return None;
            };
            let outcome = mcp_session::await_completion(&state, &ext, &elicit_id).await;
            let (frame, next) = match outcome {
                mcp_session::ElicitOutcome::FollowUp(next_id) if follow_ups_left > 0 => {
                    let default_ttl = org_remember_ttl_secs(&state, &ext, org_id).await;
                    let frame = json!({
                        "jsonrpc": "2.0",
                        "id": next_id,
                        "method": "elicitation/create",
                        "params": remember_params(&pending_outcome, default_ttl),
                    });
                    let next = StreamStep::Poll {
                        elicit_id: next_id,
                        follow_ups_left: follow_ups_left - 1,
                    };
                    (frame, next)
                }
                mcp_session::ElicitOutcome::FollowUp(next_id) => {
                    // Only one follow-up is defined. Retire the extra row so
                    // it does not keep suppressing auto-call on the approval.
                    let _ = overslash_db::repos::mcp_elicitation::cancel(state.db(&ext), &next_id)
                        .await;
                    let frame = elicit_result_event(
                        &rpc_id,
                        mcp_session::ElicitOutcome::Abandoned,
                        &pending_outcome,
                    );
                    (frame, StreamStep::Done)
                }
                other => (
                    elicit_result_event(&rpc_id, other, &pending_outcome),
                    StreamStep::Done,
                ),
            };
            Some((
                Ok::<_, Infallible>(Event::default().json_data(frame).unwrap()),
                next,
            ))
        }
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
    json!({
        "jsonrpc": "2.0",
        "id": rpc_id,
        "result": elicit_result(outcome, pending_outcome),
    })
}

/// The `tools/call` result a settled elicitation ends in — shared by the
/// legacy SSE tail and the 2026-07-28 retry, so the two eras can never
/// disagree about what a denial or an unanswered dialog looks like.
pub(super) fn elicit_result(outcome: mcp_session::ElicitOutcome, pending_outcome: &Value) -> Value {
    match outcome {
        mcp_session::ElicitOutcome::Completed(v) => json!({
            "content": [{ "type": "text", "text": serde_json::to_string(&v).unwrap_or_default() }],
        }),
        mcp_session::ElicitOutcome::Failed(v) => json!({
            "isError": true,
            "content": [{ "type": "text", "text": serde_json::to_string(&v).unwrap_or_default() }],
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
        // The stream turns a `FollowUp` into a second dialog before it ever
        // reaches here; one that does is a dialog nobody finished.
        mcp_session::ElicitOutcome::Abandoned | mcp_session::ElicitOutcome::FollowUp(_) => {
            super::tools_call::pending_approval_result(pending_outcome)
        }
    }
}

/// Build the elicitation/create params for a permission gap: the decision
/// only, mirroring the dashboard `ApprovalDetail` buttons.
///
/// MCP forms are flat — every field renders at once and none can depend on
/// another — so nothing that only matters to one choice belongs here. Scope
/// and duration only mean something for "Allow & remember", so they live in
/// the follow-up dialog that choice raises ([`remember_params`]). Answers are
/// translated in `mcp_session::complete_from_elicitation`.
pub(super) fn elicitation_params(action_summary: &str, pending_outcome: &Value) -> Value {
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
                }
            },
            "required": ["decision"]
        },
        "_meta": dialog_meta(pending_outcome)
    })
}

/// Build the follow-up dialog "Allow & remember" raises: which scope level to
/// remember, and for how long — the dashboard's `RememberControl` and
/// `ExpiryControl`.
///
/// Each scope option's value is the tier's keys as a JSON-encoded array,
/// since MCP enum values must be strings and a tier can hold several keys.
/// The receiver forwards them as `remember_keys`, and `/resolve` validates
/// them against the approval, so nothing here is trusted. The narrowest tier
/// is the default. With no tiers the scope field is left out and the
/// approval's own keys are remembered.
///
/// `default_ttl_secs` is the org's default expiry (`None` = forever), from
/// [`org_remember_ttl_secs`]; it pre-selects the duration field.
pub(super) fn remember_params(pending_outcome: &Value, default_ttl_secs: Option<i32>) -> Value {
    let action_summary = pending_outcome
        .get("action_description")
        .and_then(Value::as_str)
        .unwrap_or("this action");

    let scope_options: Vec<Value> = pending_outcome
        .get("suggested_tiers")
        .and_then(Value::as_array)
        .map(|tiers| {
            tiers
                .iter()
                .filter_map(|tier| {
                    let keys: Vec<&str> = tier
                        .get("keys")?
                        .as_array()?
                        .iter()
                        .filter_map(Value::as_str)
                        .collect();
                    if keys.is_empty() {
                        return None;
                    }
                    let title = tier
                        .get("description")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .unwrap_or_else(|| keys.join(", "));
                    Some(json!({
                        "const": serde_json::to_string(&keys).unwrap_or_default(),
                        "title": title,
                    }))
                })
                .collect()
        })
        .unwrap_or_default();

    let mut properties = serde_json::Map::new();
    if let Some(default) = scope_options.first().map(|o| o["const"].clone()) {
        properties.insert(
            "scope".into(),
            json!({
                "type": "string",
                "title": "Remember for",
                "oneOf": scope_options,
                "default": default,
            }),
        );
    }
    let mut ttl_options: Vec<Value> = TTL_PRESETS
        .iter()
        .map(|(value, _, title)| json!({ "const": value, "title": title }))
        .collect();
    let default_ttl = match TTL_PRESETS.iter().find(|(_, s, _)| *s == default_ttl_secs) {
        Some((value, _, _)) => value.to_string(),
        // An org default set through the API to an off-menu duration still
        // has to be selectable, or the dialog would pre-select nothing.
        None => {
            let secs = default_ttl_secs.unwrap_or_default();
            let value = format!("{secs}s");
            ttl_options.push(json!({ "const": value, "title": humanize_secs(secs) }));
            value
        }
    };
    properties.insert(
        "ttl".into(),
        json!({
            "type": "string",
            "title": "For how long",
            "oneOf": ttl_options,
            "default": default_ttl
        }),
    );

    json!({
        "message": format!("Remember permission to: {}", action_summary),
        "requestedSchema": {
            "type": "object",
            "properties": properties,
        },
        "_meta": dialog_meta(pending_outcome)
    })
}

/// The remember dialog's duration menu: `(ttl value, seconds, title)`, in the
/// order the dashboard's `ExpiryControl` lists them. `None` seconds = forever.
const TTL_PRESETS: [(&str, Option<i32>, &str); 5] = [
    ("forever", None, "Forever"),
    ("1h", Some(3_600), "1 hour"),
    ("24h", Some(86_400), "24 hours"),
    ("7d", Some(604_800), "7 days"),
    ("30d", Some(2_592_000), "30 days"),
];

/// What the remember dialog pre-selects when the org's setting cannot be
/// read — the column's own default.
const FALLBACK_REMEMBER_TTL_SECS: i32 = 604_800;

/// The org's default "Allow & remember" expiry (`None` = forever). A failed
/// lookup falls back to 7 days rather than failing the dialog: it is only a
/// pre-selection, and `/resolve` re-reads the setting for an omitted `ttl`.
pub(super) async fn org_remember_ttl_secs(
    state: &AppState,
    ext: &axum::http::Extensions,
    org_id: Uuid,
) -> Option<i32> {
    match overslash_db::repos::org::get_default_remember_ttl_secs(state.db(ext), org_id).await {
        Ok(Some(secs)) => secs,
        Ok(None) => Some(FALLBACK_REMEMBER_TTL_SECS),
        Err(e) => {
            tracing::warn!(%org_id, "read default_remember_ttl_secs failed: {e}");
            Some(FALLBACK_REMEMBER_TTL_SECS)
        }
    }
}

/// "2 days", "90 minutes" — the largest whole unit an off-menu duration fits.
fn humanize_secs(secs: i32) -> String {
    let (n, unit) = [(86_400, "day"), (3_600, "hour"), (60, "minute")]
        .into_iter()
        .find(|(size, _)| secs % size == 0)
        .map(|(size, unit)| (secs / size, unit))
        .unwrap_or((secs, "second"));
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

/// The descriptive render-form fields the envelope carries, so either dialog
/// can show *what* is being approved (the labeled disclosure summary + risk
/// class) and the scope ladder, mirroring the dashboard review card. All read
/// straight off the in-hand outcome — no extra work.
fn dialog_meta(pending_outcome: &Value) -> Value {
    let field = |name: &str| {
        pending_outcome
            .get(name)
            .cloned()
            .unwrap_or_else(|| Value::Array(vec![]))
    };
    json!({
        "io.overslash/suggested_tiers": field("suggested_tiers"),
        "io.overslash/disclosed_fields": field("disclosed_fields"),
        "io.overslash/risk": pending_outcome.get("risk").cloned().unwrap_or(Value::Null)
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

    /// `elicitation: {}` predates modes and means form; a client that lists
    /// modes gets a form only if it listed `form`.
    #[test]
    fn form_support_follows_the_declared_modes() {
        for (caps, form) in [
            (json!({ "elicitation": {} }), true),
            (json!({ "elicitation": { "form": {} } }), true),
            (json!({ "elicitation": { "form": {}, "url": {} } }), true),
            (json!({ "elicitation": { "url": {} } }), false),
            (json!({ "roots": {} }), false),
            (json!({}), false),
        ] {
            assert_eq!(supports_form_elicitation(&caps), form, "{caps}");
        }
    }

    /// The decision dialog must not ask anything that only one choice uses:
    /// a duration next to "Deny" reads as "deny for how long?".
    #[test]
    fn decision_dialog_asks_only_for_the_decision() {
        let p = elicitation_params("send an email", &envelope());
        let props = p["requestedSchema"]["properties"].as_object().unwrap();
        assert_eq!(props.keys().collect::<Vec<_>>(), vec!["decision"]);
    }

    #[test]
    fn remember_dialog_offers_each_tier_narrowest_first_plus_duration() {
        let mut env = envelope();
        env["suggested_tiers"] = json!([
            { "keys": ["gmail:send:to=bob@x"], "description": "Emails to bob@x" },
            { "keys": ["gmail:send:*", "gmail:read:*"], "description": "Any send or read" },
        ]);
        let p = remember_params(&env, Some(604_800));
        let props = &p["requestedSchema"]["properties"];

        let scope = &props["scope"];
        assert_eq!(scope["default"], r#"["gmail:send:to=bob@x"]"#);
        assert_eq!(scope["oneOf"][0]["title"], "Emails to bob@x");
        assert_eq!(
            serde_json::from_str::<Vec<String>>(scope["oneOf"][1]["const"].as_str().unwrap())
                .unwrap(),
            vec!["gmail:send:*", "gmail:read:*"],
            "a multi-key tier must round-trip through its string value"
        );
        assert_eq!(props["ttl"]["default"], "7d");
        assert_eq!(p["message"], "Remember permission to: send an email");
    }

    /// The org default pre-selects the duration; "forever" stays a choice,
    /// and an off-menu default is appended so it can still be the default.
    #[test]
    fn remember_dialog_defaults_to_the_org_ttl() {
        let ttl = |secs| {
            remember_params(&envelope(), secs)["requestedSchema"]["properties"]["ttl"].clone()
        };

        assert_eq!(ttl(None)["default"], "forever");
        assert_eq!(ttl(Some(3_600))["default"], "1h");
        assert_eq!(ttl(Some(3_600))["oneOf"].as_array().unwrap().len(), 5);

        let custom = ttl(Some(172_800));
        assert_eq!(custom["default"], "172800s");
        let last = custom["oneOf"].as_array().unwrap().last().unwrap().clone();
        assert_eq!(last, json!({ "const": "172800s", "title": "2 days" }));
    }

    #[test]
    fn humanize_secs_picks_the_largest_whole_unit() {
        assert_eq!(humanize_secs(86_400), "1 day");
        assert_eq!(humanize_secs(5_400), "90 minutes");
        assert_eq!(humanize_secs(7_200), "2 hours");
        assert_eq!(humanize_secs(61), "61 seconds");
    }

    #[test]
    fn remember_dialog_without_tiers_asks_only_for_duration() {
        let p = remember_params(&envelope(), Some(604_800));
        let props = p["requestedSchema"]["properties"].as_object().unwrap();
        assert_eq!(props.keys().collect::<Vec<_>>(), vec!["ttl"]);
    }

    /// A `FollowUp` that reaches the result builder was never shown to
    /// anyone; it must fall back exactly like an unanswered dialog.
    #[test]
    fn stray_follow_up_falls_back_to_the_pending_envelope() {
        let outcome = envelope();
        let ev = elicit_result_event(
            &json!(3),
            mcp_session::ElicitOutcome::FollowUp("elicit_remember_x".into()),
            &outcome,
        );
        assert_eq!(
            ev["result"],
            super::super::tools_call::pending_approval_result(&outcome)
        );
    }
}
