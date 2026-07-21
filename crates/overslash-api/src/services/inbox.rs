//! The agent's polling inbox — "what needs my attention right now?".
//!
//! Shared by the MCP `overslash` platform actions (`get_events`,
//! `list_pending`) and the CLI (`overslash inbox`). Both surfaces poll the
//! same two REST listings and must classify the rows identically, so the
//! classification lives here rather than being written twice.
//!
//! # Why an inbox exists at all
//!
//! Under `auto_call_on_approve` (the default) the gateway replays an approved
//! action in a background task. The result lands in `executions.result` and
//! the requesting agent is never told: `POST /v1/approvals/{id}/call` answers
//! 409 `execution has already completed` once the execution is terminal, and
//! the MCP transport has no server-initiated channel (`GET /mcp` is a 405).
//! Polling is therefore the only way an agent can learn what its own approved
//! action returned, and [`build_events`] is that poll.
//!
//! # Read-tracking
//!
//! `result_unread` self-clears: `executions.result_viewed_at` is stamped when
//! the requesting agent fetches the outcome (`GET /v1/approvals/{id}/execution`)
//! or receives it in-band from its own `POST /v1/approvals/{id}/call`. Reads by
//! anyone else — dashboard, resolver — deliberately leave it unread, so the
//! "agent hasn't collected this yet" signal survives an operator looking at it.
//!
//! Note that other endpoints (`list_pending`, `GET /v1/approvals/{id}`) nest
//! the result body without stamping anything. An agent that scrapes the body
//! from those keeps a permanently repeating `result_unread` event, which is why
//! the event feed itself omits `result` — the only way to see the payload is
//! also the way to acknowledge it.

use serde_json::{Map, Value};

/// Event categories returned by [`build_events`].
pub mod event_type {
    /// A request from somewhere in the caller's subtree is parked on a
    /// permission gap the caller can close by resolving it.
    pub const APPROVAL_NEEDED: &str = "approval_needed";
    /// The caller's own approved action is waiting to be dispatched
    /// (deferred-execution mode; the execution row has a 15-minute TTL).
    pub const READY_TO_CALL: &str = "ready_to_call";
    /// The caller's own action already ran and the output has never been
    /// fetched.
    pub const RESULT_UNREAD: &str = "result_unread";
}

/// Status of the execution row attached to an approval, if any. Absent for
/// pending / denied / bubbled-up approvals — `execution` is
/// `skip_serializing_if = "Option::is_none"` on the wire.
pub fn execution_status(approval: &Value) -> Option<&str> {
    approval.get("execution")?.get("status")?.as_str()
}

/// Whether the requesting agent has already fetched this execution's output.
///
/// Missing or non-boolean reads as unread: callers only consult this for
/// terminal executions, where showing a result twice is a far cheaper failure
/// than silently swallowing one.
pub fn output_read(approval: &Value) -> bool {
    approval
        .get("execution")
        .and_then(|e| e.get("output_read"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// Does this approval from the caller's own `status=allowed` listing still
/// need something from the caller?
///
/// An approval's status stays `allowed` long after its execution has been
/// dispatched, failed, or expired, so the raw listing is far too broad. Two
/// classes survive:
///   * `pending` — still dispatchable.
///   * terminal but unread — already ran, output never collected.
///
/// Anything else (`executing`, `cancelled`, `expired`, or already-read) is
/// settled and would be noise on every subsequent poll.
pub fn needs_attention(approval: &Value) -> bool {
    match execution_status(approval) {
        Some("pending") => true,
        Some("executed") | Some("failed") => !output_read(approval),
        _ => false,
    }
}

/// Merge the two upstream listings into one flat, typed event feed.
///
/// * `actionable` — the body of `GET /v1/approvals?scope=actionable`. That
///   scope is pending-only in SQL and already excludes the caller's own
///   requests, so every row is an unresolved ask *for* the caller.
/// * `mine` — the body of `GET /v1/approvals?scope=mine&status=allowed`,
///   split by [`needs_attention`] into `ready_to_call` vs `result_unread`.
///
/// Non-array inputs contribute nothing, so a caller that passes a typed-error
/// envelope by mistake gets an empty feed rather than a panic.
///
/// Denied and expired approvals are deliberately absent: they carry no unread
/// marker, so they would repeat on every poll forever. Surfacing them needs a
/// cursor the listing endpoint does not have yet.
pub fn build_events(actionable: &Value, mine: &Value) -> Vec<Value> {
    let mut events = Vec::new();
    for item in actionable.as_array().into_iter().flatten() {
        events.push(event_from_approval(item, event_type::APPROVAL_NEEDED));
    }
    for item in mine.as_array().into_iter().flatten() {
        match execution_status(item) {
            Some("pending") => events.push(event_from_approval(item, event_type::READY_TO_CALL)),
            Some("executed") | Some("failed") if !output_read(item) => {
                events.push(event_from_approval(item, event_type::RESULT_UNREAD));
            }
            _ => {}
        }
    }
    events
}

/// Project an `ApprovalResponse` down to an inbox event.
///
/// Deliberately narrow: enough for the agent to decide what to do next and
/// which id to pass, with the bulky fields (`action_detail`,
/// `disclosed_fields`, the identity-path arrays, and above all
/// `execution.result`) left for the follow-up fetch. One unread 256 KiB body
/// would otherwise dominate every poll — and leaving the payload behind is
/// what gives the read-acknowledgement something to do.
pub fn event_from_approval(approval: &Value, event_type: &str) -> Value {
    let mut out = Map::new();
    out.insert("type".into(), Value::String(event_type.into()));
    // `id` is renamed to `approval_id` so the value can be pasted straight
    // into the `approval_id` argument every follow-up call expects.
    if let Some(v) = approval.get("id") {
        out.insert("approval_id".into(), v.clone());
    }
    // `relationship` ("self" | "downstream") tells the agent which approve
    // tool applies without trial-and-error; the listing already computes it.
    for key in [
        "action_summary",
        "risk",
        "relationship",
        "expires_at",
        "created_at",
    ] {
        if let Some(v) = approval.get(key) {
            out.insert(key.into(), v.clone());
        }
    }
    if let Some(exec) = approval.get("execution") {
        let mut summary = Map::new();
        for key in [
            "status",
            "http_status_code",
            "error",
            "output_read",
            "expires_at",
        ] {
            if let Some(v) = exec.get(key) {
                summary.insert(key.into(), v.clone());
            }
        }
        out.insert("execution".into(), Value::Object(summary));
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn approval(id: &str, exec: Option<Value>) -> Value {
        let mut v = json!({
            "id": id,
            "action_summary": "GET https://api.example.com/things",
            "risk": "read",
            "relationship": "self",
            "created_at": "2026-07-21T10:00:00Z",
            "action_detail": {"huge": "x".repeat(100)},
        });
        if let Some(e) = exec {
            v.as_object_mut().unwrap().insert("execution".into(), e);
        }
        v
    }

    #[test]
    fn pending_execution_needs_attention() {
        let a = approval(
            "a",
            Some(json!({"status": "pending", "output_read": false})),
        );
        assert!(needs_attention(&a));
    }

    #[test]
    fn executed_but_unread_needs_attention() {
        // The regression this whole module exists for: an auto-called action
        // must stay visible until the agent has actually read the output.
        let a = approval(
            "a",
            Some(json!({"status": "executed", "output_read": false})),
        );
        assert!(needs_attention(&a));
    }

    #[test]
    fn executed_and_read_is_settled() {
        let a = approval(
            "a",
            Some(json!({"status": "executed", "output_read": true})),
        );
        assert!(!needs_attention(&a));
    }

    #[test]
    fn failed_but_unread_needs_attention() {
        let a = approval("a", Some(json!({"status": "failed", "output_read": false})));
        assert!(needs_attention(&a));
    }

    #[test]
    fn cancelled_and_expired_are_settled() {
        for status in ["cancelled", "expired", "executing"] {
            let a = approval("a", Some(json!({"status": status, "output_read": false})));
            assert!(!needs_attention(&a), "{status} should be settled");
        }
    }

    #[test]
    fn missing_execution_is_settled() {
        assert!(!needs_attention(&approval("a", None)));
    }

    #[test]
    fn missing_output_read_flag_reads_as_unread() {
        // Fail toward showing the result twice, never toward swallowing it.
        let a = approval("a", Some(json!({"status": "executed"})));
        assert!(needs_attention(&a));
    }

    #[test]
    fn build_events_assigns_the_three_types() {
        let actionable = json!([approval("needs-me", None)]);
        let mine = json!([
            approval("dispatch-me", Some(json!({"status": "pending"}))),
            approval(
                "read-me",
                Some(json!({"status": "executed", "output_read": false}))
            ),
            approval(
                "settled",
                Some(json!({"status": "executed", "output_read": true}))
            ),
        ]);
        let events = build_events(&actionable, &mine);
        let pairs: Vec<(&str, &str)> = events
            .iter()
            .map(|e| {
                (
                    e["approval_id"].as_str().unwrap(),
                    e["type"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("needs-me", "approval_needed"),
                ("dispatch-me", "ready_to_call"),
                ("read-me", "result_unread"),
            ]
        );
    }

    #[test]
    fn events_omit_bulky_fields() {
        let mine = json!([approval(
            "a",
            Some(json!({
                "status": "executed",
                "output_read": false,
                "result": {"body": "x".repeat(10_000)},
                "http_status_code": 200,
            }))
        )]);
        let events = build_events(&json!([]), &mine);
        let e = &events[0];
        assert!(
            e.get("action_detail").is_none(),
            "action_detail must not ride along"
        );
        assert!(
            e["execution"].get("result").is_none(),
            "result belongs to get_result, not the feed"
        );
        assert_eq!(e["execution"]["http_status_code"], 200);
        assert_eq!(e["relationship"], "self");
    }

    #[test]
    fn non_array_inputs_yield_no_events() {
        // A typed-error envelope reaching here must not panic.
        let err = json!({"error": "not_in_your_chain"});
        assert!(build_events(&err, &err).is_empty());
    }
}
