//! The agent polling inbox: the `overslash` platform actions `get_events`
//! and `get_result`, plus the broadened `list_pending`.
//!
//! The gap these close: under `auto_call_on_approve` (the default) the
//! gateway replays an approved action in a background task and nothing tells
//! the requesting agent what it returned. `POST /v1/approvals/{id}/call`
//! answers 409 once the execution is terminal, `list_pending` used to filter
//! terminal executions straight out, and the MCP transport has no
//! server-initiated channel. An MCP-only client was simply blind to the
//! result of its own approved action.
//!
//! Everything here goes through `POST /mcp` as a real JSON-RPC client so the
//! assertions cover the tool surface an agent actually sees, not just the
//! REST endpoints underneath.
//!
//! Run with `--test-threads=4` (or similar) — see CLAUDE.md.

#![allow(clippy::disallowed_methods)]

use crate::common;

use std::time::Duration;

use axum::{Json, Router, http::HeaderMap, routing::get};
use reqwest::Client;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use uuid::Uuid;

// ── Fixture ─────────────────────────────────────────────────────────────

struct Fx {
    base: String,
    client: Client,
    agent_key: String,
    /// Key bound to `test-user`, the agent's parent — the identity an
    /// approval actually bubbles to. The org bootstrap key is bound to a
    /// *different* (admin) identity that is not an ancestor of the agent, so
    /// it sees an empty `scope=actionable`.
    user_key: String,
    admin_key: String,
    mock_addr: std::net::SocketAddr,
}

async fn start_mock() -> std::net::SocketAddr {
    common::allow_loopback_ssrf();
    async fn echo(_h: HeaderMap) -> Json<Value> {
        Json(json!({"ok": true}))
    }
    let app = Router::new().route("/echo", get(echo));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// Org + user + agent, a secret to inject (so the call needs a permission the
/// agent doesn't have and parks as pending), and auto-call left at whatever
/// the caller wants.
async fn bootstrap(auto_call: bool) -> Fx {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool).await;
    let base = format!("http://{api_addr}");
    let mock_addr = start_mock().await;

    let (org_id, agent_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    let user_key = mint_parent_user_key(&base, &client, &admin_key, org_id, agent_id).await;

    // `bootstrap_org_identity` disables auto-call so the older manual-call
    // tests keep passing; set it explicitly here so each test states the mode
    // it is exercising rather than inheriting one.
    let resp = client
        .patch(format!(
            "{base}/v1/identities/{agent_id}/auto-call-on-approve"
        ))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"enabled": auto_call}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "toggle auto-call: {resp:?}");

    client
        .put(format!("{base}/v1/secrets/tk"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"value": "v"}))
        .send()
        .await
        .unwrap();

    Fx {
        base,
        client,
        agent_key,
        user_key,
        admin_key,
        mock_addr,
    }
}

/// Mint an identity-bound key for the agent's parent. `bootstrap_org_identity`
/// hands back the org bootstrap key (bound to the auto-created admin user),
/// which is a sibling of `test-user` rather than an ancestor of the agent —
/// so it is *not* the identity an approval bubbles to.
async fn mint_parent_user_key(
    base: &str,
    client: &Client,
    admin_key: &str,
    org_id: Uuid,
    agent_id: Uuid,
) -> String {
    let listing: Value = client
        .get(format!("{base}/v1/identities"))
        .header(common::auth(admin_key).0, common::auth(admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rows = listing
        .as_array()
        .or_else(|| listing.get("identities").and_then(Value::as_array))
        .unwrap_or_else(|| panic!("unexpected identities listing: {listing}"));
    let agent = rows
        .iter()
        .find(|i| i["id"].as_str() == Some(&agent_id.to_string()))
        .unwrap_or_else(|| panic!("agent {agent_id} not in listing: {listing}"));
    let parent_id = agent["parent_id"]
        .as_str()
        .unwrap_or_else(|| panic!("agent should have a parent: {agent}"));

    let key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header(common::auth(admin_key).0, common::auth(admin_key).1)
        .json(&json!({"org_id": org_id, "identity_id": parent_id, "name": "parent-user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    key["key"].as_str().unwrap().to_string()
}

// ── MCP + REST helpers ──────────────────────────────────────────────────

/// `tools/call` against `/mcp`, returning the parsed tool payload. Every
/// action here is read-class and expected to succeed, so this unwraps the
/// success frame and fails loudly on `isError`.
async fn platform_action(fx: &Fx, tool: &str, action: &str, params: Value) -> Value {
    platform_action_as(fx, &fx.agent_key, tool, action, params).await
}

async fn platform_action_as(
    fx: &Fx,
    bearer: &str,
    tool: &str,
    action: &str,
    params: Value,
) -> Value {
    let mut args = json!({"service": "overslash", "action": action});
    if !params.is_null() {
        args["params"] = params;
    }
    let frame: Value = fx
        .client
        .post(format!("{}/mcp", fx.base))
        .header("Authorization", format!("Bearer {bearer}"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool, "arguments": args}
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let result = frame
        .get("result")
        .unwrap_or_else(|| panic!("expected result frame for {action}: {frame:?}"));
    assert_ne!(
        result.get("isError").and_then(Value::as_bool),
        Some(true),
        "{action} returned isError: {frame:?}"
    );
    let text = result["content"][0]["text"].as_str().unwrap();
    serde_json::from_str(text).unwrap_or_else(|e| panic!("parse {action} payload: {e}: {text}"))
}

async fn get_events(fx: &Fx) -> Vec<Value> {
    get_events_as(fx, &fx.agent_key).await
}

async fn get_events_as(fx: &Fx, bearer: &str) -> Vec<Value> {
    platform_action_as(fx, bearer, "overslash_call", "get_events", Value::Null)
        .await
        .as_array()
        .cloned()
        .unwrap()
}

fn events_of_type<'a>(events: &'a [Value], t: &str) -> Vec<&'a Value> {
    events
        .iter()
        .filter(|e| e["type"].as_str() == Some(t))
        .collect()
}

/// Fire a Mode-A call the agent has no permission for → 202 pending_approval.
async fn create_pending_approval(fx: &Fx) -> String {
    let resp = fx
        .client
        .post(format!("{}/v1/actions/call", fx.base))
        .header("Authorization", format!("Bearer {}", fx.agent_key))
        .json(&json!({
            "service": "http",
            "method": "GET",
            "url": format!("http://{}/echo", fx.mock_addr),
            "secrets": [{"name": "tk", "inject_as": "header", "header_name": "X-Auth"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202, "expected pending_approval");
    let body: Value = resp.json().await.unwrap();
    body["approval_id"].as_str().unwrap().to_string()
}

async fn allow(fx: &Fx, approval_id: &str) {
    let resp = fx
        .client
        .post(format!("{}/v1/approvals/{approval_id}/resolve", fx.base))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(&json!({"resolution": "allow"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "resolve failed");
}

/// Auto-call is spawned, so `/resolve` returns before the replay has run.
/// Poll the inbox until a `result_unread` event shows up.
async fn await_unread_result(fx: &Fx) -> Value {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let events = get_events(fx).await;
        if let Some(e) = events_of_type(&events, "result_unread").first() {
            return (*e).clone();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no result_unread event within 5s: {events:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

/// The headline case. Auto-call runs the action in the background; the agent
/// learns about it from `get_events` and reads the body with `get_result`.
#[tokio::test]
async fn auto_executed_result_is_reachable_over_mcp() {
    let fx = bootstrap(true).await;
    let approval_id = create_pending_approval(&fx).await;

    // Before resolution there is nothing for the requesting agent to do.
    assert!(
        get_events(&fx).await.is_empty(),
        "a still-pending approval is not the requester's problem"
    );

    allow(&fx, &approval_id).await;
    let event = await_unread_result(&fx).await;

    assert_eq!(event["approval_id"], approval_id);
    assert_eq!(event["execution"]["status"], "executed");
    assert_eq!(event["execution"]["output_read"], json!(false));
    // The feed carries the lifecycle, never the payload.
    assert!(
        event["execution"].get("result").is_none(),
        "result must not ride along in the feed: {event}"
    );

    // get_result is the only way to see what the action returned — and it
    // acknowledges the read.
    let exec = platform_action(
        &fx,
        "overslash_call",
        "get_result",
        json!({"approval_id": approval_id}),
    )
    .await;
    assert_eq!(exec["status"], "executed");
    assert_eq!(exec["triggered_by"], "auto");
    assert_eq!(exec["result"]["status_code"], 200);

    // Read once → gone from the inbox. This is what stops the feed from
    // repeating the same finished action forever.
    let after = get_events(&fx).await;
    assert!(
        events_of_type(&after, "result_unread").is_empty(),
        "result_unread must clear once read: {after:?}"
    );
}

/// The 409 an agent hits when it tries to /call an already-auto-executed
/// approval must name the recovery path rather than dead-ending.
#[tokio::test]
async fn call_after_auto_execution_points_at_get_result() {
    let fx = bootstrap(true).await;
    let approval_id = create_pending_approval(&fx).await;
    allow(&fx, &approval_id).await;
    await_unread_result(&fx).await;

    let resp = fx
        .client
        .post(format!("{}/v1/approvals/{approval_id}/call", fx.base))
        .header("Authorization", format!("Bearer {}", fx.agent_key))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("get_result"),
        "409 should name the recovery path: {body}"
    );
}

/// Deferred-execution mode: the approved action waits to be dispatched, and
/// the inbox says so.
#[tokio::test]
async fn deferred_mode_surfaces_ready_to_call() {
    let fx = bootstrap(false).await;
    let approval_id = create_pending_approval(&fx).await;
    allow(&fx, &approval_id).await;

    let events = get_events(&fx).await;
    let ready = events_of_type(&events, "ready_to_call");
    assert_eq!(ready.len(), 1, "expected one ready_to_call: {events:?}");
    assert_eq!(ready[0]["approval_id"], approval_id);
    assert_eq!(ready[0]["execution"]["status"], "pending");
    assert_eq!(
        ready[0]["relationship"], "self",
        "the agent's own request must classify as self"
    );

    // Dispatching it returns the body in-band, so nothing is left unread.
    let called = platform_action(
        &fx,
        "overslash_call",
        "call_pending",
        json!({"approval_id": approval_id}),
    )
    .await;
    assert!(
        called.get("status").is_some(),
        "dispatch returned: {called}"
    );

    // Dispatching returns the body in-band, so the inbox must go fully quiet
    // — not just lose the `ready_to_call`. Asserting emptiness (rather than
    // "no ready_to_call") is what catches a manual /call that forgets to
    // stamp `result_viewed_at` and leaves a permanent `result_unread` behind.
    let after = get_events(&fx).await;
    assert!(
        after.is_empty(),
        "a dispatched-and-returned action must leave nothing unread: {after:?}"
    );
}

/// An approval parked on the *user* shows up in that user's inbox as
/// `approval_needed`, and never in the requesting agent's own feed.
#[tokio::test]
async fn resolver_sees_approval_needed_requester_does_not() {
    let fx = bootstrap(true).await;
    let approval_id = create_pending_approval(&fx).await;

    // The requesting agent has nothing to act on — it is waiting on someone
    // else, which is precisely the state `approval_needed` must not claim.
    let own = get_events(&fx).await;
    assert!(own.is_empty(), "requester should see nothing yet: {own:?}");

    // The parent user polls the same inbox and finds work to do.
    let events = get_events_as(&fx, &fx.user_key).await;
    let needed = events_of_type(&events, "approval_needed");
    assert_eq!(
        needed.len(),
        1,
        "parent should see exactly one approval_needed: {events:?}"
    );
    assert_eq!(needed[0]["approval_id"], approval_id);
    assert_eq!(
        needed[0]["relationship"], "downstream",
        "an ancestor resolving a descendant's request is downstream — that is \
         what tells the agent to use overslash_approve, not _self"
    );
    assert!(
        needed[0].get("action_summary").is_some(),
        "the resolver needs to know what they are approving: {:?}",
        needed[0]
    );
}

/// `list_pending` keeps everything it used to return and now also holds onto
/// terminal-but-unread executions instead of dropping them on the floor.
#[tokio::test]
async fn list_pending_retains_unread_results() {
    let fx = bootstrap(true).await;
    let approval_id = create_pending_approval(&fx).await;
    allow(&fx, &approval_id).await;
    await_unread_result(&fx).await;

    let listed = platform_action(&fx, "overslash_call", "list_pending", Value::Null).await;
    let ids: Vec<&str> = listed
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|a| a["id"].as_str())
        .collect();
    assert!(
        ids.contains(&approval_id.as_str()),
        "auto-executed-but-unread must survive the filter: {listed:?}"
    );

    // Acknowledge, then it drops out.
    platform_action(
        &fx,
        "overslash_call",
        "get_result",
        json!({"approval_id": approval_id}),
    )
    .await;
    let after = platform_action(&fx, "overslash_call", "list_pending", Value::Null).await;
    assert!(
        after.as_array().unwrap().is_empty(),
        "read result should leave list_pending: {after:?}"
    );
}

/// Both new actions are read-class, so `overslash_read` must accept them —
/// that is what lets an MCP client poll without tripping a write-confirmation
/// prompt on every tick.
#[tokio::test]
async fn both_actions_are_reachable_through_the_read_tool() {
    let fx = bootstrap(true).await;
    let approval_id = create_pending_approval(&fx).await;
    allow(&fx, &approval_id).await;
    await_unread_result(&fx).await;

    let events = platform_action(&fx, "overslash_read", "get_events", Value::Null).await;
    assert!(!events.as_array().unwrap().is_empty());

    let exec = platform_action(
        &fx,
        "overslash_read",
        "get_result",
        json!({"approval_id": approval_id}),
    )
    .await;
    assert_eq!(exec["status"], "executed");
}

/// A missing `approval_id` is a caller error, and the message should say
/// which argument is missing rather than 500ing or silently listing.
#[tokio::test]
async fn get_result_without_approval_id_is_a_clear_error() {
    let fx = bootstrap(true).await;
    let frame: Value = fx
        .client
        .post(format!("{}/mcp", fx.base))
        .header("Authorization", format!("Bearer {}", fx.agent_key))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "overslash_call",
                "arguments": {"service": "overslash", "action": "get_result"}
            }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let text = serde_json::to_string(&frame).unwrap();
    assert!(
        text.contains("approval_id"),
        "error should name the missing argument: {text}"
    );
}
