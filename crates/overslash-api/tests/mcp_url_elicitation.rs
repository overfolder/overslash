//! URL-mode MCP elicitation, driven over the real `/mcp`.
//!
//! Each test hands the user a browser link through the client, completes (or
//! abandons) the browser side by writing what the browser flow would have
//! written, and checks what the tool call answers:
//!
//! - an auth envelope replays the call once the OAuth flow completes;
//! - a credential link reports the original result, marked `completed`;
//! - an approval (form dialog unavailable) calls the approved action;
//! - declined / failed hand-offs return the original body with a
//!   `url_elicitation` note.
//!
//! Both transports: the 2026-07-28 multi round-trip (the retry waits on the
//! flow) and the 2025-era SSE stream (`elicitation/create` with an
//! `elicitationId`, the answer on a separate POST, then
//! `notifications/elicitation/complete`).

// Seeds and asserts on flow / request rows directly.
#![allow(clippy::disallowed_methods)]

use crate::common;
use crate::mcp_modern_protocol::{
    Fx, claude_code_caps, envelope_of, modern, only_pending_approval, response_body, setup,
};

use std::time::Duration;

use overslash_db::repos as db;
use serde_json::{Value, json};
use uuid::Uuid;

const MODERN: &str = "2026-07-28";

/// A 2026-07-28 `tools/call overslash_call` with an arbitrary bearer (an agent
/// `osk_` key is enough: a modern request declares its capabilities itself).
async fn modern_call(
    client: &reqwest::Client,
    base: &str,
    bearer: &str,
    extra: Value,
    caps: Value,
) -> Value {
    let mut params = json!({
        "name": "overslash_call",
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": MODERN,
            "io.modelcontextprotocol/clientInfo": { "name": "claude-code", "version": "2.1.283" },
            "io.modelcontextprotocol/clientCapabilities": caps,
        }
    });
    if let (Value::Object(p), Value::Object(e)) = (&mut params, extra) {
        p.extend(e);
    }
    let resp = client
        .post(format!("{base}/mcp"))
        .bearer_auth(bearer)
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", MODERN)
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "overslash_call")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": Uuid::new_v4().to_string(),
            "method": "tools/call",
            "params": params,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    response_body(resp).await
}

fn url_caps() -> Value {
    json!({ "elicitation": { "url": {} } })
}

/// The link an `input_required` URL hand-off asks the user to open.
fn asked_url(result: &Value) -> String {
    assert_eq!(result["resultType"], "input_required", "{result}");
    let ask = &result["inputRequests"]["url"];
    assert_eq!(ask["method"], "elicitation/create");
    assert_eq!(ask["params"]["mode"], "url");
    assert!(
        ask["params"].get("elicitationId").is_none(),
        "2026-07-28 removed elicitationId: {ask}"
    );
    assert!(
        ask["params"]["message"]
            .as_str()
            .is_some_and(|m| !m.is_empty())
    );
    ask["params"]["url"].as_str().unwrap().to_string()
}

fn flow_id_of(auth_url: &str) -> String {
    let url = url::Url::parse(auth_url).unwrap();
    assert_eq!(url.path(), "/connect-authorize", "{auth_url}");
    url.query_pairs()
        .find(|(k, _)| k == "id")
        .unwrap()
        .1
        .into_owned()
}

fn text_of(result: &Value) -> Value {
    serde_json::from_str(result["content"][0]["text"].as_str().expect("text block")).unwrap()
}

// ── Auth envelopes: replay once the OAuth flow completes ────────────────────

struct XFx {
    base: String,
    client: reqwest::Client,
    pool: sqlx::PgPool,
    agent_key: String,
}

/// The bundled `x` template with no connection: every call answers
/// `needs_authentication` with a gated connect link.
async fn x_setup() -> XFx {
    let pool = common::test_pool().await;
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", "x_test_client");
        std::env::set_var("OAUTH_X_CLIENT_SECRET", "x_test_secret");
    }
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (_org, ident_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    let resp = client
        .post(format!("{base}/v1/services"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({
            "template_key": "x",
            "name": "x",
            "user_level": false,
            "groups": common::everyone_grant(&base, &client, &admin_key).await,
            "status": "active",
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{:?}", resp.text().await);
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({ "identity_id": ident_id, "action_pattern": "x:*:*" }))
        .send()
        .await
        .unwrap();
    XFx {
        base,
        client,
        pool,
        agent_key,
    }
}

fn get_me() -> Value {
    json!({ "arguments": { "service": "x", "action": "get_me", "params": {} } })
}

fn retry(first: &Value, action: &str) -> Value {
    json!({
        "arguments": { "service": "x", "action": "get_me", "params": {} },
        "inputResponses": { "url": { "action": action } },
        "requestState": first["requestState"],
    })
}

#[tokio::test]
async fn an_auth_link_replays_the_call_once_the_flow_completes() {
    let fx = x_setup().await;
    let first = modern_call(&fx.client, &fx.base, &fx.agent_key, get_me(), url_caps()).await;
    let first = first["result"].clone();
    let flow_id = flow_id_of(&asked_url(&first));

    // The user accepts; the client retries while they are in the browser.
    let pending = {
        let (client, base, key, body) = (
            fx.client.clone(),
            fx.base.clone(),
            fx.agent_key.clone(),
            retry(&first, "accept"),
        );
        tokio::spawn(async move { modern_call(&client, &base, &key, body, url_caps()).await })
    };
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(!pending.is_finished(), "the retry must wait for the flow");

    // What the OAuth callback writes when the provider sends the user back.
    db::oauth_connection_flow::mark_finished(&fx.pool, &flow_id, true)
        .await
        .unwrap();
    let done = tokio::time::timeout(Duration::from_secs(20), pending)
        .await
        .expect("the retry answers once the flow completes")
        .unwrap();
    let r = &done["result"];
    assert_eq!(r["resultType"], "complete", "{done}");

    // No real token was minted here, so the replayed call still lacks auth —
    // which is what proves it *was* replayed: a fresh envelope, a fresh link,
    // and no note (the note is only for hand-offs that did not complete).
    let env = text_of(r);
    assert_eq!(env["error"], "needs_authentication", "{env}");
    assert!(env.get("url_elicitation").is_none(), "{env}");
    let replayed_flow = flow_id_of(env["auth_url"].as_str().unwrap());
    assert_ne!(replayed_flow, flow_id, "the replay minted its own flow");
}

#[tokio::test]
async fn declining_or_failing_the_link_returns_the_envelope_with_a_note() {
    let fx = x_setup().await;

    let first = modern_call(&fx.client, &fx.base, &fx.agent_key, get_me(), url_caps()).await;
    let first = first["result"].clone();
    let link = asked_url(&first);
    let done = modern_call(
        &fx.client,
        &fx.base,
        &fx.agent_key,
        retry(&first, "decline"),
        url_caps(),
    )
    .await;
    let r = &done["result"];
    assert_eq!(r["isError"], true, "{done}");
    let env = text_of(r);
    assert_eq!(env["error"], "needs_authentication");
    assert_eq!(env["url_elicitation"], "declined");
    assert_eq!(env["auth_url"], json!(link), "the same link, still usable");

    // The provider bounced the user back with an error.
    let first = modern_call(&fx.client, &fx.base, &fx.agent_key, get_me(), url_caps()).await;
    let first = first["result"].clone();
    let flow_id = flow_id_of(&asked_url(&first));
    db::oauth_connection_flow::mark_finished(&fx.pool, &flow_id, false)
        .await
        .unwrap();
    let done = modern_call(
        &fx.client,
        &fx.base,
        &fx.agent_key,
        retry(&first, "accept"),
        url_caps(),
    )
    .await;
    assert_eq!(
        text_of(&done["result"])["url_elicitation"],
        "failed",
        "{done}"
    );
}

#[tokio::test]
async fn a_client_without_url_mode_gets_the_plain_envelope() {
    let fx = x_setup().await;
    for caps in [json!({ "elicitation": { "form": {} } }), json!({})] {
        let done = modern_call(&fx.client, &fx.base, &fx.agent_key, get_me(), caps.clone()).await;
        let r = &done["result"];
        assert_eq!(r["resultType"], "complete", "caps {caps}: {done}");
        assert_eq!(r["isError"], true);
        let env = text_of(r);
        assert_eq!(env["error"], "needs_authentication");
        assert!(env.get("url_elicitation").is_none());
    }
}

// ── Credential entry: report the original result once fulfilled ─────────────

#[tokio::test]
async fn a_secret_request_reports_completed_once_the_user_enters_it() {
    let fx = x_setup().await;
    let call = json!({ "arguments": {
        "service": "overslash",
        "action": "request_secret",
        "params": { "secret_name": "acme_token", "purpose": "the Acme API" },
    }});
    let first = modern_call(
        &fx.client,
        &fx.base,
        &fx.agent_key,
        call.clone(),
        url_caps(),
    )
    .await;
    let first = first["result"].clone();
    let link = asked_url(&first);
    assert!(link.contains("/secrets/provide/"), "{link}");

    let pending = {
        let mut body = call.clone();
        body["inputResponses"] = json!({ "url": { "action": "accept" } });
        body["requestState"] = first["requestState"].clone();
        let (client, base, key) = (fx.client.clone(), fx.base.clone(), fx.agent_key.clone());
        tokio::spawn(async move { modern_call(&client, &base, &key, body, url_caps()).await })
    };
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let request_id = link
        .split("/secrets/provide/")
        .nth(1)
        .unwrap()
        .split('?')
        .next()
        .unwrap()
        .to_string();
    assert!(
        db::secret_request::mark_fulfilled(&fx.pool, &request_id)
            .await
            .unwrap()
    );

    let done = tokio::time::timeout(Duration::from_secs(20), pending)
        .await
        .unwrap()
        .unwrap();
    let out = text_of(&done["result"]);
    assert_eq!(out["url_elicitation"], "completed", "{out}");
    // The platform result wraps the action's own body; the note sits on the
    // outside, and the original result is carried through untouched.
    assert!(
        out.to_string().contains(&request_id),
        "the original result is what comes back: {out}"
    );
}

// ── Approvals, with the in-client form unavailable ──────────────────────────

async fn resolve(fx: &Fx, approval_id: &str, resolution: &str) {
    let resp = fx
        .client
        .post(format!("{}/v1/approvals/{approval_id}/resolve", fx.base))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(&json!({ "resolution": resolution }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "resolve: {:?}", resp.text().await);
}

/// "Approve in your client" off: the approval goes to the dashboard as a URL
/// hand-off, and the call finishes itself once the user approves there.
#[tokio::test]
async fn an_opted_out_approval_is_a_link_that_finishes_the_call() {
    let fx = setup().await;
    db::mcp_client_agent_binding::set_elicitation_opted_out_for_agent(&fx.pool, fx.agent_id, true)
        .await
        .unwrap();

    let first = fx.gated_call("via-dashboard", claude_code_caps()).await;
    let link = asked_url(&first);
    let approval_id = only_pending_approval(&fx).await;
    assert!(link.contains(&approval_id), "{link}");

    let pending = {
        let body = json!({
            "name": "overslash_call",
            "arguments": fx.call_args("via-dashboard"),
            "inputResponses": { "url": { "action": "accept" } },
            "requestState": first["requestState"],
        });
        let fx2 = (fx.client.clone(), fx.base.clone(), fx.token.clone());
        tokio::spawn(async move {
            let resp = fx2
                .0
                .post(format!("{}/mcp", fx2.1))
                .bearer_auth(&fx2.2)
                .header("Accept", "application/json, text/event-stream")
                .header("MCP-Protocol-Version", MODERN)
                .header("Mcp-Method", "tools/call")
                .header("Mcp-Name", "overslash_call")
                .json(&json!({
                    "jsonrpc": "2.0", "id": 9, "method": "tools/call",
                    "params": {
                        "_meta": {
                            "io.modelcontextprotocol/protocolVersion": MODERN,
                            "io.modelcontextprotocol/clientCapabilities": claude_code_caps(),
                        },
                        "name": body["name"],
                        "arguments": body["arguments"],
                        "inputResponses": body["inputResponses"],
                        "requestState": body["requestState"],
                    },
                }))
                .send()
                .await
                .unwrap();
            response_body(resp).await
        })
    };
    tokio::time::sleep(Duration::from_millis(1500)).await;
    resolve(&fx, &approval_id, "allow").await;

    let done = tokio::time::timeout(Duration::from_secs(20), pending)
        .await
        .unwrap()
        .unwrap();
    let r = &done["result"];
    assert!(r.get("isError").is_none(), "{done}");
    let text = r["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("via-dashboard"),
        "the approved call ran: {text}"
    );
    assert_eq!(fx.approval_status(&approval_id).await, "allowed");
}

#[tokio::test]
async fn declining_an_approval_link_is_not_a_denial() {
    let fx = setup().await;
    db::mcp_client_agent_binding::set_elicitation_opted_out_for_agent(&fx.pool, fx.agent_id, true)
        .await
        .unwrap();
    let first = fx.gated_call("not-now", claude_code_caps()).await;
    asked_url(&first);
    let approval_id = only_pending_approval(&fx).await;

    let (_, done) = modern(
        &fx,
        "tools/call",
        json!({
            "name": "overslash_call",
            "arguments": fx.call_args("not-now"),
            "inputResponses": { "url": { "action": "decline" } },
            "requestState": first["requestState"],
        }),
        claude_code_caps(),
    )
    .await;
    let env = envelope_of(&done["result"]);
    assert_eq!(env["status"], "pending_approval");
    assert_eq!(env["url_elicitation"], "declined");
    assert_eq!(fx.approval_status(&approval_id).await, "pending");
}

// ── The 2025-era transport: one SSE stream around the hand-off ──────────────

/// Reads a `text/event-stream` response one `data:` event at a time.
struct Events {
    resp: reqwest::Response,
    buf: String,
}

impl Events {
    async fn next(&mut self) -> Value {
        loop {
            if let Some(end) = self.buf.find("\n\n") {
                let block: String = self.buf.drain(..end + 2).collect();
                let data: Vec<&str> = block
                    .lines()
                    .filter_map(|l| l.strip_prefix("data:"))
                    .map(str::trim)
                    .collect();
                if data.is_empty() {
                    continue; // keep-alive comment
                }
                return serde_json::from_str(&data.join("\n")).unwrap();
            }
            let chunk = tokio::time::timeout(Duration::from_secs(20), self.resp.chunk())
                .await
                .expect("stream stalled")
                .unwrap()
                .expect("stream ended early");
            self.buf.push_str(&String::from_utf8_lossy(&chunk));
        }
    }
}

/// A 2025-era connection that declared URL mode (and only URL mode) at
/// `initialize` — what Codex does, minus the form.
async fn legacy_url_client(fx: &Fx) {
    db::oauth_mcp_client::update_initialize_state(
        &fx.pool,
        &fx.client_id,
        &json!({ "elicitation": { "url": {} } }),
        &json!({ "name": "codex-mcp-client", "version": "0.157.0" }),
        "2025-06-18",
        Uuid::new_v4(),
    )
    .await
    .unwrap();
}

async fn legacy_gated_call(fx: &Fx, x: &str) -> Events {
    let resp = fx
        .client
        .post(format!("{}/mcp", fx.base))
        .bearer_auth(&fx.token)
        .header("Accept", "application/json, text/event-stream")
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "overslash_call", "arguments": fx.call_args(x) },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    Events {
        resp,
        buf: String::new(),
    }
}

async fn legacy_answer(fx: &Fx, elicit_id: &str, action: &str) {
    let resp = fx
        .client
        .post(format!("{}/mcp", fx.base))
        .bearer_auth(&fx.token)
        .json(&json!({ "jsonrpc": "2.0", "id": elicit_id, "result": { "action": action } }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202, "{:?}", resp.text().await);
}

#[tokio::test]
async fn legacy_accept_completes_then_answers_with_the_result() {
    let fx = setup().await;
    legacy_url_client(&fx).await;
    let mut events = legacy_gated_call(&fx, "legacy-yes").await;

    let ask = events.next().await;
    assert_eq!(ask["method"], "elicitation/create", "{ask}");
    assert_eq!(ask["params"]["mode"], "url");
    let eid = ask["id"].as_str().unwrap().to_string();
    assert_eq!(ask["params"]["elicitationId"], json!(eid));
    let approval_id = only_pending_approval(&fx).await;

    legacy_answer(&fx, &eid, "accept").await;
    resolve(&fx, &approval_id, "allow").await;

    let complete = events.next().await;
    assert_eq!(
        complete["method"], "notifications/elicitation/complete",
        "{complete}"
    );
    assert_eq!(complete["params"]["elicitationId"], json!(eid));
    let result = events.next().await;
    assert_eq!(result["id"], 1);
    let text = result["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("legacy-yes"), "{text}");
}

#[tokio::test]
async fn legacy_decline_ends_the_stream_with_the_noted_envelope() {
    let fx = setup().await;
    legacy_url_client(&fx).await;
    let mut events = legacy_gated_call(&fx, "legacy-no").await;
    let ask = events.next().await;
    let eid = ask["id"].as_str().unwrap().to_string();

    legacy_answer(&fx, &eid, "decline").await;
    let result = events.next().await;
    let env = envelope_of(&result["result"]);
    assert_eq!(env["status"], "pending_approval");
    assert_eq!(env["url_elicitation"], "declined");
}
