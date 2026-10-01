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
    org_id: Uuid,
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
    let (org_id, ident_id, agent_key, admin_key) =
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
        org_id,
    }
}

impl XFx {
    /// The first leg: a fresh call answered with the auth link.
    async fn first(&self) -> Value {
        modern_call(
            &self.client,
            &self.base,
            &self.agent_key,
            get_me(),
            url_caps(),
        )
        .await["result"]
            .clone()
    }

    async fn retry(&self, first: &Value, action: &str) -> Value {
        modern_call(
            &self.client,
            &self.base,
            &self.agent_key,
            retry(first, action),
            url_caps(),
        )
        .await
    }
}

/// An auth link whose browser side ended is handed back as a *fresh* link —
/// the original flow was consumed when the user opened it, so relaying it
/// would give the agent a dead link.
fn assert_fresh_link(done: &Value, old_flow: &str, note: &str, reason: Option<&str>) {
    let r = &done["result"];
    assert_eq!(r["isError"], true, "{done}");
    let env = text_of(r);
    assert_eq!(env["error"], "needs_authentication", "{env}");
    assert_eq!(env["url_elicitation"], note, "{env}");
    assert_eq!(
        env.get("url_elicitation_error").and_then(Value::as_str),
        reason,
        "{env}"
    );
    let fresh = flow_id_of(env["auth_url"].as_str().unwrap());
    assert_ne!(
        fresh, old_flow,
        "the dead link must not be handed back: {env}"
    );
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
    db::oauth_connection_flow::mark_finished(&fx.pool, &flow_id, Ok(()))
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
async fn declining_in_the_client_keeps_the_unopened_link() {
    let fx = x_setup().await;
    let first = fx.first().await;
    let link = asked_url(&first);
    let done = fx.retry(&first, "decline").await;
    let r = &done["result"];
    assert_eq!(r["isError"], true, "{done}");
    let env = text_of(r);
    assert_eq!(env["error"], "needs_authentication");
    assert_eq!(env["url_elicitation"], "declined");
    assert!(env.get("url_elicitation_error").is_none(), "{env}");
    assert_eq!(
        env["auth_url"],
        json!(link),
        "never opened, so still usable"
    );
}

#[tokio::test]
async fn a_failed_callback_hands_back_a_fresh_link_and_the_reason() {
    let fx = x_setup().await;
    let first = fx.first().await;
    let flow_id = flow_id_of(&asked_url(&first));
    db::oauth_connection_flow::mark_finished(&fx.pool, &flow_id, Err("server_error"))
        .await
        .unwrap();
    let done = fx.retry(&first, "accept").await;
    assert_fresh_link(&done, &flow_id, "failed", Some("server_error"));
}

/// The user pressed Deny at the provider, which redirects back with
/// `?error=access_denied` and no `code`. That redirect used to bounce off the
/// callback's query extractor, leaving the waiting call to time out.
#[tokio::test]
async fn a_deny_at_the_provider_ends_the_wait_as_declined() {
    let fx = x_setup().await;
    let first = fx.first().await;
    let flow_id = flow_id_of(&asked_url(&first));

    let pending = {
        let (client, base, key, body) = (
            fx.client.clone(),
            fx.base.clone(),
            fx.agent_key.clone(),
            retry(&first, "accept"),
        );
        tokio::spawn(async move { modern_call(&client, &base, &key, body, url_caps()).await })
    };
    tokio::time::sleep(Duration::from_millis(800)).await;
    let resp = fx
        .client
        .get(format!(
            "{}/v1/oauth/callback?state={flow_id}&error=access_denied&error_description=nope",
            fx.base
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "the callback still reports the refusal");
    let flow = db::oauth_connection_flow::completion(&fx.pool, &flow_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(flow.failure.as_deref(), Some("access_denied"));

    let done = tokio::time::timeout(Duration::from_secs(20), pending)
        .await
        .expect("the refusal ends the wait now, not at the timeout")
        .unwrap();
    assert_fresh_link(&done, &flow_id, "declined", Some("access_denied"));
}

/// A provider error code outside RFC 6749's character set is not relayed.
#[tokio::test]
async fn an_odd_provider_error_code_is_not_relayed() {
    let fx = x_setup().await;
    let first = fx.first().await;
    let flow_id = flow_id_of(&asked_url(&first));
    fx.client
        .get(format!(
            "{}/v1/oauth/callback?state={flow_id}&error=%3Cscript%3E",
            fx.base
        ))
        .send()
        .await
        .unwrap();
    let flow = db::oauth_connection_flow::completion(&fx.pool, &flow_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(flow.failure.as_deref(), Some("provider_error"));
}

/// Cancel on the consent interstitial records the refusal on the flow.
#[tokio::test]
async fn cancel_on_the_consent_page_ends_the_wait_as_declined() {
    let fx = x_setup().await;
    let first = fx.first().await;
    let flow_id = flow_id_of(&asked_url(&first));

    // Without a session the POST is refused and records nothing.
    let resp = fx
        .client
        .post(format!("{}/connect-authorize/cancel", fx.base))
        .form(&[("id", flow_id.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // A signed-in user who could not have continued this flow — here, one
    // from another org — cannot cancel it either.
    let resp = fx
        .client
        .post(format!("{}/connect-authorize/cancel", fx.base))
        .header(
            "Cookie",
            common::session_cookie(Uuid::new_v4(), Uuid::new_v4()),
        )
        .form(&[("id", flow_id.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "{:?}", resp.text().await);
    let flow = db::oauth_connection_flow::completion(&fx.pool, &flow_id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        flow.failed_at.is_none(),
        "a stranger's cancel records nothing"
    );

    // The flow's owner, signed in, can.
    let owner = db::oauth_connection_flow::get_by_id(&fx.pool, &flow_id)
        .await
        .unwrap()
        .unwrap()
        .identity_id;

    let resp = fx
        .client
        .post(format!("{}/connect-authorize/cancel", fx.base))
        .header("Cookie", common::session_cookie(fx.org_id, owner))
        .form(&[("id", flow_id.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.text().await.unwrap().contains("Connection cancelled"));

    let done = fx.retry(&first, "accept").await;
    assert_fresh_link(&done, &flow_id, "declined", Some("cancelled_by_user"));
}

/// Retrying after the state expired gets an answer, not a JSON-RPC error. The
/// link was never opened, so it is still good and comes back as it was —
/// no second flow minted, none orphaned.
#[tokio::test]
async fn a_late_retry_gets_the_fallback_not_an_error() {
    let fx = x_setup().await;
    let first = fx.first().await;
    let link = asked_url(&first);
    let mut late = first.clone();
    late["requestState"] = json!(expire(first["requestState"].as_str().unwrap()));
    let done = fx.retry(&late, "accept").await;
    assert!(done.get("error").is_none(), "{done}");
    let env = text_of(&done["result"]);
    assert_eq!(env["url_elicitation"], "timed_out", "{env}");
    assert_eq!(env["auth_url"], json!(link), "unopened, so still usable");
}

/// Timed out after the user *opened* the link: the flow is consumed, so the
/// agent gets a fresh link rather than the spent one.
#[tokio::test]
async fn a_link_opened_then_abandoned_is_replaced_on_timeout() {
    let fx = x_setup().await;
    let first = fx.first().await;
    let flow_id = flow_id_of(&asked_url(&first));
    // What the gate does when the user opens the link.
    db::oauth_connection_flow::consume(&fx.pool, &flow_id)
        .await
        .unwrap()
        .expect("consumable");
    let mut late = first.clone();
    late["requestState"] = json!(expire(first["requestState"].as_str().unwrap()));
    let done = fx.retry(&late, "accept").await;
    assert_fresh_link(&done, &flow_id, "timed_out", None);
}

/// Re-sign a request state as if it had expired ten minutes ago — past the
/// verifier's 60s clock leeway, which would otherwise still accept it.
fn expire(state: &str) -> String {
    let key = common::signing_key_bytes();
    let mut claims =
        overslash_api::services::jwt::verify_mcp_request_state(&key, state).expect("fresh state");
    claims.exp = time::OffsetDateTime::now_utc().unix_timestamp() - 600;
    overslash_api::services::jwt::mint_mcp_request_state(&key, &claims).unwrap()
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

/// Deny on the provide page records the refusal; the waiting call ends now
/// with the original result, marked declined.
#[tokio::test]
async fn deny_on_the_provide_page_ends_the_wait_as_declined() {
    let fx = x_setup().await;
    let call = json!({ "arguments": {
        "service": "overslash",
        "action": "request_secret",
        "params": { "secret_name": "acme_key", "purpose": "the Acme API" },
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
    let link = url::Url::parse(&asked_url(&first)).unwrap();
    let request_id = link.path().rsplit('/').next().unwrap().to_string();
    let token = link
        .query_pairs()
        .find(|(k, _)| k == "token")
        .unwrap()
        .1
        .into_owned();

    let pending = {
        let mut body = call.clone();
        body["inputResponses"] = json!({ "url": { "action": "accept" } });
        body["requestState"] = first["requestState"].clone();
        let (client, base, key) = (fx.client.clone(), fx.base.clone(), fx.agent_key.clone());
        tokio::spawn(async move { modern_call(&client, &base, &key, body, url_caps()).await })
    };
    tokio::time::sleep(Duration::from_millis(800)).await;

    // A wrong token declines nothing.
    let resp = fx
        .client
        .post(format!(
            "{}/public/secrets/provide/{request_id}/decline",
            fx.base
        ))
        .json(&json!({ "token": "nope" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let resp = fx
        .client
        .post(format!(
            "{}/public/secrets/provide/{request_id}/decline",
            fx.base
        ))
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let done = tokio::time::timeout(Duration::from_secs(20), pending)
        .await
        .expect("the Deny ends the wait now")
        .unwrap();
    let out = text_of(&done["result"]);
    assert_eq!(out["url_elicitation"], "declined", "{out}");
    assert_eq!(out["url_elicitation_error"], "declined_on_page", "{out}");
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

/// A form dialog answered after its state expired: the envelope, not an
/// error — and nothing is resolved on the strength of a stale state.
#[tokio::test]
async fn a_late_answer_to_a_form_dialog_gets_the_envelope() {
    let fx = setup().await;
    let first = fx.gated_call("too-late", claude_code_caps()).await;
    assert_eq!(first["resultType"], "input_required", "{first}");
    let approval_id = only_pending_approval(&fx).await;
    let late = expire(first["requestState"].as_str().unwrap());

    let (_, done) = modern(
        &fx,
        "tools/call",
        json!({
            "name": "overslash_call",
            "arguments": fx.call_args("too-late"),
            "inputResponses": { "decision": { "action": "accept", "content": { "decision": "allow" } } },
            "requestState": late,
        }),
        claude_code_caps(),
    )
    .await;
    assert!(done.get("error").is_none(), "{done}");
    assert_eq!(envelope_of(&done["result"])["status"], "pending_approval");
    assert_eq!(
        fx.approval_status(&approval_id).await,
        "pending",
        "an \"allow\" on a stale state must not resolve anything"
    );
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

/// The browser side ending in a "no" still closes the out-of-band
/// interaction: the client gets `notifications/elicitation/complete`, then
/// the denial.
#[tokio::test]
async fn legacy_dashboard_denial_completes_then_fails_the_call() {
    let fx = setup().await;
    legacy_url_client(&fx).await;
    let mut events = legacy_gated_call(&fx, "legacy-denied").await;
    let ask = events.next().await;
    let eid = ask["id"].as_str().unwrap().to_string();
    let approval_id = only_pending_approval(&fx).await;

    legacy_answer(&fx, &eid, "accept").await;
    resolve(&fx, &approval_id, "deny").await;

    let complete = events.next().await;
    assert_eq!(
        complete["method"], "notifications/elicitation/complete",
        "{complete}"
    );
    let result = events.next().await;
    assert_eq!(result["result"]["isError"], true, "{result}");
    assert_eq!(text_of(&result["result"])["resolution"], "denied");
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
