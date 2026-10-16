//! The `User-Agent` an upstream sees. Some upstreams — GitHub — refuse a
//! request without one, and reqwest sends none by default.
//!
//! - An inline call forwards the caller's own ahead of ours:
//!   `<caller> Overslash/<version>` (RFC 9110 §10.1.5 product tokens).
//! - No caller value, or a call replayed later (approval): `Overslash/<version>`.
//! - A `User-Agent` already on the request (Mode A header) is left as it is.
//!
//! See `extractors::CallerUserAgent` and `ssrf_guard::default_user_agent`.

use crate::common;

use reqwest::Client;
use serde_json::{Value, json};

const OURS: &str = "Overslash/";

struct Fixture {
    base: String,
    mock: std::net::SocketAddr,
    key: String,
    admin_key: String,
}

/// `gated`: the agent gets no permissions, so a write files an approval.
async fn setup(gated: bool) -> Fixture {
    let pool = common::test_pool().await;
    let mock = common::start_mock().await;
    let (api, client) = common::start_api(pool).await;
    let base = format!("http://{api}");
    let (_org_id, _ident_id, key, admin_key) = if gated {
        common::bootstrap_org_identity_no_seed(&base, &client).await
    } else {
        common::bootstrap_org_identity(&base, &client).await
    };
    Fixture {
        base,
        mock,
        key,
        admin_key,
    }
}

/// A Mode A `GET /echo`. `inbound_ua` is the header on the request *to us*;
/// `extra` is merged into the Mode A request body.
async fn call(fx: &Fixture, inbound_ua: Option<&str>, extra: Value) -> Value {
    let mut body = json!({
        "service": "http",
        "method": "GET",
        "url": format!("http://{}/echo", fx.mock),
    });
    if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
        b.extend(e.clone());
    }
    // A bare client sends no User-Agent of its own.
    let mut req = Client::new()
        .post(format!("{}/v1/actions/call", fx.base))
        .header(common::auth(&fx.key).0, common::auth(&fx.key).1)
        .json(&body);
    if let Some(ua) = inbound_ua {
        req = req.header("User-Agent", ua);
    }
    req.send().await.unwrap().json().await.unwrap()
}

async fn upstream_ua(fx: &Fixture) -> String {
    let sent = common::last_received(fx.mock).await;
    sent["headers"]["user-agent"]
        .as_str()
        .unwrap_or_else(|| panic!("upstream got no User-Agent: {sent}"))
        .to_string()
}

fn ours() -> String {
    format!("{OURS}{}", overslash_core::build_info::build_info().version)
}

#[tokio::test]
async fn inline_call_forwards_the_callers_user_agent_ahead_of_ours() {
    let fx = setup(false).await;
    let body = call(&fx, Some("agent-x/1.0 (+https://example.test)"), json!({})).await;
    assert_eq!(body["status"], "called", "{body}");
    assert_eq!(
        upstream_ua(&fx).await,
        format!("agent-x/1.0 (+https://example.test) {}", ours())
    );
}

#[tokio::test]
async fn inline_call_without_a_user_agent_sends_ours() {
    let fx = setup(false).await;
    let body = call(&fx, None, json!({})).await;
    assert_eq!(body["status"], "called", "{body}");
    assert_eq!(upstream_ua(&fx).await, ours());
}

#[tokio::test]
async fn caller_sending_ours_is_not_doubled() {
    // What an MCP client with no User-Agent looks like on the loopback.
    let fx = setup(false).await;
    let body = call(&fx, Some(&ours()), json!({})).await;
    assert_eq!(body["status"], "called", "{body}");
    assert_eq!(upstream_ua(&fx).await, ours());
}

#[tokio::test]
async fn explicit_mode_a_user_agent_is_left_alone() {
    let fx = setup(false).await;
    let body = call(
        &fx,
        Some("agent-x/1.0"),
        json!({"headers": {"user-agent": "explicit/2"}}),
    )
    .await;
    assert_eq!(body["status"], "called", "{body}");
    assert_eq!(upstream_ua(&fx).await, "explicit/2");
}

#[tokio::test]
async fn approval_replay_sends_ours() {
    // No permissions and a credentialed write: the call is gated, and the
    // bootstrap turns auto-call off, so it runs only on the explicit replay
    // below.
    let fx = setup(true).await;
    let resp = Client::new()
        .put(format!("{}/v1/secrets/ua_token", fx.base))
        .header(common::auth(&fx.key).0, common::auth(&fx.key).1)
        .json(&json!({"value": "tok"}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let body = call(
        &fx,
        Some("agent-x/1.0"),
        json!({
            "method": "POST",
            "body": "{}",
            "secrets": [{"name": "ua_token", "inject_as": "header", "header_name": "X-Token"}],
        }),
    )
    .await;
    let approval_id = body["approval_id"]
        .as_str()
        .unwrap_or_else(|| panic!("expected a pending approval: {body}"))
        .to_string();

    let resp = Client::new()
        .post(format!("{}/v1/approvals/{approval_id}/resolve", fx.base))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(&json!({"resolution": "allow"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());

    let resp = Client::new()
        .post(format!("{}/v1/approvals/{approval_id}/call", fx.base))
        .header(common::auth(&fx.key).0, common::auth(&fx.key).1)
        .header("User-Agent", "replayer/9")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    assert_eq!(upstream_ua(&fx).await, ours());
}

/// An MCP tool call reaches `/v1/actions/call` over a loopback; the MCP
/// client's User-Agent has to survive that hop, once, with ours after it.
#[tokio::test]
async fn mcp_tool_call_forwards_the_mcp_clients_user_agent() {
    let pool = common::test_pool().await;
    common::allow_loopback_ssrf();
    let mock = common::start_mock().await;
    let (api, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api}");
    let (org_id, ident_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    let admin =
        |r: reqwest::RequestBuilder| r.header("Authorization", format!("Bearer {admin_key}"));

    // A template rather than raw HTTP: MCP has no Mode A.
    let openapi = format!(
        "openapi: 3.1.0\n\
         info:\n  title: UA Echo\n  key: uaecho\n\
         servers:\n  - url: http://{mock}\n\
         paths:\n  /echo:\n    get:\n      operationId: echo\n      \
         summary: Echo the request\n      risk: read\n"
    );
    let resp = admin(client.post(format!("{base}/v1/templates")))
        .json(&json!({ "openapi": openapi, "user_level": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "template: {:?}", resp.text().await);
    admin(client.post(format!("{base}/v1/permissions")))
        .json(&json!({"identity_id": ident_id, "action_pattern": "uaecho:**", "effect": "allow"}))
        .send()
        .await
        .unwrap();

    // An org-level instance needs a group grant to be visible to the agent's
    // owner — the same wiring `response_too_large_hint.rs` does.
    let owner_id = common::owner_user_id(&pool, org_id).await;
    let groups: Value = admin(client.get(format!("{base}/v1/groups")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admins = groups
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["name"] == "Admins")
        .expect("Admins group")["id"]
        .as_str()
        .unwrap()
        .to_string();
    admin(client.post(format!("{base}/v1/groups/{admins}/members")))
        .json(&json!({ "identity_id": owner_id }))
        .send()
        .await
        .unwrap();
    let inst: Value = admin(client.post(format!("{base}/v1/services")))
        .json(&json!({"name": "uaecho", "template_key": "uaecho", "url": format!("http://{mock}")}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let inst_id = inst["id"]
        .as_str()
        .unwrap_or_else(|| panic!("instance create failed: {inst}"))
        .to_string();
    admin(client.post(format!("{base}/v1/groups/{admins}/grants")))
        .json(&json!({ "service_instance_id": inst_id, "access_level": "write" }))
        .send()
        .await
        .unwrap();

    let frame: Value = client
        .post(format!("{base}/mcp"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .header("User-Agent", "mcp-client/1")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "overslash_read",
                "arguments": {"service": "uaecho", "action": "echo", "params": {}},
            },
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(frame.get("error").is_none(), "{frame}");

    let sent = common::last_received(mock).await;
    assert_eq!(
        sent["headers"]["user-agent"],
        format!("mcp-client/1 {}", ours()),
        "{sent}"
    );
}
