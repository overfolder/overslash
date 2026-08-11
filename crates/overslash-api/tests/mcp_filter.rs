//! The response `filter` over MCP.
//!
//! `filter` is the one server-side lever that shrinks a response *before* it
//! enters an agent's context, and until D57 it was unreachable from the
//! surface that needs it most: both MCP tool schemas are
//! `additionalProperties: false` and neither declared it, so an agent could
//! not pass one, and `dispatch.rs` would not have forwarded it if it had.
//!
//! What this file pins:
//!   * both tools declare `filter`, or the schema rejects the argument
//!   * the existing 400s still reach the caller through the MCP frame
//!
//! The bare-string → `{lang, expr}` lift is unit-tested next to the code that
//! does it (`routes::mcp::dispatch`), and the filter's actual behaviour is
//! covered over REST in `response_filter.rs` — neither needs a live upstream,
//! which a DB-defined template pointed at the in-process mock cannot reach.
//!   * bad syntax and `filter` + `deliver: "url"` are not swallowed at the
//!     MCP layer

#![allow(clippy::disallowed_methods)]

use crate::common;

use serde_json::{Value, json};

async fn rpc(
    client: &reqwest::Client,
    base: &str,
    bearer: &str,
    method: &str,
    params: Value,
) -> Value {
    client
        .post(format!("{base}/mcp"))
        .header("Authorization", format!("Bearer {bearer}"))
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// Stand up a credential-free template pointing at the mock's `/echo`, an
/// instance of it, and an agent permitted to call it. Returns the agent key.
///
/// A template rather than raw HTTP because MCP has no Mode A: both call tools
/// require `service` + `action`, so `service: "http"` never gets past
/// `dispatch_read`. That constraint is the reason `filter` had to be declared
/// on the tool schemas at all — an MCP caller has no other way in.
async fn echo_service(
    base: &str,
    client: &reqwest::Client,
    mock_addr: std::net::SocketAddr,
) -> String {
    let (_org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(base, client).await;

    let resp = client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "openapi": format!("openapi: 3.1.0\n\
                info:\n  title: Echo\n  key: echosvc\n\
                servers:\n  - url: http://{mock_addr}\n\
                paths:\n  /echo:\n    get:\n      operationId: echo\n      summary: Echo\n      risk: read\n"),
            "user_level": false,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "template: {:?}", resp.text().await);

    let create = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "template_key": "echosvc",
            "name": "echosvc",
            "user_level": false,
            "groups": common::everyone_grant(base, client, &admin_key).await,
            "status": "active",
        }))
        .send()
        .await
        .unwrap();
    assert!(
        create.status().is_success(),
        "service create: {:?}",
        create.text().await
    );

    client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"identity_id": ident_id, "action_pattern": "echosvc:*:*"}))
        .send()
        .await
        .unwrap();

    api_key
}

/// Both call tools declare `filter`. This is not cosmetic: the schemas set
/// `additionalProperties: false`, so an undeclared property is a hard reject
/// — declaring it is exactly what makes it reachable.
#[tokio::test]
async fn both_call_tools_declare_filter() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool, None).await;
    let (_org_id, _ident_id, api_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let frame = rpc(&client, &base, &api_key, "tools/list", json!({})).await;
    let tools = frame["result"]["tools"].as_array().expect("tools");

    for name in ["overslash_call", "overslash_read"] {
        let tool = tools
            .iter()
            .find(|t| t["name"] == name)
            .unwrap_or_else(|| panic!("{name} missing from tools/list"));
        let filter = &tool["inputSchema"]["properties"]["filter"];
        assert_eq!(filter["type"], "string", "{name} must declare filter");
        let desc = filter["description"].as_str().unwrap_or("");
        // The description is the only thing standing between an agent and
        // the wrong mental model, and the wrong model here is expensive:
        // believing a filter shrinks what the *upstream* sends is what makes
        // an agent skip the action's own paging params.
        assert!(
            desc.contains("size cap"),
            "{name}'s filter description must say the cap fires first: {desc}"
        );
    }
}

/// A malformed filter still 400s. Forwarding is deliberately "only when
/// explicitly set" so a typo produces a real error, rather than vanishing at
/// the MCP layer and letting a caller believe it narrowed a response it then
/// receives whole.
#[tokio::test]
async fn a_malformed_filter_still_errors_through_mcp() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let (base, client) = common::start_api_with_registry(pool, None).await;
    let api_key = echo_service(&base, &client, mock_addr).await;

    let frame = rpc(
        &client,
        &base,
        &api_key,
        "tools/call",
        json!({
            "name": "overslash_read",
            "arguments": {
                "service": "echosvc",
                "action": "echo",
                "params": {},
                "filter": "{unclosed",
            }
        }),
    )
    .await;

    let rendered = frame.to_string();
    assert!(
        rendered.contains("filter"),
        "a bad filter must surface as an error naming it: {rendered}"
    );
    assert!(
        !rendered.contains("\"headers\""),
        "a bad filter must not fall through to an unfiltered success: {rendered}"
    );
}

/// `filter` + `deliver: "url"` stays a 400. With deferred delivery the bytes
/// never pass through the gateway at call time, so there is no body to
/// filter — silently honouring one and dropping the other would be worse
/// than refusing.
#[tokio::test]
async fn filter_with_deliver_url_still_rejects() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let (base, client) = common::start_api_with_registry(pool, None).await;
    let api_key = echo_service(&base, &client, mock_addr).await;

    let frame = rpc(
        &client,
        &base,
        &api_key,
        "tools/call",
        json!({
            "name": "overslash_read",
            "arguments": {
                "service": "echosvc",
                "action": "echo",
                "params": {},
                "filter": ".uri",
                "deliver": "url",
            }
        }),
    )
    .await;

    let rendered = frame.to_string();
    assert!(
        rendered.contains("filter") && rendered.contains("deliver"),
        "the refusal must name both flags: {rendered}"
    );
    assert!(
        !rendered.contains("download_url"),
        "a refused combination must not mint anything: {rendered}"
    );
}
