//! `response_too_large` names only the recoveries the caller can actually
//! perform.
//!
//! The 5 MB buffering cap is a wall an agent hits without warning, so the hint
//! attached to it is the whole recovery path. It used to name two options —
//! `deliver: "url"` and `prefer_stream: true` — regardless of who was asking.
//! Over MCP the second is dead: it is absent from the `overslash_read` /
//! `overslash_call` input schemas, which are `additionalProperties: false`, and
//! `deferred::validate_flags` rejects it alongside `deliver: "url"` anyway. An
//! agent told to retry with it spends a round trip discovering it cannot.
//!
//! MCP tool calls arrive here as a loopback HTTP request indistinguishable from
//! a direct REST call, so `routes::mcp::forward` stamps `X-Overslash-Transport`
//! and `extractors::CallerTransport` reads it back. These tests drive the real
//! `POST /mcp` surface rather than setting the header by hand — the stamp is
//! half the mechanism, and a test that supplies it itself would pass with the
//! stamp deleted.

use crate::common;

use serde_json::{Value, json};

/// A template with one read action pointing at the fake's `/large-file`, an
/// instance, permissions, and the group ceiling the instance needs.
/// Returns `(base, agent_key, client)`. The API buffers at 1 KB, so any
/// `size` above that trips the cap.
async fn setup(pool: sqlx::PgPool) -> (String, String, reqwest::Client) {
    common::allow_loopback_ssrf();
    let mock_addr = common::start_mock().await;
    let (api_addr, client) = common::start_api_with_body_limit(pool.clone(), 1024).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let openapi = format!(
        "openapi: 3.1.0\n\
         info:\n  title: Big Response Svc\n  key: bigresp\n\
         servers:\n  - url: http://{mock_addr}\n\
         paths:\n  /large-file:\n    get:\n      operationId: get_large\n      \
         summary: Get a large file\n      risk: read\n      parameters:\n        \
         - name: size\n          in: query\n          required: true\n          \
         description: Bytes to return\n          schema:\n            type: integer\n"
    );
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "openapi": openapi, "user_level": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "template: {:?}", resp.text().await);

    client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "identity_id": ident_id,
            "action_pattern": "bigresp:**",
            "effect": "allow",
        }))
        .send()
        .await
        .unwrap();

    // The group ceiling gates services independently of permission rules, and
    // attaches to the owner user rather than the calling agent.
    let owner_id = common::owner_user_id(&pool, org_id).await;
    let groups: Value = client
        .get(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {admin_key}"))
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
    client
        .post(format!("{base}/v1/groups/{admins}/members"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "identity_id": owner_id }))
        .send()
        .await
        .unwrap();

    // The upstream is pinned per instance, the way every other template test
    // points at its mock — the template's `servers[0].url` is only the default.
    let inst: Value = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "name": "bigresp",
            "template_key": "bigresp",
            "url": format!("http://{mock_addr}"),
        }))
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
    client
        .post(format!("{base}/v1/groups/{admins}/grants"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "service_instance_id": inst_id, "access_level": "write" }))
        .send()
        .await
        .unwrap();

    (base, agent_key, client)
}

/// `tools/call` against our own `/mcp`, returning the raw JSON-RPC frame.
async fn mcp_call(
    base: &str,
    client: &reqwest::Client,
    bearer: &str,
    tool: &str,
    args: Value,
) -> Value {
    client
        .post(format!("{base}/mcp"))
        .header("Authorization", format!("Bearer {bearer}"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": tool, "arguments": args },
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn a_minted_download_supersedes_both_recoveries() {
    let pool = common::test_pool().await;
    let (base, agent_key, client) = setup(pool).await;

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": "bigresp",
            "action": "get_large",
            "params": { "size": 10240 },
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert_eq!(status, 502, "expected the buffering cap to trip: {text}");

    let body: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(body["error"], "response_too_large", "{text}");
    assert_eq!(body["limit_bytes"], 1024);

    // D57: this service can be minted from (no OAuth, no inline credential),
    // so the retry the hint used to *name* has already been performed. Both
    // flags drop out — telling a caller to retry with `deliver: "url"` when
    // its URL is already in the body is the wasted round trip this hint
    // exists to prevent, in the same way naming `prefer_stream` over MCP was.
    let url = body["download_url"]
        .as_str()
        .expect("a mintable service mints");
    let hint = body["hint"].as_str().expect("hint present");
    assert!(
        !hint.contains("prefer_stream") && !hint.contains("deliver"),
        "a minted URL supersedes both recoveries: {hint}"
    );
    assert!(hint.contains("download_url"), "{hint}");

    // And the URL has to work, or this trades one dead end for another.
    let fetched = client.get(url).send().await.unwrap();
    assert_eq!(fetched.status(), 200, "the minted URL must redeem");
    assert_eq!(fetched.bytes().await.unwrap().len(), 10240);
}

/// The REST/MCP wording split still applies whenever a mint is *not*
/// available. Both fallbacks are unit-tested in `error.rs`
/// (`response_too_large_names_only_reachable_recoveries`), because reaching
/// them end-to-end needs a service minting refuses — an OAuth-injected one,
/// whose whole setup is orthogonal to what the hint says. What this file
/// still owns is the half a unit test cannot fake: that
/// `X-Overslash-Transport` is really stamped and really read back.

#[tokio::test]
async fn mcp_caller_is_not_offered_prefer_stream() {
    let pool = common::test_pool().await;
    let (base, agent_key, client) = setup(pool).await;

    let frame = mcp_call(
        &base,
        &client,
        &agent_key,
        "overslash_read",
        json!({
            "service": "bigresp",
            "action": "get_large",
            "params": { "size": 10240 },
        }),
    )
    .await;

    // The oversized body is a non-success status, so `forward` relays the
    // upstream envelope verbatim rather than whitelisting it as a typed
    // error — the hint text rides through in the JSON-RPC error message.
    let rendered = serde_json::to_string(&frame).unwrap();
    assert!(
        rendered.contains("response_too_large"),
        "expected the cap to trip over MCP: {rendered}"
    );
    // Whatever else the envelope says, `prefer_stream` must never appear: it
    // is absent from the MCP tool schemas, which are
    // `additionalProperties: false`. This holds in all three hint states, so
    // it is the assertion that keeps pinning the transport stamp now that
    // this service mints and the wording moved on.
    assert!(
        !rendered.contains("prefer_stream"),
        "prefer_stream is not in the MCP tool schemas — naming it sends the \
         agent down a dead end: {rendered}"
    );
    // The recovery the MCP caller gets is the minted URL itself (D57), not an
    // instruction to go and ask for one.
    assert!(
        rendered.contains("download_url"),
        "an MCP caller should receive the minted URL, not a retry: {rendered}"
    );
}

/// The recovery the MCP hint names has to actually work, or the fix just
/// moves the wasted round trip somewhere else.
#[tokio::test]
async fn the_recovery_the_hint_names_succeeds_over_mcp() {
    let pool = common::test_pool().await;
    let (base, agent_key, client) = setup(pool).await;

    let frame = mcp_call(
        &base,
        &client,
        &agent_key,
        "overslash_read",
        json!({
            "service": "bigresp",
            "action": "get_large",
            "params": { "size": 10240 },
            "deliver": "url",
        }),
    )
    .await;

    let rendered = serde_json::to_string(&frame).unwrap();
    assert!(
        !rendered.contains("response_too_large"),
        "deliver: \"url\" must bypass the buffering cap: {rendered}"
    );
    assert!(
        rendered.contains("download_url"),
        "expected a descriptor carrying a download URL: {rendered}"
    );
}
