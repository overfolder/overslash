//! Verifies the `require_risk` gate on POST /v1/actions/call.
//!
//! `require_risk` is the enforcement layer behind the MCP `overslash_read`
//! tool's `readOnlyHint: true`. The gate must reject mutating requests
//! before any permission walk or upstream call so a misbehaving (or
//! malicious) caller can't laundering writes through a tool clients are
//! told is read-only.

#![allow(clippy::disallowed_methods)]

mod common;

use serde_json::json;

#[tokio::test]
async fn require_risk_read_rejects_post_method_in_raw_http_mode() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool).await;
    let base = format!("http://{api_addr}");
    let (_org_id, _ident_id, agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Mode-A POST → Risk::Write inferred from the HTTP method. The
    // require_risk=read gate must reject with 400 before any permission
    // walk or upstream request happens.
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "method": "POST",
            "url": "http://127.0.0.1:1/never-reached",
            "require_risk": "read",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("risk=write"),
        "error body should mention the resolved risk: {body}"
    );
    assert!(
        body.contains("overslash_call"),
        "error should point the caller at overslash_call: {body}"
    );
}

#[tokio::test]
async fn require_risk_read_rejects_delete_method_in_raw_http_mode() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool).await;
    let base = format!("http://{api_addr}");
    let (_org_id, _ident_id, agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "method": "DELETE",
            "url": "http://127.0.0.1:1/never-reached",
            "require_risk": "read",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("risk=delete"),
        "error body should mention risk=delete: {body}"
    );
}

/// Regression for the "params: null → 422" bug surfaced by the PR review.
///
/// `CallRequest.params: HashMap<String, _>` with `#[serde(default)]` fills an
/// empty map only when the key is *absent* — an explicit `null` is rejected
/// with `invalid type: null, expected a map`. The MCP `dispatch_read` /
/// `dispatch_call` therefore must not forward `"params": null`; they omit
/// the key entirely when the caller didn't supply a map. This test guards
/// the receiving end so a future contributor doesn't reintroduce a
/// `"params": null` forward and break parameterless tool calls.
#[tokio::test]
async fn actions_call_rejects_explicit_null_params() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let (api_addr, client) = common::start_api(pool).await;
    let base = format!("http://{api_addr}");
    let (_org_id, _ident_id, agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "method": "GET",
            "url": format!("http://{mock_addr}/echo"),
            "params": null,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        422,
        "explicit `params: null` is the failure mode dispatch_read/_call avoid by omitting the key"
    );

    // Counter-test: omitting `params` entirely succeeds. Together these two
    // assertions pin down the contract: keys must be absent, not null.
    let resp_ok = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "method": "GET",
            "url": format!("http://{mock_addr}/echo"),
        }))
        .send()
        .await
        .unwrap();
    let status = resp_ok.status();
    let body = resp_ok.text().await.unwrap();
    assert!(
        status.is_success() || status.as_u16() == 202,
        "absent params must be accepted; status={status} body={body}"
    );
}

#[tokio::test]
async fn require_risk_read_does_not_block_get_method() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let (api_addr, client) = common::start_api(pool).await;
    let base = format!("http://{api_addr}");
    let (_org_id, _ident_id, agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Mode-A GET → Risk::Read inferred. The require_risk gate must let it
    // through. (What happens next — auth, permission walk, upstream — is
    // outside this test's scope; the invariant is "no risk-class 400".)
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "method": "GET",
            "url": format!("http://{mock_addr}/echo"),
            "require_risk": "read",
        }))
        .send()
        .await
        .unwrap();

    let status = resp.status();
    let body = resp.text().await.unwrap();
    assert!(
        !body.contains("only permits risk=read"),
        "GET must not trip the require_risk=read gate; status={status} body={body}"
    );
}
