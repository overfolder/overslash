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
