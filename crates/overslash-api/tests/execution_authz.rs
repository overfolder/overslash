//! Who may read an execution's result body.
//!
//! This file is the regression net for a real hole: before
//! `services::execution_access`, `GET /v1/approvals/{id}/execution` checked
//! only org scope, so any identity-bound credential in the org could read any
//! execution's upstream response — including whatever a token-minting endpoint
//! or a config read returned. Fixing that endpoint alone was not enough:
//! `GET /v1/approvals/{id}` and the list embed the same body.
//!
//! Run with `--test-threads=4` (or similar) — see CLAUDE.md.

#![allow(clippy::disallowed_methods)]

use crate::common;

use reqwest::Client;
use serde_json::{Value, json};
use uuid::Uuid;

struct Fixture {
    base: String,
    client: Client,
    /// The agent that made the call.
    requester_key: String,
    /// Same org, non-admin, Read level, no ancestry to the requester.
    stranger_key: String,
    admin_key: String,
    approval_id: String,
}

/// Create an approval, allow it, run it, and mint a same-org stranger.
async fn fixture(pool: sqlx::PgPool) -> Fixture {
    common::allow_loopback_ssrf();
    let mock = common::start_mock().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (org_id, ident_id, requester_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Cut the agent off from its parent's permissions, or nothing gates and
    // there is no execution to guard — `inherit_permissions` defaults on.
    client
        .patch(format!("{base}/v1/identities/{ident_id}"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"inherit_permissions": false}))
        .send()
        .await
        .unwrap();

    // Inject a secret so the call carries real risk. A bare GET is read-class
    // and D53 auto-approve would allow it outright, leaving no approval — and
    // therefore nothing for this file to be about.
    client
        .put(format!("{base}/v1/secrets/tk"))
        .header(
            common::auth(&requester_key).0,
            common::auth(&requester_key).1,
        )
        .json(&json!({"value": "v"}))
        .send()
        .await
        .unwrap();

    // Ungated call → approval.
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(
            common::auth(&requester_key).0,
            common::auth(&requester_key).1,
        )
        .json(&json!({
            "service": "http", "method": "GET", "url": format!("http://{mock}/echo"),
            "secrets": [{"name": "tk", "inject_as": "header", "header_name": "X-Auth"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202, "expected a gated call");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "pending_approval");
    let approval_id = body["approval_id"].as_str().unwrap().to_string();

    // Allow it, then run it as the requester.
    client
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"resolution": "allow"}))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/v1/approvals/{approval_id}/call"))
        .header(
            common::auth(&requester_key).0,
            common::auth(&requester_key).1,
        )
        .send()
        .await
        .unwrap();

    // A second, unrelated user identity in the same org, Read level only.
    let stranger: Value = client
        .post(format!("{base}/v1/identities"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"name": format!("stranger-{}", Uuid::new_v4()), "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let stranger_id = stranger["id"]
        .as_str()
        .unwrap_or_else(|| panic!("create stranger identity: {stranger}"));
    let key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({
            "org_id": org_id, "identity_id": stranger_id, "name": "stranger-key"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let stranger_key = key["key"]
        .as_str()
        .unwrap_or_else(|| panic!("mint stranger key: {key}"))
        .to_string();

    Fixture {
        base,
        client,
        requester_key,
        stranger_key,
        admin_key,
        approval_id,
    }
}

async fn get(f: &Fixture, path: &str, key: &str) -> (u16, Value) {
    let resp = f
        .client
        .get(format!("{}{path}", f.base))
        .header(common::auth(key).0, common::auth(key).1)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// The requester reads its own result; a same-org stranger does not.
#[tokio::test]
async fn a_same_org_stranger_cannot_read_the_result_body() {
    let pool = common::test_pool().await;
    let f = fixture(pool).await;
    let path = format!("/v1/approvals/{}/execution", f.approval_id);

    let (status, body) = get(&f, &path, &f.requester_key).await;
    assert_eq!(status, 200);
    assert!(body["result"].is_object() || body["result"].is_string());

    // 403 rather than 404: the caller can already see the approval itself, so
    // pretending the execution does not exist would be a lie.
    let (status, _) = get(&f, &path, &f.stranger_key).await;
    assert_eq!(
        status, 403,
        "a same-org identity outside the chain must not read the body"
    );

    let (status, body) = get(&f, &path, &f.admin_key).await;
    assert_eq!(status, 200, "org admins keep full visibility");
    assert!(!body["result"].is_null());
}

/// Fixing only `/execution` would leave the hole open one route over: the
/// approval detail and list both embed the same summary.
#[tokio::test]
async fn the_embedded_summary_is_redacted_on_the_detail_and_list() {
    let pool = common::test_pool().await;
    let f = fixture(pool).await;

    let (status, body) = get(
        &f,
        &format!("/v1/approvals/{}", f.approval_id),
        &f.stranger_key,
    )
    .await;
    assert_eq!(status, 200, "the approval itself stays visible");
    let exec = &body["execution"];
    assert!(!exec.is_null(), "the execution should still be listed");
    assert!(
        exec["result"].is_null(),
        "the body must be hidden from a stranger: {exec}"
    );
    assert_eq!(
        exec["result_redacted"], true,
        "redaction must be explicit so the UI can say 'hidden', not render empty"
    );

    // Same on the list path — a separate code path, and equally leaky before.
    let (status, body) = get(&f, "/v1/approvals?scope=assigned", &f.stranger_key).await;
    assert_eq!(status, 200);
    if let Some(rows) = body.as_array() {
        for row in rows {
            let exec = &row["execution"];
            if !exec.is_null() && exec["status"] == "executed" {
                assert!(
                    exec["result"].is_null(),
                    "list leaked a result body: {exec}"
                );
            }
        }
    }

    // The requester still sees its own, on both paths.
    let (_, body) = get(
        &f,
        &format!("/v1/approvals/{}", f.approval_id),
        &f.requester_key,
    )
    .await;
    assert!(!body["execution"]["result"].is_null());
    assert!(body["execution"]["result_redacted"].is_null());
}

/// The standalone resource applies the same rule, including for a row that was
/// never gated (`resolver_id` is `None` there, which must not widen access).
#[tokio::test]
async fn the_standalone_execution_endpoint_applies_the_same_rule() {
    let pool = common::test_pool().await;
    let f = fixture(pool).await;

    let (_, approval) = get(
        &f,
        &format!("/v1/approvals/{}", f.approval_id),
        &f.requester_key,
    )
    .await;
    let exec_id = approval["execution"]["id"].as_str().unwrap();

    let (status, _) = get(&f, &format!("/v1/executions/{exec_id}"), &f.stranger_key).await;
    assert_eq!(status, 403);

    let (status, body) = get(&f, &format!("/v1/executions/{exec_id}"), &f.requester_key).await;
    assert_eq!(status, 200);
    assert_eq!(body["origin"], "approval");
}
