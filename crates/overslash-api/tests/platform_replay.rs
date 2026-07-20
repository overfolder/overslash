//! Approval replay for Runtime::Platform action calls.
//!
//! Mirrors `mcp_replay.rs` but exercises the Platform branch added in
//! `routes/approvals.rs`. Covers: happy-path replay on `ping`,
//! `allow_remember` rule materialization, audit stamping
//! (`replayed_from_approval` / `execution_id`), missing-handler failure
//! handling, and the legacy `action_detail` fallback that lets pre-feature
//! rows replay without a `replay_payload`.

#![allow(clippy::disallowed_methods)] // tests need raw SQL for fixture poking

use crate::common;

use crate::common::auth;
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;

async fn trigger_pending_approval(
    client: &reqwest::Client,
    base: &str,
    agent_key: &str,
    action: &str,
) -> String {
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(agent_key).0, auth(agent_key).1)
        .json(&json!({"service": "overslash", "action": action}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::ACCEPTED,
        "expected pending_approval: {:?}",
        resp.text().await
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "pending_approval");
    body["approval_id"].as_str().unwrap().to_string()
}

async fn resolve(
    client: &reqwest::Client,
    base: &str,
    admin_key: &str,
    approval_id: &str,
    body: Value,
) {
    let resp = client
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header(auth(admin_key).0, auth(admin_key).1)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "resolve: {:?}", resp.text().await);
}

async fn call_approval(
    client: &reqwest::Client,
    base: &str,
    agent_key: &str,
    approval_id: &str,
) -> reqwest::Response {
    client
        .post(format!("{base}/v1/approvals/{approval_id}/call"))
        .header(auth(agent_key).0, auth(agent_key).1)
        .send()
        .await
        .unwrap()
}

/// Happy path: agent calls `overslash:ping` without permission → 202
/// pending_approval → admin allows → agent replays via `/call` → execution
/// row finalises `executed` carrying the ping handler's JSON payload.
#[tokio::test]
async fn platform_approval_replay_succeeds() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool, None).await;
    let (_org_id, _agent_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let approval_id = trigger_pending_approval(&client, &base, &agent_key, "ping").await;
    resolve(
        &client,
        &base,
        &admin_key,
        &approval_id,
        json!({"resolution": "allow"}),
    )
    .await;

    let resp = call_approval(&client, &base, &agent_key, &approval_id).await;
    assert_eq!(resp.status(), 200, "/call: {:?}", resp.text().await);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["execution"]["status"], "executed");

    // ExecutionSummary's `runtime` field is derived from the stored result
    // envelope via `extract_runtime`. A platform replay must classify as
    // `"platform"` so the dashboard renders the right runtime pill and
    // suppresses `http_status_code` (which is meaningless here).
    assert_eq!(body["execution"]["runtime"], "platform");
    assert!(
        body["execution"]["http_status_code"].is_null(),
        "platform runtime must not surface http_status_code, got: {:?}",
        body["execution"]["http_status_code"]
    );

    let result_body = body["execution"]["result"]["body"]
        .as_str()
        .expect("execution.result.body string");
    let payload: Value = serde_json::from_str(result_body).unwrap();
    assert_eq!(payload["runtime"], "platform");
    assert_eq!(payload["ok"], true);
}

/// `allow_remember` resolution + successful replay materialises a permission
/// rule so the next call from the same agent bypasses approval.
#[tokio::test]
async fn platform_approval_allow_remember_creates_rule() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (_org_id, agent_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let approval_id = trigger_pending_approval(&client, &base, &agent_key, "ping").await;
    resolve(
        &client,
        &base,
        &admin_key,
        &approval_id,
        json!({"resolution": "allow_remember"}),
    )
    .await;

    let resp = call_approval(&client, &base, &agent_key, &approval_id).await;
    assert_eq!(resp.status(), 200, "/call: {:?}", resp.text().await);
    assert_eq!(
        resp.json::<Value>().await.unwrap()["execution"]["status"],
        "executed"
    );

    // `permission` field on the ping action is `ping`, so the rule pattern is
    // `overslash:ping:*` (scope_param collapses to `*`).
    let row = sqlx::query(
        "SELECT count(*) AS n FROM permission_rules
         WHERE identity_id = $1 AND action_pattern = 'overslash:ping:*' AND effect = 'allow'",
    )
    .bind(agent_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let n: i64 = row.get("n");
    assert_eq!(n, 1, "expected exactly one allow rule for overslash:ping:*");

    // Second direct call bypasses approval and returns 200 called.
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({"service": "overslash", "action": "ping"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "second call: {:?}", resp.text().await);
    assert_eq!(resp.json::<Value>().await.unwrap()["status"], "called");
}

/// The `action.executed` audit row written during replay carries
/// `replayed_from_approval` and `execution_id` in its detail blob, matching
/// the convention HTTP/MCP replays already follow.
#[tokio::test]
async fn platform_approval_replay_audit_stamped() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool, None).await;
    let (_org_id, _agent_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let approval_id = trigger_pending_approval(&client, &base, &agent_key, "ping").await;
    resolve(
        &client,
        &base,
        &admin_key,
        &approval_id,
        json!({"resolution": "allow"}),
    )
    .await;
    let resp = call_approval(&client, &base, &agent_key, &approval_id).await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let execution_id = body["execution"]["id"].as_str().unwrap().to_string();

    let audit: Value = client
        .get(format!("{base}/v1/audit"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let executed = audit
        .as_array()
        .unwrap()
        .iter()
        .find(|e| {
            e["action"] == "action.executed"
                && e["detail"]["replayed_from_approval"] == Value::String(approval_id.clone())
        })
        .expect("action.executed entry stamped with replayed_from_approval");
    assert_eq!(executed["detail"]["runtime"], "platform");
    assert_eq!(executed["detail"]["action"], "ping");
    assert_eq!(executed["detail"]["service"], "overslash");
    assert_eq!(executed["detail"]["execution_id"], execution_id);
}

/// If the stored replay payload references an action_key that is no longer
/// registered in the platform registry (e.g. a handler was removed between
/// approval-creation and replay), the execution finalises as `failed` with a
/// meaningful error rather than panicking or 5xx-ing.
#[tokio::test]
async fn platform_approval_replay_handler_missing_marks_failed() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (_org_id, _agent_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let approval_id = trigger_pending_approval(&client, &base, &agent_key, "ping").await;
    resolve(
        &client,
        &base,
        &admin_key,
        &approval_id,
        json!({"resolution": "allow"}),
    )
    .await;

    // Corrupt the stored replay_payload.action to a non-existent handler key.
    let approval_uuid: Uuid = approval_id.parse().unwrap();
    sqlx::query(
        "UPDATE approvals
            SET replay_payload = jsonb_set(replay_payload, '{action}', '\"no_such_handler\"')
          WHERE id = $1",
    )
    .bind(approval_uuid)
    .execute(&pool)
    .await
    .unwrap();

    let resp = call_approval(&client, &base, &agent_key, &approval_id).await;
    // `/call` returns 200 with the failed execution row inline — same shape
    // as the HTTP/MCP replay-failure paths.
    assert_eq!(resp.status(), 200, "/call: {:?}", resp.text().await);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["execution"]["status"], "failed");
    let err = body["execution"]["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("no_such_handler") || err.contains("not registered"),
        "error should reference the missing handler, got: {err}"
    );
}

/// Legacy platform approvals were created with `replay_payload = NULL`; their
/// `action_detail` projection (`{ runtime: "platform", action, params,
/// service }`) is structurally a valid `StoredPlatformCall`, so the fallback
/// path replays them cleanly. Simulated by nulling replay_payload after
/// approval creation.
#[tokio::test]
async fn platform_legacy_action_detail_fallback_replays() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (_org_id, _agent_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let approval_id = trigger_pending_approval(&client, &base, &agent_key, "ping").await;
    resolve(
        &client,
        &base,
        &admin_key,
        &approval_id,
        json!({"resolution": "allow"}),
    )
    .await;

    sqlx::query("UPDATE approvals SET replay_payload = NULL WHERE id = $1")
        .bind(approval_id.parse::<Uuid>().unwrap())
        .execute(&pool)
        .await
        .unwrap();

    let resp = call_approval(&client, &base, &agent_key, &approval_id).await;
    assert_eq!(resp.status(), 200, "/call: {:?}", resp.text().await);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["execution"]["status"], "executed");

    let result_body = body["execution"]["result"]["body"]
        .as_str()
        .expect("execution.result.body string");
    let payload: Value = serde_json::from_str(result_body).unwrap();
    assert_eq!(payload["runtime"], "platform");
}
