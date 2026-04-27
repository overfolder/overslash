/// Integration tests for Runtime::Platform dispatch.
///
/// `start_api_with_registry` loads the real `services/` directory so
/// `overslash.yaml` (with `x-overslash-runtime: platform`) is present and the
/// platform actions are live.
mod common;

use serde_json::{Value, json};

// ── helpers ───────────────────────────────────────────────────────────────────

async fn call(
    client: &reqwest::Client,
    base: &str,
    api_key: &str,
    body: Value,
) -> reqwest::Response {
    client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&body)
        .send()
        .await
        .unwrap()
}

async fn grant(
    client: &reqwest::Client,
    base: &str,
    admin_key: &str,
    identity_id: uuid::Uuid,
    pattern: &str,
) {
    let resp = client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "identity_id": identity_id,
            "action_pattern": pattern,
            "effect": "allow",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "grant failed");
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// An unpermitted agent calling a platform action gets a 202 pending_approval.
/// Verifies the permission-chain walk runs before platform dispatch.
#[tokio::test]
async fn ping_no_permission_triggers_approval() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool, None).await;
    let (_org_id, _agent_id, agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let resp = call(
        &client,
        &base,
        &agent_key,
        json!({"service": "overslash", "action": "ping"}),
    )
    .await;

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::ACCEPTED,
        "unpermitted agent must get 202 approval bubble"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "pending_approval");
    assert!(body["approval_id"].is_string());
}

/// An agent with `overslash:ping:*` calls ping and gets the ok payload back.
#[tokio::test]
async fn ping_with_permission_returns_ok() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool, None).await;
    let (_org_id, agent_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    grant(&client, &base, &admin_key, agent_id, "overslash:ping:*").await;

    let resp = call(
        &client,
        &base,
        &agent_key,
        json!({"service": "overslash", "action": "ping"}),
    )
    .await;

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");

    let result_body: Value =
        serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(result_body["runtime"], "platform");
    assert_eq!(result_body["ok"], true);
}

/// An agent with `overslash:manage_templates:*` can list_templates and gets a JSON array.
#[tokio::test]
async fn list_templates_with_permission_returns_array() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool, None).await;
    let (_org_id, agent_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    grant(
        &client,
        &base,
        &admin_key,
        agent_id,
        "overslash:manage_templates:*",
    )
    .await;

    let resp = call(
        &client,
        &base,
        &agent_key,
        json!({"service": "overslash", "action": "list_templates"}),
    )
    .await;

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");

    let result_body: Value =
        serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert!(
        result_body.is_array(),
        "result body should be an array, got: {result_body}"
    );
    assert!(
        !result_body.as_array().unwrap().is_empty(),
        "global services should appear in list"
    );
}

/// The approval permission_keys use the `permission` anchor
/// (`overslash:manage_templates:*`) not the raw action key (`list_templates`).
#[tokio::test]
async fn permission_key_uses_anchor_not_action_key() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool, None).await;
    let (_org_id, _agent_id, agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // No grant — we want the approval bubble.
    let resp = call(
        &client,
        &base,
        &agent_key,
        json!({"service": "overslash", "action": "list_templates"}),
    )
    .await;

    assert_eq!(resp.status(), reqwest::StatusCode::ACCEPTED);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "pending_approval");

    let approval_id = body["approval_id"].as_str().unwrap();
    let approval_resp = client
        .get(format!("{base}/v1/approvals/{approval_id}"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(approval_resp.status(), reqwest::StatusCode::OK);
    let approval: Value = approval_resp.json().await.unwrap();

    let keys = approval["permission_keys"]
        .as_array()
        .expect("permission_keys must be an array");
    assert!(
        keys.iter()
            .any(|k| k.as_str() == Some("overslash:manage_templates:*")),
        "approval must include overslash:manage_templates:*, got: {keys:?}"
    );
    assert!(
        !keys
            .iter()
            .any(|k| k.as_str() == Some("overslash:list_templates:*")),
        "raw action key must not be in permission_keys, got: {keys:?}"
    );
}
