//! Google Tasks E2E tests — task list + task CRUD against a local mock server,
//! with a focus on the per-operation OAuth scope split:
//!
//!   * read actions  (list/get) require only  `…/auth/tasks.readonly`
//!   * write/delete  actions     require the full `…/auth/tasks`
//!
//! A connection granted only the read-only scope must therefore be able to
//! invoke every read action but be rejected (403 `missing_scopes`) on writes.
//! Scope gating is enforced by `check_required_scopes`
//! (crates/overslash-api/src/routes/actions/auth.rs).

// Test setup requires dynamic SQL for provider endpoint overrides and DB seeding.
#![allow(clippy::disallowed_methods)]

use crate::common;

use serde_json::{Value, json};

const TASKS_FULL: &str = "https://www.googleapis.com/auth/tasks";
const TASKS_READONLY: &str = "https://www.googleapis.com/auth/tasks.readonly";

/// Boot the API with `google_tasks` pointed at a mock upstream, bootstrap an
/// org/agent, grant the service + permissions, and seed one google connection
/// carrying exactly `scopes`. Returns `(base, client, key)` ready to call.
async fn setup_with_connection(scopes: &[&str]) -> (String, reqwest::Client, String) {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let mock_host = format!("http://{mock_addr}");

    // Point google provider's token_endpoint at the mock (matches gcal test).
    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'google'")
        .bind(format!("http://{mock_addr}/oauth/token"))
        .execute(&pool)
        .await
        .unwrap();

    let (base, client) =
        common::start_api_with_registry(pool.clone(), Some(("google_tasks", mock_host))).await;

    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    // Connections resolve at the owner identity (D22).
    let owner_id = common::owner_user_id(&pool, org_id).await;

    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "google_tasks:*:*"}))
        .send()
        .await
        .unwrap();

    // Mode C requires Layer-1 access to the service instance.
    common::grant_service_to_everyone(&base, &client, &admin_key, "google_tasks").await;

    // Seed an OAuth connection with the requested scopes.
    let enc_key = overslash_core::crypto::Keyring::test();
    let encrypted_token =
        overslash_core::crypto::encrypt(&enc_key, b"google-tasks-token-123").unwrap();
    let future_time = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let encrypted_cid = overslash_core::crypto::encrypt(&enc_key, b"mock_client_id").unwrap();
    let encrypted_csec = overslash_core::crypto::encrypt(&enc_key, b"mock_client_secret").unwrap();
    let byoc = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_byoc_credential(
            ident_id,
            "google",
            &encrypted_cid,
            &encrypted_csec,
            &serde_json::json!({}),
        )
        .await
        .unwrap();
    let scope_vec: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
    overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: owner_id,
            provider_key: "google",
            encrypted_access_token: &encrypted_token,
            encrypted_refresh_token: None,
            token_expires_at: Some(future_time),
            scopes: Some(&scope_vec),
            account_email: None,
            account_picture: None,
            byoc_credential_id: Some(byoc.id),
        })
        .await
        .unwrap();

    (base, client, key)
}

async fn call(
    client: &reqwest::Client,
    base: &str,
    key: &str,
    action: &str,
    params: Value,
) -> reqwest::Response {
    client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(key).0, common::auth(key).1)
        .json(&json!({ "service": "google_tasks", "action": action, "params": params }))
        .send()
        .await
        .unwrap()
}

// ============================================================================
// Read-only connection: reads succeed, writes are rejected with missing_scopes
// ============================================================================

#[tokio::test]
async fn test_google_tasks_readonly_scope_split() {
    let (base, client, key) = setup_with_connection(&[TASKS_READONLY]).await;

    // ===== list_tasklists (read, no path params) — readonly scope suffices =====
    let resp = call(&client, &base, &key, "list_tasklists", json!({})).await;
    assert_eq!(
        resp.status(),
        200,
        "list_tasklists should succeed with read-only scope"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert!(
        echo["uri"]
            .as_str()
            .unwrap()
            .contains("/tasks/v1/users/@me/lists"),
        "unexpected upstream uri: {}",
        echo["uri"]
    );
    assert_eq!(
        echo["headers"]["authorization"], "Bearer google-tasks-token-123",
        "OAuth token should be auto-resolved from the connection"
    );

    // ===== list_tasks (read, scope_param tasklist) — readonly scope suffices =====
    let resp = call(
        &client,
        &base,
        &key,
        "list_tasks",
        json!({"tasklist": "@default", "showCompleted": true}),
    )
    .await;
    assert_eq!(
        resp.status(),
        200,
        "list_tasks should succeed with read-only scope"
    );
    let body: Value = resp.json().await.unwrap();
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let uri = echo["uri"].as_str().unwrap();
    assert!(
        uri.contains("/tasks/v1/lists/@default/tasks"),
        "unexpected uri: {uri}"
    );
    assert!(
        uri.contains("showCompleted=true"),
        "query param should be appended: {uri}"
    );

    // ===== create_task (write) — read-only connection must be rejected =====
    let resp = call(
        &client,
        &base,
        &key,
        "create_task",
        json!({"tasklist": "@default", "title": "Buy milk"}),
    )
    .await;
    assert_eq!(
        resp.status(),
        403,
        "create_task must be rejected for a read-only connection"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "missing_scopes");
    let missing = body["missing"].as_array().unwrap();
    assert!(
        missing.iter().any(|s| s.as_str() == Some(TASKS_FULL)),
        "missing scopes should name the full tasks scope, got: {missing:?}"
    );

    // ===== delete_tasklist (delete) — read-only connection must be rejected =====
    let resp = call(
        &client,
        &base,
        &key,
        "delete_tasklist",
        json!({"tasklist": "@default"}),
    )
    .await;
    assert_eq!(
        resp.status(),
        403,
        "delete_tasklist must be rejected for a read-only connection"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "missing_scopes");
}

// ============================================================================
// Full-scope connection: writes and deletes reach the upstream
// ============================================================================

#[tokio::test]
async fn test_google_tasks_full_scope_writes() {
    let (base, client, key) = setup_with_connection(&[TASKS_FULL]).await;

    // ===== create_task (POST + body) — full scope unlocks writes =====
    let resp = call(
        &client,
        &base,
        &key,
        "create_task",
        json!({"tasklist": "@default", "title": "Buy milk", "notes": "2%", "status": "needsAction"}),
    )
    .await;
    assert_eq!(
        resp.status(),
        200,
        "create_task should succeed with full scope: {:?}",
        resp.status()
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert!(
        echo["uri"]
            .as_str()
            .unwrap()
            .contains("/tasks/v1/lists/@default/tasks"),
        "unexpected uri: {}",
        echo["uri"]
    );
    let req_body: Value = serde_json::from_str(echo["body"].as_str().unwrap()).unwrap();
    assert_eq!(req_body["title"], "Buy milk");
    assert_eq!(req_body["notes"], "2%");
    assert_eq!(req_body["status"], "needsAction");

    // ===== update_task (PATCH + body) =====
    let resp = call(
        &client,
        &base,
        &key,
        "update_task",
        json!({"tasklist": "@default", "task": "task123", "status": "completed"}),
    )
    .await;
    assert_eq!(
        resp.status(),
        200,
        "update_task should succeed with full scope"
    );
    let body: Value = resp.json().await.unwrap();
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert!(
        echo["uri"]
            .as_str()
            .unwrap()
            .contains("/tasks/v1/lists/@default/tasks/task123"),
        "unexpected uri: {}",
        echo["uri"]
    );

    // ===== delete_task (DELETE, no body) =====
    let resp = call(
        &client,
        &base,
        &key,
        "delete_task",
        json!({"tasklist": "@default", "task": "task123"}),
    )
    .await;
    assert_eq!(
        resp.status(),
        200,
        "delete_task should succeed with full scope"
    );
    let body: Value = resp.json().await.unwrap();
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert!(
        echo["uri"]
            .as_str()
            .unwrap()
            .contains("/tasks/v1/lists/@default/tasks/task123"),
        "unexpected uri: {}",
        echo["uri"]
    );
}
