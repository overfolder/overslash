//! Integration tests: full API flows against real Postgres + in-process mock target.

use std::net::SocketAddr;

use reqwest::Client;
use serde_json::{Value, json};
use sqlx::PgPool;
use tokio::net::TcpListener;
use uuid::Uuid;

/// Start the Overslash API server in-process on a random port.
async fn start_api(pool: PgPool) -> (SocketAddr, Client) {
    let config = overslash_api::config::Config {
        host: "127.0.0.1".into(),
        port: 0,
        database_url: String::new(), // unused, we pass pool directly
        secrets_encryption_key: "ab".repeat(32),
        approval_expiry_secs: 1800,
    };

    // Build the app with the test pool directly
    let state = overslash_api::AppState {
        db: pool,
        config,
        http_client: reqwest::Client::new(),
    };

    let app = axum::Router::new()
        .merge(overslash_api::routes::health::router())
        .merge(overslash_api::routes::orgs::router())
        .merge(overslash_api::routes::identities::router())
        .merge(overslash_api::routes::api_keys::router())
        .merge(overslash_api::routes::secrets::router())
        .merge(overslash_api::routes::permissions::router())
        .merge(overslash_api::routes::actions::router())
        .merge(overslash_api::routes::approvals::router())
        .merge(overslash_api::routes::audit::router())
        .merge(overslash_api::routes::webhooks::router())
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, Client::new())
}

/// Start the mock target in-process on a random port.
async fn start_mock() -> SocketAddr {
    use axum::{
        Json, Router,
        body::Bytes,
        extract::State,
        http::HeaderMap,
        routing::{get, post},
    };
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[derive(Default)]
    struct MockState {
        webhooks: Vec<Value>,
    }

    type S = Arc<Mutex<MockState>>;

    async fn echo(headers: HeaderMap, body: Bytes) -> Json<Value> {
        let h: serde_json::Map<String, Value> = headers
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), json!(v.to_str().unwrap_or(""))))
            .collect();
        Json(json!({ "headers": h, "body": String::from_utf8_lossy(&body).to_string() }))
    }

    async fn receive_webhook(State(s): State<S>, Json(p): Json<Value>) -> &'static str {
        s.lock().await.webhooks.push(p);
        "ok"
    }

    async fn list_webhooks(State(s): State<S>) -> Json<Value> {
        Json(json!({ "webhooks": s.lock().await.webhooks.clone() }))
    }

    let state: S = Arc::new(Mutex::new(MockState::default()));
    let app = Router::new()
        .route("/echo", post(echo))
        .route("/webhooks/receive", post(receive_webhook))
        .route("/webhooks/received", get(list_webhooks))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// Helper: create org + identity + api key, return (api_base_url, api_key, org_id, identity_id)
async fn setup(pool: PgPool) -> (String, String, Uuid, Uuid) {
    let (api_addr, client) = start_api(pool).await;
    let base = format!("http://{api_addr}");

    // Create org
    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "TestOrg", "slug": format!("test-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();

    // Create API key (org-level bootstrap)
    let key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "bootstrap"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let raw_key = key["key"].as_str().unwrap().to_string();

    // Create identity
    let ident: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {raw_key}"))
        .json(&json!({"name": "test-agent", "kind": "agent"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ident_id: Uuid = ident["id"].as_str().unwrap().parse().unwrap();

    // Create identity-bound API key
    let agent_key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "identity_id": ident_id, "name": "agent"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_raw = agent_key["key"].as_str().unwrap().to_string();

    (base, agent_raw, org_id, ident_id)
}

fn auth(key: &str) -> (&'static str, String) {
    ("Authorization", format!("Bearer {key}"))
}

// ============================================================================
// Tests
// ============================================================================

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_health(pool: PgPool) {
    let (api_addr, client) = start_api(pool).await;
    let resp: Value = client
        .get(format!("http://{api_addr}/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "ok");
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_happy_path_execute_with_permission(pool: PgPool) {
    let mock_addr = start_mock().await;
    let (base, key, _org_id, ident_id) = setup(pool).await;
    let client = Client::new();

    // Store secret
    let resp = client
        .put(format!("{base}/v1/secrets/my_token"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"value": "secret-value-123"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Create permission rule
    let resp = client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "identity_id": ident_id,
            "action_pattern": "http:**",
            "effect": "allow"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Execute action — should auto-approve
    let resp = client.post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "method": "POST",
            "url": format!("http://{mock_addr}/echo"),
            "headers": {"Content-Type": "application/json"},
            "body": "{\"test\":true}",
            "secrets": [{"name": "my_token", "inject_as": "header", "header_name": "X-Token", "prefix": "tok_"}]
        }))
        .send().await.unwrap();
    assert_eq!(resp.status(), 200);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");

    // Verify secret injection in echo response
    let echo_body: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(echo_body["headers"]["x-token"], "tok_secret-value-123");
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_approval_flow(pool: PgPool) {
    let mock_addr = start_mock().await;
    let (base, key, _org_id, _ident_id) = setup(pool).await;
    let client = Client::new();

    // Store secret
    client
        .put(format!("{base}/v1/secrets/tk"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"value": "v"}))
        .send()
        .await
        .unwrap();

    // Execute without permission — should get 202
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "method": "GET",
            "url": format!("http://{mock_addr}/echo"),
            "secrets": [{"name": "tk", "inject_as": "header", "header_name": "X-Auth"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "pending_approval");
    let approval_id = body["approval_id"].as_str().unwrap();

    // Resolve with allow
    let resp = client
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"decision": "allow"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resolved: Value = resp.json().await.unwrap();
    assert_eq!(resolved["status"], "allowed");
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_allow_remember_creates_rule(pool: PgPool) {
    let mock_addr = start_mock().await;
    let (base, key, _org_id, _ident_id) = setup(pool).await;
    let client = Client::new();

    client
        .put(format!("{base}/v1/secrets/tk"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"value": "v"}))
        .send()
        .await
        .unwrap();

    // First execute — needs approval
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "method": "POST",
            "url": format!("http://{mock_addr}/echo"),
            "secrets": [{"name": "tk", "inject_as": "header", "header_name": "X-Auth"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    let approval_id = resp.json::<Value>().await.unwrap()["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Resolve with allow_remember
    client
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"decision": "allow_remember"}))
        .send()
        .await
        .unwrap();

    // Second execute — should auto-approve (rule was created)
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "method": "POST",
            "url": format!("http://{mock_addr}/echo"),
            "secrets": [{"name": "tk", "inject_as": "header", "header_name": "X-Auth"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.json::<Value>().await.unwrap()["status"], "executed");
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_secret_versioning(pool: PgPool) {
    let (base, key, _org_id, _ident_id) = setup(pool).await;
    let client = Client::new();

    // v1
    let r = client
        .put(format!("{base}/v1/secrets/s1"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"value": "version-1"}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(r["version"], 1);

    // v2
    let r = client
        .put(format!("{base}/v1/secrets/s1"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"value": "version-2"}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(r["version"], 2);

    // Get metadata
    let r = client
        .get(format!("{base}/v1/secrets/s1"))
        .header(auth(&key).0, auth(&key).1)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(r["current_version"], 2);
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_deny_keeps_gating(pool: PgPool) {
    let mock_addr = start_mock().await;
    let (base, key, _org_id, _ident_id) = setup(pool).await;
    let client = Client::new();

    client
        .put(format!("{base}/v1/secrets/tk"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"value": "v"}))
        .send()
        .await
        .unwrap();

    // First — needs approval
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "method": "GET",
            "url": format!("http://{mock_addr}/echo"),
            "secrets": [{"name": "tk", "inject_as": "header", "header_name": "X-Auth"}]
        }))
        .send()
        .await
        .unwrap();
    let approval_id = resp.json::<Value>().await.unwrap()["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Deny
    client
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"decision": "deny"}))
        .send()
        .await
        .unwrap();

    // Second — still needs approval (deny doesn't create allow rule)
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "method": "GET",
            "url": format!("http://{mock_addr}/echo"),
            "secrets": [{"name": "tk", "inject_as": "header", "header_name": "X-Auth"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_unauthenticated_request_no_gate(pool: PgPool) {
    let mock_addr = start_mock().await;
    let (base, key, _org_id, _ident_id) = setup(pool).await;
    let client = Client::new();

    // Execute without secrets — should go through without permission check
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "method": "POST",
            "url": format!("http://{mock_addr}/echo"),
            "headers": {"Content-Type": "application/json"},
            "body": "hello"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.json::<Value>().await.unwrap()["status"], "executed");
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_trail(pool: PgPool) {
    let mock_addr = start_mock().await;
    let (base, key, _org_id, ident_id) = setup(pool).await;
    let client = Client::new();

    // Create permission + execute an action
    client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "http:**"}))
        .send()
        .await
        .unwrap();

    client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "method": "GET",
            "url": format!("http://{mock_addr}/echo")
        }))
        .send()
        .await
        .unwrap();

    // Query audit
    let resp = client
        .get(format!("{base}/v1/audit"))
        .header(auth(&key).0, auth(&key).1)
        .send()
        .await
        .unwrap();
    let entries: Vec<Value> = resp.json().await.unwrap();
    assert!(!entries.is_empty());
    assert!(entries.iter().any(|e| e["action"] == "action.executed"));
}
