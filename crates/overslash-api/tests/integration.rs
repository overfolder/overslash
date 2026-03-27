//! Integration tests: full API flows against real Postgres + in-process mock target.

use std::net::SocketAddr;

use std::sync::Arc;

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
        services_dir: "services".into(),
    };

    // Build the app with the test pool directly
    let state = overslash_api::AppState {
        db: pool,
        config,
        http_client: reqwest::Client::new(),
        registry: Arc::new(overslash_core::registry::ServiceRegistry::default()),
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
        .merge(overslash_api::routes::services::router())
        .merge(overslash_api::routes::connections::router())
        .merge(overslash_api::routes::byoc_credentials::router())
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, Client::new())
}

/// Start the mock target in-process on a random port.
/// Includes: echo, webhook receiver, and mock OAuth token endpoint.
async fn start_mock() -> SocketAddr {
    use axum::{
        Form, Json, Router,
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
        webhook_headers: Vec<Value>,
    }

    type S = Arc<Mutex<MockState>>;

    async fn echo(headers: HeaderMap, body: Bytes) -> Json<Value> {
        let h: serde_json::Map<String, Value> = headers
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), json!(v.to_str().unwrap_or(""))))
            .collect();
        Json(json!({ "headers": h, "body": String::from_utf8_lossy(&body).to_string() }))
    }

    async fn receive_webhook(
        State(s): State<S>,
        headers: HeaderMap,
        Json(p): Json<Value>,
    ) -> &'static str {
        let h: serde_json::Map<String, Value> = headers
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), json!(v.to_str().unwrap_or(""))))
            .collect();
        let mut state = s.lock().await;
        state.webhooks.push(p);
        state.webhook_headers.push(json!(h));
        "ok"
    }

    async fn list_webhooks(State(s): State<S>) -> Json<Value> {
        let state = s.lock().await;
        Json(json!({
            "webhooks": state.webhooks.clone(),
            "headers": state.webhook_headers.clone(),
        }))
    }

    // Mock OAuth token endpoint — returns fake tokens for any code/refresh_token
    async fn oauth_token(Form(params): Form<Vec<(String, String)>>) -> Json<Value> {
        let grant_type = params
            .iter()
            .find(|(k, _)| k == "grant_type")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");

        match grant_type {
            "authorization_code" => {
                let code = params
                    .iter()
                    .find(|(k, _)| k == "code")
                    .map(|(_, v)| v.as_str())
                    .unwrap_or("unknown");
                Json(json!({
                    "access_token": format!("mock_access_{code}"),
                    "refresh_token": format!("mock_refresh_{code}"),
                    "expires_in": 3600,
                    "token_type": "Bearer",
                }))
            }
            "refresh_token" => Json(json!({
                "access_token": "mock_refreshed_access_token",
                "refresh_token": "mock_refreshed_refresh_token",
                "expires_in": 3600,
                "token_type": "Bearer",
            })),
            _ => Json(json!({"error": "unsupported_grant_type"})),
        }
    }

    let state: S = Arc::new(Mutex::new(MockState::default()));
    let app = Router::new()
        .route("/echo", post(echo))
        .route("/webhooks/receive", post(receive_webhook))
        .route("/webhooks/received", get(list_webhooks))
        .route("/oauth/token", post(oauth_token))
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

/// Start the Overslash API with real service registry loaded from services/ dir,
/// bootstrap org + identity + identity-bound API key.
/// Returns (base_url, api_key, org_id, identity_id).
async fn setup_with_registry(pool: PgPool) -> (String, String, Uuid, Uuid) {
    let config = overslash_api::config::Config {
        host: "127.0.0.1".into(),
        port: 0,
        database_url: String::new(),
        secrets_encryption_key: "ab".repeat(32),
        approval_expiry_secs: 1800,
        services_dir: "services".into(),
    };

    let ws_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let registry =
        overslash_core::registry::ServiceRegistry::load_from_dir(&ws_root.join("services"))
            .expect("failed to load service registry");

    let state = overslash_api::AppState {
        db: pool,
        config,
        http_client: reqwest::Client::new(),
        registry: Arc::new(registry),
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
        .merge(overslash_api::routes::services::router())
        .merge(overslash_api::routes::connections::router())
        .merge(overslash_api::routes::byoc_credentials::router())
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let client = Client::new();
    let base = format!("http://{addr}");

    // Create org
    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "E2eOrg", "slug": format!("e2e-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();

    // Create org-level API key
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
        .json(&json!({"name": "e2e-agent", "kind": "agent"}))
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

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_mode_c_service_action(pool: PgPool) {
    // This test uses a mock that happens to match a custom "service" definition.
    // We test Mode C by pointing the service host at our mock target.
    let mock_addr = start_mock().await;
    let (base, key, _org_id, ident_id) = setup(pool).await;
    let client = Client::new();

    // Store a secret matching the service's default_secret_name
    client
        .put(format!("{base}/v1/secrets/github_token"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"value": "ghp_test123"}))
        .send()
        .await
        .unwrap();

    // Create a broad permission rule
    client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "http:**"}))
        .send()
        .await
        .unwrap();

    // Mode A works as before (raw HTTP pointing at mock)
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "method": "POST",
            "url": format!("http://{mock_addr}/echo"),
            "body": "{\"test\": true}"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.json::<Value>().await.unwrap()["status"], "executed");
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_service_registry_api(pool: PgPool) {
    // Start API with real service registry loaded
    let config = overslash_api::config::Config {
        host: "127.0.0.1".into(),
        port: 0,
        database_url: String::new(),
        secrets_encryption_key: "ab".repeat(32),
        approval_expiry_secs: 1800,
        services_dir: "services".into(),
    };

    // services/ is at workspace root; tests run from crate dir
    let ws_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let registry =
        overslash_core::registry::ServiceRegistry::load_from_dir(&ws_root.join("services"))
            .unwrap_or_default();

    let state = overslash_api::AppState {
        db: pool,
        config,
        http_client: reqwest::Client::new(),
        registry: Arc::new(registry),
    };

    let app = axum::Router::new()
        .merge(overslash_api::routes::health::router())
        .merge(overslash_api::routes::orgs::router())
        .merge(overslash_api::routes::api_keys::router())
        .merge(overslash_api::routes::identities::router())
        .merge(overslash_api::routes::services::router())
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let client = Client::new();
    let base = format!("http://{addr}");

    // Bootstrap: create org + key
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
    let key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "test"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let api_key = key_resp["key"].as_str().unwrap();

    // List services — should have at least github, stripe, slack
    let resp: Vec<Value> = client
        .get(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let keys: Vec<&str> = resp.iter().filter_map(|s| s["key"].as_str()).collect();
    assert!(keys.contains(&"github"), "expected github in services");
    assert!(keys.contains(&"stripe"), "expected stripe in services");

    // Search
    let resp: Vec<Value> = client
        .get(format!("{base}/v1/services/search?q=pull+request"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        !resp.is_empty(),
        "search for 'pull request' should match github"
    );

    // Get service detail
    let resp: Value = client
        .get(format!("{base}/v1/services/github"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["key"], "github");
    assert!(resp["actions"]["create_pull_request"].is_object());

    // List actions
    let actions: Vec<Value> = client
        .get(format!("{base}/v1/services/github/actions"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(actions.iter().any(|a| a["key"] == "create_pull_request"));
}

// ============================================================================
// Webhook Tests
// ============================================================================

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_webhook_dispatch_on_approval_resolve(pool: PgPool) {
    let mock_addr = start_mock().await;
    let (base, key, _org_id, _ident_id) = setup(pool).await;
    let client = Client::new();

    // Create webhook subscription for approval.resolved events
    let _wh: Value = client
        .post(format!("{base}/v1/webhooks"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "url": format!("http://{mock_addr}/webhooks/receive"),
            "events": ["approval.resolved"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Store secret + trigger approval
    client
        .put(format!("{base}/v1/secrets/tk"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"value": "v"}))
        .send()
        .await
        .unwrap();

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
    let approval_id = resp.json::<Value>().await.unwrap()["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Resolve approval — should trigger webhook
    client
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"decision": "allow"}))
        .send()
        .await
        .unwrap();

    // Give webhook dispatch a moment (it's fire-and-forget via tokio::spawn)
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Check mock received the webhook
    let received: Value = client
        .get(format!("http://{mock_addr}/webhooks/received"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let webhooks = received["webhooks"].as_array().unwrap();
    assert!(
        !webhooks.is_empty(),
        "expected at least one webhook delivery"
    );
    assert_eq!(webhooks[0]["status"], "allowed");
    assert!(webhooks[0]["approval_id"].is_string());

    // Verify HMAC signature was sent
    let headers = received["headers"].as_array().unwrap();
    let sig_header = headers[0]["x-overslash-signature"].as_str().unwrap();
    assert!(
        sig_header.starts_with("sha256="),
        "signature should start with sha256="
    );
}

// ============================================================================
// OAuth Tests
// ============================================================================

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_oauth_callback_exchanges_code_and_stores_connection(pool: PgPool) {
    let mock_addr = start_mock().await;

    // Set env vars for OAuth client credentials (the callback route reads these)
    // SAFETY: test-only, single-threaded at this point before server starts
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_GITHUB_CLIENT_ID", "test_client_id");
        std::env::set_var("OAUTH_GITHUB_CLIENT_SECRET", "test_client_secret");
    }

    // Point the "github" provider's token_endpoint at our mock.
    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'github'")
        .bind(format!("http://{mock_addr}/oauth/token"))
        .execute(&pool)
        .await
        .unwrap();

    let (api_addr, client) = start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");

    // Bootstrap org + identity
    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "OAuthOrg", "slug": format!("oauth-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();

    let key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "test"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let api_key = key_resp["key"].as_str().unwrap().to_string();

    let ident: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "oauth-agent", "kind": "agent"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ident_id: Uuid = ident["id"].as_str().unwrap().parse().unwrap();

    // Simulate OAuth callback with a code
    // State format: org_id:identity_id:provider_key:byoc_credential_id
    let state_param = format!("{org_id}:{ident_id}:github:_");
    let callback_resp: Value = client
        .get(format!(
            "{base}/v1/oauth/callback?code=test_auth_code_123&state={state_param}"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(callback_resp["status"], "connected");
    assert_eq!(callback_resp["provider"], "github");
    let conn_id = callback_resp["connection_id"].as_str().unwrap();
    assert!(!conn_id.is_empty());

    // Verify connection is listed
    let agent_key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "identity_id": ident_id, "name": "agent"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_api_key = agent_key["key"].as_str().unwrap();

    let conns: Vec<Value> = client
        .get(format!("{base}/v1/connections"))
        .header("Authorization", format!("Bearer {agent_api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(conns.len(), 1);
    assert_eq!(conns[0]["provider_key"], "github");
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_oauth_resolve_access_token_refreshes_when_expired(pool: PgPool) {
    let mock_addr = start_mock().await;

    // Point github provider at mock token endpoint
    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'github'")
        .bind(format!("http://{mock_addr}/oauth/token"))
        .execute(&pool)
        .await
        .unwrap();

    let enc_key_hex = "ab".repeat(32);
    let enc_key = overslash_core::crypto::parse_hex_key(&enc_key_hex).unwrap();

    // Create org + identity
    let org = overslash_db::repos::org::create(&pool, "RefreshOrg", "refresh-test")
        .await
        .unwrap();
    let ident = overslash_db::repos::identity::create(&pool, org.id, "agent", "agent", None)
        .await
        .unwrap();

    // Store a connection with an EXPIRED access token
    let expired_access = overslash_core::crypto::encrypt(&enc_key, b"old_expired_token").unwrap();
    let refresh_tok = overslash_core::crypto::encrypt(&enc_key, b"valid_refresh_token").unwrap();
    let expired_time = time::OffsetDateTime::now_utc() - time::Duration::hours(1);

    let conn = overslash_db::repos::connection::create(
        &pool,
        &overslash_db::repos::connection::CreateConnection {
            org_id: org.id,
            identity_id: ident.id,
            provider_key: "github",
            encrypted_access_token: &expired_access,
            encrypted_refresh_token: Some(&refresh_tok),
            token_expires_at: Some(expired_time),
            scopes: &[],
            account_email: None,
            byoc_credential_id: None,
        },
    )
    .await
    .unwrap();

    // resolve_access_token should detect expiry and refresh
    let http_client = reqwest::Client::new();
    let new_token = overslash_api::services::oauth::resolve_access_token(
        &pool,
        &http_client,
        &enc_key,
        &conn,
        "fake_client_id",
        "fake_client_secret",
    )
    .await
    .unwrap();

    assert_eq!(new_token, "mock_refreshed_access_token");

    // Verify the DB was updated with new tokens
    let updated_conn = overslash_db::repos::connection::get_by_id(&pool, conn.id)
        .await
        .unwrap()
        .unwrap();
    let decrypted_new =
        overslash_core::crypto::decrypt(&enc_key, &updated_conn.encrypted_access_token).unwrap();
    assert_eq!(
        String::from_utf8(decrypted_new).unwrap(),
        "mock_refreshed_access_token"
    );
    // Token should now have a future expiry
    assert!(updated_conn.token_expires_at.unwrap() > time::OffsetDateTime::now_utc());
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_oauth_resolve_access_token_returns_valid_without_refresh(pool: PgPool) {
    let enc_key_hex = "ab".repeat(32);
    let enc_key = overslash_core::crypto::parse_hex_key(&enc_key_hex).unwrap();

    let org = overslash_db::repos::org::create(&pool, "ValidOrg", "valid-test")
        .await
        .unwrap();
    let ident = overslash_db::repos::identity::create(&pool, org.id, "agent", "agent", None)
        .await
        .unwrap();

    // Store a connection with a VALID (non-expired) access token
    let valid_access = overslash_core::crypto::encrypt(&enc_key, b"still_valid_token").unwrap();
    let future_time = time::OffsetDateTime::now_utc() + time::Duration::hours(1);

    let conn = overslash_db::repos::connection::create(
        &pool,
        &overslash_db::repos::connection::CreateConnection {
            org_id: org.id,
            identity_id: ident.id,
            provider_key: "github",
            encrypted_access_token: &valid_access,
            encrypted_refresh_token: None,
            token_expires_at: Some(future_time),
            scopes: &[],
            account_email: None,
            byoc_credential_id: None,
        },
    )
    .await
    .unwrap();

    // Should return the existing token without refreshing
    let http_client = reqwest::Client::new();
    let token = overslash_api::services::oauth::resolve_access_token(
        &pool,
        &http_client,
        &enc_key,
        &conn,
        "unused",
        "unused",
    )
    .await
    .unwrap();

    assert_eq!(token, "still_valid_token");
}

// ============================================================================
// BYOC Credential Tests
// ============================================================================

/// Helper: bootstrap org + identity + identity-bound API key. Returns (org_id, identity_id, api_key).
async fn bootstrap_org_identity(base: &str, client: &Client) -> (Uuid, Uuid, String) {
    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "ByocOrg", "slug": format!("byoc-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();

    // Org-level key (needed to create identity)
    let org_key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "org-admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_api_key = org_key["key"].as_str().unwrap().to_string();

    let ident: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_api_key}"))
        .json(&json!({"name": "test-agent", "kind": "agent"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ident_id: Uuid = ident["id"].as_str().unwrap().parse().unwrap();

    // Identity-bound key
    let key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "identity_id": ident_id, "name": "agent-key"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let api_key = key_resp["key"].as_str().unwrap().to_string();

    (org_id, ident_id, api_key)
}

// --- Test 1: BYOC CRUD API ---

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_byoc_credential_crud(pool: PgPool) {
    let (api_addr, client) = start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org_id, ident_id, api_key) = bootstrap_org_identity(&base, &client).await;

    // Create org-level BYOC credential
    let created: Value = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "provider": "github",
            "client_id": "org_gh_client",
            "client_secret": "org_gh_secret",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(created["id"].is_string());
    assert_eq!(created["provider_key"], "github");
    assert!(created["identity_id"].is_null());
    // Secrets must never be returned
    assert!(created.get("client_id").is_none());
    assert!(created.get("client_secret").is_none());
    assert!(created.get("encrypted_client_id").is_none());

    // Create identity-level BYOC credential
    let created_ident: Value = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "provider": "github",
            "client_id": "ident_gh_client",
            "client_secret": "ident_gh_secret",
            "identity_id": ident_id,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(created_ident["identity_id"], ident_id.to_string());

    // List — should return both
    let list: Vec<Value> = client
        .get(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.len(), 2);

    // Duplicate org-level should fail with 409
    let dup_resp = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "provider": "github",
            "client_id": "dup",
            "client_secret": "dup",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(dup_resp.status(), 409);

    // Delete org-level credential
    let del_id = created["id"].as_str().unwrap();
    let del: Value = client
        .delete(format!("{base}/v1/byoc-credentials/{del_id}"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(del["deleted"], true);

    // List should have 1 remaining
    let list2: Vec<Value> = client
        .get(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list2.len(), 1);
}

// --- Test 2: Org-level BYOC credential used in OAuth callback ---

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_oauth_callback_with_org_byoc_credential(pool: PgPool) {
    let mock_addr = start_mock().await;

    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'github'")
        .bind(format!("http://{mock_addr}/oauth/token"))
        .execute(&pool)
        .await
        .unwrap();

    let (api_addr, client) = start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, api_key) = bootstrap_org_identity(&base, &client).await;

    // Create org-level BYOC credential (no identity_id)
    let byoc: Value = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "provider": "github",
            "client_id": "org_byoc_client_id",
            "client_secret": "org_byoc_client_secret",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let byoc_id = byoc["id"].as_str().unwrap();

    // OAuth callback should resolve org-level BYOC — no env vars, no danger flag
    let state_param = format!("{org_id}:{ident_id}:github:_");
    let callback_resp: Value = client
        .get(format!(
            "{base}/v1/oauth/callback?code=byoc_test_code&state={state_param}"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(callback_resp["status"], "connected");
    assert_eq!(callback_resp["provider"], "github");

    // Verify the connection has the BYOC credential pinned
    let conn_id: Uuid = callback_resp["connection_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let conn = overslash_db::repos::connection::get_by_id(&pool, conn_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(conn.byoc_credential_id.unwrap().to_string(), byoc_id);
}

// --- Test 3: Identity-level BYOC takes priority over org-level ---

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_oauth_callback_identity_byoc_takes_priority(pool: PgPool) {
    let mock_addr = start_mock().await;

    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'github'")
        .bind(format!("http://{mock_addr}/oauth/token"))
        .execute(&pool)
        .await
        .unwrap();

    let (api_addr, client) = start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, api_key) = bootstrap_org_identity(&base, &client).await;

    // Create org-level BYOC
    client
        .post(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "provider": "github",
            "client_id": "org_client",
            "client_secret": "org_secret",
        }))
        .send()
        .await
        .unwrap();

    // Create identity-level BYOC — should win
    let ident_byoc: Value = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "provider": "github",
            "client_id": "ident_client",
            "client_secret": "ident_secret",
            "identity_id": ident_id,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ident_byoc_id = ident_byoc["id"].as_str().unwrap();

    // OAuth callback — identity-level should be selected
    let state_param = format!("{org_id}:{ident_id}:github:_");
    let callback_resp: Value = client
        .get(format!(
            "{base}/v1/oauth/callback?code=priority_code&state={state_param}"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(callback_resp["status"], "connected");

    // Verify the connection pinned the identity-level credential, not org-level
    let conn_id: Uuid = callback_resp["connection_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let conn = overslash_db::repos::connection::get_by_id(&pool, conn_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(conn.byoc_credential_id.unwrap().to_string(), ident_byoc_id);
}

// --- Test 4: Pinned BYOC credential via state parameter ---

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_oauth_callback_pinned_byoc_credential(pool: PgPool) {
    let mock_addr = start_mock().await;

    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'github'")
        .bind(format!("http://{mock_addr}/oauth/token"))
        .execute(&pool)
        .await
        .unwrap();

    let (api_addr, client) = start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, api_key) = bootstrap_org_identity(&base, &client).await;

    // Create org-level BYOC for github
    let byoc: Value = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "provider": "github",
            "client_id": "pinned_client",
            "client_secret": "pinned_secret",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let byoc_id = byoc["id"].as_str().unwrap();

    // Explicitly pin the BYOC credential in the state parameter
    let state_param = format!("{org_id}:{ident_id}:github:{byoc_id}");
    let callback_resp: Value = client
        .get(format!(
            "{base}/v1/oauth/callback?code=pinned_code&state={state_param}"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(callback_resp["status"], "connected");

    let conn_id: Uuid = callback_resp["connection_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let conn = overslash_db::repos::connection::get_by_id(&pool, conn_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(conn.byoc_credential_id.unwrap().to_string(), byoc_id);
}

// --- Test 5: No BYOC credentials and no env vars → error ---
// Uses "spotify" provider which has no env vars set (only github has them in tests)

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_oauth_callback_fails_without_credentials(pool: PgPool) {
    let (api_addr, client) = start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, _api_key) = bootstrap_org_identity(&base, &client).await;

    // Use "spotify" provider — no BYOC credentials exist, and no OAUTH_SPOTIFY_* env vars set.
    // Even if OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS is set by another test,
    // there are no OAUTH_SPOTIFY_* env vars, so env fallback also fails.
    let state_param = format!("{org_id}:{ident_id}:spotify:_");
    let resp = client
        .get(format!(
            "{base}/v1/oauth/callback?code=will_fail&state={state_param}"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    let err = body["error"].as_str().unwrap();
    assert!(
        err.contains("no OAuth client"),
        "expected credential error, got: {err}"
    );
}

// ============================================================================
// E2E Tests — Real External Services (gated on env vars)
// ============================================================================

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_e2e_resend_send_email(pool: PgPool) {
    let resend_api_key = match std::env::var("RESEND_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            eprintln!("RESEND_API_KEY not set, skipping E2E Resend send_email test");
            return;
        }
    };

    let (base, key, _org_id, ident_id) = setup_with_registry(pool).await;
    let client = Client::new();

    // Store the real Resend API key
    client
        .put(format!("{base}/v1/secrets/resend_key"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"value": resend_api_key}))
        .send()
        .await
        .unwrap();

    // Create permission rule
    client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "http:**"}))
        .send()
        .await
        .unwrap();

    // Execute Mode C: service=resend, action=send_email
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "service": "resend",
            "action": "send_email",
            "params": {
                "from": "onboarding@resend.dev",
                "to": "angel.overspiral@gmail.com",
                "subject": "Overslash E2E Test",
                "html": "<h1>It works!</h1><p>This email was sent via Overslash Mode C → Resend API.</p>"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let result: Value = resp.json().await.unwrap();
    assert_eq!(result["status"], "executed");

    // Resend returns {"id": "..."} on successful send
    let body: Value = serde_json::from_str(result["result"]["body"].as_str().unwrap()).unwrap();
    assert!(
        body["id"].is_string(),
        "expected 'id' in Resend send response, got: {body}"
    );
}
