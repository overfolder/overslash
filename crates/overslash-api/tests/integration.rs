//! Integration tests: full API flows against real Postgres + in-process mock target.

mod common;

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
        signing_key: "cd".repeat(32),
        approval_expiry_secs: 1800,
        services_dir: "services".into(),
        google_auth_client_id: None,
        google_auth_client_secret: None,
        github_auth_client_id: None,
        github_auth_client_secret: None,
        public_url: "http://localhost:3000".into(),
        dev_auth_enabled: false,
        max_response_body_bytes: 5_242_880,
        dashboard_url: "/".into(),
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
        .merge(overslash_api::routes::templates::router())
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

    async fn echo(uri: axum::http::Uri, headers: HeaderMap, body: Bytes) -> Json<Value> {
        let h: serde_json::Map<String, Value> = headers
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), json!(v.to_str().unwrap_or(""))))
            .collect();
        Json(json!({
            "headers": h,
            "body": String::from_utf8_lossy(&body).to_string(),
            "uri": uri.to_string(),
        }))
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
        .route("/echo", get(echo).post(echo).put(echo).delete(echo))
        .route("/webhooks/receive", post(receive_webhook))
        .route("/webhooks/received", get(list_webhooks))
        .route("/oauth/token", post(oauth_token))
        .fallback(echo)
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

    // Create user identity (agents require a parent)
    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {raw_key}"))
        .json(&json!({"name": "test-user", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = user["id"].as_str().unwrap();

    // Create agent identity under user
    let ident: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {raw_key}"))
        .json(&json!({"name": "test-agent", "kind": "agent", "parent_id": user_id}))
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

#[tokio::test]
async fn test_health() {
    let pool = common::test_pool().await;
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

#[tokio::test]
async fn test_happy_path_execute_with_permission() {
    let pool = common::test_pool().await;
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

#[tokio::test]
async fn test_approval_flow() {
    let pool = common::test_pool().await;
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
        .json(&json!({"resolution": "allow"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resolved: Value = resp.json().await.unwrap();
    assert_eq!(resolved["status"], "allowed");
}

#[tokio::test]
async fn test_allow_remember_creates_rule() {
    let pool = common::test_pool().await;
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
        .json(&json!({"resolution": "allow_remember"}))
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

#[tokio::test]
async fn test_resolve_rejects_invalid_remember_keys() {
    let pool = common::test_pool().await;
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

    // Resolve with remember_keys not in the approval's permission_keys → 400
    let resp = client
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "resolution": "allow_remember",
            "remember_keys": ["admin:*:*"]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_resolve_rejects_invalid_ttl() {
    let pool = common::test_pool().await;
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

    // Resolve with invalid ttl → 400
    let resp = client
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "resolution": "allow_remember",
            "ttl": "not_a_duration"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_secret_versioning() {
    let pool = common::test_pool().await;
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

#[tokio::test]
async fn test_deny_keeps_gating() {
    let pool = common::test_pool().await;
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
        .json(&json!({"resolution": "deny"}))
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

#[tokio::test]
async fn test_unauthenticated_request_no_gate() {
    let pool = common::test_pool().await;
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

#[tokio::test]
async fn test_audit_trail() {
    let pool = common::test_pool().await;
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

#[tokio::test]
async fn test_mode_c_service_action() {
    let pool = common::test_pool().await;
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

#[tokio::test]
async fn test_service_registry_api() {
    let pool = common::test_pool().await;
    // Start API with real service registry loaded
    let config = overslash_api::config::Config {
        host: "127.0.0.1".into(),
        port: 0,
        database_url: String::new(),
        secrets_encryption_key: "ab".repeat(32),
        signing_key: "cd".repeat(32),
        approval_expiry_secs: 1800,
        services_dir: "services".into(),
        google_auth_client_id: None,
        google_auth_client_secret: None,
        github_auth_client_id: None,
        github_auth_client_secret: None,
        public_url: "http://localhost:3000".into(),
        dev_auth_enabled: false,
        max_response_body_bytes: 5_242_880,
        dashboard_url: "/".into(),
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
        .merge(overslash_api::routes::templates::router())
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

    // List templates — should have at least github, stripe, slack (global tier)
    let resp: Vec<Value> = client
        .get(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let keys: Vec<&str> = resp.iter().filter_map(|s| s["key"].as_str()).collect();
    assert!(keys.contains(&"github"), "expected github in templates");
    assert!(keys.contains(&"stripe"), "expected stripe in templates");

    // Search
    let resp: Vec<Value> = client
        .get(format!("{base}/v1/templates/search?q=pull+request"))
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

    // Get template detail
    let resp: Value = client
        .get(format!("{base}/v1/templates/github"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["key"], "github");
    assert!(resp["actions"]["create_pull_request"].is_object());

    // List template actions
    let actions: Vec<Value> = client
        .get(format!("{base}/v1/templates/github/actions"))
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

#[tokio::test]
async fn test_webhook_dispatch_on_approval_resolve() {
    let pool = common::test_pool().await;
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
        .json(&json!({"resolution": "allow"}))
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

#[tokio::test]
async fn test_oauth_callback_exchanges_code_and_stores_connection() {
    let pool = common::test_pool().await;
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

    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "oauth-user", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = user["id"].as_str().unwrap();

    let ident: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "oauth-agent", "kind": "agent", "parent_id": user_id}))
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

#[tokio::test]
async fn test_oauth_resolve_access_token_refreshes_when_expired() {
    let pool = common::test_pool().await;
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

#[tokio::test]
async fn test_oauth_resolve_access_token_returns_valid_without_refresh() {
    let pool = common::test_pool().await;
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

    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_api_key}"))
        .json(&json!({"name": "test-user", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = user["id"].as_str().unwrap();

    let ident: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_api_key}"))
        .json(&json!({"name": "test-agent", "kind": "agent", "parent_id": user_id}))
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

#[tokio::test]
async fn test_byoc_credential_crud() {
    let pool = common::test_pool().await;
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

#[tokio::test]
async fn test_oauth_callback_with_org_byoc_credential() {
    let pool = common::test_pool().await;
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

#[tokio::test]
async fn test_oauth_callback_identity_byoc_takes_priority() {
    let pool = common::test_pool().await;
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

#[tokio::test]
async fn test_oauth_callback_pinned_byoc_credential() {
    let pool = common::test_pool().await;
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

#[tokio::test]
async fn test_oauth_callback_fails_without_credentials() {
    let pool = common::test_pool().await;
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
// Google Calendar — mock test (CI-safe, all three execution modes)
// ============================================================================

/// Helper: start API with real service registry, optionally overriding a service's host.
async fn start_api_with_registry(
    pool: PgPool,
    host_override: Option<(&str, String)>,
) -> (String, Client) {
    let enc_key_hex = "ab".repeat(32);
    let ws_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let mut registry =
        overslash_core::registry::ServiceRegistry::load_from_dir(&ws_root.join("services"))
            .unwrap_or_default();

    if let Some((service_key, new_host)) = host_override {
        if let Some(svc) = registry.get(service_key) {
            let mut svc = svc.clone();
            svc.hosts = vec![new_host];
            registry.insert(svc);
        }
    }

    let config = overslash_api::config::Config {
        host: "127.0.0.1".into(),
        port: 0,
        database_url: String::new(),
        secrets_encryption_key: enc_key_hex,
        signing_key: "cd".repeat(32),
        approval_expiry_secs: 1800,
        services_dir: "services".into(),
        google_auth_client_id: None,
        google_auth_client_secret: None,
        github_auth_client_id: None,
        github_auth_client_secret: None,
        public_url: "http://localhost:3000".into(),
        dev_auth_enabled: false,
        max_response_body_bytes: 5_242_880,
        dashboard_url: "/".into(),
    };

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
        .merge(overslash_api::routes::templates::router())
        .merge(overslash_api::routes::connections::router())
        .merge(overslash_api::routes::byoc_credentials::router())
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    (format!("http://{addr}"), Client::new())
}

#[tokio::test]
async fn test_google_calendar_three_modes() {
    let pool = common::test_pool().await;
    let mock_addr = start_mock().await;
    let mock_host = format!("http://{mock_addr}");

    // Point google provider's token_endpoint at mock
    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'google'")
        .bind(format!("http://{mock_addr}/oauth/token"))
        .execute(&pool)
        .await
        .unwrap();

    // Start API with registry, override google_calendar host to mock
    let (base, client) =
        start_api_with_registry(pool.clone(), Some(("google_calendar", mock_host.clone()))).await;

    // Bootstrap org + identity + API key
    let (org_id, ident_id, key) = bootstrap_org_identity(&base, &client).await;

    // Create broad permission rules: http:** for Mode A/B, google_calendar:*:* for Mode C
    client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "http:**"}))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "google_calendar:*:*"}))
        .send()
        .await
        .unwrap();

    // ===== MODE A: Raw HTTP with secret injection =====
    client
        .put(format!("{base}/v1/secrets/gcal_token"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"value": "manual-token-xyz"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "method": "GET",
            "url": format!("http://{mock_addr}/echo"),
            "secrets": [{
                "name": "gcal_token",
                "inject_as": "header",
                "header_name": "Authorization",
                "prefix": "Bearer "
            }]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(
        echo["headers"]["authorization"], "Bearer manual-token-xyz",
        "Mode A: secret should be injected as Authorization header"
    );

    // ===== MODE B: Connection-based OAuth =====
    let enc_key = overslash_core::crypto::parse_hex_key(&"ab".repeat(32)).unwrap();
    let encrypted_token =
        overslash_core::crypto::encrypt(&enc_key, b"google-oauth-token-123").unwrap();
    let future_time = time::OffsetDateTime::now_utc() + time::Duration::hours(1);

    // Create a BYOC credential so client_credentials::resolve succeeds
    let encrypted_cid = overslash_core::crypto::encrypt(&enc_key, b"mock_client_id").unwrap();
    let encrypted_csec = overslash_core::crypto::encrypt(&enc_key, b"mock_client_secret").unwrap();
    let byoc = overslash_db::repos::byoc_credential::create(
        &pool,
        &overslash_db::repos::byoc_credential::CreateByocCredential {
            org_id,
            identity_id: None,
            provider_key: "google",
            encrypted_client_id: &encrypted_cid,
            encrypted_client_secret: &encrypted_csec,
        },
    )
    .await
    .unwrap();

    let conn = overslash_db::repos::connection::create(
        &pool,
        &overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: ident_id,
            provider_key: "google",
            encrypted_access_token: &encrypted_token,
            encrypted_refresh_token: None,
            token_expires_at: Some(future_time),
            scopes: &[],
            account_email: None,
            byoc_credential_id: Some(byoc.id),
        },
    )
    .await
    .unwrap();

    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "connection": conn.id.to_string(),
            "method": "GET",
            "url": format!("http://{mock_addr}/echo")
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(
        echo["headers"]["authorization"], "Bearer google-oauth-token-123",
        "Mode B: OAuth token should be injected from connection"
    );

    // ===== MODE C (POST): create_event — path template + JSON body + OAuth auto-resolve =====
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "service": "google_calendar",
            "action": "create_event",
            "params": {
                "calendarId": "primary",
                "summary": "Team Meeting",
                "start": {"dateTime": "2026-03-27T10:00:00Z"},
                "end": {"dateTime": "2026-03-27T11:00:00Z"},
                "description": "Weekly sync"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");

    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let uri = echo["uri"].as_str().unwrap();
    assert!(
        uri.contains("/calendar/v3/calendars/primary/events"),
        "Mode C POST: URL should contain resolved path, got: {uri}"
    );

    // Verify body contains non-path params as JSON
    let req_body: Value = serde_json::from_str(echo["body"].as_str().unwrap()).unwrap();
    assert_eq!(req_body["summary"], "Team Meeting");
    assert_eq!(req_body["description"], "Weekly sync");

    // Verify auth was auto-resolved from the connection
    assert_eq!(
        echo["headers"]["authorization"], "Bearer google-oauth-token-123",
        "Mode C: OAuth token should be auto-resolved from connection"
    );

    // ===== MODE C (GET): list_events — query param construction =====
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "service": "google_calendar",
            "action": "list_events",
            "params": {
                "calendarId": "primary",
                "timeMin": "2026-03-27T00:00:00Z",
                "maxResults": 10
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");

    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let uri = echo["uri"].as_str().unwrap();
    assert!(
        uri.contains("/calendar/v3/calendars/primary/events"),
        "Mode C GET: URL should contain resolved path, got: {uri}"
    );
    assert!(
        uri.contains("timeMin="),
        "Mode C GET: query params should be appended, got: {uri}"
    );
    assert!(
        uri.contains("maxResults="),
        "Mode C GET: query params should be appended, got: {uri}"
    );

    // ===== MODE C (GET): list_calendars — no path params =====
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "service": "google_calendar",
            "action": "list_calendars",
            "params": {}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let uri = echo["uri"].as_str().unwrap();
    assert!(
        uri.contains("/calendar/v3/users/me/calendarList"),
        "Mode C GET: list_calendars path should be correct, got: {uri}"
    );
}

// ============================================================================
// Google Calendar — real test (requires GOOGLE_TEST_REFRESH_TOKEN, uses BYOC)
// ============================================================================

#[ignore] // Write test: creates/deletes real calendar events. Run with --ignored.
#[tokio::test]
async fn test_google_calendar_real_byoc() {
    let pool = common::test_pool().await;
    // Skip if required env vars are not set
    let refresh_token = match std::env::var("GOOGLE_TEST_REFRESH_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => {
            eprintln!("SKIP: GOOGLE_TEST_REFRESH_TOKEN not set");
            return;
        }
    };
    let client_id = std::env::var("OAUTH_GOOGLE_CLIENT_ID")
        .expect("OAUTH_GOOGLE_CLIENT_ID required for real test");
    let client_secret = std::env::var("OAUTH_GOOGLE_CLIENT_SECRET")
        .expect("OAUTH_GOOGLE_CLIENT_SECRET required for real test");

    // Start API with real service registry (no host override — hits real Google)
    let (base, client) = start_api_with_registry(pool.clone(), None).await;

    // Bootstrap org + identity + API key
    let (org_id, ident_id, key) = bootstrap_org_identity(&base, &client).await;

    // Store BYOC credential via API (production path)
    let byoc_resp: Value = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "provider": "google",
            "client_id": client_id,
            "client_secret": client_secret
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let byoc_id: Uuid = byoc_resp["id"].as_str().unwrap().parse().unwrap();

    // Exchange refresh token for access token via real Google token endpoint
    let token_resp: Value = reqwest::Client::new()
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh_token),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let access_token = token_resp["access_token"]
        .as_str()
        .expect("failed to get access_token from Google token endpoint");
    let expires_in = token_resp["expires_in"].as_i64().unwrap_or(3600);

    // Encrypt tokens and insert connection in DB
    let enc_key = overslash_core::crypto::parse_hex_key(&"ab".repeat(32)).unwrap();
    let encrypted_access =
        overslash_core::crypto::encrypt(&enc_key, access_token.as_bytes()).unwrap();
    let encrypted_refresh =
        overslash_core::crypto::encrypt(&enc_key, refresh_token.as_bytes()).unwrap();
    let expires_at = time::OffsetDateTime::now_utc() + time::Duration::seconds(expires_in);

    let conn = overslash_db::repos::connection::create(
        &pool,
        &overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: ident_id,
            provider_key: "google",
            encrypted_access_token: &encrypted_access,
            encrypted_refresh_token: Some(&encrypted_refresh),
            token_expires_at: Some(expires_at),
            scopes: &["https://www.googleapis.com/auth/calendar".to_string()],
            account_email: Some("angel.overspiral@gmail.com"),
            byoc_credential_id: Some(byoc_id),
        },
    )
    .await
    .unwrap();

    // Create broad permission rules: http:** for raw HTTP, google_calendar:*:* for Mode C
    client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "http:**"}))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "google_calendar:*:*"}))
        .send()
        .await
        .unwrap();

    // ===== TEST 1: list_calendars (Mode C) =====
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "service": "google_calendar",
            "action": "list_calendars",
            "params": {}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");
    let gcal_body: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert!(
        gcal_body["items"].is_array(),
        "list_calendars should return items array, got: {gcal_body}"
    );
    eprintln!(
        "  list_calendars: found {} calendars",
        gcal_body["items"].as_array().unwrap().len()
    );

    // ===== TEST 2: create_event (Mode C) =====
    let now = time::OffsetDateTime::now_utc();
    let start = now + time::Duration::hours(1);
    let end = now + time::Duration::hours(2);
    let event_summary = format!("Overslash Test - {}", now.unix_timestamp());

    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "service": "google_calendar",
            "action": "create_event",
            "params": {
                "calendarId": "primary",
                "summary": event_summary,
                "start": {"dateTime": start.format(&time::format_description::well_known::Rfc3339).unwrap()},
                "end": {"dateTime": end.format(&time::format_description::well_known::Rfc3339).unwrap()},
                "description": "Integration test event — will be deleted"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");
    let created: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let event_id = created["id"]
        .as_str()
        .expect("created event should have an id");
    eprintln!("  create_event: created {event_id}");

    // ===== TEST 3: list_events with query params (Mode C, GET) =====
    let time_min = now
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "service": "google_calendar",
            "action": "list_events",
            "params": {
                "calendarId": "primary",
                "timeMin": time_min,
                "maxResults": 10,
                "singleEvents": true,
                "orderBy": "startTime"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");
    let events: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert!(
        events["items"].is_array(),
        "list_events should return items array"
    );
    let found = events["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["summary"].as_str() == Some(&event_summary));
    assert!(found, "created event should appear in list_events");
    eprintln!("  list_events: found test event in listing");

    // ===== TEST 4: get_event (Mode C) =====
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "service": "google_calendar",
            "action": "get_event",
            "params": {
                "calendarId": "primary",
                "eventId": event_id
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");
    let fetched: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(fetched["id"].as_str().unwrap(), event_id);
    assert_eq!(fetched["summary"].as_str().unwrap(), event_summary);
    eprintln!("  get_event: verified event {event_id}");

    // ===== TEST 5: Mode A — raw HTTP with secret =====
    // Store the access token as a secret for raw HTTP mode
    client
        .put(format!("{base}/v1/secrets/gcal_raw_token"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"value": access_token}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "method": "GET",
            "url": format!(
                "https://www.googleapis.com/calendar/v3/calendars/primary/events/{event_id}"
            ),
            "secrets": [{
                "name": "gcal_raw_token",
                "inject_as": "header",
                "header_name": "Authorization",
                "prefix": "Bearer "
            }]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");
    let raw_fetched: Value =
        serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(raw_fetched["id"].as_str().unwrap(), event_id);
    eprintln!("  Mode A raw HTTP: verified event via direct URL");

    // ===== TEST 6: Mode B — connection-based =====
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "connection": conn.id.to_string(),
            "method": "GET",
            "url": format!(
                "https://www.googleapis.com/calendar/v3/calendars/primary/events/{event_id}"
            )
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");
    let conn_fetched: Value =
        serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(conn_fetched["id"].as_str().unwrap(), event_id);
    eprintln!("  Mode B connection: verified event via OAuth connection");

    // ===== CLEANUP: delete_event (Mode C) =====
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "service": "google_calendar",
            "action": "delete_event",
            "params": {
                "calendarId": "primary",
                "eventId": event_id
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");
    // Google returns 204 No Content for successful delete
    let status_code = body["result"]["status_code"].as_u64().unwrap();
    assert!(
        status_code == 204 || status_code == 200,
        "delete should return 204 or 200, got: {status_code}"
    );
    eprintln!("  delete_event: cleaned up test event");
    eprintln!("  All Google Calendar real tests passed!");
}

// ============================================================================
// E2E Tests — Real External Services (gated on env vars)
// ============================================================================

#[ignore] // Write test: sends real email via Resend. Run with --ignored.
#[tokio::test]
async fn test_e2e_resend_send_email() {
    let pool = common::test_pool().await;
    let resend_api_key = match std::env::var("RESEND_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            eprintln!("RESEND_API_KEY not set, skipping E2E Resend send_email test");
            return;
        }
    };

    // Use start_api_with_registry (no host override — hits real Resend)
    let (base, client) = start_api_with_registry(pool, None).await;
    let (_org_id, ident_id, key) = bootstrap_org_identity(&base, &client).await;

    // Store the real Resend API key (matches default_secret_name in resend.yaml)
    client
        .put(format!("{base}/v1/secrets/resend_key"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"value": resend_api_key}))
        .send()
        .await
        .unwrap();

    // Create permission rules: http:** for raw HTTP, resend:*:* for Mode C
    client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "http:**"}))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "resend:*:*"}))
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
                "to": "amanuelmartincanto@gmail.com",
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

// ── derived_keys / suggested_tiers tests ──────────────────────────────

#[tokio::test]
async fn test_approval_response_includes_derived_keys_and_tiers() {
    let pool = common::test_pool().await;
    let mock_addr = start_mock().await;
    let (base, key, _org_id, _ident_id) = setup(pool).await;
    let client = Client::new();

    // Store a secret so the execute triggers gating
    client
        .put(format!("{base}/v1/secrets/tk"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"value": "v"}))
        .send()
        .await
        .unwrap();

    // Execute without permission → 202 pending approval
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
    let exec_body: Value = resp.json().await.unwrap();
    let approval_id = exec_body["approval_id"].as_str().unwrap();

    // GET the approval — verify derived_keys and suggested_tiers are present
    let resp = client
        .get(format!("{base}/v1/approvals/{approval_id}"))
        .header(auth(&key).0, auth(&key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let approval: Value = resp.json().await.unwrap();

    // derived_keys should be a non-empty array of objects with key/service/action/arg
    let derived_keys = approval["derived_keys"].as_array().unwrap();
    assert!(!derived_keys.is_empty());
    for dk in derived_keys {
        assert!(dk["key"].is_string());
        assert!(dk["service"].is_string());
        assert!(dk["action"].is_string());
        assert!(dk["arg"].is_string());
    }

    // suggested_tiers should have 2-4 entries with keys and description
    let tiers = approval["suggested_tiers"].as_array().unwrap();
    assert!(tiers.len() >= 2 && tiers.len() <= 4);
    for tier in tiers {
        assert!(tier["keys"].is_array());
        assert!(!tier["keys"].as_array().unwrap().is_empty());
        assert!(tier["description"].is_string());
        assert!(!tier["description"].as_str().unwrap().is_empty());
    }

    // First tier should be the most specific (exact keys)
    assert_eq!(
        tiers[0]["keys"].as_array().unwrap(),
        approval["permission_keys"].as_array().unwrap()
    );

    // permission_keys should still be present for backward compat
    assert!(approval["permission_keys"].is_array());
}

#[tokio::test]
async fn test_resolve_with_broader_remember_keys_succeeds() {
    let pool = common::test_pool().await;
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

    // Execute → 202
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

    // GET the approval to read the suggested tiers
    let resp = client
        .get(format!("{base}/v1/approvals/{approval_id}"))
        .header(auth(&key).0, auth(&key).1)
        .send()
        .await
        .unwrap();
    let approval: Value = resp.json().await.unwrap();
    let tiers = approval["suggested_tiers"].as_array().unwrap();
    assert!(tiers.len() >= 2, "should have at least 2 tiers");

    // Use the broadest tier's keys (last tier) as remember_keys
    let broadest_tier_keys: Vec<String> = tiers.last().unwrap()["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    // Verify the broadest tier is actually broader than the exact keys
    assert_ne!(
        tiers.first().unwrap()["keys"],
        tiers.last().unwrap()["keys"],
        "broadest tier should differ from exact tier"
    );

    // Resolve with the broadest suggested tier — should succeed
    let resp = client
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "resolution": "allow_remember",
            "remember_keys": broadest_tier_keys
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "broader remember_key from suggested tier should be accepted"
    );
}

#[tokio::test]
async fn test_resolve_with_unrelated_broader_keys_still_fails() {
    let pool = common::test_pool().await;
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

    // Resolve with an unrelated broader key — should still fail
    let resp = client
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "resolution": "allow_remember",
            "remember_keys": ["slack:*:*"]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        400,
        "unrelated broader key should be rejected"
    );
}
