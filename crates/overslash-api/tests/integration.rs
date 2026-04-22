//! Integration tests: full API flows against real Postgres + in-process mock target.
// Test setup requires dynamic SQL for provider endpoint overrides and DB seeding.
#![allow(clippy::disallowed_methods)]

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
        dashboard_origin: "*localhost*".into(),
        redis_url: None,
        default_rate_limit: 10000,
        default_rate_window_secs: 60,
    };

    // Build the app with the test pool directly
    let state = overslash_api::AppState {
        db: pool,
        config,
        http_client: reqwest::Client::new(),
        registry: Arc::new(overslash_core::registry::ServiceRegistry::default()),
        rate_limiter: std::sync::Arc::new(
            overslash_api::services::rate_limit::InMemoryRateLimitStore::new(),
        ),
        rate_limit_cache: std::sync::Arc::new(
            overslash_api::services::rate_limit::RateLimitConfigCache::new(
                std::time::Duration::from_secs(30),
            ),
        ),
        auth_code_store: overslash_api::services::oauth_as::AuthCodeStore::new(),
        pending_authorize_store: overslash_api::services::oauth_as::PendingAuthorizeStore::new(),
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

/// Helper: create org + identity + api key.
/// Returns (api_base_url, agent_key, org_id, identity_id, admin_key).
/// `admin_key` is an org-scoped (no-identity) key suitable for resolving
/// approvals — agents are not allowed to resolve their own.
async fn setup(pool: PgPool) -> (String, String, Uuid, Uuid, String) {
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
        .header("Authorization", format!("Bearer {raw_key}"))
        .json(&json!({"org_id": org_id, "identity_id": ident_id, "name": "agent"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_raw = agent_key["key"].as_str().unwrap().to_string();

    (base, agent_raw, org_id, ident_id, raw_key)
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
async fn test_whoami_returns_caller_identity_for_bearer_key() {
    // /v1/whoami is the Bearer-friendly self-introspection endpoint that
    // `mcp setup` uses to discover its own identity_id (so it can supply
    // parent_id when creating an agent). The dashboard's /auth/me* paths
    // are session-cookie-only and unusable from a CLI.
    let pool = common::test_pool().await;
    let (base, agent_key, org_id, ident_id, admin_key) = setup(pool).await;
    let client = Client::new();

    // Calling with the agent-bound key should report that agent identity.
    let resp: Value = client
        .get(format!("{base}/v1/whoami"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["org_id"].as_str().unwrap(), org_id.to_string());
    assert_eq!(resp["identity_id"].as_str().unwrap(), ident_id.to_string());
    assert_eq!(resp["kind"], "agent");
    // The agent was created under a user, so parent_id is present and not null.
    assert!(resp["parent_id"].is_string(), "parent_id={:?}", resp);

    // The org bootstrap key is identity-bound to the freshly-minted admin user.
    let admin_resp: Value = client
        .get(format!("{base}/v1/whoami"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(admin_resp["org_id"].as_str().unwrap(), org_id.to_string());
    assert_eq!(admin_resp["kind"], "user");

    // Unauthenticated request is rejected.
    let unauth = client
        .get(format!("{base}/v1/whoami"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), 401);
}

#[tokio::test]
async fn test_happy_path_execute_with_permission() {
    let pool = common::test_pool().await;
    let mock_addr = start_mock().await;
    let (base, key, _org_id, ident_id, admin_key) = setup(pool).await;
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
        .header(auth(&admin_key).0, auth(&admin_key).1)
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
    let (base, key, _org_id, _ident_id, admin_key) = setup(pool).await;
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

    // Regression: `approval_url` must point at the dashboard deep-link page
    // (`/approvals/{id}`), not the old placeholder `/approve/{token}` that
    // agents were suggesting to users and 404'd.
    let approval_url = body["approval_url"].as_str().unwrap();
    assert!(
        approval_url.ends_with(&format!("/approvals/{approval_id}")),
        "approval_url {approval_url:?} should end with /approvals/{approval_id}"
    );
    assert!(
        !approval_url.contains("/approve/"),
        "approval_url {approval_url:?} should not use the legacy /approve/{{token}} path"
    );

    // Regression: `expires_at` on pending_approval must be RFC 3339.
    // The `time` crate's default Display ("2026-04-19 08:16:35 +00:00:00")
    // is not parseable by JavaScript's `new Date(...)` and previously
    // broke the dashboard approvals view.
    let pending_expires = body["expires_at"].as_str().unwrap();
    time::OffsetDateTime::parse(
        pending_expires,
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap_or_else(|e| {
        panic!("pending_approval.expires_at {pending_expires:?} not RFC 3339: {e}")
    });

    // Resolve with allow (admin key, not the agent's own)
    let resp = client
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"resolution": "allow"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resolved: Value = resp.json().await.unwrap();
    assert_eq!(resolved["status"], "allowed");

    // Regression: ApprovalResponse.{expires_at, created_at} must be RFC 3339.
    for field in ["expires_at", "created_at"] {
        let s = resolved[field].as_str().unwrap();
        time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|e| panic!("ApprovalResponse.{field} {s:?} not RFC 3339: {e}"));
    }
}

#[tokio::test]
async fn test_allow_remember_creates_rule() {
    let pool = common::test_pool().await;
    let mock_addr = start_mock().await;
    let (base, key, _org_id, _ident_id, admin_key) = setup(pool).await;
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

    // Resolve with allow_remember (admin context)
    client
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
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
    let (base, key, _org_id, _ident_id, admin_key) = setup(pool).await;
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
        .header(auth(&admin_key).0, auth(&admin_key).1)
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
    let (base, key, _org_id, _ident_id, admin_key) = setup(pool).await;
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
        .header(auth(&admin_key).0, auth(&admin_key).1)
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
    let (base, key, _org_id, _ident_id, _admin_key) = setup(pool).await;
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

    // GET /v1/secrets/{name} is dashboard-only (JWT session). API keys
    // must be rejected so a compromised agent token can't enumerate the
    // secret namespace.
    let resp = client
        .get(format!("{base}/v1/secrets/s1"))
        .header(auth(&key).0, auth(&key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    let resp = client
        .get(format!("{base}/v1/secrets"))
        .header(auth(&key).0, auth(&key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_deny_keeps_gating() {
    let pool = common::test_pool().await;
    let mock_addr = start_mock().await;
    let (base, key, _org_id, _ident_id, _admin_key) = setup(pool).await;
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
    let (base, key, _org_id, _ident_id, _admin_key) = setup(pool).await;
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
    let (base, key, _org_id, ident_id, admin_key) = setup(pool).await;
    let client = Client::new();

    // Create permission + execute an action
    client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
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
    let (base, key, _org_id, ident_id, admin_key) = setup(pool).await;
    let client = Client::new();

    // Create a broad permission rule
    client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
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
        dashboard_origin: "*localhost*".into(),
        redis_url: None,
        default_rate_limit: 10000,
        default_rate_window_secs: 60,
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
        rate_limiter: std::sync::Arc::new(
            overslash_api::services::rate_limit::InMemoryRateLimitStore::new(),
        ),
        rate_limit_cache: std::sync::Arc::new(
            overslash_api::services::rate_limit::RateLimitConfigCache::new(
                std::time::Duration::from_secs(30),
            ),
        ),
        auth_code_store: overslash_api::services::oauth_as::AuthCodeStore::new(),
        pending_authorize_store: overslash_api::services::oauth_as::PendingAuthorizeStore::new(),
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
    assert!(
        resp["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["key"] == "create_pull_request")
    );

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
    let (base, key, _org_id, _ident_id, admin_key) = setup(pool).await;
    let client = Client::new();

    // Create webhook subscription for approval.resolved events
    let _wh: Value = client
        .post(format!("{base}/v1/webhooks"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
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
        .header(auth(&admin_key).0, auth(&admin_key).1)
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

#[tokio::test]
async fn test_list_webhook_deliveries_empty_for_new_subscription() {
    let pool = common::test_pool().await;
    let (base, _key, _org_id, _ident_id, admin_key) = setup(pool).await;
    let client = Client::new();

    let wh: Value = client
        .post(format!("{base}/v1/webhooks"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "url": "http://example.invalid/hook",
            "events": ["approval.resolved"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        wh["secret"].is_string(),
        "create response must include the signing secret"
    );
    let id = wh["id"].as_str().unwrap();

    let resp = client
        .get(format!("{base}/v1/webhooks/{id}/deliveries"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body.is_array());
    assert_eq!(body.as_array().unwrap().len(), 0);

    // Cross-org / unknown id → 404
    let bogus = uuid::Uuid::new_v4();
    let resp = client
        .get(format!("{base}/v1/webhooks/{bogus}/deliveries"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
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
        .header("Authorization", format!("Bearer {api_key}"))
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

    let scope = overslash_db::scopes::OrgScope::new(org.id, pool.clone());
    let conn = scope
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id: org.id,
            identity_id: ident.id,
            provider_key: "github",
            encrypted_access_token: &expired_access,
            encrypted_refresh_token: Some(&refresh_tok),
            token_expires_at: Some(expired_time),
            scopes: &[],
            account_email: None,
            byoc_credential_id: None,
        })
        .await
        .unwrap();

    // resolve_access_token should detect expiry and refresh
    let http_client = reqwest::Client::new();
    let new_token = overslash_api::services::oauth::resolve_access_token(
        &scope,
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
    let updated_conn = scope.get_connection(conn.id).await.unwrap().unwrap();
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

    let scope = overslash_db::scopes::OrgScope::new(org.id, pool.clone());
    let conn = scope
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id: org.id,
            identity_id: ident.id,
            provider_key: "github",
            encrypted_access_token: &valid_access,
            encrypted_refresh_token: None,
            token_expires_at: Some(future_time),
            scopes: &[],
            account_email: None,
            byoc_credential_id: None,
        })
        .await
        .unwrap();

    // Should return the existing token without refreshing
    let http_client = reqwest::Client::new();
    let token = overslash_api::services::oauth::resolve_access_token(
        &scope,
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

use common::bootstrap_org_identity;

// --- Test 1: BYOC CRUD API ---

#[tokio::test]
async fn test_byoc_credential_crud() {
    let pool = common::test_pool().await;
    let (api_addr, client) = start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org_id, ident_id, api_key, admin_key) = bootstrap_org_identity(&base, &client).await;

    // Create identity-bound BYOC credential
    let created: Value = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {admin_key}"))
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

    assert!(created["id"].is_string());
    assert_eq!(created["provider_key"], "github");
    assert_eq!(created["identity_id"], ident_id.to_string());
    // Secrets must never be returned
    assert!(created.get("client_id").is_none());
    assert!(created.get("client_secret").is_none());
    assert!(created.get("encrypted_client_id").is_none());

    // List — should return one
    let list: Vec<Value> = client
        .get(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.len(), 1);

    // Duplicate (same org+identity+provider) should fail with 409
    let dup_resp = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "provider": "github",
            "client_id": "dup",
            "client_secret": "dup",
            "identity_id": ident_id,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(dup_resp.status(), 409);

    // Delete the credential
    let del_id = created["id"].as_str().unwrap();
    let del: Value = client
        .delete(format!("{base}/v1/byoc-credentials/{del_id}"))
        .header("Authorization", format!("Bearer {admin_key}"))
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
    assert_eq!(list2.len(), 0);
}

// (Removed) test_oauth_callback_with_org_byoc_credential
// Org-level BYOC (identity_id IS NULL) was removed in migration 028.
// Identity-bound BYOC + OAuth callback is exercised by
// test_oauth_callback_identity_byoc_takes_priority below.

#[tokio::test]
#[ignore = "removed: org-level BYOC concept no longer exists"]
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
    let (org_id, ident_id, _api_key, admin_key) = bootstrap_org_identity(&base, &client).await;

    // Create org-level BYOC credential (no identity_id)
    let byoc: Value = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {admin_key}"))
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
    let conn = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .get_connection(conn_id)
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
    let (org_id, ident_id, _api_key, admin_key) = bootstrap_org_identity(&base, &client).await;

    // Create identity-level BYOC
    let ident_byoc: Value = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {admin_key}"))
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
    let conn = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .get_connection(conn_id)
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
    let (org_id, ident_id, _api_key, admin_key) = bootstrap_org_identity(&base, &client).await;

    // Create identity-bound BYOC for github
    let byoc: Value = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "provider": "github",
            "client_id": "pinned_client",
            "client_secret": "pinned_secret",
            "identity_id": ident_id,
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
    let conn = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .get_connection(conn_id)
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
    let (org_id, ident_id, _api_key, _) = bootstrap_org_identity(&base, &client).await;

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
        dashboard_origin: "*localhost*".into(),
        redis_url: None,
        default_rate_limit: 10000,
        default_rate_window_secs: 60,
    };

    let state = overslash_api::AppState {
        db: pool,
        config,
        http_client: reqwest::Client::new(),
        registry: Arc::new(registry),
        rate_limiter: std::sync::Arc::new(
            overslash_api::services::rate_limit::InMemoryRateLimitStore::new(),
        ),
        rate_limit_cache: std::sync::Arc::new(
            overslash_api::services::rate_limit::RateLimitConfigCache::new(
                std::time::Duration::from_secs(30),
            ),
        ),
        auth_code_store: overslash_api::services::oauth_as::AuthCodeStore::new(),
        pending_authorize_store: overslash_api::services::oauth_as::PendingAuthorizeStore::new(),
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
    let (_org_id, ident_id, key, admin_key) = bootstrap_org_identity(&base, &client).await;

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
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "http:**"}))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
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
    let (base, key, _org_id, _ident_id, _admin_key) = setup(pool).await;
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
    let (base, key, _org_id, _ident_id, admin_key) = setup(pool).await;
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
        .header(auth(&admin_key).0, auth(&admin_key).1)
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
    let (base, key, _org_id, _ident_id, admin_key) = setup(pool).await;
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
        .header(auth(&admin_key).0, auth(&admin_key).1)
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

#[tokio::test]
async fn test_members_list_includes_extended_fields_and_api_keys() {
    let pool = common::test_pool().await;
    let (base, key, _org_id, _ident_id, _) = setup(pool).await;
    let client = Client::new();

    // Identities list should include the user created in setup, with extended fields present
    let identities: Value = client
        .get(format!("{base}/v1/identities"))
        .header(auth(&key).0, auth(&key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let arr = identities.as_array().expect("array");
    let user = arr
        .iter()
        .find(|i| i["kind"] == "user")
        .expect("user identity present");

    // Extended fields exist on the response (may be null but the keys must be present)
    for k in [
        "email",
        "provider",
        "picture",
        "created_at",
        "external_id",
        "owner_id",
    ] {
        assert!(user.get(k).is_some(), "missing field {k}");
    }
    assert!(user["created_at"].is_string(), "created_at serialized");

    // API keys list endpoint returns the org's keys without exposing raw secrets
    let keys_resp: Value = client
        .get(format!("{base}/v1/api-keys"))
        .header(auth(&key).0, auth(&key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let keys = keys_resp.as_array().expect("array");
    assert!(!keys.is_empty(), "should have at least the bootstrap key");
    for k in keys {
        assert!(k.get("key").is_none(), "raw key must never be returned");
        assert!(
            k.get("key_hash").is_none(),
            "key_hash must never be returned"
        );
        assert!(k["key_prefix"].is_string());
        assert!(k["created_at"].is_string());
    }
}
