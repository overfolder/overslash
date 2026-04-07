//! Shared test helpers for integration tests.
#![allow(dead_code)]
// Test setup requires dynamic SQL for updating provider endpoints, creating template DBs, etc.
#![allow(clippy::disallowed_methods)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use reqwest::Client;
use serde_json::{Value, json};
use sqlx::{Connection, PgPool, Row};
use tokio::net::TcpListener;
use uuid::Uuid;

/// Shared template DB name. Created once per Postgres instance, never dropped.
/// Concurrent test processes (e.g. nextest) coordinate via a Postgres advisory
/// lock so exactly one creates+migrates it; the rest wait, then `CREATE
/// DATABASE … TEMPLATE` from it.
const TEMPLATE_DB_NAME: &str = "overslash_test_template";
/// Arbitrary key for the advisory lock used to serialize template creation.
const TEMPLATE_LOCK_KEY: i64 = 0x0_5_0_E_5_7_5_7;

/// Returns a fresh `PgPool` backed by a clone of the migrated template database.
/// nextest-safe: each test runs in its own process, all sharing one template.
pub async fn test_pool() -> PgPool {
    let base_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    ensure_template(&base_url).await;

    // Clone template for this test.
    let test_db = format!("test_{}", Uuid::new_v4().simple());
    let admin_pool = PgPool::connect(&base_url).await.unwrap();
    sqlx::query(&format!(
        "CREATE DATABASE \"{test_db}\" TEMPLATE \"{TEMPLATE_DB_NAME}\""
    ))
    .execute(&admin_pool)
    .await
    .unwrap();
    admin_pool.close().await;

    let test_url = replace_db_name(&base_url, &test_db);
    PgPool::connect(&test_url).await.unwrap()
}

/// Create+migrate the shared template if it doesn't exist yet.
/// Uses a Postgres advisory lock to serialize concurrent processes.
async fn ensure_template(base_url: &str) {
    let admin_pool = PgPool::connect(base_url).await.unwrap();

    // Fast path: template already exists.
    if template_exists(&admin_pool).await {
        admin_pool.close().await;
        return;
    }

    // Slow path: take a session-scoped advisory lock on a single connection
    // that we DETACH from the pool. Detaching is the panic-safety mechanism:
    // if CREATE DATABASE or MIGRATOR.run() panics, the owned PgConnection is
    // dropped, the underlying socket is closed, the Postgres session ends, and
    // session-level advisory locks held by that session are released
    // automatically. If we used a PoolConnection it would be returned to the
    // pool on unwind with the lock still held.
    //
    // CREATE DATABASE can't run inside a transaction block, so we use a
    // session lock instead of pg_advisory_xact_lock.
    let mut conn = admin_pool.acquire().await.unwrap().detach();
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(TEMPLATE_LOCK_KEY)
        .execute(&mut conn)
        .await
        .unwrap();

    let exists: Option<sqlx::postgres::PgRow> =
        sqlx::query("SELECT 1 FROM pg_database WHERE datname = $1")
            .bind(TEMPLATE_DB_NAME)
            .fetch_optional(&mut conn)
            .await
            .unwrap();

    if exists.is_none() {
        sqlx::query(&format!("CREATE DATABASE \"{TEMPLATE_DB_NAME}\""))
            .execute(&mut conn)
            .await
            .unwrap();
        let tpl_url = replace_db_name(base_url, TEMPLATE_DB_NAME);
        let tpl_pool = PgPool::connect(&tpl_url).await.unwrap();
        overslash_db::MIGRATOR.run(&tpl_pool).await.unwrap();
        tpl_pool.close().await;
    }

    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(TEMPLATE_LOCK_KEY)
        .execute(&mut conn)
        .await
        .unwrap();
    let _ = conn.close().await;
    admin_pool.close().await;
}

async fn template_exists(admin_pool: &PgPool) -> bool {
    sqlx::query("SELECT 1 FROM pg_database WHERE datname = $1")
        .bind(TEMPLATE_DB_NAME)
        .fetch_optional(admin_pool)
        .await
        .unwrap()
        .map(|r| r.try_get::<i32, _>(0).unwrap_or(0) == 1)
        .unwrap_or(false)
}

/// Replace the database name in a Postgres URL.
/// Handles both `postgres://user:pass@host:port/dbname` and with query params.
fn replace_db_name(url: &str, new_db: &str) -> String {
    // Find the last '/' before any '?' query string
    let (base, query) = url.split_once('?').unwrap_or((url, ""));
    let last_slash = base.rfind('/').expect("invalid DATABASE_URL: no /");
    let mut result = format!("{}/{}", &base[..last_slash], new_db);
    if !query.is_empty() {
        result.push('?');
        result.push_str(query);
    }
    result
}

/// Start the Overslash API server in-process on a random port.
pub async fn start_api(pool: PgPool) -> (SocketAddr, Client) {
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
        .merge(overslash_api::routes::auth::router())
        .merge(overslash_api::routes::org_idp_configs::router())
        .merge(overslash_api::routes::enrollment::router())
        .merge(overslash_api::routes::groups::router())
        .merge(overslash_api::routes::rate_limits::router())
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, Client::new())
}

/// Start API with dev auth enabled. Returns (base_url, client).
pub async fn start_api_with_dev_auth(pool: PgPool) -> (String, Client) {
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
        dev_auth_enabled: true,
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
        registry: Arc::new(overslash_core::registry::ServiceRegistry::default()),
        rate_limiter: std::sync::Arc::new(
            overslash_api::services::rate_limit::InMemoryRateLimitStore::new(),
        ),
        rate_limit_cache: std::sync::Arc::new(
            overslash_api::services::rate_limit::RateLimitConfigCache::new(
                std::time::Duration::from_secs(30),
            ),
        ),
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
        .merge(overslash_api::routes::auth::router())
        .merge(overslash_api::routes::org_idp_configs::router())
        .merge(overslash_api::routes::enrollment::router())
        .merge(overslash_api::routes::groups::router())
        .merge(overslash_api::routes::rate_limits::router())
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    (format!("http://{addr}"), Client::new())
}

/// Start API with configurable auth providers for OIDC/OAuth testing.
/// `public_url` is used as the base for callback redirect_uri construction.
pub async fn start_api_with_auth_providers(
    pool: PgPool,
    google_creds: Option<(String, String)>,
    github_creds: Option<(String, String)>,
    public_url: &str,
) -> (String, Client) {
    let config = overslash_api::config::Config {
        host: "127.0.0.1".into(),
        port: 0,
        database_url: String::new(),
        secrets_encryption_key: "ab".repeat(32),
        signing_key: "cd".repeat(32),
        approval_expiry_secs: 1800,
        services_dir: "services".into(),
        google_auth_client_id: google_creds.as_ref().map(|(id, _)| id.clone()),
        google_auth_client_secret: google_creds.map(|(_, s)| s),
        github_auth_client_id: github_creds.as_ref().map(|(id, _)| id.clone()),
        github_auth_client_secret: github_creds.map(|(_, s)| s),
        public_url: public_url.to_string(),
        dev_auth_enabled: true,
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
        http_client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
        registry: Arc::new(overslash_core::registry::ServiceRegistry::default()),
        rate_limiter: std::sync::Arc::new(
            overslash_api::services::rate_limit::InMemoryRateLimitStore::new(),
        ),
        rate_limit_cache: std::sync::Arc::new(
            overslash_api::services::rate_limit::RateLimitConfigCache::new(
                std::time::Duration::from_secs(30),
            ),
        ),
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
        .merge(overslash_api::routes::auth::router())
        .merge(overslash_api::routes::org_idp_configs::router())
        .merge(overslash_api::routes::enrollment::router())
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // Non-redirecting client so tests can inspect 303 responses
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    (format!("http://{addr}"), client)
}

/// Start the mock target in-process on a random port.
/// Includes: echo, webhook receiver, and mock OAuth token endpoint.
pub async fn start_mock() -> SocketAddr {
    use axum::{
        Form, Json, Router,
        body::Bytes,
        extract::State,
        http::HeaderMap,
        routing::{get, post},
    };
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

    /// Returns N bytes of 0xAB. Usage: GET /large-file?size=1000
    async fn large_file(
        axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
    ) -> axum::response::Response {
        let size: usize = params
            .get("size")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1024);
        let data = vec![0xABu8; size];
        ([("content-type", "application/octet-stream")], data).into_response()
    }

    use axum::response::IntoResponse;

    /// Simulates Google Drive redirect: returns 302 to /drive/files/content
    async fn drive_download(
        headers: HeaderMap,
        axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
    ) -> axum::response::Response {
        // Verify auth header is present
        let has_auth = headers.get("authorization").is_some();
        let size: usize = params
            .get("size")
            .and_then(|s| s.parse().ok())
            .unwrap_or(4096);
        if !has_auth {
            return (axum::http::StatusCode::UNAUTHORIZED, "missing auth").into_response();
        }
        // Redirect to content endpoint (simulating Google's redirect)
        axum::response::Redirect::temporary(&format!("/drive/files/content?size={size}"))
            .into_response()
    }

    /// Serves file content (redirect target — no auth required, like Google's CDN)
    async fn drive_content(
        axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
    ) -> axum::response::Response {
        let size: usize = params
            .get("size")
            .and_then(|s| s.parse().ok())
            .unwrap_or(4096);
        let data = vec![0xCDu8; size];
        ([("content-type", "application/pdf")], data).into_response()
    }

    // Mock OIDC userinfo endpoint — returns a standard OIDC claims set.
    // The access token encodes the user identity: "mock_access_<code>".
    async fn oidc_userinfo(headers: HeaderMap) -> Json<Value> {
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("unknown");
        Json(json!({
            "sub": format!("oidc-sub-{token}"),
            "email": "testuser@example.com",
            "name": "Test User",
            "picture": "https://example.com/avatar.png",
        }))
    }

    // Mock GitHub user endpoint
    async fn github_user(headers: HeaderMap) -> Json<Value> {
        let _token = headers.get("authorization");
        Json(json!({
            "id": 12345,
            "login": "testuser",
            "name": "Test GitHub User",
            "avatar_url": "https://github.com/avatar.png",
        }))
    }

    // Mock GitHub user emails endpoint
    async fn github_user_emails() -> Json<Value> {
        Json(json!([
            { "email": "testuser@example.com", "primary": true, "verified": true },
            { "email": "other@example.com", "primary": false, "verified": true },
        ]))
    }

    // Mock OIDC Discovery endpoint — returns a well-known config document.
    // The issuer is dynamically constructed from the Host header so tests can
    // use the mock server's address and pass issuer validation.
    async fn oidc_discovery(headers: HeaderMap) -> Json<Value> {
        let host = headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("localhost");
        let base = format!("http://{host}");
        Json(json!({
            "issuer": base,
            "authorization_endpoint": format!("{base}/oauth/authorize"),
            "token_endpoint": format!("{base}/oauth/token"),
            "userinfo_endpoint": format!("{base}/oidc/userinfo"),
            "jwks_uri": format!("{base}/oidc/jwks"),
            "scopes_supported": ["openid", "email", "profile", "offline_access"],
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        }))
    }

    // Mock GitHub user endpoint with no verified emails (edge case)
    async fn github_user_emails_none_verified() -> Json<Value> {
        Json(json!([
            { "email": "unverified@example.com", "primary": true, "verified": false },
        ]))
    }

    let state: S = Arc::new(Mutex::new(MockState::default()));
    let app = Router::new()
        .route("/echo", post(echo))
        .route("/large-file", get(large_file))
        .route("/drive/files/download", get(drive_download))
        .route("/drive/files/content", get(drive_content))
        .route("/webhooks/receive", post(receive_webhook))
        .route("/webhooks/received", get(list_webhooks))
        .route("/oauth/token", post(oauth_token))
        .route("/oidc/userinfo", get(oidc_userinfo))
        .route("/.well-known/openid-configuration", get(oidc_discovery))
        .route("/github/user", get(github_user))
        .route("/github/user/emails", get(github_user_emails))
        .route(
            "/github/user/emails-none-verified",
            get(github_user_emails_none_verified),
        )
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// Bootstrap org + identity + identity-bound API key.
/// Returns (org_id, identity_id, agent_api_key, org_admin_api_key).
pub async fn bootstrap_org_identity(base: &str, client: &Client) -> (Uuid, Uuid, String, String) {
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

    // Create a user identity first (agents require a parent)
    let user_ident: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_api_key}"))
        .json(&json!({"name": "test-user", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id: Uuid = user_ident["id"].as_str().unwrap().parse().unwrap();

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

    // Identity-bound key (requires admin auth now that org has keys)
    let key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {org_api_key}"))
        .json(&json!({"org_id": org_id, "identity_id": ident_id, "name": "agent-key"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let api_key = key_resp["key"].as_str().unwrap().to_string();

    (org_id, ident_id, api_key, org_api_key)
}

pub fn auth(key: &str) -> (&'static str, String) {
    ("Authorization", format!("Bearer {key}"))
}

/// Start API with real service registry loaded from `services/` directory.
/// Optionally override a service's host (useful for mock-based tests).
pub async fn start_api_with_registry(
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
        .merge(overslash_api::routes::auth::router())
        .merge(overslash_api::routes::org_idp_configs::router())
        .merge(overslash_api::routes::enrollment::router())
        .merge(overslash_api::routes::groups::router())
        .merge(overslash_api::routes::rate_limits::router())
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    (format!("http://{addr}"), Client::new())
}

/// Start API with a custom max response body size (for testing size limits).
pub async fn start_api_with_body_limit(pool: PgPool, max_bytes: usize) -> (SocketAddr, Client) {
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
        max_response_body_bytes: max_bytes,
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
        registry: Arc::new(overslash_core::registry::ServiceRegistry::default()),
        rate_limiter: std::sync::Arc::new(
            overslash_api::services::rate_limit::InMemoryRateLimitStore::new(),
        ),
        rate_limit_cache: std::sync::Arc::new(
            overslash_api::services::rate_limit::RateLimitConfigCache::new(
                std::time::Duration::from_secs(30),
            ),
        ),
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
        .merge(overslash_api::routes::auth::router())
        .merge(overslash_api::routes::org_idp_configs::router())
        .merge(overslash_api::routes::enrollment::router())
        .merge(overslash_api::routes::groups::router())
        .merge(overslash_api::routes::rate_limits::router())
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    (addr, Client::new())
}
