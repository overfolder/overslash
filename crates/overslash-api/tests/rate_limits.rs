// Test setup uses dynamic SQL (sqlx::query) for seeding rate-limit rows.
#![allow(clippy::disallowed_methods)]

mod common;

use rand::RngExt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{Router, routing::get};
use serde_json::{Value, json};
use sqlx::PgPool;
use tokio::net::TcpListener;
use uuid::Uuid;

/// Bootstrap: org + user + org-admin API key. Returns (base_url, client, org_id, org_api_key).
async fn bootstrap() -> (String, reqwest::Client, Uuid, String) {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

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

    let key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "org-admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_api_key = key["key"].as_str().unwrap().to_string();

    (base, client, org_id, org_api_key)
}

/// Create a user identity. Returns the user's identity ID.
async fn create_user(base: &str, client: &reqwest::Client, key: &str, name: &str) -> Uuid {
    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({"name": name, "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    user["id"].as_str().unwrap().parse().unwrap()
}

#[tokio::test]
async fn test_upsert_org_default() {
    let (base, client, _org_id, key) = bootstrap().await;

    let resp = client
        .put(format!("{base}/v1/rate-limits"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({
            "scope": "org",
            "max_requests": 100,
            "window_seconds": 60,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "first upsert should succeed");

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["scope"], "org");
    assert_eq!(body["max_requests"], 100);
    assert_eq!(body["window_seconds"], 60);
    assert!(body["identity_id"].is_null());
    assert!(body["group_id"].is_null());

    // Idempotent: second upsert with new values updates the same row
    let resp2 = client
        .put(format!("{base}/v1/rate-limits"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({
            "scope": "org",
            "max_requests": 200,
            "window_seconds": 30,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp2.status(),
        200,
        "second upsert should succeed (no race)"
    );
    let body2: Value = resp2.json().await.unwrap();
    assert_eq!(body2["id"], body["id"], "should update the same row");
    assert_eq!(body2["max_requests"], 200);
    assert_eq!(body2["window_seconds"], 30);
}

#[tokio::test]
async fn test_upsert_user_scope_requires_identity() {
    let (base, client, _org_id, key) = bootstrap().await;

    let resp = client
        .put(format!("{base}/v1/rate-limits"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({
            "scope": "user",
            "max_requests": 50,
            "window_seconds": 60,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_upsert_identity_cap() {
    let (base, client, _org_id, key) = bootstrap().await;
    let user_id = create_user(&base, &client, &key, "alice").await;

    let resp = client
        .put(format!("{base}/v1/rate-limits"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({
            "scope": "identity_cap",
            "identity_id": user_id,
            "max_requests": 5,
            "window_seconds": 60,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["scope"], "identity_cap");
    assert_eq!(body["identity_id"], user_id.to_string());
}

#[tokio::test]
async fn test_upsert_invalid_scope() {
    let (base, client, _org_id, key) = bootstrap().await;

    let resp = client
        .put(format!("{base}/v1/rate-limits"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({
            "scope": "nonsense",
            "max_requests": 100,
            "window_seconds": 60,
        }))
        .send()
        .await
        .unwrap();
    // Serde rejects unknown enum variant → 422 (or 400 depending on extractor)
    assert!(
        resp.status() == 400 || resp.status() == 422,
        "got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_upsert_negative_max_requests_rejected() {
    let (base, client, _org_id, key) = bootstrap().await;

    let resp = client
        .put(format!("{base}/v1/rate-limits"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({
            "scope": "org",
            "max_requests": -1,
            "window_seconds": 60,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_list_rate_limits() {
    let (base, client, _org_id, key) = bootstrap().await;

    // Initially empty
    let resp = client
        .get(format!("{base}/v1/rate-limits"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let list: Value = resp.json().await.unwrap();
    assert_eq!(list.as_array().unwrap().len(), 0);

    // Add an org default
    client
        .put(format!("{base}/v1/rate-limits"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({"scope": "org", "max_requests": 100, "window_seconds": 60}))
        .send()
        .await
        .unwrap();

    let list: Value = client
        .get(format!("{base}/v1/rate-limits"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn test_delete_rate_limit() {
    let (base, client, _org_id, key) = bootstrap().await;

    let body: Value = client
        .put(format!("{base}/v1/rate-limits"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({"scope": "org", "max_requests": 100, "window_seconds": 60}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = body["id"].as_str().unwrap();

    let resp = client
        .delete(format!("{base}/v1/rate-limits/{id}"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Second delete returns 404
    let resp = client
        .delete(format!("{base}/v1/rate-limits/{id}"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_in_memory_store_check_and_increment() {
    use overslash_api::services::rate_limit::{InMemoryRateLimitStore, RateLimitStore};

    let store = InMemoryRateLimitStore::new();
    let key = "test-key";

    // First 3 requests should be allowed
    for i in 0..3 {
        let result = store.check_and_increment(key, 3, 60).await;
        assert!(result.allowed, "request {i} should be allowed");
        assert_eq!(result.limit, 3);
        assert_eq!(result.remaining, 3 - (i + 1));
    }

    // 4th should be denied
    let result = store.check_and_increment(key, 3, 60).await;
    assert!(!result.allowed);
    assert_eq!(result.remaining, 0);
}

#[tokio::test]
async fn test_in_memory_store_evict_expired() {
    use overslash_api::services::rate_limit::{InMemoryRateLimitStore, RateLimitStore};

    let store = InMemoryRateLimitStore::new();
    // Use a 1-second window so we can wait it out
    store.check_and_increment("k1", 100, 1).await;
    store.check_and_increment("k2", 100, 1).await;

    // Wait for the window to elapse
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    store.evict_expired();

    // After eviction, fresh requests start at count=1
    let result = store.check_and_increment("k1", 5, 1).await;
    assert!(result.allowed);
    assert_eq!(result.remaining, 4);
}

#[tokio::test]
async fn test_resolve_user_budget_falls_back_to_org_default() {
    use overslash_api::services::rate_limit::RateLimitConfigCache;
    use std::time::Duration;

    let pool = common::test_pool().await;
    let (_addr, _client) = common::start_api(pool.clone()).await;

    // Create an org and a user via SQL (simpler than API for this unit test)
    let org_id = Uuid::new_v4();
    sqlx::query("INSERT INTO orgs (id, name, slug) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind("test-org")
        .bind(format!("test-{}", Uuid::new_v4()))
        .execute(&pool)
        .await
        .unwrap();

    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO identities (id, org_id, name, kind) VALUES ($1, $2, $3, 'user')")
        .bind(user_id)
        .bind(org_id)
        .bind("test-user")
        .execute(&pool)
        .await
        .unwrap();

    // Set an org-wide default
    overslash_db::OrgScope::new(org_id, pool.clone())
        .upsert_rate_limit("org", None, None, 250, 60)
        .await
        .unwrap();

    // Resolve user budget — should fall back to org default
    let cache = RateLimitConfigCache::new(Duration::from_secs(30));
    let config = overslash_api::config::Config {
        host: "127.0.0.1".into(),
        port: 0,
        database_url: String::new(),
        secrets_encryption_key: "ab".repeat(32),
        signing_key: "cd".repeat(32),
        approval_expiry_secs: 1800,
        execution_pending_ttl_secs: 900,
        execution_replay_timeout_secs: 30,
        services_dir: "services".into(),
        google_auth_client_id: None,
        google_auth_client_secret: None,
        github_auth_client_id: None,
        github_auth_client_secret: None,
        public_url: "http://localhost:3000".into(),
        dev_auth_enabled: false,
        max_response_body_bytes: 5_242_880,
        filter_timeout_ms: 2000,
        dashboard_url: "/".into(),
        dashboard_origin: "*localhost*".into(),
        redis_url: None,
        default_rate_limit: 9999,
        default_rate_window_secs: 60,
        allow_org_creation: true,
        single_org_mode: None,
        app_host_suffix: None,
        api_host_suffix: None,
        session_cookie_domain: None,
        cloud_billing: false,
        stripe_secret_key: None,
        stripe_webhook_secret: None,
        stripe_eur_price_id: None,
        stripe_usd_price_id: None,
        stripe_eur_lookup_key: "overslash_seat_eur".into(),
        stripe_usd_lookup_key: "overslash_seat_usd".into(),
        stripe_api_base: "https://api.stripe.com/v1".into(),
    };
    let resolved = cache
        .resolve_user_budget(&pool, &config, org_id, user_id)
        .await;

    assert_eq!(resolved.max_requests, 250);
    assert_eq!(resolved.window_seconds, 60);
}

#[tokio::test]
async fn test_resolve_identity_cap_returns_none_when_unset() {
    use overslash_api::services::rate_limit::RateLimitConfigCache;
    use std::time::Duration;

    let pool = common::test_pool().await;
    let (_addr, _client) = common::start_api(pool.clone()).await;

    let org_id = Uuid::new_v4();
    sqlx::query("INSERT INTO orgs (id, name, slug) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind("test-org")
        .bind(format!("test-{}", Uuid::new_v4()))
        .execute(&pool)
        .await
        .unwrap();

    let identity_id = Uuid::new_v4();
    sqlx::query("INSERT INTO identities (id, org_id, name, kind) VALUES ($1, $2, $3, 'agent')")
        .bind(identity_id)
        .bind(org_id)
        .bind("test-agent")
        .execute(&pool)
        .await
        .unwrap();

    let cache = RateLimitConfigCache::new(Duration::from_secs(30));
    let resolved = cache.resolve_identity_cap(&pool, org_id, identity_id).await;
    assert!(resolved.is_none());
}

#[tokio::test]
async fn test_resolve_identity_cap_returns_some_when_set() {
    use overslash_api::services::rate_limit::RateLimitConfigCache;
    use std::time::Duration;

    let pool = common::test_pool().await;
    let (_addr, _client) = common::start_api(pool.clone()).await;

    let org_id = Uuid::new_v4();
    sqlx::query("INSERT INTO orgs (id, name, slug) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind("test-org")
        .bind(format!("test-{}", Uuid::new_v4()))
        .execute(&pool)
        .await
        .unwrap();

    let identity_id = Uuid::new_v4();
    sqlx::query("INSERT INTO identities (id, org_id, name, kind) VALUES ($1, $2, $3, 'agent')")
        .bind(identity_id)
        .bind(org_id)
        .bind("test-agent")
        .execute(&pool)
        .await
        .unwrap();

    overslash_db::OrgScope::new(org_id, pool.clone())
        .upsert_rate_limit("identity_cap", Some(identity_id), None, 7, 60)
        .await
        .unwrap();

    let cache = RateLimitConfigCache::new(Duration::from_secs(30));
    let resolved = cache
        .resolve_identity_cap(&pool, org_id, identity_id)
        .await
        .expect("identity cap should be set");
    assert_eq!(resolved.max_requests, 7);
    assert_eq!(resolved.window_seconds, 60);
}

#[tokio::test]
async fn test_in_memory_store_separate_keys_independent() {
    use overslash_api::services::rate_limit::{InMemoryRateLimitStore, RateLimitStore};

    let store = InMemoryRateLimitStore::new();

    // Saturate key A
    for _ in 0..3 {
        store.check_and_increment("a", 3, 60).await;
    }
    let a_blocked = store.check_and_increment("a", 3, 60).await;
    assert!(!a_blocked.allowed);

    // Key B is independent
    let b_allowed = store.check_and_increment("b", 3, 60).await;
    assert!(b_allowed.allowed);
    assert_eq!(b_allowed.remaining, 2);
}

#[tokio::test]
async fn test_in_memory_store_window_rolls_over() {
    use overslash_api::services::rate_limit::{InMemoryRateLimitStore, RateLimitStore};

    let store = InMemoryRateLimitStore::new();
    // Burn through a 1-second window
    for _ in 0..3 {
        store.check_and_increment("rollover", 3, 1).await;
    }
    let blocked = store.check_and_increment("rollover", 3, 1).await;
    assert!(!blocked.allowed);

    // Wait for the window to elapse
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let allowed = store.check_and_increment("rollover", 3, 1).await;
    assert!(allowed.allowed, "new window should reset the counter");
}

#[tokio::test]
async fn test_get_most_permissive_for_groups_picks_highest_throughput() {
    let pool = common::test_pool().await;
    let (_addr, _client) = common::start_api(pool.clone()).await;

    let org_id = Uuid::new_v4();
    sqlx::query("INSERT INTO orgs (id, name, slug) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind("test-org")
        .bind(format!("test-{}", Uuid::new_v4()))
        .execute(&pool)
        .await
        .unwrap();

    let g1 = Uuid::new_v4();
    let g2 = Uuid::new_v4();
    sqlx::query("INSERT INTO groups (id, org_id, name) VALUES ($1, $2, $3), ($4, $2, $5)")
        .bind(g1)
        .bind(org_id)
        .bind("g1")
        .bind(g2)
        .bind("g2")
        .execute(&pool)
        .await
        .unwrap();

    // g1: 200 / 3600s = 0.055/s
    // g2: 100 / 60s   = 1.667/s   ← higher throughput, should win
    overslash_db::OrgScope::new(org_id, pool.clone())
        .upsert_rate_limit("group", None, Some(g1), 200, 3600)
        .await
        .unwrap();
    overslash_db::OrgScope::new(org_id, pool.clone())
        .upsert_rate_limit("group", None, Some(g2), 100, 60)
        .await
        .unwrap();

    let row = overslash_db::OrgScope::new(org_id, pool.clone())
        .most_permissive_group_rate_limit(&[g1, g2])
        .await
        .unwrap()
        .expect("should find a group limit");

    assert_eq!(row.group_id, Some(g2));
    assert_eq!(row.max_requests, 100);
    assert_eq!(row.window_seconds, 60);
}

#[tokio::test]
async fn test_resolve_user_budget_per_user_override_wins() {
    use overslash_api::services::rate_limit::RateLimitConfigCache;
    use std::time::Duration;

    let pool = common::test_pool().await;
    let (_addr, _client) = common::start_api(pool.clone()).await;

    let org_id = Uuid::new_v4();
    sqlx::query("INSERT INTO orgs (id, name, slug) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind("test-org")
        .bind(format!("test-{}", Uuid::new_v4()))
        .execute(&pool)
        .await
        .unwrap();

    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO identities (id, org_id, name, kind) VALUES ($1, $2, $3, 'user')")
        .bind(user_id)
        .bind(org_id)
        .bind("test-user")
        .execute(&pool)
        .await
        .unwrap();

    // Org default + user override
    overslash_db::OrgScope::new(org_id, pool.clone())
        .upsert_rate_limit("org", None, None, 100, 60)
        .await
        .unwrap();
    overslash_db::OrgScope::new(org_id, pool.clone())
        .upsert_rate_limit("user", Some(user_id), None, 500, 60)
        .await
        .unwrap();

    let cache = RateLimitConfigCache::new(Duration::from_secs(30));
    let config = overslash_api::config::Config {
        host: "127.0.0.1".into(),
        port: 0,
        database_url: String::new(),
        secrets_encryption_key: "ab".repeat(32),
        signing_key: "cd".repeat(32),
        approval_expiry_secs: 1800,
        execution_pending_ttl_secs: 900,
        execution_replay_timeout_secs: 30,
        services_dir: "services".into(),
        google_auth_client_id: None,
        google_auth_client_secret: None,
        github_auth_client_id: None,
        github_auth_client_secret: None,
        public_url: "http://localhost:3000".into(),
        dev_auth_enabled: false,
        max_response_body_bytes: 5_242_880,
        filter_timeout_ms: 2000,
        dashboard_url: "/".into(),
        dashboard_origin: "*localhost*".into(),
        redis_url: None,
        default_rate_limit: 9999,
        default_rate_window_secs: 60,
        allow_org_creation: true,
        single_org_mode: None,
        app_host_suffix: None,
        api_host_suffix: None,
        session_cookie_domain: None,
        cloud_billing: false,
        stripe_secret_key: None,
        stripe_webhook_secret: None,
        stripe_eur_price_id: None,
        stripe_usd_price_id: None,
        stripe_eur_lookup_key: "overslash_seat_eur".into(),
        stripe_usd_lookup_key: "overslash_seat_usd".into(),
        stripe_api_base: "https://api.stripe.com/v1".into(),
    };
    let resolved = cache
        .resolve_user_budget(&pool, &config, org_id, user_id)
        .await;

    assert_eq!(
        resolved.max_requests, 500,
        "user override should win over org default"
    );
}

// ── Middleware end-to-end tests ─────────────────────────────────────
//
// These tests build a minimal Axum app with the rate_limit_middleware
// in front of an "echo" handler so we can exercise the middleware end-to-end:
// header parsing, identity resolution, two-counter check, 429 generation,
// and response header injection.

/// Build a test AppState with an in-memory rate limiter.
async fn make_app_state(pool: PgPool) -> overslash_api::AppState {
    let config = overslash_api::config::Config {
        host: "127.0.0.1".into(),
        port: 0,
        database_url: String::new(),
        secrets_encryption_key: "ab".repeat(32),
        signing_key: "cd".repeat(32),
        approval_expiry_secs: 1800,
        execution_pending_ttl_secs: 900,
        execution_replay_timeout_secs: 30,
        services_dir: "services".into(),
        google_auth_client_id: None,
        google_auth_client_secret: None,
        github_auth_client_id: None,
        github_auth_client_secret: None,
        public_url: "http://localhost:3000".into(),
        dev_auth_enabled: false,
        max_response_body_bytes: 5_242_880,
        filter_timeout_ms: 2000,
        dashboard_url: "/".into(),
        dashboard_origin: "*localhost*".into(),
        redis_url: None,
        default_rate_limit: 1000,
        default_rate_window_secs: 60,
        allow_org_creation: true,
        single_org_mode: None,
        app_host_suffix: None,
        api_host_suffix: None,
        session_cookie_domain: None,
        cloud_billing: false,
        stripe_secret_key: None,
        stripe_webhook_secret: None,
        stripe_eur_price_id: None,
        stripe_usd_price_id: None,
        stripe_eur_lookup_key: "overslash_seat_eur".into(),
        stripe_usd_lookup_key: "overslash_seat_usd".into(),
        stripe_api_base: "https://api.stripe.com/v1".into(),
    };
    overslash_api::AppState {
        db: pool,
        config,
        http_client: reqwest::Client::new(),
        registry: Arc::new(overslash_core::registry::ServiceRegistry::default()),
        rate_limiter: Arc::new(overslash_api::services::rate_limit::InMemoryRateLimitStore::new()),
        rate_limit_cache: Arc::new(
            overslash_api::services::rate_limit::RateLimitConfigCache::new(Duration::from_secs(30)),
        ),
        auth_code_store: overslash_api::services::oauth_as::AuthCodeStore::new(),
        pending_authorize_store: overslash_api::services::oauth_as::PendingAuthorizeStore::new(),
        embedder: std::sync::Arc::new(overslash_core::embeddings::DisabledEmbedder),
        embeddings_available: false,
        platform_registry: std::sync::Arc::new(
            overslash_api::services::platform_registry::build_registry(),
        ),
    }
}

/// Spawn an Axum server with the rate_limit_middleware in front of an echo handler.
/// Returns the bound address.
async fn spawn_middleware_app(state: overslash_api::AppState) -> SocketAddr {
    async fn echo() -> &'static str {
        "ok"
    }

    let app = Router::new()
        .route("/echo", get(echo))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            overslash_api::middleware::rate_limit::rate_limit_middleware,
        ))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// Create an org + user identity + user-bound API key directly in the DB.
/// Returns (org_id, user_id, raw_api_key).
async fn make_org_user_key(pool: &PgPool) -> (Uuid, Uuid, String) {
    let org_id = Uuid::new_v4();
    sqlx::query("INSERT INTO orgs (id, name, slug) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind("test-org")
        .bind(format!("test-{}", Uuid::new_v4()))
        .execute(pool)
        .await
        .unwrap();

    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO identities (id, org_id, name, kind) VALUES ($1, $2, $3, 'user')")
        .bind(user_id)
        .bind(org_id)
        .bind("test-user")
        .execute(pool)
        .await
        .unwrap();

    // Generate an API key. Format must be osk_<random>. The prefix (12 chars) is what
    // the middleware uses for the lookup; we hash the full key with argon2.
    let suffix: String = (0..32)
        .map(|_| {
            let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            chars[rand::rng().random_range(0..chars.len())] as char
        })
        .collect();
    let raw_key = format!("osk_{suffix}");
    let prefix = raw_key[..12].to_string();

    use argon2::{
        Argon2,
        password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
    };
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(raw_key.as_bytes(), &salt)
        .unwrap()
        .to_string();

    sqlx::query(
        "INSERT INTO api_keys (org_id, identity_id, name, key_hash, key_prefix, scopes)
         VALUES ($1, $2, $3, $4, $5, ARRAY[]::text[])",
    )
    .bind(org_id)
    .bind(user_id)
    .bind("test-key")
    .bind(&hash)
    .bind(&prefix)
    .execute(pool)
    .await
    .unwrap();

    (org_id, user_id, raw_key)
}

#[tokio::test]
async fn test_middleware_passes_through_without_auth() {
    let pool = common::test_pool().await;
    let state = make_app_state(pool).await;
    let addr = spawn_middleware_app(state).await;

    let resp = reqwest::get(format!("http://{addr}/echo")).await.unwrap();
    assert_eq!(resp.status(), 200);
    // No rate limit headers because middleware skipped (no auth header)
    assert!(resp.headers().get("x-ratelimit-limit").is_none());
}

#[tokio::test]
async fn test_middleware_passes_through_with_non_osk_auth() {
    let pool = common::test_pool().await;
    let state = make_app_state(pool).await;
    let addr = spawn_middleware_app(state).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{addr}/echo"))
        .header("authorization", "Bearer not-an-osk-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().get("x-ratelimit-limit").is_none());
}

#[tokio::test]
async fn test_middleware_passes_through_for_unknown_key() {
    let pool = common::test_pool().await;
    let state = make_app_state(pool).await;
    let addr = spawn_middleware_app(state).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{addr}/echo"))
        .header("authorization", "Bearer osk_unknown_prefix_xxxxxxxxxxxx")
        .send()
        .await
        .unwrap();
    // Unknown key → middleware skips, handler runs (200)
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().get("x-ratelimit-limit").is_none());
}

#[tokio::test]
async fn test_middleware_attaches_headers_for_known_key() {
    let pool = common::test_pool().await;
    let (_org_id, _user_id, raw_key) = make_org_user_key(&pool).await;
    let state = make_app_state(pool).await;
    let addr = spawn_middleware_app(state).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{addr}/echo"))
        .header("authorization", format!("Bearer {raw_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let limit = resp.headers().get("x-ratelimit-limit").unwrap();
    let remaining = resp.headers().get("x-ratelimit-remaining").unwrap();
    let reset = resp.headers().get("x-ratelimit-reset").unwrap();
    assert_eq!(limit.to_str().unwrap(), "1000");
    assert_eq!(remaining.to_str().unwrap(), "999");
    assert!(reset.to_str().unwrap().parse::<u64>().is_ok());
}

#[tokio::test]
async fn test_middleware_returns_429_when_user_bucket_exhausted() {
    let pool = common::test_pool().await;
    let (org_id, user_id, raw_key) = make_org_user_key(&pool).await;

    // Set a tiny user budget: 2 requests per minute
    overslash_db::OrgScope::new(org_id, pool.clone())
        .upsert_rate_limit("user", Some(user_id), None, 2, 60)
        .await
        .unwrap();

    let state = make_app_state(pool).await;
    let addr = spawn_middleware_app(state).await;
    let client = reqwest::Client::new();

    // First two requests should succeed
    for i in 0..2 {
        let resp = client
            .get(format!("http://{addr}/echo"))
            .header("authorization", format!("Bearer {raw_key}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "request {i} should succeed");
    }

    // Third should be rate-limited
    let resp = client
        .get(format!("http://{addr}/echo"))
        .header("authorization", format!("Bearer {raw_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429);
    assert_eq!(
        resp.headers()
            .get("x-ratelimit-limit")
            .unwrap()
            .to_str()
            .unwrap(),
        "2"
    );
    assert_eq!(
        resp.headers()
            .get("x-ratelimit-remaining")
            .unwrap()
            .to_str()
            .unwrap(),
        "0"
    );
    assert!(resp.headers().get("retry-after").is_some());
    assert!(resp.headers().get("x-ratelimit-reset").is_some());

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "rate limit exceeded");
}

#[tokio::test]
async fn test_middleware_identity_cap_kicks_in_before_user_bucket() {
    let pool = common::test_pool().await;
    let (org_id, user_id, raw_key) = make_org_user_key(&pool).await;

    // User bucket: 1000/min (generous), identity cap: 1/min (tight)
    overslash_db::OrgScope::new(org_id, pool.clone())
        .upsert_rate_limit("identity_cap", Some(user_id), None, 1, 60)
        .await
        .unwrap();

    let state = make_app_state(pool).await;
    let addr = spawn_middleware_app(state).await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("http://{addr}/echo"))
        .header("authorization", format!("Bearer {raw_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = client
        .get(format!("http://{addr}/echo"))
        .header("authorization", format!("Bearer {raw_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429, "identity cap should kick in");
}

#[tokio::test]
async fn test_middleware_skips_expired_key() {
    let pool = common::test_pool().await;
    let (_org_id, _user_id, raw_key) = make_org_user_key(&pool).await;

    // Mark the key as expired
    let prefix = &raw_key[..12];
    sqlx::query("UPDATE api_keys SET expires_at = now() - INTERVAL '1 hour' WHERE key_prefix = $1")
        .bind(prefix)
        .execute(&pool)
        .await
        .unwrap();

    let state = make_app_state(pool).await;
    let addr = spawn_middleware_app(state).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{addr}/echo"))
        .header("authorization", format!("Bearer {raw_key}"))
        .send()
        .await
        .unwrap();
    // Expired key → middleware skips, handler runs (echo doesn't check auth)
    assert_eq!(resp.status(), 200);
    // No headers because middleware bailed out before counting
    assert!(resp.headers().get("x-ratelimit-limit").is_none());
}

// ── Unit tests for extract_osk_prefix ───────────────────────────────

#[test]
fn test_extract_osk_prefix_valid() {
    use axum::body::Body;
    let req = axum::http::Request::builder()
        .header("authorization", "Bearer osk_abcdefgh1234567890")
        .body(Body::empty())
        .unwrap();
    let prefix = overslash_api::middleware::rate_limit::extract_osk_prefix(&req);
    assert_eq!(prefix.as_deref(), Some("osk_abcdefgh"));
}

#[test]
fn test_extract_osk_prefix_no_header() {
    use axum::body::Body;
    let req = axum::http::Request::builder().body(Body::empty()).unwrap();
    let prefix = overslash_api::middleware::rate_limit::extract_osk_prefix(&req);
    assert!(prefix.is_none());
}

#[test]
fn test_extract_osk_prefix_no_bearer() {
    use axum::body::Body;
    let req = axum::http::Request::builder()
        .header("authorization", "Basic abcd")
        .body(Body::empty())
        .unwrap();
    let prefix = overslash_api::middleware::rate_limit::extract_osk_prefix(&req);
    assert!(prefix.is_none());
}

#[test]
fn test_extract_osk_prefix_wrong_scheme() {
    use axum::body::Body;
    let req = axum::http::Request::builder()
        .header("authorization", "Bearer xyz_notanoskkey")
        .body(Body::empty())
        .unwrap();
    let prefix = overslash_api::middleware::rate_limit::extract_osk_prefix(&req);
    assert!(prefix.is_none());
}

#[test]
fn test_extract_osk_prefix_too_short() {
    use axum::body::Body;
    let req = axum::http::Request::builder()
        .header("authorization", "Bearer osk_abc") // < 12 chars
        .body(Body::empty())
        .unwrap();
    let prefix = overslash_api::middleware::rate_limit::extract_osk_prefix(&req);
    assert!(prefix.is_none());
}

#[test]
fn test_extract_osk_prefix_non_ascii_header() {
    use axum::body::Body;
    // Headers with bytes that fail to_str() should yield None
    let req = axum::http::Request::builder()
        .header(
            "authorization",
            axum::http::HeaderValue::from_bytes(b"Bearer \xff\xfe\xfd").unwrap(),
        )
        .body(Body::empty())
        .unwrap();
    let prefix = overslash_api::middleware::rate_limit::extract_osk_prefix(&req);
    assert!(prefix.is_none());
}

#[tokio::test]
async fn test_cache_invalidation_user_budget() {
    use overslash_api::services::rate_limit::RateLimitConfigCache;

    let pool = common::test_pool().await;
    let (_addr, _client) = common::start_api(pool.clone()).await;

    let org_id = Uuid::new_v4();
    sqlx::query("INSERT INTO orgs (id, name, slug) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind("o")
        .bind(format!("test-{}", Uuid::new_v4()))
        .execute(&pool)
        .await
        .unwrap();

    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO identities (id, org_id, name, kind) VALUES ($1, $2, $3, 'user')")
        .bind(user_id)
        .bind(org_id)
        .bind("u")
        .execute(&pool)
        .await
        .unwrap();

    overslash_db::OrgScope::new(org_id, pool.clone())
        .upsert_rate_limit("user", Some(user_id), None, 100, 60)
        .await
        .unwrap();

    let cache = RateLimitConfigCache::new(Duration::from_secs(300));
    let config = overslash_api::config::Config {
        host: "127.0.0.1".into(),
        port: 0,
        database_url: String::new(),
        secrets_encryption_key: "ab".repeat(32),
        signing_key: "cd".repeat(32),
        approval_expiry_secs: 1800,
        execution_pending_ttl_secs: 900,
        execution_replay_timeout_secs: 30,
        services_dir: "services".into(),
        google_auth_client_id: None,
        google_auth_client_secret: None,
        github_auth_client_id: None,
        github_auth_client_secret: None,
        public_url: "http://localhost:3000".into(),
        dev_auth_enabled: false,
        max_response_body_bytes: 5_242_880,
        filter_timeout_ms: 2000,
        dashboard_url: "/".into(),
        dashboard_origin: "*localhost*".into(),
        redis_url: None,
        default_rate_limit: 9999,
        default_rate_window_secs: 60,
        allow_org_creation: true,
        single_org_mode: None,
        app_host_suffix: None,
        api_host_suffix: None,
        session_cookie_domain: None,
        cloud_billing: false,
        stripe_secret_key: None,
        stripe_webhook_secret: None,
        stripe_eur_price_id: None,
        stripe_usd_price_id: None,
        stripe_eur_lookup_key: "overslash_seat_eur".into(),
        stripe_usd_lookup_key: "overslash_seat_usd".into(),
        stripe_api_base: "https://api.stripe.com/v1".into(),
    };

    // Prime the cache
    let r1 = cache
        .resolve_user_budget(&pool, &config, org_id, user_id)
        .await;
    assert_eq!(r1.max_requests, 100);

    // Update the limit in DB
    overslash_db::OrgScope::new(org_id, pool.clone())
        .upsert_rate_limit("user", Some(user_id), None, 555, 60)
        .await
        .unwrap();

    // Without invalidation, cache still returns the stale value
    let r2 = cache
        .resolve_user_budget(&pool, &config, org_id, user_id)
        .await;
    assert_eq!(r2.max_requests, 100, "stale cache hit");

    // Invalidate, then re-resolve
    cache.invalidate_user_budget(org_id, user_id);
    let r3 = cache
        .resolve_user_budget(&pool, &config, org_id, user_id)
        .await;
    assert_eq!(r3.max_requests, 555, "fresh value after invalidation");
}

#[tokio::test]
async fn test_cache_invalidation_identity_cap() {
    use overslash_api::services::rate_limit::RateLimitConfigCache;

    let pool = common::test_pool().await;
    let (_addr, _client) = common::start_api(pool.clone()).await;

    let org_id = Uuid::new_v4();
    sqlx::query("INSERT INTO orgs (id, name, slug) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind("o")
        .bind(format!("test-{}", Uuid::new_v4()))
        .execute(&pool)
        .await
        .unwrap();

    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO identities (id, org_id, name, kind) VALUES ($1, $2, $3, 'agent')")
        .bind(id)
        .bind(org_id)
        .bind("a")
        .execute(&pool)
        .await
        .unwrap();

    let cache = RateLimitConfigCache::new(Duration::from_secs(300));

    // No cap → cached as None
    assert!(
        cache
            .resolve_identity_cap(&pool, org_id, id)
            .await
            .is_none()
    );

    // Set a cap
    overslash_db::OrgScope::new(org_id, pool.clone())
        .upsert_rate_limit("identity_cap", Some(id), None, 7, 60)
        .await
        .unwrap();

    // Cache still returns None (stale)
    assert!(
        cache
            .resolve_identity_cap(&pool, org_id, id)
            .await
            .is_none()
    );

    // Invalidate → fresh value
    cache.invalidate_identity_cap(org_id, id);
    let cap = cache
        .resolve_identity_cap(&pool, org_id, id)
        .await
        .expect("cap should exist after invalidation");
    assert_eq!(cap.max_requests, 7);
}

#[tokio::test]
async fn test_cache_invalidation_org_flushes_all() {
    use overslash_api::services::rate_limit::RateLimitConfigCache;

    let pool = common::test_pool().await;
    let (_addr, _client) = common::start_api(pool.clone()).await;

    let org_id = Uuid::new_v4();
    sqlx::query("INSERT INTO orgs (id, name, slug) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind("o")
        .bind(format!("test-{}", Uuid::new_v4()))
        .execute(&pool)
        .await
        .unwrap();

    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO identities (id, org_id, name, kind) VALUES ($1, $2, $3, 'user')")
        .bind(user_id)
        .bind(org_id)
        .bind("u")
        .execute(&pool)
        .await
        .unwrap();

    overslash_db::OrgScope::new(org_id, pool.clone())
        .upsert_rate_limit("org", None, None, 100, 60)
        .await
        .unwrap();

    let cache = RateLimitConfigCache::new(Duration::from_secs(300));
    let config = overslash_api::config::Config {
        host: "127.0.0.1".into(),
        port: 0,
        database_url: String::new(),
        secrets_encryption_key: "ab".repeat(32),
        signing_key: "cd".repeat(32),
        approval_expiry_secs: 1800,
        execution_pending_ttl_secs: 900,
        execution_replay_timeout_secs: 30,
        services_dir: "services".into(),
        google_auth_client_id: None,
        google_auth_client_secret: None,
        github_auth_client_id: None,
        github_auth_client_secret: None,
        public_url: "http://localhost:3000".into(),
        dev_auth_enabled: false,
        max_response_body_bytes: 5_242_880,
        filter_timeout_ms: 2000,
        dashboard_url: "/".into(),
        dashboard_origin: "*localhost*".into(),
        redis_url: None,
        default_rate_limit: 9999,
        default_rate_window_secs: 60,
        allow_org_creation: true,
        single_org_mode: None,
        app_host_suffix: None,
        api_host_suffix: None,
        session_cookie_domain: None,
        cloud_billing: false,
        stripe_secret_key: None,
        stripe_webhook_secret: None,
        stripe_eur_price_id: None,
        stripe_usd_price_id: None,
        stripe_eur_lookup_key: "overslash_seat_eur".into(),
        stripe_usd_lookup_key: "overslash_seat_usd".into(),
        stripe_api_base: "https://api.stripe.com/v1".into(),
    };

    let r1 = cache
        .resolve_user_budget(&pool, &config, org_id, user_id)
        .await;
    assert_eq!(r1.max_requests, 100);

    // Update the org default
    overslash_db::OrgScope::new(org_id, pool.clone())
        .upsert_rate_limit("org", None, None, 999, 60)
        .await
        .unwrap();

    // Stale cache hit
    let r2 = cache
        .resolve_user_budget(&pool, &config, org_id, user_id)
        .await;
    assert_eq!(r2.max_requests, 100);

    // invalidate_org flushes everything for the org
    cache.invalidate_org(org_id);
    let r3 = cache
        .resolve_user_budget(&pool, &config, org_id, user_id)
        .await;
    assert_eq!(r3.max_requests, 999);
}

// (Removed) make_org_unbound_key + test_middleware_org_unbound_key_uses_org_bucket
// Migration 028 enforces api_keys.identity_id NOT NULL: a "naked org key" can
// no longer exist, so the scenario this test guarded against (an org-unbound
// key being charged to the org-default rate-limit bucket) is unreachable.
