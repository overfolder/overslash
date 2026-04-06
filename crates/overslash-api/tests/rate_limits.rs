mod common;

use serde_json::{Value, json};
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
    overslash_db::repos::rate_limit::upsert(&pool, org_id, "org", None, None, 250, 60)
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
        services_dir: "services".into(),
        google_auth_client_id: None,
        google_auth_client_secret: None,
        github_auth_client_id: None,
        github_auth_client_secret: None,
        public_url: "http://localhost:3000".into(),
        dev_auth_enabled: false,
        max_response_body_bytes: 5_242_880,
        dashboard_url: "/".into(),
        redis_url: None,
        default_rate_limit: 9999,
        default_rate_window_secs: 60,
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

    overslash_db::repos::rate_limit::upsert(
        &pool,
        org_id,
        "identity_cap",
        Some(identity_id),
        None,
        7,
        60,
    )
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
    overslash_db::repos::rate_limit::upsert(&pool, org_id, "group", None, Some(g1), 200, 3600)
        .await
        .unwrap();
    overslash_db::repos::rate_limit::upsert(&pool, org_id, "group", None, Some(g2), 100, 60)
        .await
        .unwrap();

    let row =
        overslash_db::repos::rate_limit::get_most_permissive_for_groups(&pool, org_id, &[g1, g2])
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
    overslash_db::repos::rate_limit::upsert(&pool, org_id, "org", None, None, 100, 60)
        .await
        .unwrap();
    overslash_db::repos::rate_limit::upsert(&pool, org_id, "user", Some(user_id), None, 500, 60)
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
        services_dir: "services".into(),
        google_auth_client_id: None,
        google_auth_client_secret: None,
        github_auth_client_id: None,
        github_auth_client_secret: None,
        public_url: "http://localhost:3000".into(),
        dev_auth_enabled: false,
        max_response_body_bytes: 5_242_880,
        dashboard_url: "/".into(),
        redis_url: None,
        default_rate_limit: 9999,
        default_rate_window_secs: 60,
    };
    let resolved = cache
        .resolve_user_budget(&pool, &config, org_id, user_id)
        .await;

    assert_eq!(
        resolved.max_requests, 500,
        "user override should win over org default"
    );
}
