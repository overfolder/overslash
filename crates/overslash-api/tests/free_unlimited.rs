// Integration tests for the `free_unlimited` org tier — set out-of-band by
// an operator (`UPDATE orgs SET plan='free_unlimited'`). Exercises both the
// rate-limit middleware bypass and the synthetic `/v1/orgs/{id}/subscription`
// response.

#![allow(clippy::disallowed_methods)]

use crate::common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{Router, routing::get};
use serde_json::Value;
use sqlx::PgPool;
use tokio::net::TcpListener;
use uuid::Uuid;

// ── Helpers (mirrors rate_limits.rs) ─────────────────────────────────

// `make_app_state` now lives in `common` — three files wanted it.
use crate::common::make_app_state;

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

async fn make_org_user_key(pool: &PgPool, is_personal: bool) -> (Uuid, Uuid, String) {
    common::seed_org_user_key(
        pool,
        common::SeedOptions {
            is_personal,
            is_admin: false,
        },
    )
    .await
}

async fn set_plan(pool: &PgPool, org_id: Uuid, plan: &str) {
    sqlx::query("UPDATE orgs SET plan = $2 WHERE id = $1")
        .bind(org_id)
        .bind(plan)
        .execute(pool)
        .await
        .unwrap();
}

// ── Tests ────────────────────────────────────────────────────────────

#[tokio::test]
async fn free_unlimited_bypasses_rate_limit() {
    let pool = common::test_pool().await;
    let (org_id, user_id, raw_key) = make_org_user_key(&pool, false).await;

    // Tight budget that would block almost immediately for a standard org.
    overslash_db::OrgScope::new(org_id, pool.clone())
        .upsert_rate_limit("user", Some(user_id), None, 2, 60)
        .await
        .unwrap();

    set_plan(&pool, org_id, "free_unlimited").await;

    let state = make_app_state(pool).await;
    let addr = spawn_middleware_app(state).await;
    let client = reqwest::Client::new();

    // Fire 5 requests — 3 past the 2-request budget — all must succeed.
    for i in 0..5 {
        let resp = client
            .get(format!("http://{addr}/echo"))
            .header("authorization", format!("Bearer {raw_key}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "request {i} should succeed");
        assert_eq!(
            resp.headers()
                .get("x-ratelimit-limit")
                .unwrap()
                .to_str()
                .unwrap(),
            "unlimited"
        );
        assert_eq!(
            resp.headers()
                .get("x-ratelimit-remaining")
                .unwrap()
                .to_str()
                .unwrap(),
            "unlimited"
        );
        // Reset header is intentionally absent for unlimited bypass.
        assert!(resp.headers().get("x-ratelimit-reset").is_none());
    }
}

#[tokio::test]
async fn standard_org_still_rate_limited() {
    // Control case: identical setup, plan stays 'standard'. Verifies the
    // bypass really is gated on the column and we haven't accidentally
    // disabled rate limits everywhere.
    let pool = common::test_pool().await;
    let (org_id, user_id, raw_key) = make_org_user_key(&pool, false).await;

    overslash_db::OrgScope::new(org_id, pool.clone())
        .upsert_rate_limit("user", Some(user_id), None, 2, 60)
        .await
        .unwrap();

    let state = make_app_state(pool).await;
    let addr = spawn_middleware_app(state).await;
    let client = reqwest::Client::new();

    for _ in 0..2 {
        let resp = client
            .get(format!("http://{addr}/echo"))
            .header("authorization", format!("Bearer {raw_key}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

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
}

#[tokio::test]
async fn cache_invalidation_propagates_plan_change() {
    let pool = common::test_pool().await;
    let (org_id, user_id, raw_key) = make_org_user_key(&pool, false).await;

    overslash_db::OrgScope::new(org_id, pool.clone())
        .upsert_rate_limit("user", Some(user_id), None, 2, 60)
        .await
        .unwrap();

    // Use a 5-minute TTL so the cache wouldn't expire on its own during
    // the test; only an explicit `invalidate()` call should propagate.
    let mut state = make_app_state(pool.clone()).await;
    state.free_unlimited_cache = Arc::new(
        overslash_api::services::billing_tier::FreeUnlimitedCache::new(Duration::from_secs(300)),
    );

    set_plan(&pool, org_id, "free_unlimited").await;
    let cache = state.free_unlimited_cache.clone();
    let addr = spawn_middleware_app(state).await;
    let client = reqwest::Client::new();

    // Warm the cache as `free_unlimited`.
    let resp = client
        .get(format!("http://{addr}/echo"))
        .header("authorization", format!("Bearer {raw_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("x-ratelimit-limit")
            .unwrap()
            .to_str()
            .unwrap(),
        "unlimited"
    );

    // Flip back to standard. Without invalidation, cached state lingers.
    set_plan(&pool, org_id, "standard").await;

    // Sanity check: cache still says unlimited (3 more calls, all 200 with
    // `unlimited` headers — would otherwise tick down toward 429 quickly).
    for _ in 0..3 {
        let resp = client
            .get(format!("http://{addr}/echo"))
            .header("authorization", format!("Bearer {raw_key}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers()
                .get("x-ratelimit-limit")
                .unwrap()
                .to_str()
                .unwrap(),
            "unlimited"
        );
    }

    cache.invalidate(org_id);

    // First two post-invalidate requests fall under the 2/min user budget
    // and succeed; the third must return 429.
    for _ in 0..2 {
        let resp = client
            .get(format!("http://{addr}/echo"))
            .header("authorization", format!("Bearer {raw_key}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers()
                .get("x-ratelimit-limit")
                .unwrap()
                .to_str()
                .unwrap(),
            "2"
        );
    }
    let resp = client
        .get(format!("http://{addr}/echo"))
        .header("authorization", format!("Bearer {raw_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429);
}

#[tokio::test]
async fn personal_org_can_be_free_unlimited() {
    // `is_personal` is independent of `plan`. Operators can grant the
    // courtesy tier to a personal org if they choose.
    let pool = common::test_pool().await;
    let (org_id, user_id, raw_key) = make_org_user_key(&pool, true).await;

    overslash_db::OrgScope::new(org_id, pool.clone())
        .upsert_rate_limit("user", Some(user_id), None, 1, 60)
        .await
        .unwrap();

    set_plan(&pool, org_id, "free_unlimited").await;

    let state = make_app_state(pool).await;
    let addr = spawn_middleware_app(state).await;
    let client = reqwest::Client::new();

    for i in 0..3 {
        let resp = client
            .get(format!("http://{addr}/echo"))
            .header("authorization", format!("Bearer {raw_key}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            200,
            "personal-org request {i} should succeed"
        );
        assert_eq!(
            resp.headers()
                .get("x-ratelimit-limit")
                .unwrap()
                .to_str()
                .unwrap(),
            "unlimited"
        );
    }
}

#[tokio::test]
async fn subscription_endpoint_returns_synthetic_body() {
    // Full API path — the dashboard's billing card depends on this endpoint
    // returning 200 (not 404) for free-unlimited orgs. The `/v1/orgs/.../
    // subscription` route is only mounted when `cloud_billing=true`, which
    // is the only mode where this endpoint matters in the first place.
    //
    // We bypass `POST /v1/orgs` (it 403s when cloud_billing is on) and seed
    // an org + admin identity + key directly, then start the API with the
    // billing routes mounted.
    let pool = common::test_pool().await;
    let (org_id, _user_id, raw_key) = common::seed_org_user_key(
        &pool,
        common::SeedOptions {
            is_personal: false,
            is_admin: true,
        },
    )
    .await;
    set_plan(&pool, org_id, "free_unlimited").await;

    let (addr, client) = common::start_api_with(pool.clone(), |cfg| {
        cfg.cloud_billing = true;
    })
    .await;
    let base = format!("http://{addr}");

    let resp = client
        .get(format!("{base}/v1/orgs/{org_id}/subscription"))
        .header("authorization", format!("Bearer {raw_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["plan"], "free_unlimited");
    assert_eq!(body["status"], "active");
    assert_eq!(body["seats"], 0);
    assert_eq!(body["currency"], "");
    assert!(body["current_period_end"].is_null());
    assert_eq!(body["cancel_at_period_end"], false);
}
