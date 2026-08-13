// Integration tests for org trial mode.
//
// Two mechanisms are exercised:
//  - the instance-admin-managed trial tier (`plan='trial'` + `trial_ends_at`,
//    started/extended via the instance-admin endpoints), and
//  - its surfacing through `/v1/orgs/{id}/subscription` and
//    `/auth/me/identity`.
//
// The banner-only enforcement policy (DECISIONS D25) is proven by
// `expired_trial_is_not_blocked_and_not_unlimited`: an expired trial keeps
// working and is still subject to normal rate limits (it is NOT free_unlimited).

#![allow(clippy::disallowed_methods)]

use crate::common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{Router, routing::get};
use overslash_api::services::jwt;
use overslash_db::repos::user as user_repo;
use serde_json::{Value, json};
use sqlx::PgPool;
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::net::TcpListener;
use uuid::Uuid;

// ── Helpers ──────────────────────────────────────────────────────────

/// Mint a dashboard session JWT carrying `user_id` (copied from
/// instance_admin.rs — matches the production mint flow).
fn mint_session_with_user(org_id: Uuid, identity_id: Uuid, user_id: Uuid) -> String {
    let secret = hex::decode("cd".repeat(32)).expect("valid hex");
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = jwt::Claims {
        sub: identity_id,
        org: org_id,
        email: "trial-test@example.com".into(),
        aud: jwt::AUD_SESSION.into(),
        iat: now,
        exp: now + 3600,
        user_id: Some(user_id),
        mcp_client_id: None,
    };
    jwt::mint(&secret, &claims).expect("mint jwt")
}

/// Create an Overslash-backed user + non-personal org + admin identity.
/// Returns `(user_id, org_id, identity_id)`.
async fn make_overslash_user_with_org(pool: &PgPool, email: &str) -> (Uuid, Uuid, Uuid) {
    let subject = format!("subj-{}", Uuid::new_v4());
    let user = user_repo::create_overslash_backed(
        pool,
        Some(email),
        Some("Test User"),
        "google",
        &subject,
    )
    .await
    .unwrap();
    let org = overslash_db::repos::org::create(
        pool,
        "Trial Org",
        &format!("trial-{}", Uuid::new_v4().simple()),
        "standard",
    )
    .await
    .unwrap();
    let ident = overslash_db::repos::identity::create_with_email(
        pool,
        org.id,
        "Test User",
        "user",
        None,
        Some(email),
        serde_json::json!({}),
    )
    .await
    .unwrap();
    overslash_db::repos::identity::set_user_id(pool, org.id, ident.id, Some(user.id))
        .await
        .unwrap();
    overslash_db::repos::identity::set_is_org_admin(pool, org.id, ident.id, true)
        .await
        .unwrap();
    (user.id, org.id, ident.id)
}

/// Set plan + trial_ends_at directly (bypasses the endpoints / cache).
async fn force_trial(pool: &PgPool, org_id: Uuid, ends_at: OffsetDateTime) {
    sqlx::query("UPDATE orgs SET plan = 'trial', trial_ends_at = $2 WHERE id = $1")
        .bind(org_id)
        .bind(ends_at)
        .execute(pool)
        .await
        .unwrap();
}

async fn read_billing(pool: &PgPool, org_id: Uuid) -> (String, Option<OffsetDateTime>) {
    overslash_db::repos::org::get_billing(pool, org_id)
        .await
        .unwrap()
        .expect("org exists")
}

// make_app_state / spawn_middleware_app mirror free_unlimited.rs so the
// banner-only test can drive the rate-limit middleware in isolation.
async fn make_app_state(pool: PgPool) -> overslash_api::AppState {
    let config = overslash_api::config::Config {
        async_execution: Default::default(),
        call_stream_idle_timeout_ms: 30_000,
        call_timeout_max_ms: 110_000,
        call_timeout_ms: 30_000,
        host: "127.0.0.1".into(),
        port: 0,
        database_url: String::new(),
        db_max_connections: 5,
        db_min_connections: 1,
        db_acquire_timeout_secs: 10,
        events_stream_max_connection_secs: 30,
        live_map_enabled: false,
        db_background_max_connections: 2,
        secrets_encryption_key: "ab".repeat(32),
        secrets_encryption_key_previous: None,
        secrets_encryption_key_active_id: 1,
        secrets_encryption_key_previous_id: 0,
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
        magic_link_enabled: true,
        max_response_body_bytes: 5_242_880,
        audit_response_body_max_bytes: 65_536,
        filter_timeout_ms: 2000,
        download_token_ttl_secs: 900,
        call_result_max_bytes: 1024 * 1024,
        dashboard_url: "/".into(),
        dashboard_origin: "*localhost*".into(),
        mcp_extra_origins: String::new(),
        redis_url: None,
        resolve_cache_ttl_secs: 300,
        resolve_cache_negative_ttl_secs: 30,
        resolve_cache_scope_ttl_max_secs: 300,
        resolve_cache_timeout_ms: 100,
        resolve_cache_max_entries: 10_000,
        resolve_cache_namespace: None,
        default_rate_limit: 1000,
        default_rate_window_secs: 60,
        allow_org_creation: true,
        trial_default_duration_days: 30,
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
        service_base_overrides: std::collections::HashMap::new(),
        platform_credential: None,
        oversla_sh_base_url: None,
        oversla_sh_api_key: None,
        email_provider: None,
        email_from: None,
        email_reply_to: None,
        email_api_key: None,
        preview_origin_allowlist: None,
        overslash_env: None,
        connection_return_url_allowed_hosts: Vec::new(),
    };
    let free_unlimited_cache = Arc::new(
        overslash_api::services::billing_tier::FreeUnlimitedCache::new(Duration::from_millis(1)),
    );
    overslash_api::AppState {
        db: pool,
        config,
        http_client: reqwest::Client::new(),
        registry: Arc::new(overslash_core::registry::ServiceRegistry::default()),
        rate_limiter: Arc::new(overslash_api::services::rate_limit::InMemoryRateLimitStore::new()),
        rate_limit_cache: Arc::new(
            overslash_api::services::rate_limit::RateLimitConfigCache::new(Duration::from_secs(30)),
        ),
        free_unlimited_cache,
        auth_code_store: overslash_api::services::oauth_as::AuthCodeStore::new(),
        pending_authorize_store: overslash_api::services::oauth_as::PendingAuthorizeStore::new(),
        embedder: std::sync::Arc::new(overslash_core::embeddings::DisabledEmbedder),
        embeddings_available: false,
        platform_registry: std::sync::Arc::new(
            overslash_api::services::platform_registry::build_registry(),
        ),
        mailer: std::sync::Arc::new(overslash_core::email::NoopMailer),
        event_bus: overslash_api::services::events::EventBus::new(),
        resolve_cache: overslash_api::services::resolve_cache::in_memory(10_000),
        test_resources: None,
        background_db: None,
    }
}

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

// ── Repo tests ───────────────────────────────────────────────────────

#[tokio::test]
async fn set_trial_sets_plan_and_end() {
    let pool = common::test_pool().await;
    let (_u, org_id, _i) = make_overslash_user_with_org(&pool, "repo-set@example.com").await;

    let ends = OffsetDateTime::now_utc() + TimeDuration::days(30);
    assert!(
        overslash_db::repos::org::set_trial(&pool, org_id, ends)
            .await
            .unwrap()
    );

    let (plan, trial_ends_at) = read_billing(&pool, org_id).await;
    assert_eq!(plan, "trial");
    let stored = trial_ends_at.expect("trial_ends_at set");
    assert!((stored - ends).abs() < TimeDuration::seconds(1));
}

#[tokio::test]
async fn extend_trial_only_affects_trial_orgs() {
    let pool = common::test_pool().await;
    let (_u, org_id, _i) = make_overslash_user_with_org(&pool, "repo-extend@example.com").await;

    // Standard org: extend is a no-op (guarded by `AND plan='trial'`).
    let ends = OffsetDateTime::now_utc() + TimeDuration::days(10);
    assert!(
        !overslash_db::repos::org::extend_trial(&pool, org_id, ends)
            .await
            .unwrap()
    );
    assert_eq!(read_billing(&pool, org_id).await.0, "standard");

    // On a trial: it moves the window.
    overslash_db::repos::org::set_trial(&pool, org_id, ends)
        .await
        .unwrap();
    let later = ends + TimeDuration::days(15);
    assert!(
        overslash_db::repos::org::extend_trial(&pool, org_id, later)
            .await
            .unwrap()
    );
    let stored = read_billing(&pool, org_id).await.1.unwrap();
    assert!((stored - later).abs() < TimeDuration::seconds(1));
}

#[tokio::test]
async fn set_plan_free_unlimited_clears_trial() {
    let pool = common::test_pool().await;
    let (_u, org_id, _i) = make_overslash_user_with_org(&pool, "repo-plan@example.com").await;
    force_trial(
        &pool,
        org_id,
        OffsetDateTime::now_utc() + TimeDuration::days(30),
    )
    .await;

    assert!(
        overslash_db::repos::org::set_plan(&pool, org_id, "free_unlimited")
            .await
            .unwrap()
    );
    let (plan, trial_ends_at) = read_billing(&pool, org_id).await;
    assert_eq!(plan, "free_unlimited");
    assert!(trial_ends_at.is_none(), "trial_ends_at should be cleared");
}

// ── Instance-admin endpoint tests ────────────────────────────────────

#[tokio::test]
async fn start_trial_sets_plan_and_audits() {
    let pool = common::test_pool().await;
    let (user_id, admin_org, admin_ident) =
        make_overslash_user_with_org(&pool, "admin-start@example.com").await;
    user_repo::set_instance_admin(&pool, user_id, true)
        .await
        .unwrap();

    // A separate target org the admin puts on a trial.
    let target = overslash_db::repos::org::create(
        &pool,
        "Target",
        &format!("target-{}", Uuid::new_v4().simple()),
        "standard",
    )
    .await
    .unwrap();

    let (addr, client) = common::start_api(pool.clone()).await;
    let cookie = mint_session_with_user(admin_org, admin_ident, user_id);

    let resp = client
        .post(format!("http://{addr}/v1/orgs/{}/trial", target.id))
        .header("cookie", format!("oss_session={cookie}"))
        .json(&json!({ "duration_days": 14 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "body: {:?}", resp.text().await);

    let (plan, ends) = read_billing(&pool, target.id).await;
    assert_eq!(plan, "trial");
    let ends = ends.unwrap();
    let expected = OffsetDateTime::now_utc() + TimeDuration::days(14);
    assert!((ends - expected).abs() < TimeDuration::minutes(1));

    let detail: Value = sqlx::query_scalar(
        "SELECT detail FROM audit_log WHERE org_id = $1 AND action = 'org.trial_started'",
    )
    .bind(target.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(detail["duration_days"], 14);
    assert_eq!(detail["set_by_instance_admin"], user_id.to_string());
}

#[tokio::test]
async fn start_trial_defaults_to_config_duration() {
    let pool = common::test_pool().await;
    let (user_id, admin_org, admin_ident) =
        make_overslash_user_with_org(&pool, "admin-default@example.com").await;
    user_repo::set_instance_admin(&pool, user_id, true)
        .await
        .unwrap();

    let (addr, client) = common::start_api(pool.clone()).await;
    let cookie = mint_session_with_user(admin_org, admin_ident, user_id);

    // Empty body → config default (30d in the test config).
    let resp = client
        .post(format!("http://{addr}/v1/orgs/{admin_org}/trial"))
        .header("cookie", format!("oss_session={cookie}"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let ends = read_billing(&pool, admin_org).await.1.unwrap();
    let expected = OffsetDateTime::now_utc() + TimeDuration::days(30);
    assert!((ends - expected).abs() < TimeDuration::minutes(1));
}

#[tokio::test]
async fn start_trial_rejects_non_admin_session() {
    let pool = common::test_pool().await;
    let (user_id, org_id, ident_id) =
        make_overslash_user_with_org(&pool, "nonadmin-trial@example.com").await;

    let (addr, client) = common::start_api(pool.clone()).await;
    let cookie = mint_session_with_user(org_id, ident_id, user_id);
    let resp = client
        .post(format!("http://{addr}/v1/orgs/{org_id}/trial"))
        .header("cookie", format!("oss_session={cookie}"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert_eq!(
        resp.json::<Value>().await.unwrap()["error"],
        "instance_admin_required"
    );
    // And the org stays standard.
    assert_eq!(read_billing(&pool, org_id).await.0, "standard");
}

#[tokio::test]
async fn start_trial_rejects_api_key() {
    // Bearer keys can't carry the instance-admin role (session-only).
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (org_id, _ident, agent_key, _admin) = common::bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/orgs/{org_id}/trial"))
        .header("authorization", format!("Bearer {agent_key}"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn extend_trial_bumps_end_and_rejects_non_trial() {
    let pool = common::test_pool().await;
    let (user_id, admin_org, admin_ident) =
        make_overslash_user_with_org(&pool, "admin-bump@example.com").await;
    user_repo::set_instance_admin(&pool, user_id, true)
        .await
        .unwrap();
    let (addr, client) = common::start_api(pool.clone()).await;
    let cookie = mint_session_with_user(admin_org, admin_ident, user_id);

    // A standard target: PATCH should 400 (not on a trial).
    let target = overslash_db::repos::org::create(
        &pool,
        "Bump",
        &format!("bump-{}", Uuid::new_v4().simple()),
        "standard",
    )
    .await
    .unwrap();
    let resp = client
        .patch(format!("http://{addr}/v1/orgs/{}/trial", target.id))
        .header("cookie", format!("oss_session={cookie}"))
        .json(&json!({ "extend_days": 10 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Put it on a short trial, then extend by 20 days from the current end.
    let start_end = OffsetDateTime::now_utc() + TimeDuration::days(3);
    force_trial(&pool, target.id, start_end).await;
    let resp = client
        .patch(format!("http://{addr}/v1/orgs/{}/trial", target.id))
        .header("cookie", format!("oss_session={cookie}"))
        .json(&json!({ "extend_days": 20 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let ends = read_billing(&pool, target.id).await.1.unwrap();
    let expected = start_end + TimeDuration::days(20);
    assert!((ends - expected).abs() < TimeDuration::minutes(1));
}

#[tokio::test]
async fn set_plan_flips_trial_to_free_unlimited_and_rejects_trial_value() {
    let pool = common::test_pool().await;
    let (user_id, admin_org, admin_ident) =
        make_overslash_user_with_org(&pool, "admin-optout@example.com").await;
    user_repo::set_instance_admin(&pool, user_id, true)
        .await
        .unwrap();
    let (addr, client) = common::start_api(pool.clone()).await;
    let cookie = mint_session_with_user(admin_org, admin_ident, user_id);

    let target = overslash_db::repos::org::create(
        &pool,
        "OptOut",
        &format!("optout-{}", Uuid::new_v4().simple()),
        "standard",
    )
    .await
    .unwrap();
    force_trial(
        &pool,
        target.id,
        OffsetDateTime::now_utc() + TimeDuration::days(30),
    )
    .await;

    // 'trial' is not a valid target here — starting a trial goes via POST.
    let resp = client
        .patch(format!("http://{addr}/v1/orgs/{}/plan", target.id))
        .header("cookie", format!("oss_session={cookie}"))
        .json(&json!({ "plan": "trial" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // free_unlimited opt-out clears the trial window.
    let resp = client
        .patch(format!("http://{addr}/v1/orgs/{}/plan", target.id))
        .header("cookie", format!("oss_session={cookie}"))
        .json(&json!({ "plan": "free_unlimited" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let (plan, ends) = read_billing(&pool, target.id).await;
    assert_eq!(plan, "free_unlimited");
    assert!(ends.is_none());
}

// ── Subscription surfacing ───────────────────────────────────────────

#[tokio::test]
async fn subscription_reports_active_and_expired_trial() {
    let pool = common::test_pool().await;

    // Active-trial org.
    let (active_org, _u1, active_key) = common::seed_org_user_key(
        &pool,
        common::SeedOptions {
            is_personal: false,
            is_admin: true,
        },
    )
    .await;
    force_trial(
        &pool,
        active_org,
        OffsetDateTime::now_utc() + TimeDuration::days(20),
    )
    .await;

    // Expired-trial org (backdated).
    let (expired_org, _u2, expired_key) = common::seed_org_user_key(
        &pool,
        common::SeedOptions {
            is_personal: false,
            is_admin: true,
        },
    )
    .await;
    force_trial(
        &pool,
        expired_org,
        OffsetDateTime::now_utc() - TimeDuration::days(1),
    )
    .await;

    let (addr, client) = common::start_api_with(pool.clone(), |cfg| {
        cfg.cloud_billing = true;
    })
    .await;
    let base = format!("http://{addr}");

    let active: Value = client
        .get(format!("{base}/v1/orgs/{active_org}/subscription"))
        .header("authorization", format!("Bearer {active_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(active["plan"], "trial");
    assert_eq!(active["status"], "trialing");
    assert!(active["current_period_end"].is_number());

    let expired: Value = client
        .get(format!("{base}/v1/orgs/{expired_org}/subscription"))
        .header("authorization", format!("Bearer {expired_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(expired["plan"], "trial");
    assert_eq!(expired["status"], "trial_expired");
}

// ── /auth/me/identity trial summary (member-visible banner source) ────

#[tokio::test]
async fn me_identity_surfaces_trial_and_clears_on_optout() {
    let pool = common::test_pool().await;
    let (user_id, org_id, ident_id) =
        make_overslash_user_with_org(&pool, "me-trial@example.com").await;
    force_trial(
        &pool,
        org_id,
        OffsetDateTime::now_utc() + TimeDuration::days(30),
    )
    .await;

    let (addr, client) = common::start_api(pool.clone()).await;
    let cookie = mint_session_with_user(org_id, ident_id, user_id);

    let body: Value = client
        .get(format!("http://{addr}/auth/me/identity"))
        .header("cookie", format!("oss_session={cookie}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["trial"]["status"], "active");
    let days = body["trial"]["days_remaining"].as_i64().unwrap();
    assert!((29..=30).contains(&days), "days_remaining was {days}");

    // free_unlimited is exempt — the trial summary disappears.
    overslash_db::repos::org::set_plan(&pool, org_id, "free_unlimited")
        .await
        .unwrap();
    let body: Value = client
        .get(format!("http://{addr}/auth/me/identity"))
        .header("cookie", format!("oss_session={cookie}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        body["trial"].is_null(),
        "expected trial cleared, got {body:?}"
    );
}

// ── Banner-only enforcement proof (DECISIONS D25) ────────────────────

#[tokio::test]
async fn expired_trial_is_not_blocked_and_not_unlimited() {
    // The core proof of the banner-only policy: an org whose trial expired
    // yesterday still serves API requests (no hard gate) AND is still subject
    // to normal rate limits (it is NOT free_unlimited — the limit header is a
    // number, never the 'unlimited' sentinel).
    let pool = common::test_pool().await;
    let (org_id, _user_id, raw_key) = common::seed_org_user_key(
        &pool,
        common::SeedOptions {
            is_personal: false,
            is_admin: false,
        },
    )
    .await;
    force_trial(
        &pool,
        org_id,
        OffsetDateTime::now_utc() - TimeDuration::days(1),
    )
    .await;

    let state = make_app_state(pool).await;
    let addr = spawn_middleware_app(state).await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("http://{addr}/echo"))
        .header("authorization", format!("Bearer {raw_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "expired trial must not be blocked");
    let limit = resp
        .headers()
        .get("x-ratelimit-limit")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_ne!(
        limit, "unlimited",
        "trial must not get the free_unlimited bypass"
    );
    assert!(
        limit.parse::<u32>().is_ok(),
        "expected numeric limit, got {limit}"
    );
}
