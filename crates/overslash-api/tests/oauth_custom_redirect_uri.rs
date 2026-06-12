//! End-to-end coverage for white-label custom OAuth `redirect_uri`.
//!
//! Three surfaces:
//!   1. Create-flow validation — `POST /v1/connections` bakes a partner
//!      `redirect_uri` into the authorize URL and persists it on the flow row,
//!      but only when its host is on the org's `oauth_callback_allowed_hosts`
//!      allow-list (otherwise 400).
//!   2. The `POST /v1/oauth/exchange` server-to-server token-exchange endpoint
//!      (org boundary, single-use consume, reused redirect_uri).
//!   3. The `GET/PATCH /v1/orgs/{id}/oauth-callback-settings` management API.
//!
//! Companion to `parse_redirect_uri` / `normalize_callback_hosts` logic — these
//! exercise the wired behavior, not just the parsers.
#![allow(clippy::disallowed_methods)]

mod common;

use common::{SeedOptions, auth, seed_org_user_key, start_api};
use overslash_db::repos::oauth_connection_flow::{self, CreateOauthConnectionFlow};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const PARTNER_REDIRECT: &str = "https://app.overfolder.com/auth/google/integrations/callback";

/// Mirror the env dance the other OAuth tests use: the kernel resolves client
/// credentials via an env fallback gated behind the DANGER flag.
fn set_github_creds_env() {
    // SAFETY: test-only, set before the server boots; all tests set the same
    // values so concurrent runs don't conflict.
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_GITHUB_CLIENT_ID", "test_client_id");
        std::env::set_var("OAUTH_GITHUB_CLIENT_SECRET", "test_client_secret");
    }
}

async fn set_allowed_hosts(pool: &sqlx::PgPool, org_id: Uuid, csv: &str) {
    sqlx::query("UPDATE orgs SET oauth_callback_allowed_hosts = $1 WHERE id = $2")
        .bind(csv)
        .bind(org_id)
        .execute(pool)
        .await
        .unwrap();
}

/// Seed a flow row directly, optionally carrying a custom `redirect_uri`.
async fn seed_flow(
    pool: &sqlx::PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    redirect_uri: Option<&str>,
) -> String {
    let flow_id = format!("flow_{}", &Uuid::new_v4().simple().to_string()[..16]);
    oauth_connection_flow::create(
        pool,
        &CreateOauthConnectionFlow {
            id: &flow_id,
            org_id,
            identity_id,
            actor_identity_id: identity_id,
            provider_key: "github",
            byoc_credential_id: None,
            scopes: &[],
            pkce_code_verifier: None,
            upstream_authorize_url: "https://github.com/login/oauth/authorize",
            expires_at: OffsetDateTime::now_utc() + Duration::minutes(10),
            created_ip: None,
            created_user_agent: None,
            return_url: None,
            redirect_uri,
            upgrade_connection_id: None,
            service_instance_id: None,
        },
    )
    .await
    .unwrap();
    flow_id
}

/// Point the github provider's token endpoint at the in-process fakes so the
/// exchange path resolves to a real 200.
async fn override_github_token_endpoint(pool: &sqlx::PgPool, mock: std::net::SocketAddr) {
    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'github'")
        .bind(format!("http://{mock}/oauth/token"))
        .execute(pool)
        .await
        .unwrap();
}

// ─── Create-flow validation ─────────────────────────────────────────────────

#[tokio::test]
async fn create_connection_with_allowed_redirect_uri_persists_and_builds_authorize() {
    set_github_creds_env();
    let pool = common::test_pool().await;
    let (org_id, _user, key) = seed_org_user_key(
        &pool,
        SeedOptions {
            is_admin: true,
            ..Default::default()
        },
    )
    .await;
    set_allowed_hosts(&pool, org_id, "app.overfolder.com").await;

    let (addr, client) = start_api(pool.clone()).await;
    let (h, v) = auth(&key);
    let resp = client
        .post(format!("http://{addr}/v1/connections"))
        .header(h, v.as_str())
        .json(&json!({
            "provider": "github",
            "include_raw": true,
            "redirect_uri": PARTNER_REDIRECT,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();

    // The authorize URL the provider will see carries the partner redirect_uri.
    let raw = body["raw"].as_str().expect("include_raw → raw present");
    let raw_url = url::Url::parse(raw).unwrap();
    let built_redirect = raw_url
        .query_pairs()
        .find(|(k, _)| k == "redirect_uri")
        .map(|(_, v)| v.into_owned());
    assert_eq!(built_redirect.as_deref(), Some(PARTNER_REDIRECT));

    // ...and it's persisted on the flow row so token-exchange byte-matches it.
    let stored: Option<String> =
        sqlx::query_scalar("SELECT redirect_uri FROM oauth_connection_flows WHERE org_id = $1")
            .bind(org_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored.as_deref(), Some(PARTNER_REDIRECT));
}

#[tokio::test]
async fn create_connection_rejects_redirect_uri_host_not_on_allow_list() {
    set_github_creds_env();
    let pool = common::test_pool().await;
    let (org_id, _user, key) = seed_org_user_key(
        &pool,
        SeedOptions {
            is_admin: true,
            ..Default::default()
        },
    )
    .await;
    // Allow-list has a different host.
    set_allowed_hosts(&pool, org_id, "other.test").await;

    let (addr, client) = start_api(pool.clone()).await;
    let (h, v) = auth(&key);
    let resp = client
        .post(format!("http://{addr}/v1/connections"))
        .header(h, v.as_str())
        .json(&json!({ "provider": "github", "redirect_uri": PARTNER_REDIRECT }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);

    // No flow row should have been minted.
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM oauth_connection_flows WHERE org_id = $1")
            .bind(org_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn create_connection_rejects_redirect_uri_when_allow_list_empty() {
    set_github_creds_env();
    let pool = common::test_pool().await;
    let (_org_id, _user, key) = seed_org_user_key(
        &pool,
        SeedOptions {
            is_admin: true,
            ..Default::default()
        },
    )
    .await;
    // Default allow-list is empty — any custom redirect_uri is rejected.

    let (addr, client) = start_api(pool.clone()).await;
    let (h, v) = auth(&key);
    let resp = client
        .post(format!("http://{addr}/v1/connections"))
        .header(h, v.as_str())
        .json(&json!({ "provider": "github", "redirect_uri": PARTNER_REDIRECT }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
}

// ─── Exchange endpoint ──────────────────────────────────────────────────────

#[tokio::test]
async fn exchange_completes_flow_and_is_single_use() {
    set_github_creds_env();
    let pool = common::test_pool().await;
    let mock = common::start_mock().await;
    override_github_token_endpoint(&pool, mock).await;

    let (org_id, user_id, key) = seed_org_user_key(
        &pool,
        SeedOptions {
            is_admin: true,
            ..Default::default()
        },
    )
    .await;
    let flow_id = seed_flow(&pool, org_id, user_id, Some(PARTNER_REDIRECT)).await;

    let (addr, client) = start_api(pool.clone()).await;
    let (h, v) = auth(&key);
    let resp = client
        .post(format!("http://{addr}/v1/oauth/exchange"))
        .header(h, v.as_str())
        .json(&json!({ "code": "test_code", "state": flow_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "connected");
    assert_eq!(body["provider"], "github");
    assert!(body["connection_id"].is_string());

    // Connection landed.
    let conns: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM connections WHERE org_id = $1 AND identity_id = $2",
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(conns, 1);

    // Single-use: replaying the same state is rejected.
    let replay = client
        .post(format!("http://{addr}/v1/oauth/exchange"))
        .header(h, v.as_str())
        .json(&json!({ "code": "test_code", "state": flow_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status().as_u16(), 400);
}

#[tokio::test]
async fn exchange_rejects_cross_org_state_without_consuming() {
    set_github_creds_env();
    let pool = common::test_pool().await;
    let mock = common::start_mock().await;
    override_github_token_endpoint(&pool, mock).await;

    // Org A holds the key; the flow belongs to org B.
    let (_org_a, _user_a, key_a) = seed_org_user_key(
        &pool,
        SeedOptions {
            is_admin: true,
            ..Default::default()
        },
    )
    .await;
    let (org_b, user_b, _key_b) = seed_org_user_key(&pool, SeedOptions::default()).await;
    let flow_id = seed_flow(&pool, org_b, user_b, Some(PARTNER_REDIRECT)).await;

    let (addr, client) = start_api(pool.clone()).await;
    let (h, v) = auth(&key_a);
    let resp = client
        .post(format!("http://{addr}/v1/oauth/exchange"))
        .header(h, v.as_str())
        .json(&json!({ "code": "test_code", "state": flow_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);

    // The org-mismatch rejection must NOT have burned the flow.
    let consumed: Option<OffsetDateTime> =
        sqlx::query_scalar("SELECT consumed_at FROM oauth_connection_flows WHERE id = $1")
            .bind(&flow_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        consumed.is_none(),
        "cross-org call must not consume the flow"
    );
}

#[tokio::test]
async fn unauthenticated_callback_refuses_white_label_flow() {
    // A white-label flow (custom redirect_uri) must NOT be completable through
    // the unauthenticated GET /v1/oauth/callback — that would sidestep the
    // WriteAcl org-boundary + single-use guarantees of /v1/oauth/exchange.
    set_github_creds_env();
    let pool = common::test_pool().await;
    let mock = common::start_mock().await;
    override_github_token_endpoint(&pool, mock).await;

    let (org_id, user_id, _key) = seed_org_user_key(
        &pool,
        SeedOptions {
            is_admin: true,
            ..Default::default()
        },
    )
    .await;
    let flow_id = seed_flow(&pool, org_id, user_id, Some(PARTNER_REDIRECT)).await;

    let (addr, _client) = start_api(pool.clone()).await;
    // No-redirect client so we observe the 400 rather than following anything.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let resp = client
        .get(format!(
            "http://{addr}/v1/oauth/callback?code=test_code&state={flow_id}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);

    // The flow must remain unconsumed and no connection created.
    let consumed: Option<OffsetDateTime> =
        sqlx::query_scalar("SELECT consumed_at FROM oauth_connection_flows WHERE id = $1")
            .bind(&flow_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(consumed.is_none());
    let conns: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM connections WHERE org_id = $1")
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(conns, 0);
}

#[tokio::test]
async fn exchange_rejects_unknown_state() {
    set_github_creds_env();
    let pool = common::test_pool().await;
    let (_org, _user, key) = seed_org_user_key(
        &pool,
        SeedOptions {
            is_admin: true,
            ..Default::default()
        },
    )
    .await;

    let (addr, client) = start_api(pool.clone()).await;
    let (h, v) = auth(&key);
    let resp = client
        .post(format!("http://{addr}/v1/oauth/exchange"))
        .header(h, v.as_str())
        .json(&json!({ "code": "test_code", "state": "flow_does_not_exist" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
}

#[tokio::test]
async fn exchange_rejects_regular_flow_without_custom_redirect_uri() {
    // Symmetric to the callback guard: a regular flow (redirect_uri NULL) must
    // complete via GET /v1/oauth/callback, not the exchange endpoint.
    set_github_creds_env();
    let pool = common::test_pool().await;
    let mock = common::start_mock().await;
    override_github_token_endpoint(&pool, mock).await;

    let (org_id, user_id, key) = seed_org_user_key(
        &pool,
        SeedOptions {
            is_admin: true,
            ..Default::default()
        },
    )
    .await;
    // No custom redirect_uri → regular flow.
    let flow_id = seed_flow(&pool, org_id, user_id, None).await;

    let (addr, client) = start_api(pool.clone()).await;
    let (h, v) = auth(&key);
    let resp = client
        .post(format!("http://{addr}/v1/oauth/exchange"))
        .header(h, v.as_str())
        .json(&json!({ "code": "test_code", "state": flow_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);

    // Rejected before consume — the flow is untouched.
    let consumed: Option<OffsetDateTime> =
        sqlx::query_scalar("SELECT consumed_at FROM oauth_connection_flows WHERE id = $1")
            .bind(&flow_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(consumed.is_none());
}

// ─── Org settings management API ────────────────────────────────────────────

#[tokio::test]
async fn callback_settings_default_empty_then_normalized_round_trip() {
    let pool = common::test_pool().await;
    let (org_id, _user, key) = seed_org_user_key(
        &pool,
        SeedOptions {
            is_admin: true,
            ..Default::default()
        },
    )
    .await;

    let (addr, client) = start_api(pool.clone()).await;
    let (h, v) = auth(&key);

    // Default is an empty list.
    let resp = client
        .get(format!(
            "http://{addr}/v1/orgs/{org_id}/oauth-callback-settings"
        ))
        .header(h, v.as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["allowed_hosts"], json!([]));

    // PATCH normalizes (lowercase, trim, dedupe) and round-trips.
    let resp = client
        .patch(format!("http://{addr}/v1/orgs/{org_id}/oauth-callback-settings"))
        .header(h, v.as_str())
        .json(&json!({
            "allowed_hosts": ["App.Overfolder.com", " app.overfolder.com ", "staging.overfolder.com"]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["allowed_hosts"],
        json!(["app.overfolder.com", "staging.overfolder.com"])
    );

    // GET reflects the persisted value.
    let resp = client
        .get(format!(
            "http://{addr}/v1/orgs/{org_id}/oauth-callback-settings"
        ))
        .header(h, v.as_str())
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["allowed_hosts"],
        json!(["app.overfolder.com", "staging.overfolder.com"])
    );
}

#[tokio::test]
async fn callback_settings_rejects_invalid_host() {
    let pool = common::test_pool().await;
    let (org_id, _user, key) = seed_org_user_key(
        &pool,
        SeedOptions {
            is_admin: true,
            ..Default::default()
        },
    )
    .await;

    let (addr, client) = start_api(pool.clone()).await;
    let (h, v) = auth(&key);
    // A full URL is not a bare hostname.
    let resp = client
        .patch(format!(
            "http://{addr}/v1/orgs/{org_id}/oauth-callback-settings"
        ))
        .header(h, v.as_str())
        .json(&json!({ "allowed_hosts": ["https://app.overfolder.com/cb"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
}

#[tokio::test]
async fn callback_settings_patch_requires_admin() {
    let pool = common::test_pool().await;
    // Non-admin user key.
    let (org_id, _user, key) = seed_org_user_key(&pool, SeedOptions::default()).await;

    let (addr, client) = start_api(pool.clone()).await;
    let (h, v) = auth(&key);
    let resp = client
        .patch(format!(
            "http://{addr}/v1/orgs/{org_id}/oauth-callback-settings"
        ))
        .header(h, v.as_str())
        .json(&json!({ "allowed_hosts": ["app.overfolder.com"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
}
