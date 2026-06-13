//! End-to-end coverage for white-label per-org OAuth `redirect_uri`.
//!
//! The model: an org admin sets a single `oauth_redirect_url`; a connect/reauth
//! flow opts into it per request via `use_org_redirect`. Surfaces exercised:
//!   1. Create-flow — `POST /v1/connections` with `use_org_redirect: true` bakes
//!      the org URL into the authorize URL and persists it on the flow row;
//!      without the flag it uses the default Overslash callback; with the flag
//!      but no configured URL it 400s.
//!   2. The `POST /v1/oauth/exchange` server-to-server token-exchange endpoint
//!      (org boundary, single-use consume, reused redirect_uri).
//!   3. The `GET/PATCH /v1/orgs/{id}/oauth-redirect-settings` management API.
#![allow(clippy::disallowed_methods)]

mod common;

use common::{SeedOptions, auth, seed_org_user_key, start_api};
use overslash_core::crypto;
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

/// Set the org's admin-managed white-label callback URL.
async fn set_oauth_redirect_url(pool: &sqlx::PgPool, org_id: Uuid, url: &str) {
    sqlx::query("UPDATE orgs SET oauth_redirect_url = $1 WHERE id = $2")
        .bind(url)
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

/// Read the `redirect_uri` query param from a built authorize URL.
fn redirect_uri_param(authorize_url: &str) -> Option<String> {
    url::Url::parse(authorize_url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "redirect_uri")
        .map(|(_, v)| v.into_owned())
}

// ─── Create-flow ────────────────────────────────────────────────────────────

#[tokio::test]
async fn create_connection_with_use_org_redirect_persists_and_builds_authorize() {
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
    set_oauth_redirect_url(&pool, org_id, PARTNER_REDIRECT).await;

    let (addr, client) = start_api(pool.clone()).await;
    let (h, v) = auth(&key);
    let resp = client
        .post(format!("http://{addr}/v1/connections"))
        .header(h, v.as_str())
        .json(&json!({
            "provider": "github",
            "include_raw": true,
            "use_org_redirect": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();

    // The authorize URL the provider will see carries the org redirect_uri.
    let raw = body["raw"].as_str().expect("include_raw → raw present");
    assert_eq!(redirect_uri_param(raw).as_deref(), Some(PARTNER_REDIRECT));

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
async fn create_connection_use_org_redirect_without_configured_url_rejected() {
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
    // Org has no oauth_redirect_url configured (default empty).

    let (addr, client) = start_api(pool.clone()).await;
    let (h, v) = auth(&key);
    let resp = client
        .post(format!("http://{addr}/v1/connections"))
        .header(h, v.as_str())
        .json(&json!({ "provider": "github", "use_org_redirect": true }))
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
async fn create_connection_without_flag_uses_default_callback() {
    // The default path (and the dashboard's own Connect flows): no
    // `use_org_redirect`, so the flow row keeps `redirect_uri` NULL and the
    // authorize URL carries the default Overslash callback — even though the
    // org has a white-label URL configured.
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
    set_oauth_redirect_url(&pool, org_id, PARTNER_REDIRECT).await;

    let (addr, client) = start_api(pool.clone()).await;
    let (h, v) = auth(&key);
    let resp = client
        .post(format!("http://{addr}/v1/connections"))
        .header(h, v.as_str())
        .json(&json!({ "provider": "github", "include_raw": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();

    let raw = body["raw"].as_str().expect("include_raw → raw present");
    let built = redirect_uri_param(raw).expect("redirect_uri present");
    assert!(
        built.ends_with("/v1/oauth/callback"),
        "expected the default Overslash callback, got {built}"
    );
    assert_ne!(built, PARTNER_REDIRECT);

    // Flow row keeps redirect_uri NULL → completes via GET /v1/oauth/callback.
    let stored: Option<String> =
        sqlx::query_scalar("SELECT redirect_uri FROM oauth_connection_flows WHERE org_id = $1")
            .bind(org_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored, None);
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

// ─── Reauth / upgrade_scopes (white-label) ──────────────────────────────────

/// Seed a connection row directly so the upgrade flow has something to point
/// its `upgrade_connection_id` at, without running a full OAuth dance first.
async fn seed_connection(
    pool: &sqlx::PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    provider_key: &str,
    scopes: &[&str],
) -> Uuid {
    let enc_key = crypto::Keyring::test();
    let access = crypto::encrypt(&enc_key, b"mock_access_token").unwrap();
    let scope_vec: Vec<String> = scopes.iter().map(|s| (*s).to_string()).collect();
    sqlx::query_scalar(
        "INSERT INTO connections (org_id, identity_id, provider_key,
             encrypted_access_token, scopes, account_email, is_default)
         VALUES ($1, $2, $3, $4, $5, NULL, true) RETURNING id",
    )
    .bind(org_id)
    .bind(identity_id)
    .bind(provider_key)
    .bind(&access)
    .bind(&scope_vec)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn upgrade_scopes_include_raw_exposes_upstream_authorize_url() {
    set_github_creds_env();
    let pool = common::test_pool().await;
    let (org_id, user_id, key) = seed_org_user_key(
        &pool,
        SeedOptions {
            is_admin: true,
            ..Default::default()
        },
    )
    .await;
    set_oauth_redirect_url(&pool, org_id, PARTNER_REDIRECT).await;
    let conn_id = seed_connection(&pool, org_id, user_id, "github", &["read:user"]).await;

    let (addr, client) = start_api(pool.clone()).await;
    let (h, v) = auth(&key);
    let resp = client
        .post(format!(
            "http://{addr}/v1/connections/{conn_id}/upgrade_scopes"
        ))
        .header(h, v.as_str())
        .json(&json!({
            "scopes": ["user:email"],
            "use_org_redirect": true,
            "include_raw": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();

    // `auth_url` stays the gated proxy form...
    let auth_url = body["auth_url"].as_str().unwrap();
    assert!(
        auth_url.contains("/connect-authorize?id="),
        "auth_url should be the gated proxy URL, got {auth_url}"
    );

    // ...while `raw` is the upstream provider URL (bypasses the gate) carrying
    // the org redirect_uri, so the white-label `/v1/oauth/exchange` follow-up
    // can complete without the gate consuming the flow first.
    let raw = body["raw"].as_str().expect("include_raw → raw present");
    let raw_url = url::Url::parse(raw).unwrap();
    assert_eq!(raw_url.host_str(), Some("github.com"));
    assert_eq!(redirect_uri_param(raw).as_deref(), Some(PARTNER_REDIRECT));

    // The minted flow is the white-label kind: org redirect_uri persisted
    // and pointed at the connection being upgraded.
    let row: (Option<String>, Option<Uuid>) = sqlx::query_as(
        "SELECT redirect_uri, upgrade_connection_id
           FROM oauth_connection_flows WHERE org_id = $1",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.0.as_deref(), Some(PARTNER_REDIRECT));
    assert_eq!(row.1, Some(conn_id));
}

#[tokio::test]
async fn upgrade_scopes_omits_raw_by_default() {
    set_github_creds_env();
    let pool = common::test_pool().await;
    let (org_id, user_id, key) = seed_org_user_key(
        &pool,
        SeedOptions {
            is_admin: true,
            ..Default::default()
        },
    )
    .await;
    set_oauth_redirect_url(&pool, org_id, PARTNER_REDIRECT).await;
    let conn_id = seed_connection(&pool, org_id, user_id, "github", &["read:user"]).await;

    let (addr, client) = start_api(pool.clone()).await;
    let (h, v) = auth(&key);
    let resp = client
        .post(format!(
            "http://{addr}/v1/connections/{conn_id}/upgrade_scopes"
        ))
        .header(h, v.as_str())
        // No `include_raw` — same white-label opt-in, gated form only.
        .json(&json!({
            "scopes": ["user:email"],
            "use_org_redirect": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["auth_url"].is_string());
    assert!(
        body.get("raw").is_none() || body["raw"].is_null(),
        "raw must be omitted without include_raw, got {body}"
    );
}

// ─── Org settings management API ────────────────────────────────────────────

#[tokio::test]
async fn redirect_settings_default_empty_then_round_trip_and_clear() {
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

    // Default is an empty string.
    let resp = client
        .get(format!(
            "http://{addr}/v1/orgs/{org_id}/oauth-redirect-settings"
        ))
        .header(h, v.as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["redirect_url"], "");

    // PATCH a valid URL → round-trips.
    let resp = client
        .patch(format!(
            "http://{addr}/v1/orgs/{org_id}/oauth-redirect-settings"
        ))
        .header(h, v.as_str())
        .json(&json!({ "redirect_url": PARTNER_REDIRECT }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["redirect_url"], PARTNER_REDIRECT);

    // GET reflects the persisted value.
    let resp = client
        .get(format!(
            "http://{addr}/v1/orgs/{org_id}/oauth-redirect-settings"
        ))
        .header(h, v.as_str())
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["redirect_url"], PARTNER_REDIRECT);

    // PATCH empty string clears it (disables white-label).
    let resp = client
        .patch(format!(
            "http://{addr}/v1/orgs/{org_id}/oauth-redirect-settings"
        ))
        .header(h, v.as_str())
        .json(&json!({ "redirect_url": "" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["redirect_url"], "");
}

#[tokio::test]
async fn redirect_settings_rejects_invalid_url() {
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

    // A bare hostname is not a valid URL; a non-https scheme, a fragment, and
    // embedded userinfo are all rejected by the shared `parse_redirect_uri`.
    for bad in [
        "app.overfolder.com",
        "http://app.overfolder.com/cb",
        "https://app.overfolder.com/cb#frag",
        "https://u:p@app.overfolder.com/cb",
    ] {
        let resp = client
            .patch(format!(
                "http://{addr}/v1/orgs/{org_id}/oauth-redirect-settings"
            ))
            .header(h, v.as_str())
            .json(&json!({ "redirect_url": bad }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 400, "expected 400 for {bad}");
    }
}

#[tokio::test]
async fn redirect_settings_patch_requires_admin() {
    let pool = common::test_pool().await;
    // Non-admin user key.
    let (org_id, _user, key) = seed_org_user_key(&pool, SeedOptions::default()).await;

    let (addr, client) = start_api(pool.clone()).await;
    let (h, v) = auth(&key);
    let resp = client
        .patch(format!(
            "http://{addr}/v1/orgs/{org_id}/oauth-redirect-settings"
        ))
        .header(h, v.as_str())
        .json(&json!({ "redirect_url": PARTNER_REDIRECT }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
}
