//! Integration coverage for the `return_url` hint on reactive auth flows
//! minted during `POST /v1/actions/call`.
//!
//! Companion to `oauth_return_url.rs` (which seeds a flow row directly and
//! asserts the callback's 303/JSON behavior) and `actions_reauth.rs` (which
//! asserts the typed `reauth_required` / `needs_authentication` envelopes).
//! Here we drive the *mint* side end-to-end: a call that trips a reactive
//! OAuth flow must stamp the caller-supplied `return_url` onto the minted
//! flow row so the callback can redirect the user back to the partner —
//! the same redirect first-connect already gets.
// Test setup writes oauth_provider rows directly and seeds connections via
// raw SQL — both trip the workspace's disallowed-methods lint.
#![allow(clippy::disallowed_methods)]

mod common;

use axum::http::StatusCode;
use overslash_core::crypto;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

/// Seed an OAuth connection with an expired access token and no refresh
/// token — drives `OAuthError::NoRefreshToken → Reauth("no_refresh_token")`,
/// so a service call against it returns `reauth_required`. Mirrors the helper
/// in `actions_reauth.rs`.
async fn seed_connection_no_refresh_expired(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    provider_key: &str,
) -> Uuid {
    let enc_key = crypto::Keyring::test();
    let access = crypto::encrypt(&enc_key, b"mock_expired_access_token").unwrap();
    let expired_at = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO connections (org_id, identity_id, provider_key,
         encrypted_access_token, token_expires_at, scopes, account_email)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
    )
    .bind(org_id)
    .bind(identity_id)
    .bind(provider_key)
    .bind(&access)
    .bind(expired_at)
    .bind::<Vec<String>>(vec!["tweet.read".into(), "users.read".into()])
    .bind(Some("mock@x"))
    .fetch_one(pool)
    .await
    .unwrap();
    row.0
}

/// Bring up the API with the bundled registry (for the `x` template), the
/// allow-list set to `allowed.test`, the env-var OAuth credentials the
/// callback's credential resolver needs, and the `x` provider's token
/// endpoint pointed at a local mock so the callback can complete the
/// exchange. Returns `(base_url, redirect-following client, mock addr)`.
async fn boot(pool: &PgPool, allowed_hosts: Vec<String>) -> (String, reqwest::Client, String) {
    // SAFETY: test-only, before the server boots.
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", "x_test_client");
        std::env::set_var("OAUTH_X_CLIENT_SECRET", "x_test_secret");
    }

    let mock_addr = common::start_mock().await;
    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'x'")
        .bind(format!("http://{mock_addr}/oauth/token"))
        .execute(pool)
        .await
        .unwrap();

    let (base, client) =
        common::start_api_with_registry_customized(pool.clone(), None, move |cfg| {
            cfg.connection_return_url_allowed_hosts = allowed_hosts;
        })
        .await;
    (base, client, format!("http://{mock_addr}"))
}

/// Create an org-level `x` service instance (no connection bound) and grant
/// the calling identity `x:*:*`.
async fn seed_x_service(base: &str, client: &reqwest::Client, admin_key: &str, ident_id: Uuid) {
    let create_resp = client
        .post(format!("{base}/v1/services"))
        .header(common::auth(admin_key).0, common::auth(admin_key).1)
        .json(&json!({
            "template_key": "x",
            "name": "x",
            "user_level": false,
            "status": "active",
        }))
        .send()
        .await
        .unwrap();
    assert!(
        create_resp.status().is_success(),
        "service create failed: {}",
        create_resp.status()
    );
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(admin_key).0, common::auth(admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "x:*:*"}))
        .send()
        .await
        .unwrap();
}

/// Read back the `return_url` column the mint side persisted for a flow row.
async fn flow_return_url(pool: &PgPool, flow_id: &str) -> Option<String> {
    let row: (Option<String>,) =
        sqlx::query_as("SELECT return_url FROM oauth_connection_flows WHERE id = $1")
            .bind(flow_id)
            .fetch_one(pool)
            .await
            .unwrap();
    row.0
}

/// Pull the flow-row id out of a gated `auth_url`
/// (`{public_url}/connect-authorize?id=<flow_id>`). The flow id doubles as
/// the OAuth callback `state`.
fn flow_id_from_auth_url(auth_url: &str) -> String {
    let url = url::Url::parse(auth_url).unwrap();
    url.query_pairs()
        .find(|(k, _)| k == "id")
        .map(|(_, v)| v.into_owned())
        .expect("auth_url should carry ?id=<flow>")
}

/// A reactively-minted `reauth_required` flow carries the caller's
/// allow-listed `return_url`, and the OAuth callback 303s the user back to it.
#[tokio::test]
async fn reauth_mint_stamps_allow_listed_return_url_and_callback_redirects() {
    let pool = common::test_pool().await;
    let (base, client, _mock) = boot(&pool, vec!["allowed.test".into()]).await;
    let (org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let connection_id = seed_connection_no_refresh_expired(
        &pool,
        org_id,
        common::owner_user_id(&pool, org_id).await,
        "x",
    )
    .await;
    seed_x_service(&base, &client, &admin_key, ident_id).await;

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&api_key).0, common::auth(&api_key).1)
        .json(&json!({
            "service": "x",
            "action": "get_me",
            "params": {},
            "return_url": "https://allowed.test/cb?ref=tenant",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "expected 401 reauth_required"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "reauth_required");
    assert_eq!(
        body["connection_id"].as_str().unwrap(),
        connection_id.to_string()
    );

    // The mint side stamped the hint onto the flow row.
    let flow_id = flow_id_from_auth_url(body["auth_url"].as_str().unwrap());
    assert_eq!(
        flow_return_url(&pool, &flow_id).await.as_deref(),
        Some("https://allowed.test/cb?ref=tenant"),
    );

    // End-to-end: the callback honors it and 303s back to the partner. Use a
    // non-following client so we can read the Location header. The mock
    // `/oauth/token` returns a valid token, so the upgrade succeeds.
    let no_follow = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let cb = no_follow
        .get(format!(
            "{base}/v1/oauth/callback?code=x_auth_code&state={flow_id}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(cb.status().as_u16(), 303, "callback should redirect");
    let location = cb.headers().get("location").unwrap().to_str().unwrap();
    let loc = url::Url::parse(location).unwrap();
    assert_eq!(loc.host_str(), Some("allowed.test"));
    assert_eq!(loc.path(), "/cb");
    let qs: std::collections::HashMap<String, String> = loc.query_pairs().into_owned().collect();
    assert_eq!(qs.get("ref").map(String::as_str), Some("tenant"));
    assert_eq!(qs.get("status").map(String::as_str), Some("success"));
    assert_eq!(qs.get("provider").map(String::as_str), Some("x"));
}

/// Without a `return_url` on the call, the minted flow row's column stays
/// NULL — the callback falls back to JSON exactly as before.
#[tokio::test]
async fn reauth_mint_without_return_url_leaves_flow_row_null() {
    let pool = common::test_pool().await;
    let (base, client, _mock) = boot(&pool, vec!["allowed.test".into()]).await;
    let (org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    seed_connection_no_refresh_expired(
        &pool,
        org_id,
        common::owner_user_id(&pool, org_id).await,
        "x",
    )
    .await;
    seed_x_service(&base, &client, &admin_key, ident_id).await;

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&api_key).0, common::auth(&api_key).1)
        .json(&json!({ "service": "x", "action": "get_me", "params": {} }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = resp.json().await.unwrap();
    let flow_id = flow_id_from_auth_url(body["auth_url"].as_str().unwrap());
    assert_eq!(flow_return_url(&pool, &flow_id).await, None);
}

/// A malformed `return_url` is rejected at the request boundary with 400,
/// before any flow is minted.
#[tokio::test]
async fn action_call_rejects_malformed_return_url() {
    let pool = common::test_pool().await;
    let (base, client, _mock) = boot(&pool, vec!["allowed.test".into()]).await;
    let (org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    seed_connection_no_refresh_expired(
        &pool,
        org_id,
        common::owner_user_id(&pool, org_id).await,
        "x",
    )
    .await;
    seed_x_service(&base, &client, &admin_key, ident_id).await;

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&api_key).0, common::auth(&api_key).1)
        .json(&json!({
            "service": "x",
            "action": "get_me",
            "params": {},
            "return_url": "ftp://nope.test/cb",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "malformed return_url should 400"
    );

    // Nothing was minted.
    let flows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM oauth_connection_flows WHERE org_id = $1")
            .bind(org_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(flows, 0);
}

/// The first-connect reactive path (`needs_authentication`, no connection yet)
/// also carries the `return_url` onto its minted flow row.
#[tokio::test]
async fn needs_authentication_mint_stamps_return_url() {
    let pool = common::test_pool().await;
    let (base, client, _mock) = boot(&pool, vec!["allowed.test".into()]).await;
    let (_org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // No connection seeded — the recovery arm fires `needs_authentication`.
    seed_x_service(&base, &client, &admin_key, ident_id).await;

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&api_key).0, common::auth(&api_key).1)
        .json(&json!({
            "service": "x",
            "action": "get_me",
            "params": {},
            "return_url": "https://allowed.test/landing",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "needs_authentication");

    let flow_id = flow_id_from_auth_url(body["auth_url"].as_str().unwrap());
    assert_eq!(
        flow_return_url(&pool, &flow_id).await.as_deref(),
        Some("https://allowed.test/landing"),
    );
}
