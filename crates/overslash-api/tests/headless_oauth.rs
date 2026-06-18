//! Headless (white-label) org auth-recovery: URL-less typed envelopes.
//!
//! For a headless org, an action call that hits an auth gap
//! (`reauth_required` / `needs_authentication` / `missing_scopes`) must return
//! a typed, **URL-less** envelope — no gated `/connect-authorize` link, no
//! `short`, and (for missing_scopes) no `upgrade_url` — carrying
//! `headless: true` plus `provider`/`required_scopes`/`account_email` so the
//! integration re-runs its own OAuth dance and re-imports. Crucially, **no
//! `oauth_connection_flows` row is minted**. The gate stays fully intact for
//! non-headless dashboard customers (regression test at the end).
//!
//! See `docs/design/white-label-token-vault.md` and `routes/actions/auth.rs`.

// Seeds connections + flips the org flag via direct SQL.
#![allow(clippy::disallowed_methods)]

mod common;

use overslash_core::crypto;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

const CAL_SCOPE: &str = "https://www.googleapis.com/auth/calendar";

fn auth(key: &str) -> (&'static str, String) {
    common::auth(key)
}

/// Flip an org to headless directly (the admin endpoint is covered elsewhere;
/// here we just need the state).
async fn make_headless(pool: &PgPool, org_id: Uuid) {
    sqlx::query("UPDATE orgs SET headless = true WHERE id = $1")
        .bind(org_id)
        .execute(pool)
        .await
        .unwrap();
}

/// Seed an OAuth connection. `expired_no_refresh` produces an expired access
/// token with no refresh token (drives `reauth_required`); otherwise a
/// long-lived token. `scopes` is the recorded granted set.
async fn seed_connection(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    provider_key: &str,
    scopes: &[&str],
    account_email: &str,
    expired_no_refresh: bool,
) -> Uuid {
    let enc_key = crypto::Keyring::test();
    let access = crypto::encrypt(&enc_key, b"mock_access_token").unwrap();
    let expires_at = if expired_no_refresh {
        time::OffsetDateTime::now_utc() - time::Duration::hours(1)
    } else {
        time::OffsetDateTime::now_utc() + time::Duration::hours(1)
    };
    let scopes: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO connections (org_id, identity_id, provider_key,
         encrypted_access_token, token_expires_at, scopes, account_email)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
    )
    .bind(org_id)
    .bind(identity_id)
    .bind(provider_key)
    .bind(&access)
    .bind(expires_at)
    .bind(scopes)
    .bind(account_email)
    .fetch_one(pool)
    .await
    .unwrap();
    row.0
}

async fn flow_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM oauth_connection_flows")
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Create the `x` org-level service and grant the identity permission to call it.
async fn setup_x_service(base: &str, client: &reqwest::Client, ident_id: Uuid, admin_key: &str) {
    let resp = client
        .post(format!("{base}/v1/services"))
        .header(auth(admin_key).0, auth(admin_key).1)
        .json(&json!({
            "template_key": "x",
            "name": "x",
            "user_level": false,
            "status": "active",
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "x service create failed");

    client
        .post(format!("{base}/v1/permissions"))
        .header(auth(admin_key).0, auth(admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "x:*:*"}))
        .send()
        .await
        .unwrap();
}

async fn call_get_me(base: &str, client: &reqwest::Client, api_key: &str) -> (u16, Value) {
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(api_key).0, auth(api_key).1)
        .json(&json!({ "service": "x", "action": "get_me", "params": {} }))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap())
}

/// Headless org + a connection whose refresh token is dead → `reauth_required`
/// with no `auth_url`/`short`, `headless: true`, and the right
/// `connection_id`/`provider`/`account_email`/`required_scopes`. No flow minted.
#[tokio::test]
async fn headless_reauth_required_is_url_less() {
    let pool = common::test_pool().await;
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", "x_test_client");
        std::env::set_var("OAUTH_X_CLIENT_SECRET", "x_test_secret");
    }

    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    make_headless(&pool, org_id).await;

    let conn_id = seed_connection(
        &pool,
        org_id,
        ident_id,
        "x",
        &["tweet.read", "users.read"],
        "mock@x",
        true,
    )
    .await;
    setup_x_service(&base, &client, ident_id, &admin_key).await;

    let flows_before = flow_count(&pool).await;
    let (status, body) = call_get_me(&base, &client, &api_key).await;

    assert_eq!(status, 401, "expected reauth_required: {body}");
    assert_eq!(body["error"], "reauth_required");
    assert_eq!(body["headless"], true, "must flag headless: {body}");
    assert_eq!(body["connection_id"].as_str().unwrap(), conn_id.to_string());
    assert_eq!(body["provider"], "x");
    assert_eq!(body["account_email"], "mock@x");
    assert_eq!(body["required_scopes"], json!(["tweet.read", "users.read"]));
    assert!(
        body.get("auth_url").is_none(),
        "headless reauth must omit auth_url: {body}"
    );
    assert!(
        body.get("short").is_none(),
        "headless reauth must omit short: {body}"
    );
    assert_eq!(
        flow_count(&pool).await,
        flows_before,
        "headless reauth must not mint an oauth_connection_flows row"
    );
}

/// Headless org + no connection for the service's provider →
/// `needs_authentication` with no `auth_url`, `headless: true`, the `provider`,
/// and the action's `required_scopes`. No flow minted.
#[tokio::test]
async fn headless_needs_authentication_is_url_less() {
    let pool = common::test_pool().await;
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", "x_test_client");
        std::env::set_var("OAUTH_X_CLIENT_SECRET", "x_test_secret");
    }

    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    make_headless(&pool, org_id).await;

    // No connection seeded — the recovery arm must fire.
    setup_x_service(&base, &client, ident_id, &admin_key).await;

    let flows_before = flow_count(&pool).await;
    let (status, body) = call_get_me(&base, &client, &api_key).await;

    assert_eq!(status, 401, "expected needs_authentication: {body}");
    assert_eq!(body["error"], "needs_authentication");
    assert_eq!(body["headless"], true, "must flag headless: {body}");
    assert_eq!(body["provider"], "x");
    assert!(
        body.get("required_scopes").is_some(),
        "headless needs_authentication must carry required_scopes: {body}"
    );
    assert!(
        body.get("auth_url").is_none(),
        "headless needs_authentication must omit auth_url: {body}"
    );
    assert_eq!(
        flow_count(&pool).await,
        flows_before,
        "headless needs_authentication must not mint a flow row"
    );
}

/// Headless org + a connection missing a required scope → `missing_scopes` with
/// no `auth_url`/`short`/`upgrade_url`, `headless: true`, the `provider`, and
/// the `required`/`missing` deltas. No flow minted.
#[tokio::test]
async fn headless_missing_scopes_is_url_less() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let mock_host = format!("http://{mock_addr}");

    let (base, client) =
        common::start_api_with_registry(pool.clone(), Some(("google_calendar", mock_host))).await;
    let (org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    make_headless(&pool, org_id).await;

    for pattern in ["http:**", "google_calendar:*:*"] {
        client
            .post(format!("{base}/v1/permissions"))
            .header(auth(&admin_key).0, auth(&admin_key).1)
            .json(&json!({"identity_id": ident_id, "action_pattern": pattern}))
            .send()
            .await
            .unwrap();
    }
    common::grant_service_to_everyone(&base, &client, &admin_key, "google_calendar").await;

    // Known but insufficient scope set: list_events requires the calendar scope.
    seed_connection(
        &pool,
        org_id,
        ident_id,
        "google",
        &["https://www.googleapis.com/auth/calendar.readonly"],
        "mock@google",
        false,
    )
    .await;

    let flows_before = flow_count(&pool).await;
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(&api_key).0, auth(&api_key).1)
        .json(&json!({
            "service": "google_calendar",
            "action": "list_events",
            "params": {"calendarId": "primary"}
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap();

    assert_eq!(status, 403, "expected missing_scopes: {body}");
    assert_eq!(body["error"], "missing_scopes");
    assert_eq!(body["headless"], true, "must flag headless: {body}");
    assert_eq!(body["provider"], "google");
    assert_eq!(body["account_email"], "mock@google");
    assert_eq!(body["required"], json!([CAL_SCOPE]));
    assert_eq!(body["missing"], json!([CAL_SCOPE]));
    assert!(
        body.get("auth_url").is_none(),
        "headless missing_scopes must omit auth_url: {body}"
    );
    assert!(
        body.get("short").is_none(),
        "headless missing_scopes must omit short: {body}"
    );
    assert!(
        body.get("upgrade_url").is_none(),
        "headless missing_scopes must omit upgrade_url: {body}"
    );
    assert_eq!(
        flow_count(&pool).await,
        flows_before,
        "headless missing_scopes must not mint a flow row"
    );
}

/// Regression: a **non-headless** org with the same dead-refresh connection
/// still mints a gated `auth_url` and carries no `headless` discriminator —
/// the dashboard gate is untouched.
#[tokio::test]
async fn non_headless_reauth_still_mints_gated_url() {
    let pool = common::test_pool().await;
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", "x_test_client");
        std::env::set_var("OAUTH_X_CLIENT_SECRET", "x_test_secret");
    }

    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    // NOTE: org left non-headless.

    seed_connection(
        &pool,
        org_id,
        ident_id,
        "x",
        &["tweet.read", "users.read"],
        "mock@x",
        true,
    )
    .await;
    setup_x_service(&base, &client, ident_id, &admin_key).await;

    let (status, body) = call_get_me(&base, &client, &api_key).await;

    assert_eq!(status, 401, "expected reauth_required: {body}");
    assert_eq!(body["error"], "reauth_required");
    let auth_url = body["auth_url"].as_str().expect("non-headless must mint auth_url");
    assert!(
        auth_url.contains("/connect-authorize?id="),
        "auth_url should be a gated link: {auth_url}"
    );
    assert!(
        body.get("headless").is_none(),
        "non-headless reauth must not carry a headless discriminator: {body}"
    );
}
