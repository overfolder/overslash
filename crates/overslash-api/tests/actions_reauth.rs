//! Integration tests for the action-call path's typed auth-recovery
//! envelopes.
//!
//! Drives a `POST /v1/actions/call` against a known-broken auth state
//! and asserts the response shape:
//!
//! - `needs_authentication` — emitted when an action-shape call targets
//!   a service whose template declares OAuth and the caller has no
//!   connection for that provider. 401 with `{ error, service,
//!   service_instance_id, auth_url }`.
//!
//! `auth_url` must point at the gated
//! `{public_url}/connect-authorize?id=<flow>` shape.
//!
//! The `reauth_required` envelope (refresh-failed / no-refresh-token)
//! is exercised at unit-test level in `routes::actions::tests`
//! (`classify_oauth_*`) and by the live Mode-C path: any expired
//! instance-bound OAuth connection trips the same `oauth_error_to_app_error`
//! call site. Earlier Mode-B integration tests of this envelope were
//! removed alongside Mode B itself (see DECISIONS.md D14).
// Test setup writes oauth_provider rows directly (dynamic provider key) and
// uses sqlx::query directly for pool fixtures — both trip the workspace's
// disallowed-methods lint.
#![allow(clippy::disallowed_methods)]

mod common;

use axum::http::StatusCode;
use overslash_core::crypto;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

/// Seed an OAuth connection with an expired access token and no refresh
/// token. Mirrors the helper in `mcp_typed_errors.rs` — kept inline
/// rather than re-exporting since `common/mod.rs` doesn't expose it.
/// Drives the `OAuthError::NoRefreshToken → Reauth("no_refresh_token")`
/// classify path so a service call against this connection returns
/// `reauth_required`.
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

/// When the agent calls a service whose template declares
/// OAuth and the calling identity has no connection for that provider,
/// the action handler returns 401 `needs_authentication` with a
/// fresh-create gated `auth_url` and the resolved `service_instance_id`.
#[tokio::test]
async fn mode_c_no_connection_returns_needs_authentication() {
    let pool = common::test_pool().await;

    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", "x_test_client");
        std::env::set_var("OAUTH_X_CLIENT_SECRET", "x_test_secret");
    }

    // Use `start_api_with_registry` so the bundled `x` template is loaded
    // — the default `start_api` boots with an empty `ServiceRegistry` and
    // would 404 the create call below.
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (_org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Create an org-level service instance for the bundled `x` template.
    // No connection is bound — we want the recovery arm to fire.
    let create_resp = client
        .post(format!("{base}/v1/services"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
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
        "service create failed: {} {:?}",
        create_resp.status(),
        create_resp.text().await
    );
    let svc: Value = create_resp.json().await.unwrap();
    let svc_id = svc["id"].as_str().unwrap().to_string();

    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "x:*:*"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&api_key).0, common::auth(&api_key).1)
        .json(&json!({
            "service": "x",
            "action": "get_me",
            "params": {},
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "expected 401 needs_authentication, got: {:?}",
        resp.text().await
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "needs_authentication");
    assert_eq!(body["service"], "x");
    let auth_url = body["auth_url"].as_str().unwrap();
    assert!(
        auth_url.contains("/connect-authorize?id="),
        "auth_url should be a gated link: {auth_url}"
    );
    // service_instance_id should round-trip when one was found.
    assert_eq!(body["service_instance_id"].as_str().unwrap(), svc_id);
    // The raw upstream provider authorize URL is never surfaced — white-label
    // partners import tokens instead of wrapping an Overslash-built URL.
    assert!(
        body.get("raw").is_none_or(Value::is_null),
        "raw must never appear on the envelope: {body}"
    );
}

/// When the template declares OAuth but the org has **no OAuth client at all**
/// (no managed client, no org-level OAuth App Credentials, no BYOC), minting the
/// recovery `auth_url` fails inside the credential cascade with a `BadRequest`
/// ("no OAuth client credentials configured…"). That is a caller-actionable
/// config problem — the action handler must surface it as the same 4xx the
/// documented `create_connection` path returns, **not** bury it behind an opaque
/// 500. Uses `google` (no `OAUTH_GOOGLE_*` env is ever set in this binary) so the
/// cascade falls through to its terminal error regardless of the env flags the
/// sibling tests above toggle for the `x` provider.
#[tokio::test]
async fn mode_c_no_oauth_client_configured_returns_actionable_4xx() {
    let pool = common::test_pool().await;

    // Deliberately do NOT set OAUTH_GOOGLE_CLIENT_ID/SECRET or the danger flag:
    // we want the credential cascade to find nothing and return its terminal
    // "no OAuth client credentials configured" BadRequest.
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (_org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Org-level google_calendar instance, no connection and no client creds.
    let create_resp = client
        .post(format!("{base}/v1/services"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({
            "template_key": "google_calendar",
            "name": "google-calendar",
            "user_level": false,
            "status": "active",
        }))
        .send()
        .await
        .unwrap();
    assert!(
        create_resp.status().is_success(),
        "service create failed: {} {:?}",
        create_resp.status(),
        create_resp.text().await
    );

    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "google_calendar:*:*"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&api_key).0, common::auth(&api_key).1)
        .json(&json!({
            "service": "google_calendar",
            "action": "list_calendars",
            "params": {},
        }))
        .send()
        .await
        .unwrap();

    let status = resp.status();
    let body = resp.text().await.unwrap();
    // The actionable 4xx, never a 5xx. Before the fix this path wrapped the
    // cascade's BadRequest as `Internal` (500).
    assert!(
        status.is_client_error(),
        "expected a 4xx for missing OAuth client, got {status}: {body}"
    );
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert!(
        body.contains("no OAuth client credentials configured"),
        "expected the cascade's actionable message, got: {body}"
    );
}

/// The other half of the mint-error fork: when the failure is *not*
/// caller-actionable — here the provider's `oauth_providers` row is missing,
/// so `mint_initial_auth_url` bottoms out in `NotFound` — the handler must
/// keep wrapping it as `Internal` (500). A raw 404 on `/v1/actions/call`
/// would read as "the action doesn't exist" rather than "provider not set
/// up for this org", so only `BadRequest` is passed through verbatim.
#[tokio::test]
async fn mode_c_missing_provider_row_stays_internal_500() {
    let pool = common::test_pool().await;

    // Client creds are present, so the cascade itself would succeed — the
    // failure we want comes earlier, from the missing provider row, which
    // `kernel_create_connection` looks up before resolving credentials.
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", "x_test_client");
        std::env::set_var("OAUTH_X_CLIENT_SECRET", "x_test_secret");
    }

    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (_org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let create_resp = client
        .post(format!("{base}/v1/services"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
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
        "service create failed: {} {:?}",
        create_resp.status(),
        create_resp.text().await
    );

    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "x:*:*"}))
        .send()
        .await
        .unwrap();

    // Delete the seeded provider row so the URL mint fails with `NotFound`
    // (the `oauth_provider::get_by_key` lookup returns None) rather than a
    // caller-actionable `BadRequest` from the credential cascade.
    sqlx::query("DELETE FROM oauth_providers WHERE key = 'x'")
        .execute(&pool)
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&api_key).0, common::auth(&api_key).1)
        .json(&json!({
            "service": "x",
            "action": "get_me",
            "params": {},
        }))
        .send()
        .await
        .unwrap();

    let status = resp.status();
    let body = resp.text().await.unwrap();
    // NotFound is wrapped as Internal — never surfaced as a raw 404.
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "missing provider row should be a 500, got {status}: {body}"
    );
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "a raw 404 here reads as 'action not found': {body}"
    );
}

/// REST sibling of `mcp_call_expired_no_refresh_returns_typed_reauth_required`:
/// the action-call REST envelope for `reauth_required` on a normal
/// (orchestrated / self-refresh) connection carries the gated `auth_url`,
/// the `provider`, no `headless` discriminator, and never a raw provider URL.
#[tokio::test]
async fn reauth_required_rest_envelope_shape() {
    let pool = common::test_pool().await;

    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", "x_test_client");
        std::env::set_var("OAUTH_X_CLIENT_SECRET", "x_test_secret");
    }

    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Connections resolve at the owner identity (D22): the calling agent shares
    // its owner user's connection, so seed it on the owner ("test-user"), not on
    // the agent. `bootstrap_org_identity` puts the agent under that user.
    let owner_id = common::owner_user_id(&pool, org_id).await;
    let connection_id = seed_connection_no_refresh_expired(&pool, org_id, owner_id, "x").await;

    let create_resp = client
        .post(format!("{base}/v1/services"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({
            "template_key": "x",
            "name": "x",
            "user_level": false,
            "status": "active",
        }))
        .send()
        .await
        .unwrap();
    assert!(create_resp.status().is_success());

    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "x:*:*"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&api_key).0, common::auth(&api_key).1)
        .json(&json!({
            "service": "x",
            "action": "get_me",
            "params": {},
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "expected 401 reauth_required, got: {:?}",
        resp.text().await
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "reauth_required");
    assert_eq!(
        body["connection_id"].as_str().unwrap(),
        connection_id.to_string()
    );

    let auth_url = body["auth_url"].as_str().expect("auth_url required");
    assert!(
        auth_url.contains("/connect-authorize?id="),
        "auth_url should be a gated link: {auth_url}"
    );
    // Normal (non-headless) org: provider present, no `headless` discriminator.
    assert_eq!(body["provider"], "x");
    assert!(
        body.get("headless").is_none(),
        "headless must not appear on a non-headless reauth envelope: {body}"
    );
    // The raw upstream provider URL is never surfaced.
    assert!(
        body.get("raw").is_none_or(Value::is_null),
        "raw must never appear on the envelope: {body}"
    );
}

/// `?wrap=true` (the dashboard "try it" surface) turns the gateway's own
/// `needs_authentication` 401 into a **200** envelope with the status inside,
/// so a browser client doesn't conflate it with a session-expiry 401 and
/// bounce the user to /login. The default (no `wrap`) still returns the 401 —
/// see `mode_c_no_connection_returns_needs_authentication`.
#[tokio::test]
async fn wrap_true_returns_200_needs_authentication_envelope() {
    let pool = common::test_pool().await;

    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", "x_test_client");
        std::env::set_var("OAUTH_X_CLIENT_SECRET", "x_test_secret");
    }

    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (_org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let create_resp = client
        .post(format!("{base}/v1/services"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
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
        "service create failed: {} {:?}",
        create_resp.status(),
        create_resp.text().await
    );
    let svc: Value = create_resp.json().await.unwrap();
    let svc_id = svc["id"].as_str().unwrap().to_string();

    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "x:*:*"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/v1/actions/call?wrap=true"))
        .header(common::auth(&api_key).0, common::auth(&api_key).1)
        .json(&json!({
            "service": "x",
            "action": "get_me",
            "params": {},
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "wrap=true must surface needs_authentication as a 200, got: {:?}",
        resp.text().await
    );
    let body: Value = resp.json().await.unwrap();
    // `status` discriminant inside the body (not `error`), so it slots into
    // the dashboard's `CallResponse` union.
    assert_eq!(body["status"], "needs_authentication");
    assert_eq!(body["service"], "x");
    assert_eq!(body["service_instance_id"].as_str().unwrap(), svc_id);
    let auth_url = body["auth_url"].as_str().unwrap();
    assert!(
        auth_url.contains("/connect-authorize?id="),
        "auth_url should be a gated link: {auth_url}"
    );
}

/// `?wrap=true` likewise surfaces `reauth_required` as a 200 envelope. Mirrors
/// `reauth_required_rest_envelope_shape` (which asserts the default 401 shape).
#[tokio::test]
async fn wrap_true_returns_200_reauth_required_envelope() {
    let pool = common::test_pool().await;

    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", "x_test_client");
        std::env::set_var("OAUTH_X_CLIENT_SECRET", "x_test_secret");
    }

    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Connections resolve at the owner identity (D22): the calling agent shares
    // its owner user's connection, so seed it on the owner ("test-user"), not on
    // the agent. `bootstrap_org_identity` puts the agent under that user.
    let owner_id = common::owner_user_id(&pool, org_id).await;
    let connection_id = seed_connection_no_refresh_expired(&pool, org_id, owner_id, "x").await;

    let create_resp = client
        .post(format!("{base}/v1/services"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({
            "template_key": "x",
            "name": "x",
            "user_level": false,
            "status": "active",
        }))
        .send()
        .await
        .unwrap();
    assert!(create_resp.status().is_success());

    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "x:*:*"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/v1/actions/call?wrap=true"))
        .header(common::auth(&api_key).0, common::auth(&api_key).1)
        .json(&json!({
            "service": "x",
            "action": "get_me",
            "params": {},
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "wrap=true must surface reauth_required as a 200, got: {:?}",
        resp.text().await
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "reauth_required");
    assert_eq!(
        body["connection_id"].as_str().unwrap(),
        connection_id.to_string()
    );
    assert!(
        body["auth_url"]
            .as_str()
            .expect("auth_url required")
            .contains("/connect-authorize?id="),
    );
}
