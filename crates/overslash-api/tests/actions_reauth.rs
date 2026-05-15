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
    // The REST envelope carries the upstream provider authorize URL for
    // white-label integrators that wrap consent in their own UI. The MCP
    // forwarder strips this — see the sibling assertion in
    // `mcp_typed_errors.rs::mcp_call_no_connection_returns_typed_needs_authentication`.
    let raw = body["raw"]
        .as_str()
        .expect("REST envelope must include `raw` (upstream provider URL)");
    assert!(
        raw.starts_with("https://"),
        "raw should be the upstream provider authorize URL: {raw}"
    );
    assert!(
        !raw.contains("/connect-authorize"),
        "raw must be the upstream URL, not the gated Overslash URL: {raw}"
    );
}

/// REST sibling of `mcp_call_expired_no_refresh_returns_typed_reauth_required`:
/// the action-call REST envelope for `reauth_required` must include the
/// gated `auth_url` AND the upstream provider `raw` URL. The MCP forwarder
/// strips `raw`; the REST path always carries it so white-label integrators
/// can rewrap consent in their own UI.
#[tokio::test]
async fn reauth_required_rest_envelope_includes_raw_authorize_url() {
    let pool = common::test_pool().await;

    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", "x_test_client");
        std::env::set_var("OAUTH_X_CLIENT_SECRET", "x_test_secret");
    }

    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let connection_id = seed_connection_no_refresh_expired(&pool, org_id, ident_id, "x").await;

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

    // White-label rewrap surface: `raw` must be present on the REST path
    // and must be the upstream provider URL, not the gated form.
    let raw = body["raw"]
        .as_str()
        .expect("REST envelope must include `raw` (upstream provider URL)");
    assert!(
        raw.starts_with("https://"),
        "raw should be the upstream provider authorize URL: {raw}"
    );
    assert!(
        !raw.contains("/connect-authorize"),
        "raw must be the upstream URL, not the gated Overslash URL: {raw}"
    );
}
