//! Integration tests for the action-call path's typed auth-recovery
//! envelopes.
//!
//! Each test boots the API, drives a `POST /v1/actions/call` request
//! into a known-broken auth state, and asserts the response shape:
//!
//! - `reauth_required` — emitted when the provider rejects the
//!   connection's refresh token. 401 with `{ error, connection_id,
//!   auth_url, reason }`.
//! - `no_refresh_token` — emitted when the access token is expired and
//!   the connection has no refresh token. Same envelope shape, distinct
//!   `reason` value.
//! - `needs_authentication` — emitted when a Mode C action targets a
//!   service whose template declares OAuth and the caller has no
//!   connection for that provider. 401 with `{ error, service,
//!   service_instance_id, auth_url }`.
//!
//! All `auth_url` values must point at the gated
//! `{public_url}/connect-authorize?id=<flow>` shape.
// Test setup writes oauth_provider rows directly (dynamic provider key) and
// uses sqlx::query directly for pool fixtures — both trip the workspace's
// disallowed-methods lint.
#![allow(clippy::disallowed_methods)]

mod common;

use std::net::SocketAddr;

use axum::{Json, Router, http::StatusCode, routing::post};
use serde_json::{Value, json};

/// Spawn a minimal token endpoint that always returns
/// `400 invalid_grant`. Returns the bound address so the caller can point
/// `oauth_providers.token_endpoint` at it. Mirrors the `start_mock`
/// pattern in `tests/common/mod.rs` — the listener is leaked so it
/// outlives the test.
async fn start_failing_token_endpoint() -> SocketAddr {
    let app = Router::new().route(
        "/oauth/token",
        post(|| async {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_grant",
                    "error_description": "refresh token revoked",
                })),
            )
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    addr
}

/// Mode B: when the provider rejects the refresh token, the action
/// handler returns 401 with a `reauth_required` envelope and a gated
/// `auth_url` (no upstream call is attempted).
#[tokio::test]
async fn mode_b_refresh_failed_returns_reauth_required() {
    let pool = common::test_pool().await;
    let token_addr = start_failing_token_endpoint().await;

    // Point the `x` provider's token endpoint at the failing mock.
    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'x'")
        .bind(format!("http://{token_addr}/oauth/token"))
        .execute(&pool)
        .await
        .unwrap();

    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", "x_test_client");
        std::env::set_var("OAUTH_X_CLIENT_SECRET", "x_test_secret");
    }

    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Insert a connection whose access token is already expired and whose
    // refresh token is about to fail at the provider.
    let enc_key = overslash_core::crypto::parse_hex_key(&"ab".repeat(32)).unwrap();
    let enc_access = overslash_core::crypto::encrypt(&enc_key, b"expired_access").unwrap();
    let enc_refresh = overslash_core::crypto::encrypt(&enc_key, b"revoked_refresh").unwrap();
    let scope = overslash_db::scopes::OrgScope::new(org_id, pool.clone());
    let conn = scope
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: ident_id,
            provider_key: "x",
            encrypted_access_token: &enc_access,
            encrypted_refresh_token: Some(&enc_refresh),
            token_expires_at: Some(time::OffsetDateTime::now_utc() - time::Duration::hours(1)),
            scopes: &[],
            account_email: None,
            byoc_credential_id: None,
        })
        .await
        .unwrap();

    // Permission to call any URL (Mode B is raw HTTP under the hood).
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "http:**"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&api_key).0, common::auth(&api_key).1)
        .json(&json!({
            "method": "GET",
            "url": "https://api.twitter.com/2/users/me",
            "connection": conn.id,
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
    assert_eq!(body["connection_id"], conn.id.to_string());
    assert_eq!(body["reason"], "refresh_token_failed");
    let auth_url = body["auth_url"].as_str().unwrap();
    assert!(
        auth_url.contains("/connect-authorize?id="),
        "auth_url should be a gated link: {auth_url}"
    );
}

/// Mode B: when the access token is expired and the connection has no
/// refresh token (some providers don't issue one without
/// `offline_access`), the action handler returns the same
/// `reauth_required` envelope with `reason = no_refresh_token`.
#[tokio::test]
async fn mode_b_no_refresh_token_returns_reauth_required() {
    let pool = common::test_pool().await;

    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", "x_test_client");
        std::env::set_var("OAUTH_X_CLIENT_SECRET", "x_test_secret");
    }

    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let enc_key = overslash_core::crypto::parse_hex_key(&"ab".repeat(32)).unwrap();
    let enc_access = overslash_core::crypto::encrypt(&enc_key, b"expired_access").unwrap();
    let scope = overslash_db::scopes::OrgScope::new(org_id, pool.clone());
    let conn = scope
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: ident_id,
            provider_key: "x",
            encrypted_access_token: &enc_access,
            encrypted_refresh_token: None,
            token_expires_at: Some(time::OffsetDateTime::now_utc() - time::Duration::hours(1)),
            scopes: &[],
            account_email: None,
            byoc_credential_id: None,
        })
        .await
        .unwrap();

    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "http:**"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&api_key).0, common::auth(&api_key).1)
        .json(&json!({
            "method": "GET",
            "url": "https://api.twitter.com/2/users/me",
            "connection": conn.id,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "reauth_required");
    assert_eq!(body["reason"], "no_refresh_token");
    assert!(
        body["auth_url"]
            .as_str()
            .unwrap()
            .contains("/connect-authorize?id=")
    );
}

/// Mode C: when the agent calls a service whose template declares
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
}
