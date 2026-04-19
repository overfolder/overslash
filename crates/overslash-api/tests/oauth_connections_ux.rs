//! Integration tests for the OAuth connection UX fixes landed under
//! `/home/factory/.claude/plans/oauth-connections-provider-robust-pinwheel.md`:
//!
//! - Service creation rejects a connection that belongs to another identity
//!   or another provider (B2).
//! - `GET /v1/connections` surfaces `scopes` and `used_by_service_templates`
//!   so the dashboard can make reuse-first choices and render scope chips
//!   (B5 + D1 + D2 + D3).
//! - `POST /v1/connections/{id}/upgrade_scopes` returns an auth URL whose
//!   state encodes the existing connection id and whose scopes query param
//!   is the union of existing and requested scopes (B3).
//! - Provider ownership check rejects an upgrade against another identity's
//!   connection.
#![allow(clippy::disallowed_methods)]

mod common;

use overslash_core::crypto;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

/// Seed a connection directly into the DB so tests can exercise connection-
/// consuming endpoints without going through the full OAuth flow (which
/// requires a mock provider and adds noise unrelated to what we're testing).
async fn seed_connection(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    provider_key: &str,
    scopes: &[&str],
    account_email: Option<&str>,
) -> Uuid {
    // Tests use the same deterministic enc key `common::start_api` injects
    // (config.rs uses `"ab".repeat(32)`).
    let enc_key = crypto::parse_hex_key(&"ab".repeat(32)).unwrap();
    let access = crypto::encrypt(&enc_key, b"mock_access_token").unwrap();
    let scope_vec: Vec<String> = scopes.iter().map(|s| (*s).to_string()).collect();

    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO connections (org_id, identity_id, provider_key,
         encrypted_access_token, scopes, account_email)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(org_id)
    .bind(identity_id)
    .bind(provider_key)
    .bind(&access)
    .bind(&scope_vec)
    .bind(account_email)
    .fetch_one(pool)
    .await
    .unwrap();
    row.0
}

#[tokio::test]
async fn create_service_rejects_connection_from_wrong_provider() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Template uses google OAuth; connection is for github.
    client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "openapi": common::render_openapi(
                include_str!("fixtures/openapi/oauth_google.yaml.tmpl"),
                &[("key", "google-thing"), ("display_name", "Google Thing")],
            ),
            "user_level": false,
        }))
        .send()
        .await
        .unwrap();

    let wrong_conn_id = seed_connection(
        &pool,
        org_id,
        ident_id,
        "github",
        &["repo"],
        Some("me@github"),
    )
    .await;

    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "template_key": "google-thing",
            "name": "my-google",
            "connection_id": wrong_conn_id,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    let err = body["error"].as_str().unwrap_or("");
    assert!(
        err.contains("connection_provider_mismatch"),
        "expected connection_provider_mismatch, got body: {body}"
    );
}

#[tokio::test]
async fn list_connections_includes_scopes_and_usage() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Create a google-backed template and bind a connection to an active
    // service instance under it.
    client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "openapi": common::render_openapi(
                include_str!("fixtures/openapi/oauth_google.yaml.tmpl"),
                &[("key", "gcal"), ("display_name", "Google Calendar")],
            ),
            "user_level": false,
        }))
        .send()
        .await
        .unwrap();

    let conn_id = seed_connection(
        &pool,
        org_id,
        ident_id,
        "google",
        &[
            "openid",
            "email",
            "https://www.googleapis.com/auth/calendar",
        ],
        Some("alice@example.com"),
    )
    .await;

    let create_resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "template_key": "gcal",
            "name": "calendar-work",
            "connection_id": conn_id,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(create_resp.status(), 200, "{:?}", create_resp.text().await);

    let conns: Vec<Value> = client
        .get(format!("{base}/v1/connections"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let c = &conns[0];
    assert_eq!(c["account_email"], "alice@example.com");
    let scopes: Vec<&str> = c["scopes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(scopes.contains(&"openid"));
    let used: Vec<&str> = c["used_by_service_templates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        used,
        vec!["gcal"],
        "expected connection to report its binding to 'gcal'"
    );
}

#[tokio::test]
async fn upgrade_scopes_returns_auth_url_with_union_scopes() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, api_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Seed env creds so the credential cascade (tier 3) resolves — the
    // upgrade handler pulls creds the same way the initiate path does.
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_GOOGLE_CLIENT_ID", "g_client");
        std::env::set_var("OAUTH_GOOGLE_CLIENT_SECRET", "g_secret");
    }

    let conn_id = seed_connection(
        &pool,
        org_id,
        ident_id,
        "google",
        &["openid", "email"],
        Some("alice@example.com"),
    )
    .await;

    let resp: Value = client
        .post(format!("{base}/v1/connections/{conn_id}/upgrade_scopes"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "scopes": [
                "email",  // duplicate — should be deduped
                "https://www.googleapis.com/auth/drive.readonly"
            ]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let auth_url = resp["auth_url"].as_str().unwrap();
    let state = resp["state"].as_str().unwrap();
    let requested: Vec<&str> = resp["requested_scopes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

    // Union = existing (openid, email) ∪ requested (email, drive.readonly)
    assert!(requested.contains(&"openid"));
    assert!(requested.contains(&"email"));
    assert!(requested.contains(&"https://www.googleapis.com/auth/drive.readonly"));
    assert_eq!(
        requested.iter().filter(|s| **s == "email").count(),
        1,
        "duplicate scope should dedupe"
    );

    // State carries the existing connection id as the 7th segment so the
    // callback updates in place.
    let segs: Vec<&str> = state.split(':').collect();
    assert_eq!(segs.len(), 7, "upgrade state should have 7 segments");
    assert_eq!(
        segs[6],
        conn_id.to_string(),
        "7th segment is upgrade_connection_id"
    );

    // Auth URL preserves google's include_granted_scopes=true and the full
    // scope union.
    assert!(auth_url.contains("include_granted_scopes=true"));
    assert!(auth_url.contains("drive.readonly"));
}

#[tokio::test]
async fn service_detail_reports_needs_reconnect_when_no_action_covers() {
    // End-to-end: connection grants only `openid`; template declares an
    // action requiring `calendar`. The service should surface
    // credentials_status=needs_reconnect so the dashboard can render a
    // distinct state.
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "openapi": common::render_openapi(
                include_str!("fixtures/openapi/oauth_google_scoped.yaml.tmpl"),
                &[("key", "gcal-scoped"), ("display_name", "Google Calendar Scoped")],
            ),
            "user_level": false,
        }))
        .send()
        .await
        .unwrap();

    let conn_id = seed_connection(
        &pool,
        org_id,
        ident_id,
        "google",
        &["openid"],
        Some("alice@example.com"),
    )
    .await;

    let _ = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "template_key": "gcal-scoped",
            "name": "my-gcal",
            "connection_id": conn_id,
        }))
        .send()
        .await
        .unwrap();

    let detail: Value = client
        .get(format!("{base}/v1/services/my-gcal"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        detail["credentials_status"], "needs_reconnect",
        "service should report needs_reconnect; got {detail}"
    );

    // List endpoint carries the same field.
    let list: Vec<Value> = client
        .get(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = list
        .iter()
        .find(|s| s["name"] == "my-gcal")
        .expect("service in list");
    assert_eq!(row["credentials_status"], "needs_reconnect");
}

#[tokio::test]
async fn upgrade_scopes_rejects_cross_identity_attempts() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, _ident_id, api_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Seed a connection belonging to a *different* identity in the same
    // org. The caller should not be able to upgrade it, even though the id
    // is reachable through the shared OrgScope.
    let other_id: Uuid = sqlx::query_scalar(
        "INSERT INTO identities (org_id, name, kind, parent_id, depth, inherit_permissions)
         VALUES ($1, 'other-user', 'user', NULL, 0, false) RETURNING id",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let conn_id = seed_connection(&pool, org_id, other_id, "google", &["openid"], None).await;

    let resp = client
        .post(format!("{base}/v1/connections/{conn_id}/upgrade_scopes"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({ "scopes": ["email"] }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}
