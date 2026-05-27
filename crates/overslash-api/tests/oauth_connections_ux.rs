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
    let enc_key = crypto::Keyring::test();
    let access = crypto::encrypt(&enc_key, b"mock_access_token").unwrap();
    let scope_vec: Vec<String> = scopes.iter().map(|s| (*s).to_string()).collect();

    // `is_default` is computed like the production insert path
    // (repos::connection::create): default only when the identity has no
    // existing default for the provider. Keeps seeds compatible with the
    // single-default partial unique index when a test links two accounts to
    // the same provider.
    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO connections (org_id, identity_id, provider_key,
         encrypted_access_token, scopes, account_email, is_default)
         VALUES ($1, $2, $3, $4, $5, $6,
                 NOT EXISTS (
                     SELECT 1 FROM connections
                     WHERE identity_id = $2 AND provider_key = $3 AND is_default
                 )) RETURNING id",
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

    // `state` is the opaque flow-row id. The row carries
    // `upgrade_connection_id` pointing at the connection we're upgrading —
    // that's what tells the callback to update this row in place rather
    // than minting a new connection. The upstream provider URL stashed on
    // the row (the one the user gets redirected to from `/connect-authorize`)
    // is where google-specific bits like `include_granted_scopes` land.
    let flow = overslash_db::repos::oauth_connection_flow::get_by_id(&pool, state)
        .await
        .unwrap()
        .expect("upgrade flow row should exist");
    assert_eq!(flow.upgrade_connection_id, Some(conn_id));
    assert_eq!(flow.provider_key, "google");
    assert_eq!(flow.identity_id, ident_id);
    assert!(
        flow.upstream_authorize_url
            .contains("include_granted_scopes=true")
    );
    assert!(flow.upstream_authorize_url.contains("drive.readonly"));

    // The returned `auth_url` is the Overslash-gated `/connect-authorize?id=…`
    // URL — consistent with the initiate path so chat-delivered upgrade
    // links go through the same login bounce / mismatch UX.
    assert!(auth_url.contains("/connect-authorize?id="));
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

// ── connection detail (GET /v1/connections/{id}) ────────────────────────────

/// Helper: register a google-backed template under `key` and create an active
/// service instance `name` bound to `conn_id`. Returns nothing — callers assert
/// against the connection/service endpoints afterwards.
async fn make_google_service(
    base: &str,
    client: &reqwest::Client,
    admin_key: &str,
    api_key: &str,
    key: &str,
    name: &str,
    conn_id: Uuid,
) {
    client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "openapi": common::render_openapi(
                include_str!("fixtures/openapi/oauth_google.yaml.tmpl"),
                &[("key", key), ("display_name", "Google Thing")],
            ),
            "user_level": false,
        }))
        .send()
        .await
        .unwrap();
    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({ "template_key": key, "name": name, "connection_id": conn_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "service create failed: {:?}", resp.text().await);
}

#[tokio::test]
async fn get_connection_returns_detail_with_used_by() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let conn_id = seed_connection(
        &pool,
        org_id,
        ident_id,
        "google",
        &["openid", "email"],
        Some("alice@example.com"),
    )
    .await;
    make_google_service(&base, &client, &admin_key, &api_key, "gthing", "calendar-work", conn_id)
        .await;

    let detail: Value = client
        .get(format!("{base}/v1/connections/{conn_id}"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(detail["id"], conn_id.to_string());
    assert_eq!(detail["account_email"], "alice@example.com");
    assert_eq!(detail["is_default"], true);
    assert!(detail["updated_at"].is_string());
    let used = detail["used_by"].as_array().expect("used_by array");
    assert_eq!(used.len(), 1, "expected one bound service: {detail}");
    assert_eq!(used[0]["name"], "calendar-work");
    assert_eq!(used[0]["template_key"], "gthing");
    assert!(used[0]["id"].is_string());
}

#[tokio::test]
async fn get_connection_rejects_cross_identity() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, _ident_id, api_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

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
        .get(format!("{base}/v1/connections/{conn_id}"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ── set_default ─────────────────────────────────────────────────────────────

async fn get_is_default(base: &str, client: &reqwest::Client, api_key: &str, id: Uuid) -> bool {
    let detail: Value = client
        .get(format!("{base}/v1/connections/{id}"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    detail["is_default"].as_bool().unwrap()
}

#[tokio::test]
async fn set_default_promotes_target_and_demotes_sibling() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, api_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Two google connections for the same identity. The first becomes the
    // default (no prior default); the second does not.
    let first = seed_connection(&pool, org_id, ident_id, "google", &["openid"], Some("a@x.com"))
        .await;
    let second = seed_connection(&pool, org_id, ident_id, "google", &["openid"], Some("b@x.com"))
        .await;
    assert!(get_is_default(&base, &client, &api_key, first).await);
    assert!(!get_is_default(&base, &client, &api_key, second).await);

    let resp = client
        .post(format!("{base}/v1/connections/{second}/set_default"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Exactly one default per provider: the flag moved to `second`.
    assert!(!get_is_default(&base, &client, &api_key, first).await);
    assert!(get_is_default(&base, &client, &api_key, second).await);

    // DB-level invariant: a single is_default row for (identity, provider).
    let default_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM connections
         WHERE identity_id = $1 AND provider_key = 'google' AND is_default",
    )
    .bind(ident_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(default_count, 1);
}

#[tokio::test]
async fn set_default_rejects_cross_identity() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, _ident_id, api_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

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
        .post(format!("{base}/v1/connections/{conn_id}/set_default"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ── services ?connection= filter ────────────────────────────────────────────

#[tokio::test]
async fn services_list_connection_filter_narrows() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Two connections, two services — one bound to each.
    let conn_a = seed_connection(&pool, org_id, ident_id, "google", &["openid"], Some("a@x.com"))
        .await;
    let conn_b = seed_connection(&pool, org_id, ident_id, "google", &["openid"], Some("b@x.com"))
        .await;
    make_google_service(&base, &client, &admin_key, &api_key, "svc_a", "service-a", conn_a).await;
    make_google_service(&base, &client, &admin_key, &api_key, "svc_b", "service-b", conn_b).await;

    let filtered: Vec<Value> = client
        .get(format!("{base}/v1/services?connection={conn_a}"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(filtered.len(), 1, "filter should return one service: {filtered:?}");
    assert_eq!(filtered[0]["name"], "service-a");
    assert_eq!(filtered[0]["connection_id"], conn_a.to_string());
}
