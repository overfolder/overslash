//! Integration coverage for the auto-connect orchestration on
//! `POST /v1/services`.
//!
//! When the resolved template is OAuth-backed and the caller didn't pin a
//! `connection_id` or set `skip_connect: true`, the kernel creates the
//! instance with `connection_id = NULL` and initiates an OAuth flow in the
//! same call. The response carries a `connect` bundle that the caller hands
//! the user. The OAuth callback (driven separately by e2e tests with a
//! mock OAuth server) binds the resulting connection back onto the
//! instance via `service_instance_id` on the flow row.
//!
//! This file covers the deterministic surface (response shape, validation,
//! opt-out, non-OAuth no-op). The full OAuth-callback round-trip lives in
//! the user's e2e harness against the mock OAuth server.
#![allow(clippy::disallowed_methods)]

mod common;

use serde_json::{Value, json};

/// Set the env-var credential fallback once per process so the connect
/// kernel can resolve mock Google OAuth client credentials. Mirrors the
/// other OAuth-touching test files (`oauth_return_url.rs` etc.).
fn ensure_oauth_env() {
    // SAFETY: test-only, ahead of API boot.
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_GOOGLE_CLIENT_ID", "test_client_id");
        std::env::set_var("OAUTH_GOOGLE_CLIENT_SECRET", "test_client_secret");
    }
}

async fn seed_oauth_template(base: &str, client: &reqwest::Client, admin_key: &str, key: &str) {
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "openapi": common::render_openapi(
                include_str!("fixtures/openapi/oauth_google_multi_scoped.yaml.tmpl"),
                &[("key", key), ("display_name", "GCal Auto-Connect")],
            ),
            "user_level": false,
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "template seed failed: {} {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

async fn seed_minimal_template(base: &str, client: &reqwest::Client, admin_key: &str, key: &str) {
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "openapi": common::minimal_openapi(key),
            "user_level": false,
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "minimal template seed failed: {} {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

#[tokio::test]
async fn create_service_auto_initiates_oauth_for_oauth_template() {
    ensure_oauth_env();
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org_id, _ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    seed_oauth_template(&base, &client, &admin_key, "gcal-auto").await;

    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "template_key": "gcal-auto",
            "name": "my-gcal",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "create_service failed: {}",
        resp.text().await.unwrap_or_default()
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["template_key"], "gcal-auto");
    assert_eq!(body["name"], "my-gcal");
    // Service instance is durably created up front with no connection
    // pinned — the OAuth callback writes `connection_id` later.
    assert!(
        body.get("connection_id").is_none() || body["connection_id"].is_null(),
        "connection_id should be null pre-callback; got {body}"
    );
    let connect = body.get("connect").expect("connect bundle present");
    let auth_url = connect["auth_url"].as_str().expect("auth_url present");
    let flow_id = connect["flow_id"].as_str().expect("flow_id present");
    assert!(
        auth_url.contains("/connect-authorize?id="),
        "auth_url should be gated URL, got {auth_url}"
    );
    assert!(!flow_id.is_empty(), "flow_id should not be empty");
    assert_eq!(connect["state"], Value::String(flow_id.to_string()));

    // Confirm the flow row carries the new service instance's id so the
    // callback knows what to bind to.
    let instance_id: uuid::Uuid = body["id"].as_str().unwrap().parse().unwrap();
    let row: (Option<uuid::Uuid>,) =
        sqlx::query_as("SELECT service_instance_id FROM oauth_connection_flows WHERE id = $1")
            .bind(flow_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        row.0,
        Some(instance_id),
        "flow row should carry service_instance_id matching the new instance"
    );
}

#[tokio::test]
async fn skip_connect_opts_out_of_auto_initiate() {
    ensure_oauth_env();
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org_id, _ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    seed_oauth_template(&base, &client, &admin_key, "gcal-skip").await;

    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "template_key": "gcal-skip",
            "name": "my-gcal-noconnect",
            "skip_connect": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body.get("connect").is_none(),
        "connect bundle should be omitted when skip_connect is set; got {body}"
    );

    // And no flow row was created for this caller.
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM oauth_connection_flows")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        count.0, 0,
        "skip_connect must not leave an in-progress OAuth flow behind"
    );
}

#[tokio::test]
async fn non_oauth_template_does_not_auto_connect() {
    ensure_oauth_env();
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org_id, _ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Minimal template declares no auth scheme — nothing to OAuth into.
    seed_minimal_template(&base, &client, &admin_key, "noauth-svc").await;

    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "template_key": "noauth-svc",
            "name": "my-noauth",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body.get("connect").is_none(),
        "non-OAuth template should not carry a connect bundle; got {body}"
    );

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM oauth_connection_flows")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        count.0, 0,
        "non-OAuth template must not start an OAuth flow"
    );
}

#[tokio::test]
async fn auto_connect_failure_keeps_instance_omits_connect_bundle() {
    // No env-var fallback. Without `OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS=1`
    // the connect kernel can't resolve client credentials, so
    // `kernel_create_connection` returns BadRequest. Best-effort
    // orchestration logs and returns the instance anyway — the caller
    // can configure BYOC + retry via `POST /v1/connections` later. This
    // preserves the historical "create instance now, wire credentials
    // later" workflow that the dashboard's /services/new page has
    // always relied on.
    // SAFETY: scoped to this test, no other test in this file relies on
    // the variable being unset.
    unsafe {
        std::env::remove_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS");
    }
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org_id, _ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    seed_oauth_template(&base, &client, &admin_key, "gcal-besteffort").await;

    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "template_key": "gcal-besteffort",
            "name": "besteffort-svc",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "best-effort auto-connect failure must still return the instance; got {}: {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["name"], "besteffort-svc");
    assert!(
        body.get("connect").is_none(),
        "connect bundle should be omitted when auto-connect failed; got {body}"
    );
    // No flow row was minted (the credential resolve failed before that).
    let flow_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM oauth_connection_flows")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(flow_count.0, 0);
}
