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
    // Force the connect kernel to fail by seeding a template whose OAuth
    // provider key doesn't exist in `oauth_providers`. The kernel's
    // `oauth_provider::get_by_key` returns None, the kernel returns
    // NotFound, and best-effort orchestration logs and returns the
    // instance anyway — preserving the historical "create instance now,
    // wire credentials later" workflow.
    //
    // We deliberately avoid `env::remove_var` here because tokio's
    // multi-threaded test runtime shares env state across concurrent tests
    // in the same binary, and other tests in this file set the OAuth env
    // vars in their own `ensure_oauth_env()` calls — a remove_var race
    // would make this test flaky in parallel runs.
    ensure_oauth_env();
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org_id, _ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let openapi = "openapi: 3.1.0\n\
        info:\n  title: GCal Bogus Provider\n  key: gcal-bogus-provider\n\
        servers:\n  - url: https://example.com\n\
        components:\n  securitySchemes:\n    oauth:\n      type: oauth2\n      provider: nonexistent_provider\n      flows:\n        authorizationCode:\n          authorizationUrl: https://example.com/auth\n          tokenUrl: https://example.com/token\n          scopes:\n            read: \"\"\n\
        paths:\n  /items:\n    get:\n      operationId: list_items\n      summary: List\n      risk: read\n      security:\n        - oauth:\n            - read\n";
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "openapi": openapi, "user_level": false }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "template seed failed: {} {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );

    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "template_key": "gcal-bogus-provider",
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
    // No flow row was minted (provider lookup failed before that step).
    let flow_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM oauth_connection_flows")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(flow_count.0, 0);
}

#[tokio::test]
async fn end_to_end_oauth_callback_binds_connection_to_instance() {
    // Real round-trip: `POST /v1/services` → user clicks `connect.auth_url`
    // → callback exchanges code at the mock OAuth server → connection is
    // stored AND `service_instances.connection_id` is updated. Mirrors the
    // pattern in `oauth_x.rs` (point a provider's token_endpoint at the
    // in-process mock, then drive the callback directly).
    ensure_oauth_env();
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;

    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'google'")
        .bind(format!("http://{mock_addr}/oauth/token"))
        .execute(&pool)
        .await
        .unwrap();
    // The userinfo fetch is best-effort; point it at a known-bad URL so
    // the callback short-circuits to `account_email = None` instead of
    // hitting the real Google API.
    sqlx::query("UPDATE oauth_providers SET userinfo_endpoint = $1 WHERE key = 'google'")
        .bind(format!("http://{mock_addr}/userinfo-404"))
        .execute(&pool)
        .await
        .unwrap();

    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org_id, _ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    seed_oauth_template(&base, &client, &admin_key, "gcal-e2e").await;

    // Step 1: create the service — kicks off the OAuth flow.
    let create_resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "template_key": "gcal-e2e",
            "name": "my-gcal-e2e",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(create_resp.status().as_u16(), 200);
    let body: Value = create_resp.json().await.unwrap();
    let instance_id: uuid::Uuid = body["id"].as_str().unwrap().parse().unwrap();
    assert!(
        body["connection_id"].is_null() || body.get("connection_id").is_none(),
        "instance should start with no connection bound; got {body}"
    );
    let flow_id = body["connect"]["flow_id"].as_str().unwrap().to_string();

    // Step 2: simulate the user clicking through OAuth — hit the callback
    // directly with the flow id as `state`. The mock server's token
    // endpoint returns canned tokens for any `code`.
    let callback: Value = client
        .get(format!(
            "{base}/v1/oauth/callback?code=e2e_code&state={flow_id}"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(callback["status"], "connected");
    assert_eq!(callback["provider"], "google");
    let connection_id: uuid::Uuid = callback["connection_id"].as_str().unwrap().parse().unwrap();
    let bound_id: uuid::Uuid = callback["service_instance_id"]
        .as_str()
        .expect("service_instance_id surfaced in JSON")
        .parse()
        .unwrap();
    assert_eq!(
        bound_id, instance_id,
        "callback should report the same service_instance_id the flow row carried"
    );
    assert!(
        callback.get("service_instance_bind_error").is_none(),
        "bind should succeed; got error: {callback}"
    );

    // Step 3: re-fetch the service instance and verify `connection_id` is
    // now pinned to the new connection.
    let fetched: Value = client
        .get(format!("{base}/v1/services/my-gcal-e2e"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let fetched_conn: uuid::Uuid = fetched["connection_id"]
        .as_str()
        .expect("connection_id present after callback")
        .parse()
        .unwrap();
    assert_eq!(
        fetched_conn, connection_id,
        "service instance must be bound to the newly-created connection"
    );
}
