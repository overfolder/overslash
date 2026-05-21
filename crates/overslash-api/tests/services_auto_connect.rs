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

#[tokio::test]
async fn connect_include_raw_exposes_upstream_authorize_url() {
    // White-label integration path: when the REST caller opts in with
    // `connect_include_raw: true`, the response also carries the raw
    // upstream provider URL (e.g. accounts.google.com/...). Default
    // callers still see only the gated Overslash URL.
    ensure_oauth_env();
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org_id, _ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    seed_oauth_template(&base, &client, &admin_key, "gcal-raw").await;

    // Opt-in: raw URL is present.
    let body: Value = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "template_key": "gcal-raw",
            "name": "raw-svc",
            "connect_include_raw": true,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let connect = body.get("connect").expect("connect bundle present");
    let raw = connect["raw"].as_str().expect("raw url surfaced");
    assert!(
        raw.starts_with("https://accounts.google.com/"),
        "raw url should be the upstream provider URL; got {raw}"
    );
    let auth_url = connect["auth_url"].as_str().unwrap();
    assert!(
        auth_url.contains("/connect-authorize?id="),
        "gated auth_url still primary; got {auth_url}"
    );

    // Default (no opt-in): raw URL is absent.
    let body: Value = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "template_key": "gcal-raw",
            "name": "raw-svc-default",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let connect = body.get("connect").expect("connect bundle present");
    assert!(
        connect.get("raw").is_none() || connect["raw"].is_null(),
        "raw should be omitted without opt-in; got {body}"
    );
}

#[tokio::test]
async fn callback_bind_refuses_cross_user_service_instance() {
    // Security: the `service_instance_id` field on the flow row is set by
    // `kernel_create_service` when it orchestrates an OAuth flow, but an
    // MCP agent could in principle smuggle a spoofed id through
    // `CreateConnectionInput.service_instance_id` (defense-in-depth: the
    // MCP `dispatch_create_connection` strips this field, but the
    // callback also re-checks). The callback must refuse to bind when
    // the instance's owner doesn't match the connection's identity_id —
    // otherwise user A could hijack user B's service onto user A's
    // credentials.
    ensure_oauth_env();
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;

    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'google'")
        .bind(format!("http://{mock_addr}/oauth/token"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE oauth_providers SET userinfo_endpoint = $1 WHERE key = 'google'")
        .bind(format!("http://{mock_addr}/userinfo-404"))
        .execute(&pool)
        .await
        .unwrap();

    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, _victim_ident, _victim_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    seed_oauth_template(&base, &client, &admin_key, "gcal-hijack").await;

    // Victim creates a service instance. It belongs to the victim's user.
    let victim_svc: Value = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "template_key": "gcal-hijack",
            "name": "victim-svc",
            "skip_connect": true,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let victim_svc_id: uuid::Uuid = victim_svc["id"].as_str().unwrap().parse().unwrap();

    // Attacker: a different identity in the same org.
    let attacker_user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name": "attacker-user", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let attacker_id: uuid::Uuid = attacker_user["id"].as_str().unwrap().parse().unwrap();
    let attacker_key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"org_id": org_id, "identity_id": attacker_id, "name": "attacker-key"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let attacker_key = attacker_key_resp["key"].as_str().unwrap().to_string();

    // Attacker initiates a low-level connection flow, then injects the
    // victim's service_instance_id directly onto the flow row to model
    // the worst-case scenario where the MCP strip in
    // `dispatch_create_connection` is somehow bypassed.
    let initiate: Value = client
        .post(format!("{base}/v1/connections"))
        .header("Authorization", format!("Bearer {attacker_key}"))
        .json(&json!({ "provider": "google", "scopes": ["openid"] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let flow_id = initiate["flow_id"].as_str().unwrap().to_string();
    sqlx::query("UPDATE oauth_connection_flows SET service_instance_id = $1 WHERE id = $2")
        .bind(victim_svc_id)
        .bind(&flow_id)
        .execute(&pool)
        .await
        .unwrap();

    // Attacker completes the OAuth dance.
    let callback: Value = client
        .get(format!(
            "{base}/v1/oauth/callback?code=hijack_code&state={flow_id}"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Connection lands (OAuth tokens are real), but bind is REFUSED.
    assert_eq!(callback["status"], "connected");
    assert_eq!(
        callback["service_instance_bind_error"], "service_instance_owner_mismatch",
        "bind must refuse cross-user hijack; got {callback}"
    );
    assert!(
        callback.get("service_instance_id").is_none(),
        "service_instance_id must be suppressed on failure; got {callback}"
    );

    // And the victim's service was NOT mutated.
    let still_unbound: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT connection_id FROM service_instances WHERE id = $1")
            .bind(victim_svc_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        still_unbound.is_none(),
        "victim service must remain unbound after hijack attempt"
    );
}

#[tokio::test]
async fn org_level_service_does_not_auto_connect() {
    // Connections are identity-bound; the manual `connection_id` path on
    // `kernel_create_service` already rejects pinning a connection to an
    // org-level service. Auto-connect must obey the same rule — otherwise
    // an admin creating `user_level: false` would get an OAuth flow that
    // could never bind on the callback (the owner-mismatch gate would
    // refuse it anyway, but the better behavior is to never orchestrate
    // the flow at all).
    ensure_oauth_env();
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org_id, _ident_id, _api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    seed_oauth_template(&base, &client, &admin_key, "gcal-orglvl").await;

    // admin_key is org-level (no identity_id), so `user_level: false`
    // clears its admin gate and creates an org-level instance.
    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "template_key": "gcal-orglvl",
            "name": "orglvl-svc",
            "user_level": false,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body.get("owner_identity_id").is_none() || body["owner_identity_id"].is_null(),
        "org-level service should have no owner; got {body}"
    );
    assert!(
        body.get("connect").is_none(),
        "org-level service must not auto-connect; got {body}"
    );

    let flow_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM oauth_connection_flows")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        flow_count.0, 0,
        "org-level service must not mint an OAuth flow"
    );
}

#[tokio::test]
async fn callback_bind_error_surfaces_when_instance_missing() {
    // Defensive branch in `oauth_callback_inner`: when the flow row carries
    // a `service_instance_id` but the instance doesn't exist by the time
    // the callback runs (e.g. concurrent delete in the race window after
    // the flow read), the callback keeps the connection and surfaces
    // `service_instance_bind_error: service_instance_not_found` on the
    // response.
    //
    // The FK on the flow column is `ON DELETE SET NULL`, so a normal
    // delete of the instance would clear the flow row's id before the
    // callback even sees it. To exercise the race deterministically we
    // drop the FK constraint temporarily, point the flow row at a bogus
    // UUID, then drive the callback. Postgres still accepts the column
    // value (it's just a UUID at the type level); only the bind
    // `update_service_instance` call returns `Ok(None)` because no row
    // matches.
    ensure_oauth_env();
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;

    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'google'")
        .bind(format!("http://{mock_addr}/oauth/token"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE oauth_providers SET userinfo_endpoint = $1 WHERE key = 'google'")
        .bind(format!("http://{mock_addr}/userinfo-404"))
        .execute(&pool)
        .await
        .unwrap();

    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org_id, _ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    seed_oauth_template(&base, &client, &admin_key, "gcal-binderr").await;

    let body: Value = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({ "template_key": "gcal-binderr", "name": "binderr-svc" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let flow_id = body["connect"]["flow_id"].as_str().unwrap().to_string();

    // Drop the FK so we can simulate a missing instance without it
    // cascading to NULL on the flow row.
    sqlx::query(
        "ALTER TABLE oauth_connection_flows \
         DROP CONSTRAINT oauth_connection_flows_service_instance_id_fkey",
    )
    .execute(&pool)
    .await
    .unwrap();
    let bogus_id = uuid::Uuid::new_v4();
    sqlx::query("UPDATE oauth_connection_flows SET service_instance_id = $1 WHERE id = $2")
        .bind(bogus_id)
        .bind(&flow_id)
        .execute(&pool)
        .await
        .unwrap();

    let callback: Value = client
        .get(format!(
            "{base}/v1/oauth/callback?code=binderr_code&state={flow_id}"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Connection still landed — OAuth tokens are valuable and the bind
    // failure is reported alongside, not by tearing the connection down.
    assert_eq!(callback["status"], "connected");
    assert!(
        callback["connection_id"].is_string(),
        "connection must persist even when bind fails; got {callback}"
    );
    assert_eq!(
        callback["service_instance_bind_error"], "service_instance_not_found",
        "bind error code must surface on the response; got {callback}"
    );
    // Successful side-channel (service_instance_id) is suppressed when
    // there was a bind error — callers shouldn't be told "bound to id X"
    // alongside an error.
    assert!(
        callback.get("service_instance_id").is_none(),
        "service_instance_id should be omitted when bind failed; got {callback}"
    );
}

#[tokio::test]
async fn callback_bind_error_surfaces_on_redirect_response_too() {
    // The bind-error code also has to land on the redirect path, since
    // tenants using `return_url` never see the JSON body. Drives the same
    // scenario as `callback_bind_error_surfaces_when_instance_missing`
    // but with a configured `return_url` so the success/error path goes
    // through `success_redirect` instead of the JSON branch.
    ensure_oauth_env();
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;

    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'google'")
        .bind(format!("http://{mock_addr}/oauth/token"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE oauth_providers SET userinfo_endpoint = $1 WHERE key = 'google'")
        .bind(format!("http://{mock_addr}/userinfo-404"))
        .execute(&pool)
        .await
        .unwrap();

    // Set up the return-url allow-list + a non-redirecting client so we
    // can inspect the 303 Location header.
    let (api_addr, _) = common::start_api_with(pool.clone(), |cfg| {
        cfg.connection_return_url_allowed_hosts = vec!["cloud.example.test".into()];
    })
    .await;
    let base = format!("http://{api_addr}");
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let (_org_id, _ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    seed_oauth_template(&base, &client, &admin_key, "gcal-binderr-redir").await;

    let body: Value = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "template_key": "gcal-binderr-redir",
            "name": "binderr-redir-svc",
            "connect_return_url": "https://cloud.example.test/oauth/cb",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let flow_id = body["connect"]["flow_id"].as_str().unwrap().to_string();

    sqlx::query(
        "ALTER TABLE oauth_connection_flows \
         DROP CONSTRAINT oauth_connection_flows_service_instance_id_fkey",
    )
    .execute(&pool)
    .await
    .unwrap();
    let bogus_id = uuid::Uuid::new_v4();
    sqlx::query("UPDATE oauth_connection_flows SET service_instance_id = $1 WHERE id = $2")
        .bind(bogus_id)
        .bind(&flow_id)
        .execute(&pool)
        .await
        .unwrap();

    let resp = client
        .get(format!(
            "{base}/v1/oauth/callback?code=binderr_redir_code&state={flow_id}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 303);
    let location = resp
        .headers()
        .get("location")
        .expect("redirect carries Location header")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        location.starts_with("https://cloud.example.test/oauth/cb"),
        "redirect should target the configured return_url; got {location}"
    );
    assert!(
        location.contains("status=success"),
        "connection still succeeded; got {location}"
    );
    assert!(
        location.contains("service_instance_bind_error=service_instance_not_found"),
        "bind error code must ride the redirect query params; got {location}"
    );
    assert!(
        !location.contains("service_instance_id="),
        "service_instance_id should be omitted when bind failed; got {location}"
    );
}
