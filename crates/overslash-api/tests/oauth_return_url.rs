//! End-to-end coverage for the `return_url` redirect on `/v1/oauth/callback`.
//!
//! Companion to `parse_return_url` unit tests in `services/platform_connections.rs`:
//! those validate the format check at create time; these validate the
//! callback's allow-list gate. The OAuth `state` is now the opaque flow-row
//! id, so there's nothing for a caller to spoof — every field comes off the
//! row.
#![allow(clippy::disallowed_methods)]

mod common;

use overslash_db::repos::oauth_connection_flow::{self, CreateOauthConnectionFlow};
use serde_json::Value;
use std::net::SocketAddr;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// Bring up the API with the OAuth credential envvars + a stub mock for
/// `/oauth/token` and the allow-list set to `allowed.test`. The first
/// `unsafe set_var` block is the same dance the existing OAuth callback
/// tests use — the callback resolves client credentials via an env
/// fallback that's gated behind `OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS=1`.
async fn boot(
    pool: sqlx::PgPool,
    allowed_hosts: Vec<String>,
    token_endpoint_override: Option<String>,
) -> (SocketAddr, reqwest::Client, SocketAddr) {
    // SAFETY: test-only, before the server boots. These mirror the same
    // env-var setup the integration suite uses to inject OAuth client
    // credentials without seeding `byoc_credentials`.
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_GITHUB_CLIENT_ID", "test_client_id");
        std::env::set_var("OAUTH_GITHUB_CLIENT_SECRET", "test_client_secret");
    }

    let mock_addr = common::start_mock().await;
    let token_endpoint =
        token_endpoint_override.unwrap_or_else(|| format!("http://{mock_addr}/oauth/token"));
    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'github'")
        .bind(&token_endpoint)
        .execute(&pool)
        .await
        .unwrap();

    let (addr, _default_client) = common::start_api_with(pool.clone(), move |cfg| {
        cfg.connection_return_url_allowed_hosts = allowed_hosts;
    })
    .await;

    // The default test client follows redirects, which is fine for the
    // JSON branches but swallows the Location header we need to assert
    // on. Build a non-following client for use throughout these tests.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    (addr, client, mock_addr)
}

/// Insert a fully-formed flow row directly. We bypass `POST /v1/connections`
/// because seeding it that way means crafting a valid API key + identity
/// hierarchy for every test; here we only care about what the callback
/// does given a row, so we plant the row directly.
async fn seed_flow(
    pool: &sqlx::PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    actor_identity_id: Uuid,
    return_url: Option<&str>,
) -> String {
    let flow_id = format!("flow_{}", &Uuid::new_v4().simple().to_string()[..16]);
    oauth_connection_flow::create(
        pool,
        &CreateOauthConnectionFlow {
            id: &flow_id,
            org_id,
            identity_id,
            actor_identity_id,
            provider_key: "github",
            byoc_credential_id: None,
            scopes: &[],
            pkce_code_verifier: None,
            upstream_authorize_url: "https://github.com/login/oauth/authorize",
            expires_at: OffsetDateTime::now_utc() + Duration::minutes(10),
            created_ip: None,
            created_user_agent: None,
            return_url,
            upgrade_connection_id: None,
            service_instance_id: None,
            pin_service_instance_ids: &[],
        },
    )
    .await
    .unwrap();
    flow_id
}

/// Bootstrap a minimal org + user identity directly via repos, so we can
/// own the identity ids in our state string without round-tripping through
/// the REST surface. Returns `(org_id, user_identity_id)`.
async fn bootstrap_owner(pool: &sqlx::PgPool, slug: &str) -> (Uuid, Uuid) {
    let org = overslash_db::repos::org::create(pool, "ReturnUrlOrg", slug, "standard")
        .await
        .unwrap();
    let ident = overslash_db::repos::identity::create(pool, org.id, "owner", "user", None)
        .await
        .unwrap();
    (org.id, ident.id)
}

/// The OAuth `state` parameter is the opaque flow-row id. Wrapper exists
/// so the tests read intentionally — they're not just passing a raw string.
fn state_for(flow_id: &str) -> String {
    flow_id.to_string()
}

#[tokio::test]
async fn callback_redirects_to_allow_listed_return_url_on_success() {
    let pool = common::test_pool().await;
    let (org_id, ident_id) = bootstrap_owner(&pool, &format!("ret-ok-{}", Uuid::new_v4())).await;
    let flow_id = seed_flow(
        &pool,
        org_id,
        ident_id,
        ident_id,
        Some("https://allowed.test/cb?ref=tenant"),
    )
    .await;

    let (api_addr, client, _) = boot(pool.clone(), vec!["allowed.test".into()], None).await;
    let state = state_for(&flow_id);
    let resp = client
        .get(format!(
            "http://{api_addr}/v1/oauth/callback?code=test_code&state={state}"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 303, "expected redirect");
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    let url = url::Url::parse(location).unwrap();
    assert_eq!(url.scheme(), "https");
    assert_eq!(url.host_str(), Some("allowed.test"));
    assert_eq!(url.path(), "/cb");
    let qs: std::collections::HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(qs.get("ref").map(String::as_str), Some("tenant"));
    assert_eq!(qs.get("status").map(String::as_str), Some("success"));
    assert_eq!(qs.get("provider").map(String::as_str), Some("github"));
    assert!(qs.contains_key("connection_id"));

    // Connection row landed regardless of which response path fired.
    let conns: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM connections WHERE org_id = $1 AND identity_id = $2",
    )
    .bind(org_id)
    .bind(ident_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(conns, 1);
}

#[tokio::test]
async fn callback_falls_back_to_json_when_host_not_allow_listed() {
    let pool = common::test_pool().await;
    let (org_id, ident_id) = bootstrap_owner(&pool, &format!("ret-miss-{}", Uuid::new_v4())).await;
    let flow_id = seed_flow(
        &pool,
        org_id,
        ident_id,
        ident_id,
        Some("https://evil.test/cb"),
    )
    .await;

    // Allow-list does not include `evil.test`.
    let (api_addr, client, _) = boot(pool.clone(), vec!["allowed.test".into()], None).await;
    let state = state_for(&flow_id);
    let resp = client
        .get(format!(
            "http://{api_addr}/v1/oauth/callback?code=test_code&state={state}"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    assert!(resp.headers().get("location").is_none());
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "connected");
    assert_eq!(body["provider"], "github");
}

#[tokio::test]
async fn callback_falls_back_to_json_when_flow_row_has_no_return_url() {
    // Row exists, allow-list is configured, but the row was minted without
    // a `return_url`. The callback must take the historical JSON path
    // rather than try to redirect somewhere unspecified.
    let pool = common::test_pool().await;
    let (org_id, ident_id) =
        bootstrap_owner(&pool, &format!("ret-no-url-{}", Uuid::new_v4())).await;
    let flow_id = seed_flow(&pool, org_id, ident_id, ident_id, None).await;

    let (api_addr, client, _) = boot(pool.clone(), vec!["allowed.test".into()], None).await;
    let state = state_for(&flow_id);
    let resp = client
        .get(format!(
            "http://{api_addr}/v1/oauth/callback?code=test_code&state={state}"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    assert!(resp.headers().get("location").is_none());
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "connected");
}

#[tokio::test]
async fn callback_rejects_unknown_state() {
    // No row exists for this id → 400. With `state` now being the row id
    // itself, an attacker can't fabricate org/identity segments to extract
    // any behavior — the only thing they can supply is an opaque id, and
    // it has to resolve to a real row.
    let pool = common::test_pool().await;
    let (_org_id, _ident_id) =
        bootstrap_owner(&pool, &format!("ret-unknown-{}", Uuid::new_v4())).await;

    let (api_addr, client, _) = boot(pool.clone(), vec!["allowed.test".into()], None).await;
    let resp = client
        .get(format!(
            "http://{api_addr}/v1/oauth/callback?code=test_code&state=flow_does_not_exist"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 400);
}

#[tokio::test]
async fn callback_redirects_with_error_reason_when_token_exchange_fails() {
    // Force token exchange to fail by pointing the provider at a port
    // nothing's listening on. reqwest will surface a connection error;
    // the route translates that to `AppError::BadRequest`, which the
    // redirect path renders as `reason=bad_request`.
    let pool = common::test_pool().await;
    let (org_id, ident_id) = bootstrap_owner(&pool, &format!("ret-err-{}", Uuid::new_v4())).await;
    let flow_id = seed_flow(
        &pool,
        org_id,
        ident_id,
        ident_id,
        Some("https://allowed.test/cb"),
    )
    .await;

    let (api_addr, client, _) = boot(
        pool.clone(),
        vec!["allowed.test".into()],
        // Port 1 is reserved (tcpmux) and unbound on test boxes — reqwest
        // will get ECONNREFUSED, which is what we want here.
        Some("http://127.0.0.1:1/oauth/token".into()),
    )
    .await;
    let state = state_for(&flow_id);
    let resp = client
        .get(format!(
            "http://{api_addr}/v1/oauth/callback?code=test_code&state={state}"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 303);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    let url = url::Url::parse(location).unwrap();
    assert_eq!(url.host_str(), Some("allowed.test"));
    let qs: std::collections::HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(qs.get("status").map(String::as_str), Some("error"));
    assert_eq!(qs.get("provider").map(String::as_str), Some("github"));
    // Coarse token, NOT the raw error text — see `redirect_reason_token`.
    assert_eq!(qs.get("reason").map(String::as_str), Some("bad_request"));

    // No connection row was created on the error path.
    let conns: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM connections WHERE org_id = $1")
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(conns, 0);
}
