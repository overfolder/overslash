//! End-to-end coverage for the `return_url` redirect on `/v1/oauth/callback`.
//!
//! Companion to `parse_return_url` unit tests in `services/platform_connections.rs`:
//! those validate the format check at create time; these validate the
//! callback's allow-list gate and the spoofing defense built around the
//! flow_id state segment.
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

fn state_with_flow(org: Uuid, ident: Uuid, flow_id: &str) -> String {
    // Mirrors `kernel_create_connection`'s 8-segment format. We use the
    // owner identity for both the "owner" and "actor" slots; the callback
    // only cross-checks that they match the flow row.
    format!("{org}:{ident}:github:_:_:{ident}:_:{flow_id}")
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
    let state = state_with_flow(org_id, ident_id, &flow_id);
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
    let state = state_with_flow(org_id, ident_id, &flow_id);
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
async fn callback_falls_back_to_json_when_flow_state_mismatch() {
    // Spoof attempt: pass flow A's id but state segments naming identity B.
    // The cross-check in `resolve_redirect_target` must reject the flow row
    // and the callback must render JSON, not redirect.
    let pool = common::test_pool().await;
    let (org_a, ident_a) = bootstrap_owner(&pool, &format!("ret-spoof-a-{}", Uuid::new_v4())).await;
    let (_org_b, ident_b) =
        bootstrap_owner(&pool, &format!("ret-spoof-b-{}", Uuid::new_v4())).await;
    let flow_id_a = seed_flow(
        &pool,
        org_a,
        ident_a,
        ident_a,
        Some("https://allowed.test/cb"),
    )
    .await;

    let (api_addr, client, _) = boot(pool.clone(), vec!["allowed.test".into()], None).await;
    // State names identity B, but the supplied flow_id belongs to identity A.
    // The mocked OAuth callback wouldn't have got this far in real life —
    // an attacker would also have to forge a `code` — but the test exists
    // to verify the gate, not the upstream protocol.
    let state = state_with_flow(org_a, ident_b, &flow_id_a);
    let resp = client
        .get(format!(
            "http://{api_addr}/v1/oauth/callback?code=test_code&state={state}"
        ))
        .send()
        .await
        .unwrap();

    // Connection still gets created against `ident_b` from state, but the
    // response stays JSON because the redirect cross-check rejected the
    // stitched flow row.
    assert_eq!(resp.status().as_u16(), 200);
    assert!(resp.headers().get("location").is_none());
}

#[tokio::test]
async fn callback_falls_back_to_json_when_state_has_no_flow_id_segment() {
    // Backward-compat: an in-flight callback that was minted before this
    // PR shipped has only 7 state segments. The new parser must tolerate
    // that and take the JSON path.
    let pool = common::test_pool().await;
    let (org_id, ident_id) =
        bootstrap_owner(&pool, &format!("ret-legacy-{}", Uuid::new_v4())).await;

    let (api_addr, client, _) = boot(pool.clone(), vec!["allowed.test".into()], None).await;
    let state = format!("{org_id}:{ident_id}:github:_:_:{ident_id}:_");
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
    let state = state_with_flow(org_id, ident_id, &flow_id);
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
