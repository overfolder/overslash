//! Integration coverage for the optional `template` field on
//! `POST /v1/connections`. When set, the kernel resolves the template
//! across user → org → global tiers, verifies it declares the requested
//! OAuth provider, and seeds `scopes` with the union of every action's
//! `required_scopes` before building the authorize URL.
//!
//! Companion to the design notes in
//! `/home/factory/.claude/plans/default-oauth-scopes-rippling-fairy.md`.
#![allow(clippy::disallowed_methods)]

mod common;

use serde_json::{Value, json};

/// Set the env-var credential fallback once per process. The connect kernel
/// resolves OAuth client credentials via `client_credentials::resolve`,
/// which only consults env vars when
/// `OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS=1` is set. Other tests
/// (e.g. `oauth_return_url.rs`, `cross_user_group_reauth.rs`) do the same
/// dance; values are idempotent across concurrent tests.
fn ensure_oauth_env() {
    // SAFETY: test-only, ahead of the API boot. The variables we set are
    // namespaced to OAuth credentials and the explicit danger opt-in.
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_GOOGLE_CLIENT_ID", "test_client_id");
        std::env::set_var("OAUTH_GOOGLE_CLIENT_SECRET", "test_client_secret");
    }
}

fn scope_param(raw_url: &str) -> String {
    let url = url::Url::parse(raw_url).expect("raw url parses");
    url.query_pairs()
        .find(|(k, _)| k == "scope")
        .map(|(_, v)| v.into_owned())
        .expect("scope query param present")
}

async fn seed_multi_scoped_template(
    base: &str,
    client: &reqwest::Client,
    admin_key: &str,
    key: &str,
) {
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "openapi": common::render_openapi(
                include_str!("fixtures/openapi/oauth_google_multi_scoped.yaml.tmpl"),
                &[("key", key), ("display_name", "GCal Multi")],
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

#[tokio::test]
async fn connect_with_template_unions_action_required_scopes() {
    ensure_oauth_env();
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org_id, _ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    seed_multi_scoped_template(&base, &client, &admin_key, "gcal-union").await;

    let resp = client
        .post(format!("{base}/v1/connections"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "provider": "google",
            "template": "gcal-union",
            "include_raw": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "connect failed: {}",
        resp.text().await.unwrap_or_default()
    );
    let body: Value = resp.json().await.unwrap();
    let raw = body["raw"].as_str().expect("raw url present");
    let scope = scope_param(raw);
    assert!(
        scope.contains("https://www.googleapis.com/auth/calendar.events"),
        "scope missing calendar.events: {scope}"
    );
    assert!(
        scope.contains("https://www.googleapis.com/auth/calendar.readonly"),
        "scope missing calendar.readonly: {scope}"
    );
}

#[tokio::test]
async fn connect_with_template_merges_caller_extras() {
    ensure_oauth_env();
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org_id, _ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    seed_multi_scoped_template(&base, &client, &admin_key, "gcal-merge").await;

    let resp = client
        .post(format!("{base}/v1/connections"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "provider": "google",
            "template": "gcal-merge",
            "scopes": ["openid"],
            "include_raw": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    let raw = body["raw"].as_str().expect("raw url present");
    let scope = scope_param(raw);
    assert!(
        scope.contains("https://www.googleapis.com/auth/calendar.events"),
        "scope missing calendar.events: {scope}"
    );
    assert!(
        scope.contains("https://www.googleapis.com/auth/calendar.readonly"),
        "scope missing calendar.readonly: {scope}"
    );
    assert!(
        scope.split(' ').any(|s| s == "openid"),
        "caller-supplied 'openid' scope not folded in: {scope}"
    );
}

#[tokio::test]
async fn connect_with_template_provider_mismatch_returns_400() {
    ensure_oauth_env();
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org_id, _ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    seed_multi_scoped_template(&base, &client, &admin_key, "gcal-mismatch").await;

    let resp = client
        .post(format!("{base}/v1/connections"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "provider": "github",
            "template": "gcal-mismatch",
            "include_raw": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    let body_text = resp.text().await.unwrap();
    assert!(
        body_text.contains("google") && body_text.contains("github"),
        "expected mismatch message naming both providers, got: {body_text}"
    );
}
