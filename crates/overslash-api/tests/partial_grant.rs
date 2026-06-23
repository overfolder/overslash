//! Partial-grant detection (SPEC §9 "Per-action scopes").
//!
//! Covers the two new surfaces that let an agent notice an OAuth grant doesn't
//! cover an action *before* burning a call on it:
//!   1. Discovery annotation — `GET /v1/search` and
//!      `GET /v1/services/{name}/actions` carry per-action `scope_coverage`
//!      (`covered` / `needs_reconnect` / `unknown`) plus the `missing_scopes`
//!      delta.
//!   2. Self-heal — a token refresh whose response declares `scope` records the
//!      granted set, converting a legacy NULL-scope connection into a known one.
//!
//! Hermetic: no real Google. The scope gate / coverage classifier only compares
//! recorded scope strings, and the refresh hits the in-process OAuth fake.

#![allow(clippy::disallowed_methods)] // runtime sqlx::query for one-off test seeds

mod common;

use overslash_core::crypto;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

const READONLY: &str = "https://www.googleapis.com/auth/gmail.readonly";
const METADATA: &str = "https://www.googleapis.com/auth/gmail.metadata";

fn auth(key: &str) -> (&'static str, String) {
    ("Authorization", format!("Bearer {key}"))
}

/// Insert a `connections` row directly with a chosen scope set. `scopes = None`
/// records SQL NULL (the legacy "unknown grant" state the gate gives benefit of
/// the doubt). The encrypted token is dummy bytes — discovery never decrypts it.
async fn seed_connection(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    scopes: Option<&[&str]>,
) -> Uuid {
    let id = Uuid::new_v4();
    let scope_vec: Option<Vec<String>> = scopes.map(|s| s.iter().map(|x| x.to_string()).collect());
    sqlx::query(
        "INSERT INTO connections \
         (id, org_id, identity_id, provider_key, encrypted_access_token, \
          scopes, account_email, is_default) \
         VALUES ($1, $2, $3, 'google', $4, $5, 'alice@gmail.com', false)",
    )
    .bind(id)
    .bind(org_id)
    .bind(identity_id)
    .bind(b"fake_token".as_ref())
    .bind(scope_vec)
    .execute(pool)
    .await
    .expect("seed connection");
    id
}

/// Create a user-level gmail instance pinned to `connection_id`.
async fn create_gmail_service(
    base: &str,
    client: &reqwest::Client,
    admin_key: &str,
    name: &str,
    connection_id: Uuid,
) {
    let resp: Value = client
        .post(format!("{base}/v1/services"))
        .header(auth(admin_key).0, auth(admin_key).1)
        .json(&json!({
            "template_key": "gmail",
            "name": name,
            "connection_id": connection_id.to_string(),
            "user_level": true,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["name"], name, "create gmail service failed: {resp}");
}

/// First search row matching `(template, action)`.
fn find_action<'a>(results: &'a [Value], template: &str, action: &str) -> Option<&'a Value> {
    results
        .iter()
        .find(|r| r["template"] == template && r["action"] == action)
}

async fn search(base: &str, client: &reqwest::Client, key: &str, q: &str) -> Vec<Value> {
    let body: Value = client
        .get(format!("{base}/v1/search?q={q}"))
        .header(auth(key).0, auth(key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    body["results"].as_array().cloned().unwrap_or_default()
}

#[tokio::test]
async fn search_flags_uncovered_action_as_needs_reconnect() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let pool2 = pool.clone();
    let (base, client) = common::start_api_for_search(pool).await;
    let conn = seed_connection(&pool2, fx.org_id, fx.user_ids[0], Some(&[METADATA])).await;
    create_gmail_service(&base, &client, &fx.admin_key, "gmail-partial", conn).await;

    let results = search(&base, &client, &fx.admin_key, "messages").await;

    // list_messages requires gmail.readonly — metadata-only grant → needs_reconnect.
    let row = find_action(&results, "gmail", "list_messages")
        .unwrap_or_else(|| panic!("list_messages row missing: {results:?}"));
    assert_eq!(
        row["scope_coverage"], "needs_reconnect",
        "uncovered action should flag needs_reconnect: {row}"
    );
    let missing = row["missing_scopes"]
        .as_array()
        .expect("missing_scopes array");
    assert_eq!(missing.len(), 1, "expected one missing scope: {row}");
    assert_eq!(missing[0], READONLY);
}

#[tokio::test]
async fn search_marks_covered_action_covered() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let pool2 = pool.clone();
    let (base, client) = common::start_api_for_search(pool).await;
    // get_profile only needs gmail.metadata, which the grant has.
    let conn = seed_connection(&pool2, fx.org_id, fx.user_ids[0], Some(&[METADATA])).await;
    create_gmail_service(&base, &client, &fx.admin_key, "gmail-meta", conn).await;

    let results = search(&base, &client, &fx.admin_key, "profile").await;
    let row = find_action(&results, "gmail", "get_profile")
        .unwrap_or_else(|| panic!("get_profile row missing: {results:?}"));
    assert_eq!(row["scope_coverage"], "covered", "row: {row}");
    assert!(
        row.get("missing_scopes").is_none(),
        "covered row must omit missing_scopes: {row}"
    );
}

#[tokio::test]
async fn search_reports_unknown_for_unrecorded_scopes() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let pool2 = pool.clone();
    let (base, client) = common::start_api_for_search(pool).await;
    // NULL scopes — a legacy import. The gate gives benefit of the doubt; here
    // we surface that honestly as `unknown` rather than a false `covered`.
    let conn = seed_connection(&pool2, fx.org_id, fx.user_ids[0], None).await;
    create_gmail_service(&base, &client, &fx.admin_key, "gmail-legacy", conn).await;

    let results = search(&base, &client, &fx.admin_key, "messages").await;
    let row = find_action(&results, "gmail", "list_messages")
        .unwrap_or_else(|| panic!("list_messages row missing: {results:?}"));
    assert_eq!(row["scope_coverage"], "unknown", "row: {row}");
    assert!(row.get("missing_scopes").is_none(), "row: {row}");
}

#[tokio::test]
async fn actions_list_annotates_coverage() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let pool2 = pool.clone();
    let (base, client) = common::start_api_for_search(pool).await;
    let conn = seed_connection(&pool2, fx.org_id, fx.user_ids[0], Some(&[METADATA])).await;
    create_gmail_service(&base, &client, &fx.admin_key, "gmail-list", conn).await;

    let actions: Vec<Value> = client
        .get(format!("{base}/v1/services/gmail-list/actions"))
        .header(auth(&fx.admin_key).0, auth(&fx.admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let by_key = |k: &str| actions.iter().find(|a| a["key"] == k).cloned();

    let list_messages = by_key("list_messages").expect("list_messages action");
    assert_eq!(list_messages["scope_coverage"], "needs_reconnect");
    assert_eq!(list_messages["missing_scopes"][0], READONLY);

    let get_profile = by_key("get_profile").expect("get_profile action");
    assert_eq!(get_profile["scope_coverage"], "covered");
    assert!(
        get_profile.get("missing_scopes").is_none(),
        "covered action must omit missing_scopes: {get_profile}"
    );
}

#[tokio::test]
async fn refresh_self_heals_recorded_scopes() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let mock_addr = common::start_mock().await;

    // A dedicated provider whose token endpoint is the in-process OAuth fake.
    sqlx::query(
        "INSERT INTO oauth_providers (key, display_name, authorization_endpoint, token_endpoint) \
         VALUES ('google_selfheal', 'google_selfheal', 'http://unused.test/authorize', $1)",
    )
    .bind(format!("http://{mock_addr}/oauth/token"))
    .execute(&pool)
    .await
    .unwrap();

    // Connection with NULL scopes and an expired access token. The refresh
    // token encodes the grant the fake will echo back (`scoped:` sentinel).
    let enc = crypto::Keyring::test();
    let access = crypto::encrypt(&enc, b"stale_access").unwrap();
    let refresh = crypto::encrypt(&enc, format!("scoped:{METADATA}").as_bytes()).unwrap();
    let past = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
    let conn_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO connections \
         (id, org_id, identity_id, provider_key, encrypted_access_token, \
          encrypted_refresh_token, token_expires_at, scopes, is_default) \
         VALUES ($1, $2, $3, 'google_selfheal', $4, $5, $6, NULL, false)",
    )
    .bind(conn_id)
    .bind(fx.org_id)
    .bind(fx.user_ids[0])
    .bind(&access)
    .bind(&refresh)
    .bind(past)
    .execute(&pool)
    .await
    .unwrap();

    let scope = overslash_db::scopes::OrgScope::new(fx.org_id, pool.clone());
    let conn = scope.get_connection(conn_id).await.unwrap().unwrap();
    assert!(conn.scopes.is_none(), "precondition: scopes start NULL");

    let http = reqwest::Client::new();
    let token = overslash_api::services::oauth::resolve_access_token(
        &scope,
        &http,
        &enc,
        &conn,
        "client-id",
        "client-secret",
    )
    .await
    .expect("refresh should succeed against fake");
    assert_eq!(token, "mock_refreshed_access_token");

    // The NULL grant is now the set the refresh declared.
    let healed = scope.get_connection(conn_id).await.unwrap().unwrap();
    assert_eq!(
        healed.scopes.as_deref(),
        Some(&[METADATA.to_string()][..]),
        "refresh should self-heal recorded scopes"
    );
}
