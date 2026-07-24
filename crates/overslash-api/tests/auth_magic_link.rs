// Dynamic SQL queries assert DB side effects of the routes under test.
#![allow(clippy::disallowed_methods)]
//! Passwordless email magic-link login (`/auth/magic-link/request` + `/verify`).
//!
//! The request endpoint always returns an opaque `200 {"sent": true}` (no
//! account enumeration); under `dev_auth_enabled` (the test harness) it also
//! echoes `dev_verify_url` so the link is reachable without an inbox. Verify
//! claims a single-use, unexpired, hashed token and provisions/loads the
//! Overslash-backed `email`-provider user via the shared root path.

use crate::common;

use serde_json::Value;
use uuid::Uuid;

/// A reqwest client that does NOT follow redirects, so verify's 303 (+ its
/// `Set-Cookie`) is observable instead of being chased to the dashboard.
fn no_redirect_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

/// Unique address per test run so tests sharing the Postgres pool don't collide
/// on the `(provider='email', subject=email)` user key.
fn unique_email() -> String {
    format!("ml-{}@example.com", Uuid::new_v4())
}

async fn request_link(base: &str, client: &reqwest::Client, email: &str) -> Value {
    client
        .post(format!("{base}/auth/magic-link/request"))
        .json(&serde_json::json!({ "email": email }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

fn cookies(resp: &reqwest::Response) -> Vec<String> {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect()
}

#[tokio::test]
async fn request_returns_opaque_ok_and_mints_hashed_token() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool.clone()).await;
    let email = unique_email();

    let body = request_link(&base, &client, &email).await;
    assert_eq!(body["sent"], true);
    // Dev harness echoes the link so it's testable without a mailer.
    assert!(
        body["dev_verify_url"]
            .as_str()
            .is_some_and(|u| u.contains("/auth/magic-link/verify")),
        "expected dev_verify_url, got {body}"
    );

    // Exactly one token row was minted, and only the hash is stored (the
    // schema column is `token_hash BYTEA`; the raw token never hits the DB).
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM magic_link_tokens WHERE email = $1")
        .bind(&email)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn verify_provisions_email_user_and_sets_session_cookie() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool.clone()).await;
    let nr = no_redirect_client();
    let email = unique_email();

    let body = request_link(&base, &client, &email).await;
    let verify_url = body["dev_verify_url"].as_str().unwrap();

    let resp = nr.get(verify_url).send().await.unwrap();
    assert_eq!(resp.status(), 303);
    assert!(
        cookies(&resp).iter().any(|c| c.starts_with("oss_session=")),
        "expected oss_session cookie on verify, got {:?}",
        cookies(&resp)
    );
    // Root-apex flow: redirect to the configured dashboard ("/" in the
    // harness), never an org subdomain — magic-link mints a personal-org
    // session and must not honor a stale `oss_auth_org` cookie.
    assert_eq!(resp.headers().get("location").unwrap(), "/");

    // A new Overslash-backed `email`-provider user exists, keyed on the email.
    let user_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM users WHERE overslash_idp_provider = 'email' AND overslash_idp_subject = $1",
    )
    .bind(&email)
    .fetch_one(&pool)
    .await
    .unwrap();

    // …with a personal org, a kind='user' identity, and admin membership.
    let personal_org: Uuid = sqlx::query_scalar("SELECT personal_org_id FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let identity_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identities WHERE org_id = $1 AND user_id = $2 AND kind = 'user'",
    )
    .bind(personal_org)
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        identity_count, 1,
        "expected one user identity in personal org"
    );

    let role: String = sqlx::query_scalar(
        "SELECT role FROM user_org_memberships WHERE user_id = $1 AND org_id = $2",
    )
    .bind(user_id)
    .bind(personal_org)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(role, "admin");
}

#[tokio::test]
async fn verify_is_single_use() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool.clone()).await;
    let nr = no_redirect_client();
    let email = unique_email();

    let verify_url = request_link(&base, &client, &email).await["dev_verify_url"]
        .as_str()
        .unwrap()
        .to_string();

    let first = nr.get(&verify_url).send().await.unwrap();
    assert_eq!(first.status(), 303);
    assert!(
        cookies(&first)
            .iter()
            .any(|c| c.starts_with("oss_session="))
    );

    // Second redemption of the same token is rejected — bounced to /login with
    // no session cookie.
    let second = nr.get(&verify_url).send().await.unwrap();
    assert_eq!(second.status(), 303);
    assert_eq!(
        second.headers().get("location").unwrap(),
        "/login?reason=magic_link_invalid"
    );
    assert!(
        !cookies(&second)
            .iter()
            .any(|c| c.starts_with("oss_session=")),
        "second verify must not mint a session"
    );
}

#[tokio::test]
async fn expired_token_is_rejected() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool.clone()).await;
    let nr = no_redirect_client();
    let email = unique_email();

    let verify_url = request_link(&base, &client, &email).await["dev_verify_url"]
        .as_str()
        .unwrap()
        .to_string();

    // Age the token past its TTL without touching the raw value.
    sqlx::query(
        "UPDATE magic_link_tokens SET expires_at = now() - interval '1 hour' WHERE email = $1",
    )
    .bind(&email)
    .execute(&pool)
    .await
    .unwrap();

    let resp = nr.get(&verify_url).send().await.unwrap();
    assert_eq!(resp.status(), 303);
    assert_eq!(
        resp.headers().get("location").unwrap(),
        "/login?reason=magic_link_invalid"
    );
    assert!(!cookies(&resp).iter().any(|c| c.starts_with("oss_session=")));
}

#[tokio::test]
async fn repeated_request_resolves_to_same_user() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool.clone()).await;
    let nr = no_redirect_client();
    let email = unique_email();

    // Two full request→verify cycles for the same address.
    for _ in 0..2 {
        let url = request_link(&base, &client, &email).await["dev_verify_url"]
            .as_str()
            .unwrap()
            .to_string();
        let resp = nr.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), 303);
    }

    // Idempotent: one user, one personal org — not a fresh account per login.
    let user_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM users WHERE overslash_idp_provider = 'email' AND overslash_idp_subject = $1",
    )
    .bind(&email)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(user_count, 1);
}

#[tokio::test]
async fn unknown_and_known_email_return_identical_shape() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool.clone()).await;
    let nr = no_redirect_client();

    // Make `known` an established user first.
    let known = unique_email();
    let url = request_link(&base, &client, &known).await["dev_verify_url"]
        .as_str()
        .unwrap()
        .to_string();
    nr.get(&url).send().await.unwrap();

    let unknown = unique_email();

    let known_body = request_link(&base, &client, &known).await;
    let unknown_body = request_link(&base, &client, &unknown).await;

    // Same key set + same `sent` value regardless of whether the account
    // exists — the response cannot be used to enumerate users.
    let keys = |v: &Value| {
        let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    };
    assert_eq!(keys(&known_body), keys(&unknown_body));
    assert_eq!(known_body["sent"], unknown_body["sent"]);
}

#[tokio::test]
async fn malformed_email_is_opaque_and_mints_no_token() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool.clone()).await;

    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM magic_link_tokens")
        .fetch_one(&pool)
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/auth/magic-link/request"))
        .json(&serde_json::json!({ "email": "not-an-email" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["sent"], true);
    // A malformed address is still opaque, but no token is minted and no link
    // is echoed.
    assert!(body["dev_verify_url"].is_null());

    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM magic_link_tokens")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(after, before, "malformed email must not mint a token");
}

#[tokio::test]
async fn repeated_requests_for_one_email_are_throttled() {
    // The anonymous request endpoint isn't covered by the API-key rate-limit
    // middleware, so it throttles per-email itself (cap = 5 / 15 min). Past the
    // cap it stays opaque (200, no dev link) and mints no further tokens — the
    // inbox-bombing guard. (Per-test in-memory limiter, so no cross-test bleed.)
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool.clone()).await;
    let email = unique_email();

    // First 5 are honored (dev link echoed); the 6th is silently dropped.
    let mut links = 0;
    for _ in 0..6 {
        let body = request_link(&base, &client, &email).await;
        assert_eq!(body["sent"], true, "always opaque-200");
        if body["dev_verify_url"].as_str().is_some() {
            links += 1;
        }
    }
    assert_eq!(links, 5, "exactly the cap should produce a sendable link");

    let tokens: i64 = sqlx::query_scalar("SELECT count(*) FROM magic_link_tokens WHERE email = $1")
        .bind(&email)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(tokens, 5, "throttled requests mint no token");
}

#[tokio::test]
async fn providers_list_includes_email_method() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    let body: Value = client
        .get(format!("{base}/auth/providers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let providers = body["providers"].as_array().unwrap();
    assert!(
        providers.iter().any(|p| p["key"] == "email"),
        "expected the email magic-link method in the providers list, got {body}"
    );
}
