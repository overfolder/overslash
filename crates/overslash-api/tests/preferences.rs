//! Integration tests for /auth/me/preferences and /auth/me/identity is_org_admin.

mod common;

use serde_json::{Value, json};

async fn dev_session() -> (String, reqwest::Client, String) {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;
    let token: Value = client
        .get(format!("{base}/auth/dev/token"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = token["token"].as_str().unwrap().to_string();
    (base, client, token)
}

#[tokio::test]
async fn preferences_get_returns_empty_defaults() {
    let (base, client, token) = dev_session().await;

    let resp = client
        .get(format!("{base}/auth/me/preferences"))
        .header("cookie", format!("oss_session={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    // Defaults serialize as an empty object (skip_serializing_if = none).
    assert!(body.get("theme").is_none() || body["theme"].is_null());
    assert!(body.get("time_display").is_none() || body["time_display"].is_null());
}

#[tokio::test]
async fn preferences_put_persists_and_merges_partial_updates() {
    let (base, client, token) = dev_session().await;

    // First PUT: only theme
    let r1 = client
        .put(format!("{base}/auth/me/preferences"))
        .header("cookie", format!("oss_session={token}"))
        .json(&json!({ "theme": "dark" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), 200);
    let b1: Value = r1.json().await.unwrap();
    assert_eq!(b1["theme"], "dark");

    // Second PUT: only time_display — must NOT clobber theme
    let r2 = client
        .put(format!("{base}/auth/me/preferences"))
        .header("cookie", format!("oss_session={token}"))
        .json(&json!({ "time_display": "absolute" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 200);
    let b2: Value = r2.json().await.unwrap();
    assert_eq!(b2["theme"], "dark");
    assert_eq!(b2["time_display"], "absolute");

    // GET reflects both
    let r3: Value = client
        .get(format!("{base}/auth/me/preferences"))
        .header("cookie", format!("oss_session={token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r3["theme"], "dark");
    assert_eq!(r3["time_display"], "absolute");
}

#[tokio::test]
async fn preferences_get_unauthenticated_returns_401() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    let resp = client
        .get(format!("{base}/auth/me/preferences"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn preferences_put_unauthenticated_returns_401() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    let resp = client
        .put(format!("{base}/auth/me/preferences"))
        .json(&json!({ "theme": "dark" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn preferences_put_invalid_session_returns_401() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    let resp = client
        .put(format!("{base}/auth/me/preferences"))
        .header("cookie", "oss_session=garbage.token.here")
        .json(&json!({ "theme": "dark" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// --- /auth/me/identity ---------------------------------------------------

#[tokio::test]
async fn me_identity_returns_is_org_admin_for_dev_user() {
    let (base, client, token) = dev_session().await;

    let resp = client
        .get(format!("{base}/auth/me/identity"))
        .header("cookie", format!("oss_session={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();

    // Dev user is bootstrapped as the org admin.
    assert_eq!(body["is_org_admin"], true);
    assert!(body["org_name"].is_string());
    assert_eq!(body["email"], "dev@overslash.local");
}

// --- session-cookie auth on list endpoints used by /profile ----------------

#[tokio::test]
async fn list_permissions_works_via_session_cookie() {
    let (base, client, token) = dev_session().await;
    let resp = client
        .get(format!("{base}/v1/permissions"))
        .header("cookie", format!("oss_session={token}"))
        .send()
        .await
        .unwrap();
    // Must NOT be 401 — session cookie auth must be honored.
    assert_eq!(
        resp.status(),
        200,
        "expected 200 from session-auth list_permissions"
    );
    let body: Value = resp.json().await.unwrap();
    assert!(body.is_array());
}

#[tokio::test]
async fn list_secrets_works_via_session_cookie() {
    let (base, client, token) = dev_session().await;
    let resp = client
        .get(format!("{base}/v1/secrets"))
        .header("cookie", format!("oss_session={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "expected 200 from session-auth list_secrets"
    );
    let body: Value = resp.json().await.unwrap();
    assert!(body.is_array());
}

#[tokio::test]
async fn me_identity_returns_401_without_session() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;
    let resp = client
        .get(format!("{base}/auth/me/identity"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}
