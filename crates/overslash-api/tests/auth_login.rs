//! Integration tests for user authentication (dev token, /auth/me, Google login).

mod common;

use serde_json::Value;

// --- Dev token endpoint ---

#[tokio::test]
async fn dev_token_returns_jwt_when_enabled() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    let resp = client
        .get(format!("{base}/auth/dev/token"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    // Check session cookie is set
    let cookies: Vec<_> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert!(
        cookies.iter().any(|c| c.starts_with("oss_session=")),
        "expected oss_session cookie, got: {cookies:?}"
    );

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "authenticated");
    assert_eq!(body["email"], "dev@overslash.local");
    assert!(body["org_id"].is_string());
    assert!(body["identity_id"].is_string());
    assert!(body["token"].is_string());
}

#[tokio::test]
async fn dev_token_returns_404_when_disabled() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    let resp = client
        .get(format!("{base}/auth/dev/token"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn dev_token_is_idempotent() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    let resp1: Value = client
        .get(format!("{base}/auth/dev/token"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let resp2: Value = client
        .get(format!("{base}/auth/dev/token"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Same org and identity should be reused
    assert_eq!(resp1["org_id"], resp2["org_id"]);
    assert_eq!(resp1["identity_id"], resp2["identity_id"]);
}

// --- /auth/me endpoint ---

#[tokio::test]
async fn me_returns_user_with_valid_session() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    // Get a dev token
    let token_resp: Value = client
        .get(format!("{base}/auth/dev/token"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = token_resp["token"].as_str().unwrap();

    // Use the token to call /auth/me
    let me_resp = client
        .get(format!("{base}/auth/me"))
        .header("cookie", format!("oss_session={token}"))
        .send()
        .await
        .unwrap();

    assert_eq!(me_resp.status(), 200);
    let body: Value = me_resp.json().await.unwrap();
    assert_eq!(body["email"], "dev@overslash.local");
    assert_eq!(body["org_id"], token_resp["org_id"]);
    assert_eq!(body["identity_id"], token_resp["identity_id"]);
}

#[tokio::test]
async fn me_returns_401_without_cookie() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    let resp = client.get(format!("{base}/auth/me")).send().await.unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn me_returns_401_with_invalid_token() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    let resp = client
        .get(format!("{base}/auth/me"))
        .header("cookie", "oss_session=garbage.token.here")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn dev_user_is_org_admin_via_me_identity() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    let token_resp: Value = client
        .get(format!("{base}/auth/dev/token"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = token_resp["token"].as_str().unwrap();

    // First call: dev user freshly bootstrapped → should be org admin.
    let me1: Value = client
        .get(format!("{base}/auth/me/identity"))
        .header("cookie", format!("oss_session={token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me1["is_org_admin"], true);
    assert_eq!(me1["email"], "dev@overslash.local");

    // Second dev login: existing-user branch must also keep admin status
    // (verifies the idempotent re-bootstrap on the existing path).
    let token2: Value = client
        .get(format!("{base}/auth/dev/token"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token2_str = token2["token"].as_str().unwrap();
    let me2: Value = client
        .get(format!("{base}/auth/me/identity"))
        .header("cookie", format!("oss_session={token2_str}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me2["is_org_admin"], true);
    assert_eq!(me2["identity_id"], me1["identity_id"]);
}

// --- Google login (without credentials) ---

#[tokio::test]
async fn google_login_returns_404_when_not_configured() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    let resp = client
        .get(format!("{base}/auth/google/login"))
        .send()
        .await
        .unwrap();

    // Google auth client ID/secret not set → 404
    assert_eq!(resp.status(), 404);
}
