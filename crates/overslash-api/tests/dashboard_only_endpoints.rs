//! Positive tests for endpoints that use the dashboard-only `SessionAuth`
//! extractor. `SessionAuth` requires a valid `oss_session` JWT cookie and
//! rejects API-key bearer tokens outright.
//!
//! The 401-on-API-key side is already covered by `integration.rs` and
//! `org_acl.rs`. This file locks in the positive path: the endpoints
//! actually accept a well-formed session cookie and return data, and they
//! reject garbage cookies with 401.

mod common;

use overslash_api::services::jwt;
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

/// Mint a session JWT for the given (org, identity) using the signing key
/// the test harness configures in `common::start_api` (`"cd".repeat(32)`,
/// hex-decoded to 32 bytes). Matches the production mint/verify flow end
/// to end — no shortcuts.
fn mint_session_cookie(org_id: Uuid, identity_id: Uuid) -> String {
    let signing_key_hex = "cd".repeat(32);
    let secret = hex::decode(&signing_key_hex).expect("valid hex");
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = jwt::Claims {
        sub: identity_id,
        org: org_id,
        email: "session-test@example.com".into(),
        aud: jwt::AUD_SESSION.into(),
        iat: now,
        exp: now + 3600,
        user_id: None,
        mcp_client_id: None,
    };
    jwt::mint(&secret, &claims).expect("mint jwt")
}

#[tokio::test]
async fn test_get_secret_with_session_cookie_works() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (org_id, ident_id, agent_key, _org_admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // PUT via the agent's identity-bound key so the secret has a real
    // creator (not NULL) — non-admin visibility (SPEC §6) needs a slot
    // owner to compare against the session's ceiling user.
    let put = client
        .put(format!("{base}/v1/secrets/db_password"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({"value": "hunter2"}))
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), 200, "put secret: {:?}", put.text().await);

    // GET via a freshly-minted dashboard session cookie.
    let cookie = mint_session_cookie(org_id, ident_id);
    let resp = client
        .get(format!("{base}/v1/secrets/db_password"))
        .header("cookie", format!("oss_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["name"], "db_password");
    assert_eq!(body["current_version"], 1);
}

#[tokio::test]
async fn test_list_secrets_with_session_cookie_works() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (org_id, ident_id, agent_key, _org_admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // PUT via the identity-bound key for the same reason as above.
    let put = client
        .put(format!("{base}/v1/secrets/api_token"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({"value": "abc"}))
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), 200);

    let cookie = mint_session_cookie(org_id, ident_id);
    let resp = client
        .get(format!("{base}/v1/secrets"))
        .header("cookie", format!("oss_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Vec<Value> = resp.json().await.unwrap();
    assert!(!body.is_empty(), "expected at least one secret in list");
    assert!(body.iter().any(|s| s["name"] == "api_token"));
}

#[tokio::test]
async fn test_get_secret_with_invalid_session_cookie_returns_401() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    let resp = client
        .get(format!("{base}/v1/secrets"))
        .header("cookie", "oss_session=not.a.real.jwt")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}
