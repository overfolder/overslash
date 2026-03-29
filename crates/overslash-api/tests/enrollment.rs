mod common;

use serde_json::{json, Value};
use sqlx::PgPool;

/// Happy path: create enrollment token, enroll agent, use the returned API key.
#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn enroll_happy_path(pool: PgPool) {
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (org_id, identity_id, api_key) = common::bootstrap_org_identity(&base, &client).await;

    // Create enrollment token for the agent identity
    let resp = client
        .post(format!("{base}/v1/identities/{identity_id}/enrollment-token"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let token = body["token"].as_str().unwrap();
    assert!(token.starts_with("ose_"));
    assert!(body["expires_at"].as_str().is_some());

    // Enroll using the token (no auth header needed)
    let resp = client
        .post(format!("{base}/v1/enroll"))
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["identity_id"].as_str().unwrap(), identity_id.to_string());
    assert_eq!(body["org_id"].as_str().unwrap(), org_id.to_string());
    let enrolled_key = body["api_key"].as_str().unwrap();
    assert!(enrolled_key.starts_with("osk_"));
    assert!(body["key_prefix"].as_str().is_some());

    // Verify the returned API key works
    let resp = client
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {enrolled_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

/// Token can only be used once.
#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn enroll_already_used_token(pool: PgPool) {
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, identity_id, api_key) = common::bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/identities/{identity_id}/enrollment-token"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let token = body["token"].as_str().unwrap().to_string();

    // First use succeeds
    let resp = client
        .post(format!("{base}/v1/enroll"))
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Second use fails
    let resp = client
        .post(format!("{base}/v1/enroll"))
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let body: Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("already used"));
}

/// Expired token is rejected.
#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn enroll_expired_token(pool: PgPool) {
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (_org_id, identity_id, api_key) = common::bootstrap_org_identity(&base, &client).await;

    // Create token with minimum TTL
    let resp = client
        .post(format!("{base}/v1/identities/{identity_id}/enrollment-token"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({ "ttl_secs": 60 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let token = body["token"].as_str().unwrap().to_string();

    // Manually expire the token in the test DB
    sqlx::query("UPDATE enrollment_tokens SET expires_at = now() - interval '1 second'")
        .execute(&pool)
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/v1/enroll"))
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let body: Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("expired"));
}

/// Completely invalid token is rejected.
#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn enroll_invalid_token(pool: PgPool) {
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    let resp = client
        .post(format!("{base}/v1/enroll"))
        .json(&json!({ "token": "ose_bogus_token_value" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let body: Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("invalid"));
}

/// Enrollment token cannot be created for user identities.
#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn enroll_rejects_user_identity(pool: PgPool) {
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    // Create org + org-level key
    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "TestOrg", "slug": format!("test-{}", uuid::Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id = org["id"].as_str().unwrap();
    let org_key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let api_key = org_key["key"].as_str().unwrap();

    // Create a user identity
    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "human", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = user["id"].as_str().unwrap();

    // Attempt enrollment token for user identity
    let resp = client
        .post(format!("{base}/v1/identities/{user_id}/enrollment-token"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}
