//! Dashboard-side secret management endpoints — list (with owner +
//! timestamps), detail (with versions + used_by), reveal, restore.
//!
//! These all live behind `SessionAuth` (rejects API-key bearer tokens) and
//! enforce SPEC §6 visibility: non-admin users only see secrets in their
//! own subtree, admins see everything in the org.

mod common;

use overslash_api::services::jwt;
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

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
        // Identity is a user — set user_id so the visibility filter can
        // walk the subtree under this user.
        user_id: Some(identity_id),
    };
    jwt::mint(&secret, &claims).expect("mint jwt")
}

#[tokio::test]
async fn list_returns_owner_and_timestamps() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let admin_user = fx.user_ids[0];

    // Seed two secrets through the admin user's API key (so version 1's
    // created_by is the admin user — which makes them the owner).
    for (name, val) in [("api_token", "a"), ("db_password", "b")] {
        let r = client
            .put(format!("{base}/v1/secrets/{name}"))
            .header("Authorization", format!("Bearer {}", fx.admin_key))
            .json(&json!({"value": val}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "put {name}: {:?}", r.text().await);
    }

    // List via dashboard session.
    let cookie = mint_session_cookie(fx.org_id, admin_user);
    let resp = client
        .get(format!("{base}/v1/secrets"))
        .header("cookie", format!("oss_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Vec<Value> = resp.json().await.unwrap();

    let api_token = body
        .iter()
        .find(|s| s["name"] == "api_token")
        .expect("api_token present");
    assert_eq!(api_token["current_version"], 1);
    assert_eq!(api_token["owner_identity_id"], admin_user.to_string());
    assert!(api_token["created_at"].is_string());
    assert!(api_token["updated_at"].is_string());
}

#[tokio::test]
async fn detail_includes_versions_and_used_by() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let admin_user = fx.user_ids[0];

    // Two writes → two versions.
    for value in ["v1", "v2"] {
        let r = client
            .put(format!("{base}/v1/secrets/openai_key"))
            .header("Authorization", format!("Bearer {}", fx.admin_key))
            .json(&json!({"value": value}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
    }

    let cookie = mint_session_cookie(fx.org_id, admin_user);
    let resp = client
        .get(format!("{base}/v1/secrets/openai_key"))
        .header("cookie", format!("oss_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();

    assert_eq!(body["name"], "openai_key");
    assert_eq!(body["current_version"], 2);
    assert_eq!(body["owner_identity_id"], admin_user.to_string());

    let versions = body["versions"].as_array().unwrap();
    assert_eq!(versions.len(), 2, "two writes → two versions");
    // Newest first per `list_versions` ORDER BY DESC.
    assert_eq!(versions[0]["version"], 2);
    assert_eq!(versions[1]["version"], 1);
    assert_eq!(versions[1]["created_by"], admin_user.to_string());

    // Empty service list — nothing references this secret yet.
    assert!(body["used_by"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn reveal_returns_decrypted_value_and_audits() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let admin_user = fx.user_ids[0];

    let r = client
        .put(format!("{base}/v1/secrets/stripe_key"))
        .header("Authorization", format!("Bearer {}", fx.admin_key))
        .json(&json!({"value": "sk_test_abc123"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    let cookie = mint_session_cookie(fx.org_id, admin_user);
    let resp = client
        .post(format!("{base}/v1/secrets/stripe_key/versions/1/reveal"))
        .header("cookie", format!("oss_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["version"], 1);
    assert_eq!(body["value"], "sk_test_abc123");

    // Audit row should record the reveal so admins can detect inspection.
    let row = sqlx::query!(
        "SELECT action FROM audit_log WHERE org_id = $1 AND action = 'secret.revealed' ORDER BY created_at DESC LIMIT 1",
        fx.org_id,
    )
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(row.is_some(), "expected secret.revealed audit row");
}

#[tokio::test]
async fn reveal_unknown_version_returns_404() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let admin_user = fx.user_ids[0];

    let r = client
        .put(format!("{base}/v1/secrets/known"))
        .header("Authorization", format!("Bearer {}", fx.admin_key))
        .json(&json!({"value": "v1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    let cookie = mint_session_cookie(fx.org_id, admin_user);
    let resp = client
        .post(format!("{base}/v1/secrets/known/versions/99/reveal"))
        .header("cookie", format!("oss_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn restore_creates_new_version_with_old_value() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let admin_user = fx.user_ids[0];

    // v1 = old, v2 = new
    for value in ["old", "new"] {
        let r = client
            .put(format!("{base}/v1/secrets/rotate_me"))
            .header("Authorization", format!("Bearer {}", fx.admin_key))
            .json(&json!({"value": value}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
    }

    let cookie = mint_session_cookie(fx.org_id, admin_user);

    // Restore v1 → expect v3 with old value.
    let resp = client
        .post(format!("{base}/v1/secrets/rotate_me/versions/1/restore"))
        .header("cookie", format!("oss_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["version"], 3,
        "restore creates a new version, not in-place"
    );

    // Reveal v3 → matches the restored "old" value.
    let resp = client
        .post(format!("{base}/v1/secrets/rotate_me/versions/3/reveal"))
        .header("cookie", format!("oss_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["value"], "old");
}

#[tokio::test]
async fn non_admin_cannot_see_other_users_secrets() {
    // SPEC §6: a non-admin user only sees secrets in their own subtree.
    // The bootstrapped fixture has admin (user_ids[0]) in Admins and
    // write_user (user_ids[1]) on its own. write_user creating a secret
    // makes it visible to write_user and admin, but not visible to anyone
    // else. We check this by listing as write_user and confirming a
    // separately-seeded admin secret is hidden.
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    // Admin seeds a secret. Owner = admin user.
    let r = client
        .put(format!("{base}/v1/secrets/admin_only"))
        .header("Authorization", format!("Bearer {}", fx.admin_key))
        .json(&json!({"value": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // write-user seeds their own secret.
    let r = client
        .put(format!("{base}/v1/secrets/mine"))
        .header("Authorization", format!("Bearer {}", fx.write_key))
        .json(&json!({"value": "y"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // List as write-user → should NOT see admin_only.
    let cookie = mint_session_cookie(fx.org_id, fx.user_ids[1]);
    let resp = client
        .get(format!("{base}/v1/secrets"))
        .header("cookie", format!("oss_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Vec<Value> = resp.json().await.unwrap();
    let names: Vec<&str> = body.iter().filter_map(|s| s["name"].as_str()).collect();
    assert!(names.contains(&"mine"), "write-user should see own secret");
    assert!(
        !names.contains(&"admin_only"),
        "write-user must not see admin's secret: {names:?}"
    );

    // Direct GET of out-of-subtree secret → 404 (not 403, to avoid
    // leaking the existence of the name).
    let resp = client
        .get(format!("{base}/v1/secrets/admin_only"))
        .header("cookie", format!("oss_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}
