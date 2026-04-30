// Integration tests for the instance-admin role and the
// `POST /v1/orgs/free-unlimited` endpoint that gates on it.
//
// Covers:
//  - the CHECK constraint that ties instance-admin status to having an
//    Overslash-native IdP binding,
//  - the `is_instance_admin()` / `set_instance_admin()` repo helpers,
//  - the `InstanceAdminAuth` extractor's accept/reject paths,
//  - the new free-unlimited create endpoint (both billing modes),
//  - `/auth/me/identity` surfacing the flag.

#![allow(clippy::disallowed_methods)]

mod common;

use overslash_api::services::jwt;
use overslash_db::repos::user as user_repo;
use serde_json::{Value, json};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

// ── Helpers ──────────────────────────────────────────────────────────

/// Mint a dashboard session JWT carrying `user_id` so `SessionAuth` can
/// expose it to `InstanceAdminAuth`. Matches the production mint flow.
fn mint_session_with_user(org_id: Uuid, identity_id: Uuid, user_id: Uuid) -> String {
    let signing_key_hex = "cd".repeat(32);
    let secret = hex::decode(&signing_key_hex).expect("valid hex");
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = jwt::Claims {
        sub: identity_id,
        org: org_id,
        email: "instance-admin-test@example.com".into(),
        aud: jwt::AUD_SESSION.into(),
        iat: now,
        exp: now + 3600,
        user_id: Some(user_id),
        mcp_client_id: None,
    };
    jwt::mint(&secret, &claims).expect("mint jwt")
}

/// Create an Overslash-backed user and bootstrap a personal org + identity
/// they can authenticate as. Returns `(user_id, org_id, identity_id)`.
async fn make_overslash_user_with_org(pool: &PgPool, email: &str) -> (Uuid, Uuid, Uuid) {
    let subject = format!("subj-{}", Uuid::new_v4());
    let user = user_repo::create_overslash_backed(
        pool,
        Some(email),
        Some("Test User"),
        "google",
        &subject,
    )
    .await
    .unwrap();

    let org = overslash_db::repos::org::create(
        pool,
        "Personal",
        &format!("personal-{}", Uuid::new_v4().simple()),
        "standard",
    )
    .await
    .unwrap();

    let ident = overslash_db::repos::identity::create_with_email(
        pool,
        org.id,
        "Test User",
        "user",
        None,
        Some(email),
        serde_json::json!({}),
    )
    .await
    .unwrap();
    overslash_db::repos::identity::set_user_id(pool, org.id, ident.id, Some(user.id))
        .await
        .unwrap();
    overslash_db::repos::identity::set_is_org_admin(pool, org.id, ident.id, true)
        .await
        .unwrap();

    (user.id, org.id, ident.id)
}

// ── Repo / DB-constraint tests ──────────────────────────────────────

#[tokio::test]
async fn check_constraint_blocks_grant_to_org_only_user() {
    let pool = common::test_pool().await;
    let user = user_repo::create_org_only(&pool, Some("orgonly@example.com"), Some("Org Only"))
        .await
        .unwrap();

    let err = user_repo::set_instance_admin(&pool, user.id, true)
        .await
        .expect_err("CHECK constraint must reject org-only users");
    let msg = err.to_string();
    assert!(
        msg.contains("users_instance_admin_requires_overslash_idp"),
        "expected constraint violation, got: {msg}"
    );
}

#[tokio::test]
async fn check_constraint_blocks_provider_nullification_after_grant() {
    let pool = common::test_pool().await;
    let (user_id, _org_id, _ident_id) =
        make_overslash_user_with_org(&pool, "soon-to-fail@example.com").await;

    user_repo::set_instance_admin(&pool, user_id, true)
        .await
        .unwrap();

    let err = sqlx::query(
        "UPDATE users SET overslash_idp_provider = NULL, overslash_idp_subject = NULL
         WHERE id = $1",
    )
    .bind(user_id)
    .execute(&pool)
    .await
    .expect_err("CHECK must block null-out while flag is true");
    assert!(
        err.to_string()
            .contains("users_instance_admin_requires_overslash_idp")
    );
}

#[tokio::test]
async fn set_and_unset_instance_admin_round_trip() {
    let pool = common::test_pool().await;
    let (user_id, _org_id, _ident_id) =
        make_overslash_user_with_org(&pool, "round@example.com").await;

    assert!(!user_repo::is_instance_admin(&pool, user_id).await.unwrap());

    user_repo::set_instance_admin(&pool, user_id, true)
        .await
        .unwrap();
    assert!(user_repo::is_instance_admin(&pool, user_id).await.unwrap());

    user_repo::set_instance_admin(&pool, user_id, false)
        .await
        .unwrap();
    assert!(!user_repo::is_instance_admin(&pool, user_id).await.unwrap());
}

#[tokio::test]
async fn is_instance_admin_returns_false_for_missing_user() {
    let pool = common::test_pool().await;
    let result = user_repo::is_instance_admin(&pool, Uuid::new_v4())
        .await
        .unwrap();
    assert!(!result);
}

// ── Endpoint / extractor tests ──────────────────────────────────────

#[tokio::test]
async fn free_unlimited_endpoint_rejects_non_admin_session() {
    let pool = common::test_pool().await;
    let (user_id, org_id, ident_id) =
        make_overslash_user_with_org(&pool, "nonadmin@example.com").await;

    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let cookie = mint_session_with_user(org_id, ident_id, user_id);
    let resp = client
        .post(format!("{base}/v1/orgs/free-unlimited"))
        .header("cookie", format!("oss_session={cookie}"))
        .json(
            &json!({"name": "Partner Co", "slug": format!("partner-{}", Uuid::new_v4().simple())}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "instance_admin_required");
}

#[tokio::test]
async fn free_unlimited_endpoint_rejects_api_key() {
    // Session cookie required — bearer API keys can't carry the role
    // because the role is on the human, not on an org-bound identity.
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, _ident_id, agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/orgs/free-unlimited"))
        .header("authorization", format!("Bearer {agent_key}"))
        .json(
            &json!({"name": "Partner Co", "slug": format!("partner-{}", Uuid::new_v4().simple())}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn instance_admin_creates_free_unlimited_org_self_hosted() {
    let pool = common::test_pool().await;
    let (user_id, org_id, ident_id) =
        make_overslash_user_with_org(&pool, "admin-selfhost@example.com").await;
    user_repo::set_instance_admin(&pool, user_id, true)
        .await
        .unwrap();

    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let cookie = mint_session_with_user(org_id, ident_id, user_id);
    let new_slug = format!("partner-{}", Uuid::new_v4().simple());
    let resp = client
        .post(format!("{base}/v1/orgs/free-unlimited"))
        .header("cookie", format!("oss_session={cookie}"))
        .json(&json!({"name": "Partner Co", "slug": new_slug}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "body: {:?}", resp.text().await);
    let body: Value = resp.json().await.unwrap();
    let new_org_id: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    assert!(body["redirect_to"].is_string());

    // Plan should be free_unlimited.
    let plan: String = sqlx::query_scalar("SELECT plan FROM orgs WHERE id = $1")
        .bind(new_org_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(plan, "free_unlimited");

    // No subscription row should be written.
    let sub_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM org_subscriptions WHERE org_id = $1")
            .bind(new_org_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(sub_count, 0);

    // Bootstrap admin identity should be linked to the calling user.
    let identity_user_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM identities WHERE org_id = $1 AND is_org_admin = true",
    )
    .bind(new_org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(identity_user_id, Some(user_id));

    // Audit row exists with the expected detail.
    let audit_detail: serde_json::Value = sqlx::query_scalar(
        "SELECT detail FROM audit_log WHERE org_id = $1 AND action = 'org.created'",
    )
    .bind(new_org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit_detail["free_unlimited"], true);
    assert_eq!(
        audit_detail["created_by_instance_admin"],
        user_id.to_string()
    );
}

#[tokio::test]
async fn instance_admin_creates_free_unlimited_org_in_cloud_billing_mode() {
    // The whole point of the new endpoint is to bypass Stripe even when
    // `cloud_billing=true` — `POST /v1/orgs` returns 403 in that mode but
    // `POST /v1/orgs/free-unlimited` must still work for instance admins.
    let pool = common::test_pool().await;
    let (user_id, org_id, ident_id) =
        make_overslash_user_with_org(&pool, "admin-cloud@example.com").await;
    user_repo::set_instance_admin(&pool, user_id, true)
        .await
        .unwrap();

    let (addr, client) = common::start_api_with(pool.clone(), |cfg| {
        cfg.cloud_billing = true;
    })
    .await;
    let base = format!("http://{addr}");

    let cookie = mint_session_with_user(org_id, ident_id, user_id);
    let new_slug = format!("partner-{}", Uuid::new_v4().simple());
    let resp = client
        .post(format!("{base}/v1/orgs/free-unlimited"))
        .header("cookie", format!("oss_session={cookie}"))
        .json(&json!({"name": "Cloud Partner", "slug": new_slug}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "body: {:?}", resp.text().await);
    let body: Value = resp.json().await.unwrap();
    let new_org_id: Uuid = body["id"].as_str().unwrap().parse().unwrap();

    let plan: String = sqlx::query_scalar("SELECT plan FROM orgs WHERE id = $1")
        .bind(new_org_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(plan, "free_unlimited");
}

#[tokio::test]
async fn whoami_includes_is_instance_admin() {
    let pool = common::test_pool().await;
    let (user_id, org_id, ident_id) =
        make_overslash_user_with_org(&pool, "whoami@example.com").await;

    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    // Before granting: false.
    let cookie = mint_session_with_user(org_id, ident_id, user_id);
    let resp = client
        .get(format!("{base}/auth/me/identity"))
        .header("cookie", format!("oss_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["is_instance_admin"], false);

    // After granting: true.
    user_repo::set_instance_admin(&pool, user_id, true)
        .await
        .unwrap();
    let resp = client
        .get(format!("{base}/auth/me/identity"))
        .header("cookie", format!("oss_session={cookie}"))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["is_instance_admin"], true);
}

#[tokio::test]
async fn free_unlimited_endpoint_blocked_when_org_creation_disabled() {
    // `allow_org_creation=false` self-hosted lockdown should also gate
    // the instance-admin endpoint — operators don't want a backdoor.
    let pool = common::test_pool().await;
    let (user_id, org_id, ident_id) =
        make_overslash_user_with_org(&pool, "lockdown@example.com").await;
    user_repo::set_instance_admin(&pool, user_id, true)
        .await
        .unwrap();

    let (addr, client) = common::start_api_with(pool.clone(), |cfg| {
        cfg.allow_org_creation = false;
    })
    .await;
    let base = format!("http://{addr}");

    let cookie = mint_session_with_user(org_id, ident_id, user_id);
    let resp = client
        .post(format!("{base}/v1/orgs/free-unlimited"))
        .header("cookie", format!("oss_session={cookie}"))
        .json(&json!({"name": "Locked Out", "slug": format!("locked-{}", Uuid::new_v4().simple())}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "org_creation_disabled");
}
