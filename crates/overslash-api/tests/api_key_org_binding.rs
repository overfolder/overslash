//! An API key can only ever be minted into the caller's own org.
//!
//! Regression cover for the CASA **V2** finding. `POST /v1/api-keys` used to
//! build its `OrgScope` from `req.org_id` and honour a caller-supplied
//! `req.identity_id`, neither compared against the ACL resolved from the
//! caller's own credential — so an admin of org A could mint a live `osk_`
//! key bound to an identity in org B. It could do that because the handler
//! also carried an *unauthenticated* bootstrap branch, and that branch is the
//! only reason an org id was ever read from the body at all.
//!
//! Both halves are gone. The org now comes from the credential, and an org's
//! first admin key is minted by `POST /v1/orgs` itself and handed back once.
//!
//! Three layers, because the first two are code and code changes:
//!   - the org is never named by the caller, so a stray `org_id` cannot steer
//!     the write;
//!   - `identity_id` resolves *through* the caller's scope, so an identity in
//!     another tenant does not exist;
//!   - the database refuses a mismatched `(org_id, identity_id)` pair
//!     outright, whatever a future handler may do.

use crate::common;

use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

/// Create an org. Creation mints the first admin User and its key and returns
/// both. Returns `(org_id, admin_identity_id, admin_key)`.
async fn new_org(base: &str, client: &reqwest::Client) -> (Uuid, Uuid, String) {
    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "KeyBindTest", "slug": format!("kbt-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();
    let key = org["api_key"]
        .as_str()
        .unwrap_or_else(|| panic!("org creation did not return a key: {org}"))
        .to_string();
    let identity_id: Uuid = org["identity_id"].as_str().unwrap().parse().unwrap();

    (org_id, identity_id, key)
}

async fn key_names(base: &str, client: &reqwest::Client, key: &str) -> Vec<String> {
    let rows: Vec<Value> = client
        .get(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    rows.iter()
        .map(|r| r["name"].as_str().unwrap().to_string())
        .collect()
}

/// The field is gone from the request type, so a caller that still sends one
/// cannot steer the write with it. The key lands in the caller's own org.
#[tokio::test]
async fn a_stray_org_id_cannot_steer_the_write() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    let (_org_a, admin_a, key_a) = new_org(&base, &client).await;
    let (org_b, _admin_b, key_b) = new_org(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {key_a}"))
        .json(&json!({
            "org_id": org_b,
            "identity_id": admin_a,
            "name": "aimed-at-b",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);

    assert!(
        key_names(&base, &client, &key_a)
            .await
            .contains(&"aimed-at-b".to_string()),
        "the key belongs to the caller's own org"
    );
    assert!(
        !key_names(&base, &client, &key_b)
            .await
            .contains(&"aimed-at-b".to_string()),
        "nothing reached org B"
    );
}

/// The identity is the only thing a caller still names, and it resolves
/// through the caller's own scope.
#[tokio::test]
async fn identity_from_another_org_is_not_findable() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    let (_org_a, _admin_a, key_a) = new_org(&base, &client).await;
    let (_org_b, admin_b, _key_b) = new_org(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {key_a}"))
        .json(&json!({"identity_id": admin_b, "name": "foreign-identity"}))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status().as_u16(),
        404,
        "an identity in another org must not be bindable"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "identity not found");
}

#[tokio::test]
async fn admin_can_still_mint_into_own_org() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    let (_org_a, admin_a, key_a) = new_org(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {key_a}"))
        .json(&json!({"identity_id": admin_a, "name": "second-key"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    let minted = body["key"].as_str().unwrap();
    assert!(minted.starts_with("osk_"));
    assert_eq!(body["identity_id"].as_str().unwrap(), admin_a.to_string());

    // The new key authenticates.
    assert!(
        key_names(&base, &client, minted)
            .await
            .contains(&"second-key".to_string()),
        "the minted key should authenticate"
    );
}

/// Neither field is required: the org comes from the credential and
/// `identity_id` defaults to the caller's own identity — the "mint a key for
/// myself" case the dashboard drives.
#[tokio::test]
async fn the_request_needs_neither_org_nor_identity() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    let (_org_a, admin_a, key_a) = new_org(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {key_a}"))
        .json(&json!({"name": "for-myself"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200, "org_id is no longer a field");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["identity_id"].as_str().unwrap(), admin_a.to_string());
    assert!(body["key"].as_str().unwrap().starts_with("osk_"));
}

/// There is no unauthenticated way in any more. This is the branch that used
/// to authorise itself on an org id taken from its own body.
#[tokio::test]
async fn minting_requires_a_credential() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    let (org_id, admin_id, _key) = new_org(&base, &client).await;

    for body in [
        json!({"name": "no-credential"}),
        json!({"org_id": org_id, "name": "no-credential"}),
        json!({"org_id": org_id, "identity_id": admin_id, "name": "no-credential"}),
    ] {
        let resp = client
            .post(format!("{base}/v1/api-keys"))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            401,
            "unauthenticated mint must be refused: {body}"
        );
    }
}

/// Org creation is where the first key comes from now — once, and only in
/// that response.
#[tokio::test]
async fn org_creation_returns_the_first_admin_key_once() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    let (org_id, admin_id, key) = new_org(&base, &client).await;
    assert!(key.starts_with("osk_"));

    // It is a real admin User, in the Admins group, and the key works.
    let identities: Vec<Value> = client
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admin = identities
        .iter()
        .find(|i| i["id"].as_str().unwrap() == admin_id.to_string())
        .expect("bootstrap admin should appear in /v1/identities");
    assert_eq!(admin["kind"], "user");
    assert_eq!(admin["name"], "admin");

    // Re-reading the org does not hand the key back.
    let org: Value = client
        .get(format!("{base}/v1/orgs/{org_id}"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        org.get("api_key").is_none(),
        "the key must never be readable back: {org}"
    );
}

/// Layer three: even with both handler checks bypassed, the database refuses
/// a key whose `org_id` and `identity_id` disagree. Migration 121.
#[tokio::test]
async fn database_refuses_a_cross_tenant_pair() {
    let pool: PgPool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let (org_a, _admin_a, _key_a) = new_org(&base, &client).await;
    let (_org_b, admin_b, _key_b) = new_org(&base, &client).await;

    let err = sqlx::query!(
        "INSERT INTO api_keys (org_id, identity_id, name, key_hash, key_prefix, scopes)
         VALUES ($1, $2, $3, $4, $5, ARRAY[]::text[])",
        org_a,
        admin_b,
        "raw-sql-cross-tenant",
        "not-a-real-hash",
        format!("osk_{}", &Uuid::new_v4().simple().to_string()[..8]),
    )
    .execute(&pool)
    .await
    .expect_err("the composite foreign key must refuse this pair");

    let message = err.to_string();
    assert!(
        message.contains("api_keys_org_id_identity_id_fkey"),
        "expected the composite FK to fire, got: {message}"
    );
}
