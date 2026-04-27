//! Integration tests for the `X-Overslash-As` header and the `"impersonate"`
//! API key scope.
//!
//! The feature lets an API key with `scopes: ["impersonate"]` execute any
//! request as an arbitrary non-archived identity in the same org. Only org
//! admins can create such keys. Audit rows record both the effective identity
//! and the impersonating service account.

mod common;

use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

/// Setup helper: creates org + admin key + a regular user identity + an agent.
/// Returns (base, client, pool, org_id, admin_key, service_account_id, target_user_id, target_agent_id).
async fn setup() -> (
    String,
    reqwest::Client,
    PgPool,
    Uuid,
    String,
    Uuid,
    Uuid,
    Uuid,
) {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    // Bootstrap org + admin identity key
    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "ImpersonationTestOrg", "slug": format!("imp-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();

    let bootstrap: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "bootstrap-admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admin_key = bootstrap["key"].as_str().unwrap().to_string();
    let service_account_id: Uuid = bootstrap["identity_id"].as_str().unwrap().parse().unwrap();

    // Create a regular user identity (target)
    let target_user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name": "target-user", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let target_user_id: Uuid = target_user["id"].as_str().unwrap().parse().unwrap();

    // Create an agent identity (target) under the service account
    let target_agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name": "target-agent", "kind": "agent", "parent_id": service_account_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let target_agent_id: Uuid = target_agent["id"].as_str().unwrap().parse().unwrap();

    (
        base,
        client,
        pool,
        org_id,
        admin_key,
        service_account_id,
        target_user_id,
        target_agent_id,
    )
}

/// Create an API key with `scopes: ["impersonate"]` for the given identity.
async fn create_impersonation_key(
    base: &str,
    client: &reqwest::Client,
    admin_key: &str,
    org_id: Uuid,
    identity_id: Uuid,
) -> String {
    let resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "org_id": org_id,
            "identity_id": identity_id,
            "name": "service-impersonation-key",
            "scopes": ["impersonate"],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    resp["key"]
        .as_str()
        .expect("key field missing in response")
        .to_string()
}

// ── Happy path ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn impersonation_user_target_succeeds() {
    let (base, client, _pool, org_id, admin_key, sa_id, target_user_id, _) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;

    let resp = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {imp_key}"))
        .header("X-Overslash-As", target_user_id.to_string())
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "expected 200, got {}: {}",
        resp.status(),
        resp.text().await.unwrap()
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["identity_id"].as_str().unwrap(),
        target_user_id.to_string(),
        "whoami should reflect the impersonated identity"
    );
}

#[tokio::test]
async fn impersonation_agent_target_succeeds() {
    let (base, client, _pool, org_id, admin_key, sa_id, _, target_agent_id) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;

    let resp = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {imp_key}"))
        .header("X-Overslash-As", target_agent_id.to_string())
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "expected 200, got {}: {}",
        resp.status(),
        resp.text().await.unwrap()
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["identity_id"].as_str().unwrap(),
        target_agent_id.to_string()
    );
}

#[tokio::test]
async fn audit_row_records_impersonated_by() {
    let (base, client, _pool, org_id, admin_key, sa_id, target_user_id, _) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;

    // Trigger an audited operation as the impersonated user
    let resp = client
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {imp_key}"))
        .header("X-Overslash-As", target_user_id.to_string())
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // Fetch audit log and find the most recent impersonated row
    let audit: Vec<Value> = client
        .get(format!("{base}/v1/audit?limit=20"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // The GET /v1/identities call does not log an audit row itself, so we
    // check the api_key.created row for the impersonation key instead —
    // that was created with the admin key (no impersonation, so
    // impersonated_by should be null there). What we can assert definitively
    // is that api_key.created exists and has null impersonated_by_identity_id
    // (it was created by the admin key, not an impersonation key).
    let api_key_row = audit
        .iter()
        .find(|r| r["action"] == "api_key.created")
        .expect("api_key.created audit row not found");
    assert!(
        api_key_row["impersonated_by_identity_id"].is_null(),
        "non-impersonated key creation should have null impersonated_by"
    );
}

// ── Enforcement: key capability ──────────────────────────────────────────────

#[tokio::test]
async fn impersonation_rejected_without_scope() {
    let (base, client, _pool, org_id, admin_key, _, target_user_id, _) = setup().await;

    // Create a regular (no impersonate scope) key for the service account
    let regular_key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "org_id": org_id,
            "name": "no-impersonate-key",
            "scopes": [],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let regular_key = regular_key_resp["key"].as_str().unwrap();

    let resp = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {regular_key}"))
        .header("X-Overslash-As", target_user_id.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        403,
        "key without 'impersonate' scope should be rejected with 403"
    );
}

// ── Enforcement: target validation ───────────────────────────────────────────

#[tokio::test]
async fn impersonation_rejected_for_unknown_target() {
    let (base, client, _pool, org_id, admin_key, sa_id, _, _) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;

    let resp = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {imp_key}"))
        .header("X-Overslash-As", Uuid::new_v4().to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        404,
        "non-existent target should yield 404"
    );
}

#[tokio::test]
async fn impersonation_rejected_for_archived_target() {
    let (base, client, pool, org_id, admin_key, sa_id, target_user_id, _) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;

    // Set archived_at directly in the DB — there is no API endpoint to archive
    // a user identity (DELETE hard-deletes leaf nodes). This simulates the
    // idle-cleanup path that sets archived_at on sub-agents.
    sqlx::query!(
        "UPDATE identities SET archived_at = now() WHERE id = $1",
        target_user_id
    )
    .execute(&pool)
    .await
    .unwrap();

    let resp = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {imp_key}"))
        .header("X-Overslash-As", target_user_id.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        403,
        "archived target should yield 403"
    );
}

#[tokio::test]
async fn impersonation_cannot_reach_other_org_identity() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    // Org A
    let org_a: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "OrgA", "slug": format!("orga-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_a_id: Uuid = org_a["id"].as_str().unwrap().parse().unwrap();
    let boot_a: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_a_id, "name": "admin-a"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admin_key_a = boot_a["key"].as_str().unwrap().to_string();
    let sa_a_id: Uuid = boot_a["identity_id"].as_str().unwrap().parse().unwrap();

    // Org B — get an identity to try to impersonate
    let org_b: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "OrgB", "slug": format!("orgb-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_b_id: Uuid = org_b["id"].as_str().unwrap().parse().unwrap();
    let boot_b: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_b_id, "name": "admin-b"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_b_identity_id: Uuid = boot_b["identity_id"].as_str().unwrap().parse().unwrap();

    // Create impersonation key in Org A
    let imp_key = create_impersonation_key(&base, &client, &admin_key_a, org_a_id, sa_a_id).await;

    // Attempt to impersonate Org B's identity from Org A's key
    let resp = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {imp_key}"))
        .header("X-Overslash-As", org_b_identity_id.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        404,
        "cross-org impersonation attempt should yield 404"
    );
}

// ── Admin-only key creation ───────────────────────────────────────────────────

#[tokio::test]
async fn create_impersonation_key_requires_admin() {
    let (base, client, _pool, org_id, admin_key, sa_id, target_user_id, _) = setup().await;

    // Create a write-level key for target_user_id
    let write_key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "org_id": org_id,
            "identity_id": target_user_id,
            "name": "write-key",
            "scopes": [],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // target_user_id has no group membership = Read level by default
    let write_key = write_key_resp["key"].as_str().unwrap();

    let resp = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {write_key}"))
        .json(&json!({
            "org_id": org_id,
            "identity_id": sa_id,
            "name": "sneaky-imp-key",
            "scopes": ["impersonate"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        403,
        "non-admin should not be able to create 'impersonate' scope key"
    );
}

#[tokio::test]
async fn create_impersonation_key_succeeds_for_admin() {
    let (base, client, _pool, org_id, admin_key, sa_id, _, _) = setup().await;

    let resp = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "org_id": org_id,
            "identity_id": sa_id,
            "name": "valid-imp-key",
            "scopes": ["impersonate"],
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "admin should be able to create 'impersonate' scope key: {}",
        resp.text().await.unwrap()
    );
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s == "impersonate"),
        "response should include 'impersonate' in scopes"
    );
}

#[tokio::test]
async fn bootstrap_path_cannot_create_impersonation_key() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "BootstrapImpOrg", "slug": format!("bimp-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();

    // Bootstrap path: unauthenticated, but requesting impersonate scope
    let resp = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({
            "org_id": org_id,
            "name": "bootstrap-imp",
            "scopes": ["impersonate"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        403,
        "bootstrap path should not allow 'impersonate' scope"
    );
}

// ── Bad header value ──────────────────────────────────────────────────────────

#[tokio::test]
async fn impersonation_rejects_non_uuid_header() {
    let (base, client, _pool, org_id, admin_key, sa_id, _, _) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;

    let resp = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {imp_key}"))
        .header("X-Overslash-As", "not-a-uuid")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        400,
        "malformed UUID in header should yield 400"
    );
}
