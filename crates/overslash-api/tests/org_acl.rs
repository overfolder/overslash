//! Integration tests for org-level ACL via groups + overslash service.
//! Verifies that the system groups, overslash service, and ACL extractors
//! correctly enforce access control on admin endpoints.

mod common;

use reqwest::Client;
use serde_json::{Value, json};
use uuid::Uuid;

/// Bootstrap an org with ACL test users at different access levels.
/// Returns (base_url, client, admin_key, write_key, read_only_key, org_key, user_ids).
async fn bootstrap_acl(
    pool: sqlx::PgPool,
) -> (String, Client, String, String, String, String, [Uuid; 3]) {
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    // Create org — triggers bootstrap (Everyone + Admins groups, overslash service)
    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "ACL Test Org", "slug": format!("acl-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();

    // First API key (bootstrap — no auth required)
    let org_key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "org-admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_key = org_key_resp["key"].as_str().unwrap().to_string();

    // Find system groups
    let groups: Vec<Value> = client
        .get(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {org_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admins_id = groups.iter().find(|g| g["name"] == "Admins").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Create 3 users: admin, write, read-only
    let mut user_ids = [Uuid::nil(); 3];
    let mut keys = vec![];

    for (i, name) in ["admin-user", "write-user", "readonly-user"]
        .iter()
        .enumerate()
    {
        let user: Value = client
            .post(format!("{base}/v1/identities"))
            .header("Authorization", format!("Bearer {org_key}"))
            .json(&json!({"name": name, "kind": "user"}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let uid: Uuid = user["id"].as_str().unwrap().parse().unwrap();
        user_ids[i] = uid;

        let key_resp: Value = client
            .post(format!("{base}/v1/api-keys"))
            .header("Authorization", format!("Bearer {org_key}"))
            .json(&json!({"org_id": org_id, "identity_id": uid, "name": format!("{name}-key")}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        keys.push(key_resp["key"].as_str().unwrap().to_string());
    }

    // Admin user: add to Admins group
    client
        .post(format!("{base}/v1/groups/{admins_id}/members"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"identity_id": user_ids[0]}))
        .send()
        .await
        .unwrap();

    // Read-only user: remove from Everyone, create a Viewers group with read on overslash
    // Find overslash service instance by direct lookup
    let overslash_svc: Value = client
        .get(format!("{base}/v1/services/overslash"))
        .header("Authorization", format!("Bearer {org_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let overslash_svc_id = overslash_svc["id"].as_str().unwrap().to_string();

    let everyone_id = groups.iter().find(|g| g["name"] == "Everyone").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Remove read-only user from Everyone
    client
        .delete(format!(
            "{base}/v1/groups/{everyone_id}/members/{}",
            user_ids[2]
        ))
        .header("Authorization", format!("Bearer {org_key}"))
        .send()
        .await
        .unwrap();

    // Create Viewers group with read-only access
    let viewers: Value = client
        .post(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"name": "Viewers"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let viewers_id = viewers["id"].as_str().unwrap();

    client
        .post(format!("{base}/v1/groups/{viewers_id}/grants"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"service_instance_id": overslash_svc_id, "access_level": "read"}))
        .send()
        .await
        .unwrap();

    client
        .post(format!("{base}/v1/groups/{viewers_id}/members"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"identity_id": user_ids[2]}))
        .send()
        .await
        .unwrap();

    (
        base,
        client,
        keys[0].clone(), // admin key
        keys[1].clone(), // write key
        keys[2].clone(), // read-only key
        org_key,
        user_ids,
    )
}

fn auth(key: &str) -> (&'static str, String) {
    ("Authorization", format!("Bearer {key}"))
}

// ===========================================================================
// Tests
// ===========================================================================

#[tokio::test]
async fn test_org_bootstrap() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "Bootstrap Test", "slug": format!("bs-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id = org["id"].as_str().unwrap();

    // Bootstrap key
    let key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "test"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let key = key_resp["key"].as_str().unwrap();

    // Check system groups exist
    let groups: Vec<Value> = client
        .get(format!("{base}/v1/groups"))
        .header(auth(key).0, auth(key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let everyone = groups.iter().find(|g| g["name"] == "Everyone");
    let admins = groups.iter().find(|g| g["name"] == "Admins");
    assert!(everyone.is_some(), "Everyone group should exist");
    assert!(admins.is_some(), "Admins group should exist");
    assert_eq!(everyone.unwrap()["is_system"], true);
    assert_eq!(admins.unwrap()["is_system"], true);

    // Check overslash service exists by name
    let resp = client
        .get(format!("{base}/v1/services/overslash"))
        .header(auth(key).0, auth(key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let overslash: Value = resp.json().await.unwrap();
    assert_eq!(overslash["name"], "overslash");
    assert_eq!(overslash["is_system"], true);
}

#[tokio::test]
async fn test_system_assets_undeletable() {
    let pool = common::test_pool().await;
    let (base, client, _, _, _, org_key, _) = bootstrap_acl(pool).await;

    // Find system groups
    let groups: Vec<Value> = client
        .get(format!("{base}/v1/groups"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    for g in groups.iter().filter(|g| g["is_system"] == true) {
        let id = g["id"].as_str().unwrap();
        let resp = client
            .delete(format!("{base}/v1/groups/{id}"))
            .header(auth(&org_key).0, auth(&org_key).1)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            400,
            "should not delete system group {}",
            g["name"]
        );
    }

    // Cannot delete overslash service
    let resp = client
        .delete(format!("{base}/v1/services/overslash"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "should not delete system service");
}

#[tokio::test]
async fn test_last_admin_protected() {
    let pool = common::test_pool().await;
    let (base, client, _, _, _, org_key, user_ids) = bootstrap_acl(pool).await;

    let groups: Vec<Value> = client
        .get(format!("{base}/v1/groups"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admins_id = groups.iter().find(|g| g["name"] == "Admins").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Drop every Admins member except user_ids[0] so the "last admin"
    // protection has only one row to defend. The unauth bootstrap path now
    // creates an "admin" user that lands in Admins automatically, so the
    // Admins group starts with both that user and user_ids[0].
    let members: Vec<Uuid> = client
        .get(format!("{base}/v1/groups/{admins_id}/members"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    for mid in &members {
        if *mid == user_ids[0] {
            continue;
        }
        client
            .delete(format!("{base}/v1/groups/{admins_id}/members/{mid}"))
            .header(auth(&org_key).0, auth(&org_key).1)
            .send()
            .await
            .unwrap();
    }

    // Try to remove the only remaining admin → should fail
    let resp = client
        .delete(format!(
            "{base}/v1/groups/{admins_id}/members/{}",
            user_ids[0]
        ))
        .header(auth(&org_key).0, auth(&org_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Add second admin
    client
        .post(format!("{base}/v1/groups/{admins_id}/members"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({"identity_id": user_ids[1]}))
        .send()
        .await
        .unwrap();

    // Now can remove first admin
    let resp = client
        .delete(format!(
            "{base}/v1/groups/{admins_id}/members/{}",
            user_ids[0]
        ))
        .header(auth(&org_key).0, auth(&org_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_write_user_permissions() {
    let pool = common::test_pool().await;
    let (base, client, _, write_key, _, _, _) = bootstrap_acl(pool).await;

    // Write user can create secrets
    let resp = client
        .put(format!("{base}/v1/secrets/test-secret"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(&json!({"value": "secret123"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Write user can create agents
    let resp = client
        .post(format!("{base}/v1/identities"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(&json!({"name": "my-agent", "kind": "agent", "parent_id": null}))
        .send()
        .await
        .unwrap();
    // May fail due to parent_id requirement, that's fine — the ACL check passed (not 403)
    assert_ne!(resp.status().as_u16(), 403);

    // Write user cannot delete secrets (admin-only)
    let resp = client
        .delete(format!("{base}/v1/secrets/test-secret"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Write user cannot create groups (admin-only)
    let resp = client
        .post(format!("{base}/v1/groups"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(&json!({"name": "Forbidden Group"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Write user cannot create templates (admin-only)
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(&json!({ "openapi": common::minimal_openapi("foo") }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_read_only_user_forbidden_on_writes() {
    let pool = common::test_pool().await;
    let (base, client, _, _, ro_key, _, _) = bootstrap_acl(pool).await;

    // GET /v1/secrets is dashboard-only (JWT). API keys — even an
    // org-admin read-only key — are rejected so the secret namespace
    // never leaks to an agent token.
    let resp = client
        .get(format!("{base}/v1/secrets"))
        .header(auth(&ro_key).0, auth(&ro_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Read-only user cannot write secrets
    let resp = client
        .put(format!("{base}/v1/secrets/blocked"))
        .header(auth(&ro_key).0, auth(&ro_key).1)
        .json(&json!({"value": "nope"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Read-only user cannot create identities
    let resp = client
        .post(format!("{base}/v1/identities"))
        .header(auth(&ro_key).0, auth(&ro_key).1)
        .json(&json!({"name": "blocked", "kind": "user"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_admin_can_do_everything() {
    let pool = common::test_pool().await;
    let (base, client, admin_key, _, _, _, _) = bootstrap_acl(pool).await;

    // Admin can create secrets
    let resp = client
        .put(format!("{base}/v1/secrets/admin-secret"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"value": "admin123"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Admin can delete secrets
    let resp = client
        .delete(format!("{base}/v1/secrets/admin-secret"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Admin can create groups
    let resp = client
        .post(format!("{base}/v1/groups"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"name": "Admin Group"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_org_level_key_acts_as_admin() {
    let pool = common::test_pool().await;
    let (base, client, _, _, _, org_key, _) = bootstrap_acl(pool).await;

    // Org-level key (no identity) acts as admin
    let resp = client
        .post(format!("{base}/v1/groups"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({"name": "OrgKey Group"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = client
        .put(format!("{base}/v1/secrets/org-secret"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({"value": "org123"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = client
        .delete(format!("{base}/v1/secrets/org-secret"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_agent_inherits_owner_acl() {
    let pool = common::test_pool().await;
    let (base, client, _, _write_key, _, org_key, user_ids) = bootstrap_acl(pool).await;

    // Create agent under write-level user
    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({"name": "test-agent", "kind": "agent", "parent_id": user_ids[1]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id = agent["id"].as_str().unwrap();

    // Create agent-bound key
    let _agent_key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({"org_id": user_ids[1], "identity_id": agent_id, "name": "agent-key"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // The API key creation used the wrong org_id (user_ids[1] is not an org_id).
    // Get the actual org_id from the write user's identity
    let identities: Vec<Value> = client
        .get(format!("{base}/v1/identities"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id = identities[0]["org_id"].as_str().unwrap();

    let agent_key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({"org_id": org_id, "identity_id": agent_id, "name": "agent-key2"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_key = agent_key_resp["key"].as_str().unwrap();

    // Agent inherits write from owner — can create secrets
    let resp = client
        .put(format!("{base}/v1/secrets/agent-secret"))
        .header(auth(agent_key).0, auth(agent_key).1)
        .json(&json!({"value": "agent123"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Agent inherits write — cannot delete secrets (admin-only)
    let resp = client
        .delete(format!("{base}/v1/secrets/agent-secret"))
        .header(auth(agent_key).0, auth(agent_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_new_user_auto_joins_everyone() {
    let pool = common::test_pool().await;
    let (base, client, _, _, _, org_key, _) = bootstrap_acl(pool).await;

    // Create a new user
    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({"name": "new-user", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = user["id"].as_str().unwrap();
    let org_id = user["org_id"].as_str().unwrap();

    // Create key for this user
    let key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({"org_id": org_id, "identity_id": user_id, "name": "new-user-key"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_key = key_resp["key"].as_str().unwrap();

    // New user should have write-level access (Everyone group)
    let resp = client
        .put(format!("{base}/v1/secrets/new-user-secret"))
        .header(auth(user_key).0, auth(user_key).1)
        .json(&json!({"value": "hello"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // But not admin access
    let resp = client
        .delete(format!("{base}/v1/secrets/new-user-secret"))
        .header(auth(user_key).0, auth(user_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}
