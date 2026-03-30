mod common;

use serde_json::{Value, json};
use uuid::Uuid;

/// Bootstrap org+identity+key using the common helper, which creates them
/// without ACL roles (backward compat: no roles = allowed through).
async fn setup() -> (String, reqwest::Client, Uuid, Uuid, String) {
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL required for tests");
    let pool = sqlx::PgPool::connect(&db_url).await.unwrap();
    overslash_db::MIGRATOR.run(&pool).await.unwrap();

    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (org_id, identity_id, api_key) = common::bootstrap_org_identity(&base, &client).await;

    (base, client, org_id, identity_id, api_key)
}

#[tokio::test]
async fn backward_compat_no_roles_allows_access() {
    let (base, client, _org_id, _identity_id, api_key) = setup().await;

    // Identity with no role assignments should be able to access ACL endpoints
    let res = client
        .get(format!("{base}/v1/acl/roles"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn list_roles_returns_empty_for_new_org() {
    let (base, client, _org_id, _identity_id, api_key) = setup().await;

    let roles: Vec<Value> = client
        .get(format!("{base}/v1/acl/roles"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // New org created via bootstrap_org_identity has no builtin roles
    // (those are seeded at OAuth login / dev_token, not via manual org creation)
    assert!(
        roles.is_empty()
            || roles
                .iter()
                .all(|r| r["is_builtin"].as_bool() == Some(false))
    );
}

#[tokio::test]
async fn create_and_list_custom_role() {
    let (base, client, _org_id, _identity_id, api_key) = setup().await;

    // Create a custom role
    let role: Value = client
        .post(format!("{base}/v1/acl/roles"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "name": "Developer",
            "slug": "developer",
            "description": "Development access"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(role["name"], "Developer");
    assert_eq!(role["slug"], "developer");
    assert_eq!(role["is_builtin"], false);

    // List roles should include it
    let roles: Vec<Value> = client
        .get(format!("{base}/v1/acl/roles"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(roles.iter().any(|r| r["slug"] == "developer"));
}

#[tokio::test]
async fn set_grants_on_custom_role() {
    let (base, client, _org_id, _identity_id, api_key) = setup().await;

    // Create role
    let role: Value = client
        .post(format!("{base}/v1/acl/roles"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "name": "Viewer",
            "slug": format!("viewer-{}", Uuid::new_v4()),
            "description": "Read-only"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let role_id = role["id"].as_str().unwrap();

    // Set grants
    let grants: Vec<Value> = client
        .put(format!("{base}/v1/acl/roles/{role_id}/grants"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "grants": [
                {"resource_type": "secrets", "action": "read"},
                {"resource_type": "services", "action": "read"},
                {"resource_type": "acl", "action": "read"}
            ]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(grants.len(), 3);

    // Get role detail should include grants
    let detail: Value = client
        .get(format!("{base}/v1/acl/roles/{role_id}"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(detail["grants"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn delete_custom_role() {
    let (base, client, _org_id, _identity_id, api_key) = setup().await;

    let role: Value = client
        .post(format!("{base}/v1/acl/roles"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "name": "Temp",
            "slug": format!("temp-{}", Uuid::new_v4()),
            "description": "Temporary"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let role_id = role["id"].as_str().unwrap();

    let res = client
        .delete(format!("{base}/v1/acl/roles/{role_id}"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["deleted"], true);
}

#[tokio::test]
async fn assign_and_revoke_role() {
    let (base, client, _org_id, identity_id, api_key) = setup().await;

    // Create a role
    let role: Value = client
        .post(format!("{base}/v1/acl/roles"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "name": "Tester",
            "slug": format!("tester-{}", Uuid::new_v4()),
            "description": "Test role"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let role_id = role["id"].as_str().unwrap();

    // Assign role
    let assignment: Value = client
        .post(format!("{base}/v1/acl/assignments"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "identity_id": identity_id,
            "role_id": role_id
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(assignment["identity_id"], identity_id.to_string());
    assert_eq!(assignment["role_id"], role_id);

    let assignment_id = assignment["id"].as_str().unwrap();

    // List assignments
    let assignments: Vec<Value> = client
        .get(format!("{base}/v1/acl/assignments"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(
        assignments
            .iter()
            .any(|a| a["identity_id"] == identity_id.to_string())
    );

    // Revoke
    let res = client
        .delete(format!("{base}/v1/acl/assignments/{assignment_id}"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn my_permissions_endpoint() {
    let (base, client, _org_id, _identity_id, api_key) = setup().await;

    let perms: Value = client
        .get(format!("{base}/v1/acl/me"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(perms["identity_id"].is_string());
    assert!(perms["permissions"].is_array());
    assert!(perms["is_admin"].is_boolean());
}

#[tokio::test]
async fn acl_status_endpoint() {
    let (base, client, _org_id, _identity_id, api_key) = setup().await;

    let status: Value = client
        .get(format!("{base}/v1/acl/status"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(status["has_admin"].is_boolean());
    assert!(status["admin_count"].is_number());
    assert!(status["admin_identities"].is_array());
}

#[tokio::test]
async fn acl_audit_trail() {
    let (base, client, _org_id, _identity_id, api_key) = setup().await;

    // Create a role to trigger audit
    client
        .post(format!("{base}/v1/acl/roles"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "name": "Audited",
            "slug": format!("audited-{}", Uuid::new_v4()),
            "description": "For audit"
        }))
        .send()
        .await
        .unwrap();

    // Query audit log for ACL role events
    let entries: Vec<Value> = client
        .get(format!("{base}/v1/audit?resource_type=acl_role&limit=10"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(entries.iter().any(|e| e["action"] == "acl_role.created"));
}
