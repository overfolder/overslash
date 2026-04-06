mod common;

use serde_json::{Value, json};
use uuid::Uuid;

/// Create an org-level template + service instance. Returns the service instance ID.
async fn create_org_service(base: &str, client: &reqwest::Client, key: &str, name: &str) -> Uuid {
    // Create template
    client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({
            "key": name,
            "display_name": name,
            "hosts": [format!("{name}.example.com")],
            "user_level": false,
        }))
        .send()
        .await
        .unwrap();

    // Create org-level instance
    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({
            "template_key": name,
            "name": name,
            "user_level": false,
        }))
        .send()
        .await
        .unwrap();
    let svc: Value = resp.json().await.unwrap();
    svc["id"].as_str().unwrap().parse().unwrap()
}

/// Bootstrap: org + user identity + user-bound API key.
/// Returns (base_url, org_api_key, user_id, user_api_key).
async fn bootstrap() -> (String, String, Uuid, String) {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    // Create org
    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "TestOrg", "slug": format!("test-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();

    // Org-level key
    let org_key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "org-admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_api_key = org_key["key"].as_str().unwrap().to_string();

    // Create user identity
    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_api_key}"))
        .json(&json!({"name": "test-user", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id: Uuid = user["id"].as_str().unwrap().parse().unwrap();

    // User-bound API key (requires admin auth now that org has keys)
    let key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {org_api_key}"))
        .json(&json!({"org_id": org_id, "identity_id": user_id, "name": "user-key"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_api_key = key_resp["key"].as_str().unwrap().to_string();

    (base, org_api_key, user_id, user_api_key)
}

#[tokio::test]
async fn group_crud() {
    let (base, key, _, _) = bootstrap().await;
    let client = reqwest::Client::new();

    // Create group
    let resp = client
        .post(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({
            "name": "Engineering",
            "description": "Dev team",
            "allow_raw_http": false,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let group: Value = resp.json().await.unwrap();
    let group_id = group["id"].as_str().unwrap();
    assert_eq!(group["name"], "Engineering");
    assert_eq!(group["allow_raw_http"], false);

    // List groups
    let resp = client
        .get(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let groups: Vec<Value> = resp.json().await.unwrap();
    // 2 system groups (Everyone, Admins) + 1 test group = 3
    assert_eq!(groups.len(), 3);

    // Get group
    let resp = client
        .get(format!("{base}/v1/groups/{group_id}"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Update group
    let resp = client
        .put(format!("{base}/v1/groups/{group_id}"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({
            "name": "Engineering",
            "description": "Updated desc",
            "allow_raw_http": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let updated: Value = resp.json().await.unwrap();
    assert_eq!(updated["allow_raw_http"], true);
    assert_eq!(updated["description"], "Updated desc");

    // Delete group
    let resp = client
        .delete(format!("{base}/v1/groups/{group_id}"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let del: Value = resp.json().await.unwrap();
    assert_eq!(del["deleted"], true);

    // Verify deleted
    let resp = client
        .get(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap();
    let groups: Vec<Value> = resp.json().await.unwrap();
    // Only system groups remain
    assert_eq!(groups.len(), 2);
}

#[tokio::test]
async fn group_duplicate_name_conflict() {
    let (base, key, _, _) = bootstrap().await;
    let client = reqwest::Client::new();

    // Create first group
    let resp = client
        .post(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({"name": "Engineering"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Create duplicate — expect 409
    let resp = client
        .post(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({"name": "Engineering"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
}

#[tokio::test]
async fn member_assignment_users_only() {
    let (base, org_key, user_id, _) = bootstrap().await;
    let client = reqwest::Client::new();

    // Create group
    let group: Value = client
        .post(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"name": "Engineering"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let group_id = group["id"].as_str().unwrap();

    // Assign user — should succeed
    let resp = client
        .post(format!("{base}/v1/groups/{group_id}/members"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"identity_id": user_id}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Create an agent
    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"name": "test-agent", "kind": "agent", "parent_id": user_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id = agent["id"].as_str().unwrap();

    // Assign agent — should fail (only users allowed)
    let resp = client
        .post(format!("{base}/v1/groups/{group_id}/members"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"identity_id": agent_id}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // List members
    let resp = client
        .get(format!("{base}/v1/groups/{group_id}/members"))
        .header("Authorization", format!("Bearer {org_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let members: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0], user_id.to_string());

    // Unassign
    let resp = client
        .delete(format!("{base}/v1/groups/{group_id}/members/{user_id}"))
        .header("Authorization", format!("Bearer {org_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn grants_require_org_level_service() {
    let (base, org_key, _user_id, user_key) = bootstrap().await;
    let client = reqwest::Client::new();

    // Create group
    let group: Value = client
        .post(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"name": "Engineering"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let group_id = group["id"].as_str().unwrap();

    // Create an org-level service instance
    let svc_id = create_org_service(&base, &client, &org_key, "test-svc").await;

    // Add grant — should succeed
    let resp = client
        .post(format!("{base}/v1/groups/{group_id}/grants"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({
            "service_instance_id": svc_id.to_string(),
            "access_level": "write",
            "auto_approve_reads": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let grant: Value = resp.json().await.unwrap();
    assert_eq!(grant["access_level"], "write");
    assert_eq!(grant["auto_approve_reads"], true);
    assert_eq!(grant["service_name"], "test-svc");

    // List grants
    let resp = client
        .get(format!("{base}/v1/groups/{group_id}/grants"))
        .header("Authorization", format!("Bearer {org_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let grants: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(grants.len(), 1);

    // Create an org-level template, then a user-level service from it
    client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({
            "key": "user-svc",
            "display_name": "User Service",
            "hosts": ["user.example.com"],
        }))
        .send()
        .await
        .unwrap();
    let user_svc_resp: Value = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {user_key}"))
        .json(&json!({
            "template_key": "user-svc",
            "name": "user-svc",
            "user_level": true,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_svc_id = user_svc_resp["id"].as_str().unwrap();

    // Try to add grant for user-level service — should fail
    let resp = client
        .post(format!("{base}/v1/groups/{group_id}/grants"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({
            "service_instance_id": user_svc_id,
            "access_level": "read",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Invalid access level
    let resp = client
        .post(format!("{base}/v1/groups/{group_id}/grants"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({
            "service_instance_id": svc_id.to_string(),
            "access_level": "superadmin",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Remove grant
    let grant_id = grant["id"].as_str().unwrap();
    let resp = client
        .delete(format!("{base}/v1/groups/{group_id}/grants/{grant_id}"))
        .header("Authorization", format!("Bearer {org_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn service_visibility_filtered_by_groups() {
    let (base, org_key, user_id, user_key) = bootstrap().await;
    let client = reqwest::Client::new();

    // Create two org-level services
    let svc1_id = create_org_service(&base, &client, &org_key, "svc-a").await;
    create_org_service(&base, &client, &org_key, "svc-b").await;

    // User is only in system groups (Everyone) which don't trigger filtering.
    // Permissive mode applies — user sees all services.
    let resp = client
        .get(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {user_key}"))
        .send()
        .await
        .unwrap();
    let services: Vec<Value> = resp.json().await.unwrap();
    let before_names: Vec<&str> = services.iter().filter_map(|s| s["name"].as_str()).collect();
    assert!(
        before_names.contains(&"svc-a"),
        "permissive: should see svc-a when only in system groups"
    );
    assert!(
        before_names.contains(&"svc-b"),
        "permissive: should see svc-b when only in system groups"
    );

    // Create group with only svc-a granted
    let group: Value = client
        .post(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"name": "Limited"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let group_id = group["id"].as_str().unwrap();

    client
        .post(format!("{base}/v1/groups/{group_id}/grants"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"service_instance_id": svc1_id.to_string(), "access_level": "read"}))
        .send()
        .await
        .unwrap();

    client
        .post(format!("{base}/v1/groups/{group_id}/members"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"identity_id": user_id}))
        .send()
        .await
        .unwrap();

    // After groups: user only sees svc-a
    let resp = client
        .get(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {user_key}"))
        .send()
        .await
        .unwrap();
    let services: Vec<Value> = resp.json().await.unwrap();
    let names: Vec<&str> = services
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"svc-a"), "should see granted service");
    assert!(
        !names.contains(&"svc-b"),
        "should not see non-granted service"
    );
}
