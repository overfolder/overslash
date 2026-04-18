mod common;

use serde_json::{Value, json};
use uuid::Uuid;

/// Create an org-level template + service instance. Returns the service instance ID.
async fn create_org_service(base: &str, client: &reqwest::Client, key: &str, name: &str) -> Uuid {
    let openapi = common::minimal_openapi(name);
    client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({
            "openapi": openapi,
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
        .json(&json!({ "openapi": common::minimal_openapi("user-svc") }))
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

/// A user-defined (user-level) service must always be visible to its owner and
/// to any agent in the owner's identity chain — even when the user belongs to
/// a group whose grants do not include that service. Group grants gate
/// *org-level* services; they must not hide the user's own creations.
#[tokio::test]
async fn user_level_services_always_visible_despite_restrictive_group() {
    let (base, org_key, user_id, user_key) = bootstrap().await;
    let client = reqwest::Client::new();

    // An org-level service the user will *not* be granted via group.
    create_org_service(&base, &client, &org_key, "org-forbidden").await;

    // Another org-level service the user *will* be granted via group.
    let org_allowed_id = create_org_service(&base, &client, &org_key, "org-allowed").await;

    // Create an org-level template, then the user creates a user-level
    // service instance from it.
    client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({
            "key": "my-calendar",
            "display_name": "My Calendar",
            "hosts": ["calendar.example.com"],
        }))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {user_key}"))
        .json(&json!({
            "template_key": "my-calendar",
            "name": "my-calendar",
            "user_level": true,
        }))
        .send()
        .await
        .unwrap();

    // Put the user in a restrictive group that only grants `org-allowed`.
    let group: Value = client
        .post(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"name": "Restricted"}))
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
        .json(&json!({
            "service_instance_id": org_allowed_id.to_string(),
            "access_level": "read",
        }))
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

    // User sees their own service, the granted org service, and NOT the
    // ungranted org service.
    let resp = client
        .get(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {user_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let services: Vec<Value> = resp.json().await.unwrap();
    let names: Vec<&str> = services
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"my-calendar"),
        "user must always see their own user-level service (got: {names:?})"
    );
    assert!(
        names.contains(&"org-allowed"),
        "user should see the group-granted org service (got: {names:?})"
    );
    assert!(
        !names.contains(&"org-forbidden"),
        "user should not see the ungranted org service (got: {names:?})"
    );

    // Resolution by name works too.
    let resp = client
        .get(format!("{base}/v1/services/my-calendar"))
        .header("Authorization", format!("Bearer {user_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "user must be able to resolve their own service by name"
    );

    // An agent owned by this user also sees the user-level service.
    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"name": "calendar-agent", "kind": "agent", "parent_id": user_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id: Uuid = agent["id"].as_str().unwrap().parse().unwrap();

    let agent_key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({
            "org_id": agent["org_id"].as_str().unwrap(),
            "identity_id": agent_id,
            "name": "agent-key",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_key = agent_key_resp["key"].as_str().unwrap();

    let resp = client
        .get(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let services: Vec<Value> = resp.json().await.unwrap();
    let names: Vec<&str> = services
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"my-calendar"),
        "agent must inherit visibility of owner's user-level services (got: {names:?})"
    );
    assert!(
        !names.contains(&"org-forbidden"),
        "agent must not see ungranted org-level services (got: {names:?})"
    );

    // Agent can resolve the service by name too.
    let resp = client
        .get(format!("{base}/v1/services/my-calendar"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "agent must be able to resolve owner's user-level service by name"
    );
}

/// The read-visibility expansion must not leak into destructive paths. An
/// agent that inherits admin privileges from its owner (via the overslash
/// service group grant) shares the owner user's *read* view of services, but
/// it must not be able to delete an owner-owned service by name — that would
/// be an unintended privilege escalation. Deleting via UUID is still allowed
/// (pre-existing AdminAcl capability, unchanged by this PR).
#[tokio::test]
async fn admin_agent_cannot_delete_owner_user_service_by_name() {
    let (base, org_key, _user_id, _user_key) = bootstrap().await;
    let client = reqwest::Client::new();

    // The org_key is bound to the auto-minted bootstrap admin user. Pull its
    // identity so we can create an agent whose ceiling is that admin user.
    let whoami: Value = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {org_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admin_user_id: Uuid = whoami["identity_id"].as_str().unwrap().parse().unwrap();

    // Admin user creates a user-level service instance.
    client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({
            "key": "my-svc",
            "display_name": "My Service",
            "hosts": ["svc.example.com"],
        }))
        .send()
        .await
        .unwrap();
    let user_svc: Value = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({
            "template_key": "my-svc",
            "name": "my-svc",
            "user_level": true,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_svc_id = user_svc["id"].as_str().unwrap();

    // Agent under the admin user inherits admin ACL via the ceiling.
    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"name": "admin-agent", "kind": "agent", "parent_id": admin_user_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id: Uuid = agent["id"].as_str().unwrap().parse().unwrap();
    let agent_key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({
            "org_id": agent["org_id"].as_str().unwrap(),
            "identity_id": agent_id,
            "name": "agent-admin-key",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_key = agent_key_resp["key"].as_str().unwrap();

    // Sanity: the agent can still *see* the owner's service through the
    // read-visibility path.
    let resp = client
        .get(format!("{base}/v1/services/my-svc"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "agent must still be able to read-resolve owner's user-level service"
    );

    // Delete by name must NOT resolve through the ceiling user. Agent cannot
    // delete the owner's user-level service via name even with AdminAcl.
    let resp = client
        .delete(format!("{base}/v1/services/my-svc"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        404,
        "agent must not be able to delete owner's user-level service by name"
    );

    // Service still exists.
    let resp = client
        .get(format!("{base}/v1/services/{user_svc_id}"))
        .header("Authorization", format!("Bearer {org_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "service must still exist after denied delete"
    );
}
