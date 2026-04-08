//! Integration tests for the template/service instance split.

mod common;

use reqwest::Client;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

/// Helper: bootstrap org+identity+key, return (base_url, client, org_id, identity_id, api_key, admin_key).
/// The api_key is agent-bound (write ACL). The admin_key is org-level (admin ACL, no identity).
/// Also creates a user_admin_key: user-bound with admin ACL (user added to Admins group).
async fn setup(pool: PgPool) -> (String, Client, Uuid, Uuid, String, String) {
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (org_id, identity_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Find the user identity (parent of the agent)
    let identities: Vec<Value> = client
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // After migration 028 the unauth bootstrap path mints an "admin" user
    // automatically; here we want the *test-user* (parent of the test agent),
    // not the bootstrap admin.
    let user_id = identities
        .iter()
        .find(|i| i["kind"] == "user" && i["name"] == "test-user")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Add user to Admins group (find it first)
    let groups: Vec<Value> = client
        .get(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admins_group_id = groups.iter().find(|g| g["name"] == "Admins").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    client
        .post(format!("{base}/v1/groups/{admins_group_id}/members"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"identity_id": user_id}))
        .send()
        .await
        .unwrap();

    // Create a user-bound API key (now with admin ACL since user is in Admins)
    let key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"org_id": org_id, "identity_id": user_id, "name": "user-admin-key"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_admin_key = key_resp["key"].as_str().unwrap().to_string();

    (base, client, org_id, identity_id, api_key, user_admin_key)
}

// -- Template Tests --

#[tokio::test]
async fn test_list_templates_empty_registry() {
    let pool = common::test_pool().await;
    let (base, client, _org_id, _ident_id, api_key, _admin_key) = setup(pool).await;

    let resp: Vec<Value> = client
        .get(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Empty registry in test mode — no templates initially
    assert!(resp.is_empty());
}

#[tokio::test]
async fn test_create_and_get_org_template() {
    let pool = common::test_pool().await;
    let (base, client, _org_id, _ident_id, api_key, admin_key) = setup(pool).await;

    // Create an org-level template
    let create_resp = client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "key": "my-internal-api",
            "display_name": "My Internal API",
            "description": "Internal API for testing",
            "category": "dev-tools",
            "hosts": ["api.internal.test"],
            "auth": [{"type": "api_key", "default_secret_name": "internal_key", "injection": {"as": "header", "header_name": "X-API-Key"}}],
            "actions": {
                "list_items": {
                    "method": "GET",
                    "path": "/items",
                    "description": "List all items",
                    "risk": "read"
                }
            },
            "user_level": false
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(create_resp.status(), 200);
    let template: Value = create_resp.json().await.unwrap();
    assert_eq!(template["key"], "my-internal-api");
    assert_eq!(template["tier"], "org");
    assert!(template["id"].is_string());

    // Get the template by key
    let get_resp: Value = client
        .get(format!("{base}/v1/templates/my-internal-api"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(get_resp["key"], "my-internal-api");
    assert_eq!(get_resp["display_name"], "My Internal API");
    assert_eq!(get_resp["tier"], "org");

    // Template should appear in listing
    let list: Vec<Value> = client
        .get(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(list.iter().any(|t| t["key"] == "my-internal-api"));
}

#[tokio::test]
async fn test_create_user_template() {
    let pool = common::test_pool().await;
    let (base, client, _org_id, _ident_id, _api_key, admin_key) = setup(pool).await;

    let resp = client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "key": "my-personal-api",
            "display_name": "Personal API",
            "hosts": ["personal.api.test"],
            "user_level": true
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let template: Value = resp.json().await.unwrap();
    assert_eq!(template["key"], "my-personal-api");
    assert_eq!(template["tier"], "user");
}

#[tokio::test]
async fn test_search_templates() {
    let pool = common::test_pool().await;
    let (base, client, _org_id, _ident_id, api_key, admin_key) = setup(pool).await;

    client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "key": "searchable-api",
            "display_name": "Searchable API",
            "description": "An API that can be found via search",
            "hosts": ["search.test"],
            "user_level": false
        }))
        .send()
        .await
        .unwrap();

    let results: Vec<Value> = client
        .get(format!("{base}/v1/templates/search?q=searchable"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(!results.is_empty());
    assert!(results.iter().any(|t| t["key"] == "searchable-api"));
}

#[tokio::test]
async fn test_delete_template() {
    let pool = common::test_pool().await;
    let (base, client, _org_id, _ident_id, api_key, admin_key) = setup(pool).await;

    let create_resp: Value = client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "key": "deletable-api",
            "display_name": "Deletable API",
            "hosts": ["delete.test"],
            "user_level": false
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let id = create_resp["id"].as_str().unwrap();

    let del_resp = client
        .delete(format!("{base}/v1/templates/{id}/manage"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(del_resp.status(), 200);

    let get_resp = client
        .get(format!("{base}/v1/templates/deletable-api"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(get_resp.status(), 404);
}

// -- Service Instance Tests --

#[tokio::test]
async fn test_create_service_instance() {
    let pool = common::test_pool().await;
    let (base, client, _org_id, _ident_id, api_key, admin_key) = setup(pool).await;

    // Create template first
    client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "key": "test-svc",
            "display_name": "Test Service",
            "hosts": ["test.example.com"],
            "user_level": false
        }))
        .send()
        .await
        .unwrap();

    // Create service instance
    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "template_key": "test-svc",
            "name": "my-test-svc"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let instance: Value = resp.json().await.unwrap();
    assert_eq!(instance["name"], "my-test-svc");
    assert_eq!(instance["template_key"], "test-svc");
    assert_eq!(instance["status"], "active");
    assert!(instance["id"].is_string());
}

#[tokio::test]
async fn test_list_service_instances() {
    let pool = common::test_pool().await;
    let (base, client, _org_id, _ident_id, api_key, admin_key) = setup(pool).await;

    client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "key": "list-svc",
            "display_name": "Listable Service",
            "hosts": ["list.test"],
            "user_level": false
        }))
        .send()
        .await
        .unwrap();

    client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({ "template_key": "list-svc" }))
        .send()
        .await
        .unwrap();

    let list: Vec<Value> = client
        .get(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(list.iter().any(|i| i["name"] == "list-svc"));
}

#[tokio::test]
async fn test_service_instance_lifecycle() {
    let pool = common::test_pool().await;
    let (base, client, _org_id, _ident_id, api_key, admin_key) = setup(pool).await;

    // Create template
    client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "key": "lifecycle-svc",
            "display_name": "Lifecycle Service",
            "hosts": ["lifecycle.test"],
            "user_level": false
        }))
        .send()
        .await
        .unwrap();

    // Create as draft
    let create_resp: Value = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({ "template_key": "lifecycle-svc", "status": "draft" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(create_resp["status"], "draft");
    let id = create_resp["id"].as_str().unwrap();

    // Draft should NOT resolve by name
    let get_resp = client
        .get(format!("{base}/v1/services/lifecycle-svc"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(get_resp.status(), 404);

    // Transition to active
    let active_resp: Value = client
        .patch(format!("{base}/v1/services/{id}/status"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({ "status": "active" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(active_resp["status"], "active");

    // Now should resolve
    let get_resp = client
        .get(format!("{base}/v1/services/lifecycle-svc"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(get_resp.status(), 200);

    // Archive
    let archived_resp: Value = client
        .patch(format!("{base}/v1/services/{id}/status"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({ "status": "archived" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(archived_resp["status"], "archived");

    // Archived should NOT resolve
    let get_resp = client
        .get(format!("{base}/v1/services/lifecycle-svc"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(get_resp.status(), 404);
}

#[tokio::test]
async fn test_service_name_defaults_to_template_key() {
    let pool = common::test_pool().await;
    let (base, client, _org_id, _ident_id, api_key, admin_key) = setup(pool).await;

    client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "key": "auto-name-svc",
            "display_name": "Auto Named",
            "hosts": ["autoname.test"],
            "user_level": false
        }))
        .send()
        .await
        .unwrap();

    let instance: Value = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({ "template_key": "auto-name-svc" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(instance["name"], "auto-name-svc");
}

#[tokio::test]
async fn test_duplicate_instance_name_conflict() {
    let pool = common::test_pool().await;
    let (base, client, _org_id, _ident_id, api_key, admin_key) = setup(pool).await;

    client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "key": "dup-svc",
            "display_name": "Dup Service",
            "hosts": ["dup.test"],
            "user_level": false
        }))
        .send()
        .await
        .unwrap();

    let first = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({ "template_key": "dup-svc" }))
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 200);

    let second = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({ "template_key": "dup-svc" }))
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), 409);
}

#[tokio::test]
async fn test_template_actions_via_service() {
    let pool = common::test_pool().await;
    let (base, client, _org_id, _ident_id, api_key, admin_key) = setup(pool).await;

    client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "key": "actions-svc",
            "display_name": "Actions Service",
            "hosts": ["actions.test"],
            "actions": {
                "get_items": {
                    "method": "GET",
                    "path": "/items",
                    "description": "List items",
                    "risk": "read"
                },
                "create_item": {
                    "method": "POST",
                    "path": "/items",
                    "description": "Create item",
                    "risk": "write"
                }
            },
            "user_level": false
        }))
        .send()
        .await
        .unwrap();

    client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({ "template_key": "actions-svc" }))
        .send()
        .await
        .unwrap();

    let actions: Vec<Value> = client
        .get(format!("{base}/v1/services/actions-svc/actions"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(actions.len(), 2);
    assert!(actions.iter().any(|a| a["key"] == "get_items"));
    assert!(actions.iter().any(|a| a["key"] == "create_item"));
}

#[tokio::test]
async fn test_template_actions_listing() {
    let pool = common::test_pool().await;
    let (base, client, _org_id, _ident_id, api_key, admin_key) = setup(pool).await;

    client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "key": "tmpl-actions",
            "display_name": "Template Actions",
            "hosts": ["tmpl.test"],
            "actions": {
                "list": { "method": "GET", "path": "/", "description": "List all", "risk": "read" }
            },
            "user_level": false
        }))
        .send()
        .await
        .unwrap();

    let actions: Vec<Value> = client
        .get(format!("{base}/v1/templates/tmpl-actions/actions"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0]["key"], "list");
}
