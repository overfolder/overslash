//! Integration tests for the three-tier template registry:
//! global (shipped YAML) + org (DB, admin CRUD) + user (DB, CRUD gated by org setting).

mod common;

use reqwest::Client;
use serde_json::{Value, json};
use uuid::Uuid;

fn auth(key: &str) -> (&'static str, String) {
    ("Authorization", format!("Bearer {key}"))
}

/// Bootstrap an org with admin, write, and read-only users + keys.
/// Clones from a pre-bootstrapped DB template so the 11 setup HTTP requests
/// only run once per test suite, not once per test.
/// Returns (base_url, client, org_id, admin_key, write_key, read_key, org_key, user_ids).
async fn bootstrap(
    with_registry: bool,
) -> (
    String,
    Client,
    Uuid,
    String,
    String,
    String,
    String,
    [Uuid; 3],
) {
    let (pool, fixtures) = common::test_pool_bootstrapped().await;

    let (base, client) = if with_registry {
        common::start_api_with_registry(pool, None).await
    } else {
        let (addr, client) = common::start_api(pool).await;
        (format!("http://{addr}"), client)
    };

    (
        base,
        client,
        fixtures.org_id,
        fixtures.admin_key,
        fixtures.write_key,
        fixtures.read_key,
        fixtures.org_key,
        fixtures.user_ids,
    )
}

// ---------------------------------------------------------------------------
// User template CRUD — gated by allow_user_templates
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_user_template_blocked_when_setting_off() {
    let (base, client, _org_id, _admin_key, write_key, _, _, _) = bootstrap(false).await;

    // Default: allow_user_templates is false
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(&json!({
            "key": "my-api",
            "display_name": "My API",
            "user_level": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_user_template_crud_when_setting_on() {
    let (base, client, org_id, admin_key, write_key, _, _, _) = bootstrap(false).await;

    // Admin enables user templates
    let resp = client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"allow_user_templates": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["allow_user_templates"], true);

    // Write user creates a user-level template
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(&json!({
            "key": "my-api",
            "display_name": "My Custom API",
            "user_level": true,
            "hosts": ["api.example.com"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let created: Value = resp.json().await.unwrap();
    assert_eq!(created["tier"], "user");
    assert_eq!(created["key"], "my-api");
    let template_id = created["id"].as_str().unwrap();

    // Update the user-level template
    let resp = client
        .put(format!("{base}/v1/templates/{template_id}/manage"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(&json!({"display_name": "My API v2"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let updated: Value = resp.json().await.unwrap();
    assert_eq!(updated["display_name"], "My API v2");

    // Delete the user-level template
    let resp = client
        .delete(format!("{base}/v1/templates/{template_id}/manage"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

// ---------------------------------------------------------------------------
// Write user cannot create org-level templates
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_write_user_cannot_create_org_template() {
    let (base, client, _, _, write_key, _, _, _) = bootstrap(false).await;

    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(&json!({
            "key": "org-api",
            "display_name": "Org API",
            "user_level": false,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

// ---------------------------------------------------------------------------
// Admin can create org-level templates
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_admin_creates_org_template() {
    let (base, client, _, admin_key, _, _, _, _) = bootstrap(false).await;

    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "key": "internal-api",
            "display_name": "Internal API",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["tier"], "org");
    assert_eq!(body["key"], "internal-api");
}

// ---------------------------------------------------------------------------
// User cannot modify another user's template
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_user_cannot_modify_other_users_template() {
    let (base, client, org_id, admin_key, write_key, _, _, _user_ids) = bootstrap(false).await;

    // Enable user templates
    client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"allow_user_templates": true}))
        .send()
        .await
        .unwrap();

    // Create a key for a second write user (reuse user_ids[2] after promoting them,
    // or create a new user). Let's create a new user for clarity.
    let user2: Value = client
        .post(format!("{base}/v1/identities"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"name": "other-user", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user2_id: Uuid = user2["id"].as_str().unwrap().parse().unwrap();

    let key2_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"org_id": org_id, "identity_id": user2_id, "name": "user2-key"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user2_key = key2_resp["key"].as_str().unwrap().to_string();

    // Write user creates a template
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(&json!({
            "key": "private-api",
            "display_name": "Private API",
            "user_level": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let created: Value = resp.json().await.unwrap();
    let template_id = created["id"].as_str().unwrap();

    // Other user tries to update it -> 403
    let resp = client
        .put(format!("{base}/v1/templates/{template_id}/manage"))
        .header(auth(&user2_key).0, auth(&user2_key).1)
        .json(&json!({"display_name": "Hijacked"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Other user tries to delete it -> 403
    let resp = client
        .delete(format!("{base}/v1/templates/{template_id}/manage"))
        .header(auth(&user2_key).0, auth(&user2_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Admin CAN modify another user's template
    let resp = client
        .put(format!("{base}/v1/templates/{template_id}/manage"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"display_name": "Admin Override"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["display_name"], "Admin Override");
}

// ---------------------------------------------------------------------------
// Global templates visibility — default on, toggle off, selective enable
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_global_templates_visible_by_default() {
    let (base, client, _, admin_key, _, _, _, _) = bootstrap(true).await;

    let resp = client
        .get(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let templates: Vec<Value> = resp.json().await.unwrap();

    // With registry loaded, global templates should be present
    let global_count = templates.iter().filter(|t| t["tier"] == "global").count();
    assert!(global_count > 0, "expected global templates to be visible");
}

#[tokio::test]
async fn test_global_templates_hidden_when_disabled() {
    let (base, client, org_id, admin_key, write_key, _, _, _) = bootstrap(true).await;

    // Disable global templates
    let resp = client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"global_templates_enabled": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Write user sees no globals
    let resp = client
        .get(format!("{base}/v1/templates"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .send()
        .await
        .unwrap();
    let templates: Vec<Value> = resp.json().await.unwrap();
    let global_count = templates.iter().filter(|t| t["tier"] == "global").count();
    assert_eq!(global_count, 0, "expected no globals when disabled");

    // GET by key also returns 404 for global
    let resp = client
        .get(format!("{base}/v1/templates/github"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_selective_global_enable() {
    let (base, client, org_id, admin_key, write_key, _, _, _) = bootstrap(true).await;

    // Disable all globals
    client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"global_templates_enabled": false}))
        .send()
        .await
        .unwrap();

    // Enable just "github"
    let resp = client
        .post(format!("{base}/v1/templates/enabled-globals"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"template_key": "github"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Write user sees only github
    let resp = client
        .get(format!("{base}/v1/templates"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .send()
        .await
        .unwrap();
    let templates: Vec<Value> = resp.json().await.unwrap();
    let globals: Vec<&Value> = templates.iter().filter(|t| t["tier"] == "global").collect();
    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0]["key"], "github");

    // GET by key works for github
    let resp = client
        .get(format!("{base}/v1/templates/github"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // But not for slack
    let resp = client
        .get(format!("{base}/v1/templates/slack"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // Disable github
    let resp = client
        .delete(format!("{base}/v1/templates/enabled-globals/github"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Now no globals visible
    let resp = client
        .get(format!("{base}/v1/templates"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .send()
        .await
        .unwrap();
    let templates: Vec<Value> = resp.json().await.unwrap();
    let global_count = templates.iter().filter(|t| t["tier"] == "global").count();
    assert_eq!(global_count, 0);
}

// ---------------------------------------------------------------------------
// Admin compliance view
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_admin_compliance_view() {
    let (base, client, org_id, admin_key, write_key, _, _, _) = bootstrap(true).await;

    // Enable user templates and create one
    client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"allow_user_templates": true}))
        .send()
        .await
        .unwrap();

    client
        .post(format!("{base}/v1/templates"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(&json!({
            "key": "user-api",
            "display_name": "User API",
            "user_level": true,
        }))
        .send()
        .await
        .unwrap();

    // Admin creates an org-level template
    client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "key": "org-api",
            "display_name": "Org API",
        }))
        .send()
        .await
        .unwrap();

    // Disable globals and enable just one
    client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"global_templates_enabled": false}))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/v1/templates/enabled-globals"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"template_key": "github"}))
        .send()
        .await
        .unwrap();

    // Admin compliance view
    let resp = client
        .get(format!("{base}/v1/templates/admin"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let templates: Vec<Value> = resp.json().await.unwrap();

    // Should see ALL globals (with enabled flag)
    let globals: Vec<&Value> = templates.iter().filter(|t| t["tier"] == "global").collect();
    assert!(globals.len() > 1, "admin should see ALL globals");

    let github = globals.iter().find(|t| t["key"] == "github").unwrap();
    assert_eq!(github["enabled"], true);

    let slack = globals.iter().find(|t| t["key"] == "slack").unwrap();
    assert_eq!(slack["enabled"], false);

    // Should see the org template
    assert!(
        templates
            .iter()
            .any(|t| t["key"] == "org-api" && t["tier"] == "org")
    );

    // Should see the user's template (with owner_identity_id)
    let user_tpl = templates
        .iter()
        .find(|t| t["key"] == "user-api" && t["tier"] == "user")
        .expect("admin should see user templates");
    assert!(user_tpl["owner_identity_id"].is_string());

    // Write user cannot access admin view
    let resp = client
        .get(format!("{base}/v1/templates/admin"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

// ---------------------------------------------------------------------------
// Audit logging
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_template_operations_produce_audit_entries() {
    let (base, client, org_id, admin_key, _, _, _, _) = bootstrap(true).await;

    // Create org template (generates audit)
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "key": "audit-test-api",
            "display_name": "Audit Test",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let created: Value = resp.json().await.unwrap();
    let template_id = created["id"].as_str().unwrap();

    // Update template (generates audit)
    client
        .put(format!("{base}/v1/templates/{template_id}/manage"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"display_name": "Audit Test v2"}))
        .send()
        .await
        .unwrap();

    // Delete template (generates audit)
    client
        .delete(format!("{base}/v1/templates/{template_id}/manage"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();

    // Enable a global template (generates audit)
    client
        .post(format!("{base}/v1/templates/enabled-globals"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"template_key": "github"}))
        .send()
        .await
        .unwrap();

    // Change template settings (generates audit)
    client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"allow_user_templates": true}))
        .send()
        .await
        .unwrap();

    // Check audit log for template-related entries
    let resp = client
        .get(format!("{base}/v1/audit?resource_type=template"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let audit_entries: Vec<Value> = resp.json().await.unwrap();

    let actions: Vec<&str> = audit_entries
        .iter()
        .map(|e| e["action"].as_str().unwrap_or(""))
        .collect();

    assert!(
        actions.contains(&"template.created"),
        "expected template.created audit entry, got: {actions:?}"
    );
    assert!(
        actions.contains(&"template.updated"),
        "expected template.updated audit entry, got: {actions:?}"
    );
    assert!(
        actions.contains(&"template.deleted"),
        "expected template.deleted audit entry, got: {actions:?}"
    );
    assert!(
        actions.contains(&"template.global.enabled"),
        "expected template.global.enabled audit entry, got: {actions:?}"
    );
}

// ---------------------------------------------------------------------------
// Template settings endpoint validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_template_settings_no_fields_returns_400() {
    let (base, client, org_id, admin_key, _, _, _, _) = bootstrap(false).await;

    let resp = client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_template_settings_write_user_forbidden() {
    let (base, client, org_id, _, write_key, _, _, _) = bootstrap(false).await;

    let resp = client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(&json!({"allow_user_templates": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

// ---------------------------------------------------------------------------
// Actions endpoint respects global visibility filter
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_template_actions_respects_global_filter() {
    let (base, client, org_id, admin_key, write_key, _, _, _) = bootstrap(true).await;

    // Disable global templates
    client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"global_templates_enabled": false}))
        .send()
        .await
        .unwrap();

    // GET /v1/templates/github/actions should be 404
    let resp = client
        .get(format!("{base}/v1/templates/github/actions"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // Enable github specifically
    client
        .post(format!("{base}/v1/templates/enabled-globals"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"template_key": "github"}))
        .send()
        .await
        .unwrap();

    // Now actions should work for github
    let resp = client
        .get(format!("{base}/v1/templates/github/actions"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // But not for slack
    let resp = client
        .get(format!("{base}/v1/templates/slack/actions"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ---------------------------------------------------------------------------
// Enable nonexistent global template returns 404
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_enable_nonexistent_global_returns_404() {
    let (base, client, _, admin_key, _, _, _, _) = bootstrap(false).await;

    let resp = client
        .post(format!("{base}/v1/templates/enabled-globals"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"template_key": "nonexistent-service"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}
