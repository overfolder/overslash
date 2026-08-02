//! Integration tests for the three-tier template registry:
//! global (shipped OpenAPI YAML) + org (DB, admin CRUD) + user (DB, CRUD gated by org setting).

use crate::common;

use reqwest::Client;
use serde_json::{Value, json};
use uuid::Uuid;

fn auth(key: &str) -> (&'static str, String) {
    ("Authorization", format!("Bearer {key}"))
}

/// Minimal OpenAPI 3.1 template body loaded from
/// `tests/fixtures/openapi/minimal.yaml.tmpl` with Jinja substitution.
fn minimal_openapi(key: &str, display_name: &str) -> String {
    common::render_openapi(
        include_str!("fixtures/openapi/minimal.yaml.tmpl"),
        &[("key", key), ("display_name", display_name)],
    )
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
// User template CRUD — gated by user_template_policy
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_user_template_blocked_when_setting_off() {
    let (base, client, _org_id, _admin_key, write_key, _, _, _) = bootstrap(false).await;

    // Default: user_template_policy is 'none'
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(&json!({
            "openapi": minimal_openapi("my-api", "My API"),
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
        .json(&json!({"user_template_policy": "full"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["user_template_policy"], "full");

    // Write user creates a user-level template
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(&json!({
            "openapi": minimal_openapi("my-api", "My Custom API"),
            "user_level": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let created: Value = resp.json().await.unwrap();
    assert_eq!(created["tier"], "user");
    assert_eq!(created["key"], "my-api");
    let template_id = created["id"].as_str().unwrap();

    // Update the user-level template — full OpenAPI replacement, rename
    let resp = client
        .put(format!("{base}/v1/templates/{template_id}/manage"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(&json!({ "openapi": minimal_openapi("my-api", "My API v2") }))
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
            "openapi": minimal_openapi("org-api", "Org API"),
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
            "openapi": minimal_openapi("internal-api", "Internal API"),
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
        .json(&json!({"user_template_policy": "full"}))
        .send()
        .await
        .unwrap();

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
            "openapi": minimal_openapi("private-api", "Private API"),
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
        .json(&json!({ "openapi": minimal_openapi("private-api", "Hijacked") }))
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
        .json(&json!({ "openapi": minimal_openapi("private-api", "Admin Override") }))
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

    let global_count = templates.iter().filter(|t| t["tier"] == "global").count();
    assert!(global_count > 0, "expected global templates to be visible");
}

#[tokio::test]
async fn test_global_templates_hidden_when_disabled() {
    let (base, client, org_id, admin_key, write_key, _, _, _) = bootstrap(true).await;

    let resp = client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"global_templates_enabled": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = client
        .get(format!("{base}/v1/templates"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .send()
        .await
        .unwrap();
    let templates: Vec<Value> = resp.json().await.unwrap();
    let global_count = templates.iter().filter(|t| t["tier"] == "global").count();
    assert_eq!(global_count, 0, "expected no globals when disabled");

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

    client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"global_templates_enabled": false}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/v1/templates/enabled-globals"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"template_key": "github"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

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

    let resp = client
        .get(format!("{base}/v1/templates/github"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = client
        .get(format!("{base}/v1/templates/slack"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    let resp = client
        .delete(format!("{base}/v1/templates/enabled-globals/github"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

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
// Curated-catalog enforcement at instantiation — `allow_services_outside_catalog`.
// The allow-list already hides curated-out globals from discovery; these tests
// cover the *hard* restriction: non-admins cannot instantiate a global template
// outside the curated catalog unless the org opts into the soft (discovery-only)
// mode. Admins are always exempt.
// ---------------------------------------------------------------------------

/// GET /v1/orgs/{id}/template-settings returns all three flags and reflects
/// PATCH updates to the new `allow_services_outside_catalog` field.
#[tokio::test]
async fn test_template_settings_get_and_patch_roundtrip() {
    let (base, client, org_id, admin_key, _write_key, _, _, _) = bootstrap(true).await;

    // Defaults: globals on, user templates off, catalog restriction on.
    let settings: Value = client
        .get(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(settings["global_templates_enabled"], true);
    assert_eq!(settings["user_template_policy"], "none");
    assert_eq!(settings["allow_services_outside_catalog"], false);

    let updated: Value = client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"allow_services_outside_catalog": true}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(updated["allow_services_outside_catalog"], true);

    let settings: Value = client
        .get(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(settings["allow_services_outside_catalog"], true);
}

/// Read-only and write callers must not read org template settings.
#[tokio::test]
async fn test_template_settings_get_requires_admin() {
    let (base, client, org_id, _admin_key, write_key, _, _, _) = bootstrap(true).await;

    let resp = client
        .get(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

/// With curation on and `allow_services_outside_catalog=false` (default), a
/// non-admin gets 403 creating a service from a curated-out global, but can
/// create one from a curated-in global. Admins are exempt.
#[tokio::test]
async fn test_curated_out_global_instantiation_blocked_for_non_admin() {
    let (base, client, org_id, admin_key, write_key, _, _, _) = bootstrap(true).await;

    // Restrict the catalog to just `github`.
    client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"global_templates_enabled": false}))
        .send()
        .await
        .unwrap();
    let resp = client
        .post(format!("{base}/v1/templates/enabled-globals"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"template_key": "github"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Non-admin: curated-out global (gmail) is blocked.
    let resp = client
        .post(format!("{base}/v1/services"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(&json!({"template_key": "gmail", "name": "blocked-gmail"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "non-admin should be blocked from curated-out global"
    );

    // Non-admin: curated-in global (github) succeeds.
    let resp = client
        .post(format!("{base}/v1/services"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(&json!({"template_key": "github", "name": "ok-github"}))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "curated-in global should be creatable: {}",
        resp.status()
    );

    // Admin is exempt: can instantiate the curated-out global.
    let resp = client
        .post(format!("{base}/v1/services"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"template_key": "gmail", "name": "admin-gmail"}))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "admin should be exempt from catalog restriction: {}",
        resp.status()
    );
}

/// Flipping `allow_services_outside_catalog=true` downgrades curation to a
/// discovery-only filter: a non-admin can then instantiate a curated-out global.
#[tokio::test]
async fn test_soft_catalog_allows_outside_instantiation() {
    let (base, client, org_id, admin_key, write_key, _, _, _) = bootstrap(true).await;

    client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "global_templates_enabled": false,
            "allow_services_outside_catalog": true
        }))
        .send()
        .await
        .unwrap();

    // gmail is curated out (not in the empty allow-list) but soft mode permits it.
    let resp = client
        .post(format!("{base}/v1/services"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(&json!({"template_key": "gmail", "name": "soft-gmail"}))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "soft catalog should allow curated-out instantiation: {}",
        resp.status()
    );
}

// ---------------------------------------------------------------------------
// Hidden templates (`x-overslash-hidden`) — flagged on dashboard surfaces,
// reachable by key. Agent-facing exclusion is covered in search.rs and
// platform_dispatch.rs.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_hidden_template_flagged_in_lists_and_reachable_by_key() {
    let (base, client, _, admin_key, _, _, _, _) = bootstrap(true).await;

    // Dashboard list: hidden templates are present, flagged.
    let resp = client
        .get(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    let templates: Vec<Value> = resp.json().await.unwrap();
    let legacy = templates
        .iter()
        .find(|t| t["key"] == "github_legacy_oauth")
        .expect("github_legacy_oauth missing from /v1/templates");
    assert_eq!(legacy["hidden"], true);
    let gh = templates
        .iter()
        .find(|t| t["key"] == "github")
        .expect("github missing from /v1/templates");
    assert_eq!(gh["hidden"], false);

    // Dashboard search: same flagging.
    let resp = client
        .get(format!("{base}/v1/templates/search?q=legacy"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    let results: Vec<Value> = resp.json().await.unwrap();
    let legacy = results
        .iter()
        .find(|t| t["key"] == "github_legacy_oauth")
        .expect("github_legacy_oauth missing from /v1/templates/search");
    assert_eq!(legacy["hidden"], true);

    // Reachable by key, detail carries the flag.
    let resp = client
        .get(format!("{base}/v1/templates/github_legacy_oauth"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let detail: Value = resp.json().await.unwrap();
    assert_eq!(detail["hidden"], true);

    // Admin list flags it too.
    let resp = client
        .get(format!("{base}/v1/templates/admin"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let templates: Vec<Value> = resp.json().await.unwrap();
    let legacy = templates
        .iter()
        .find(|t| t["key"] == "github_legacy_oauth")
        .expect("github_legacy_oauth missing from /v1/templates/admin");
    assert_eq!(legacy["hidden"], true);
}

#[tokio::test]
async fn test_hidden_org_template_flagged_in_list() {
    let (base, client, _, admin_key, _, _, _, _) = bootstrap(false).await;

    // The unprefixed `hidden:` alias normalizes to `x-overslash-hidden` on
    // write and the compiled flag round-trips through the list endpoint.
    let openapi =
        minimal_openapi("shadow-api", "Shadow API").replace("info:", "info:\n  hidden: true");
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "openapi": openapi }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    assert_eq!(status, 200, "create failed: {}", resp.text().await.unwrap());

    let resp = client
        .get(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    let templates: Vec<Value> = resp.json().await.unwrap();
    let shadow = templates
        .iter()
        .find(|t| t["key"] == "shadow-api")
        .expect("shadow-api missing from /v1/templates");
    assert_eq!(shadow["tier"], "org");
    assert_eq!(shadow["hidden"], true);
}

// ---------------------------------------------------------------------------
// Admin compliance view
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_admin_compliance_view() {
    let (base, client, org_id, admin_key, write_key, _, _, _) = bootstrap(true).await;

    client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"user_template_policy": "full"}))
        .send()
        .await
        .unwrap();

    client
        .post(format!("{base}/v1/templates"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(&json!({
            "openapi": minimal_openapi("user-api", "User API"),
            "user_level": true,
        }))
        .send()
        .await
        .unwrap();

    client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "openapi": minimal_openapi("org-api", "Org API"),
        }))
        .send()
        .await
        .unwrap();

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

    let resp = client
        .get(format!("{base}/v1/templates/admin"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let templates: Vec<Value> = resp.json().await.unwrap();

    let globals: Vec<&Value> = templates.iter().filter(|t| t["tier"] == "global").collect();
    assert!(globals.len() > 1, "admin should see ALL globals");

    let github = globals.iter().find(|t| t["key"] == "github").unwrap();
    assert_eq!(github["enabled"], true);

    let slack = globals.iter().find(|t| t["key"] == "slack").unwrap();
    assert_eq!(slack["enabled"], false);

    assert!(
        templates
            .iter()
            .any(|t| t["key"] == "org-api" && t["tier"] == "org")
    );

    let user_tpl = templates
        .iter()
        .find(|t| t["key"] == "user-api" && t["tier"] == "user")
        .expect("admin should see user templates");
    assert!(user_tpl["owner_identity_id"].is_string());

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

    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "openapi": minimal_openapi("audit-test-api", "Audit Test"),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let created: Value = resp.json().await.unwrap();
    let template_id = created["id"].as_str().unwrap();

    client
        .put(format!("{base}/v1/templates/{template_id}/manage"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "openapi": minimal_openapi("audit-test-api", "Audit Test v2") }))
        .send()
        .await
        .unwrap();

    client
        .delete(format!("{base}/v1/templates/{template_id}/manage"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
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

    client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"user_template_policy": "full"}))
        .send()
        .await
        .unwrap();

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
        .json(&json!({"user_template_policy": "full"}))
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

    client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"global_templates_enabled": false}))
        .send()
        .await
        .unwrap();

    let resp = client
        .get(format!("{base}/v1/templates/github/actions"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    client
        .post(format!("{base}/v1/templates/enabled-globals"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"template_key": "github"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .get(format!("{base}/v1/templates/github/actions"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = client
        .get(format!("{base}/v1/templates/slack/actions"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ---------------------------------------------------------------------------
// Single-action detail endpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_action_detail_returns_params() {
    let (base, client, _, _, write_key, _, _, _) = bootstrap(true).await;

    let resp = client
        .get(format!(
            "{base}/v1/templates/github/actions/create_pull_request"
        ))
        .header(auth(&write_key).0, auth(&write_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["key"], "create_pull_request");
    assert_eq!(body["method"], "POST");
    assert!(
        body["path"].as_str().unwrap().contains("{repo}"),
        "path should contain the repo placeholder, got {}",
        body["path"]
    );
    assert!(body["description"].as_str().is_some());
    assert!(body["risk"].as_str().is_some());

    let params = body["params"].as_object().expect("params object");
    assert!(!params.is_empty(), "action should expose params");
    let title = params.get("title").expect("title param present");
    assert_eq!(title["type"], "string");
    assert_eq!(title["required"], true);
}

#[tokio::test]
async fn test_action_detail_missing_action_returns_404() {
    let (base, client, _, _, write_key, _, _, _) = bootstrap(true).await;

    let resp = client
        .get(format!(
            "{base}/v1/templates/github/actions/definitely_not_a_real_action"
        ))
        .header(auth(&write_key).0, auth(&write_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_action_detail_hidden_global_returns_404() {
    let (base, client, org_id, admin_key, write_key, _, _, _) = bootstrap(true).await;

    client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"global_templates_enabled": false}))
        .send()
        .await
        .unwrap();

    let resp = client
        .get(format!(
            "{base}/v1/templates/github/actions/create_pull_request"
        ))
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

// ---------------------------------------------------------------------------
// TemplateDetail.scopes — union of every action's required_scopes, surfaced
// on GET /v1/templates/{key} for white-label partners (token-vault import).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_global_template_detail_includes_scopes() {
    let (base, client, _, admin_key, _, _, _, _) = bootstrap(true).await;

    // google_calendar declares a root-level OAuth scope, so the union is
    // non-empty and deterministic.
    let resp = client
        .get(format!("{base}/v1/templates/google_calendar"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();

    let scopes: Vec<&str> = body["scopes"]
        .as_array()
        .expect("scopes field missing on global template detail")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        scopes.contains(&"https://www.googleapis.com/auth/calendar"),
        "expected calendar scope in union, got {scopes:?}"
    );
}

#[tokio::test]
async fn test_org_template_detail_includes_scopes() {
    let (base, client, _, admin_key, _, _, _, _) = bootstrap(false).await;

    // Create an org (DB-tier) template so we exercise db_row_to_detail.
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "openapi": minimal_openapi("scoped-internal", "Scoped Internal"),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let created: Value = resp.json().await.unwrap();
    // The create response is itself a TemplateDetail and carries the field.
    assert!(
        created["scopes"].is_array(),
        "create response missing scopes array: {created}"
    );

    let resp = client
        .get(format!("{base}/v1/templates/scoped-internal"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["scopes"].is_array(),
        "org template detail missing scopes array: {body}"
    );
}

// ---------------------------------------------------------------------------
// Parent→child ceiling allowance for owned templates. Mirrors the service
// allowance (services_admin_view.rs): a user may manage a template owned by an
// identity it is an ancestor of, but the reach is one-directional (no child→
// parent, no sibling). See `caller_may_manage_owned`.
// ---------------------------------------------------------------------------

/// Create an `agent`/`sub_agent` under `parent_id` and mint an API key for it.
async fn create_child(
    base: &str,
    client: &Client,
    admin_key: &str,
    org_id: Uuid,
    kind: &str,
    parent_id: Uuid,
    name: &str,
) -> (Uuid, String) {
    let ident: Value = client
        .post(format!("{base}/v1/identities"))
        .header(auth(admin_key).0, auth(admin_key).1)
        .json(&json!({ "name": name, "kind": kind, "parent_id": parent_id }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id: Uuid = ident["id"]
        .as_str()
        .unwrap_or_else(|| panic!("identity create failed: {ident}"))
        .parse()
        .unwrap();
    let key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header(auth(admin_key).0, auth(admin_key).1)
        .json(&json!({ "org_id": org_id, "identity_id": id, "name": format!("{name}-key") }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    (id, key_resp["key"].as_str().unwrap().to_string())
}

async fn enable_user_templates(base: &str, client: &Client, admin_key: &str, org_id: Uuid) {
    client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(admin_key).0, auth(admin_key).1)
        .json(&json!({ "user_template_policy": "full" }))
        .send()
        .await
        .unwrap();
}

/// The owning user may update AND delete a template owned by one of its agents.
#[tokio::test]
async fn user_manages_agent_owned_template() {
    let (base, client, org_id, admin_key, write_key, _, _, user_ids) = bootstrap(false).await;
    enable_user_templates(&base, &client, &admin_key, org_id).await;

    // Agent under the write-user creates a user-level template (owned by agent).
    let (_agent_id, agent_key) = create_child(
        &base,
        &client,
        &admin_key,
        org_id,
        "agent",
        user_ids[1],
        "tmpl-agent",
    )
    .await;
    let created: Value = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({ "openapi": minimal_openapi("agent-api", "Agent API"), "user_level": true }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let template_id = created["id"].as_str().unwrap();

    // Parent user updates it -> 200 (ceiling allowance).
    let resp = client
        .put(format!("{base}/v1/templates/{template_id}/manage"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(&json!({ "openapi": minimal_openapi("agent-api", "Parent Edit") }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "a user may update a template owned by its agent"
    );

    // Parent user deletes it -> 200.
    let resp = client
        .delete(format!("{base}/v1/templates/{template_id}/manage"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "a user may delete a template owned by its agent"
    );
}

/// One-directional: an agent may NOT manage its owner-user's template, and a
/// sibling agent may NOT manage another agent's template.
#[tokio::test]
async fn template_allowance_is_one_directional() {
    let (base, client, org_id, admin_key, write_key, _, _, user_ids) = bootstrap(false).await;
    enable_user_templates(&base, &client, &admin_key, org_id).await;

    // Parent user owns a template.
    let parent_tmpl: Value = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(
            &json!({ "openapi": minimal_openapi("parent-api", "Parent API"), "user_level": true }),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let parent_tmpl_id = parent_tmpl["id"].as_str().unwrap();

    // Agent under the parent user: child→parent must be denied.
    let (agent_id, agent_key) = create_child(
        &base,
        &client,
        &admin_key,
        org_id,
        "agent",
        user_ids[1],
        "up-agent",
    )
    .await;
    let resp = client
        .delete(format!("{base}/v1/templates/{parent_tmpl_id}/manage"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "an agent must not delete its owner-user's template"
    );

    // Sibling agent owns a template; the first agent must not reach laterally.
    let (_sib_id, sib_key) = create_child(
        &base,
        &client,
        &admin_key,
        org_id,
        "agent",
        user_ids[1],
        "sib-agent",
    )
    .await;
    let sib_tmpl: Value = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&sib_key).0, auth(&sib_key).1)
        .json(&json!({ "openapi": minimal_openapi("sib-api", "Sibling API"), "user_level": true }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sib_tmpl_id = sib_tmpl["id"].as_str().unwrap();
    let _ = agent_id;
    let resp = client
        .delete(format!("{base}/v1/templates/{sib_tmpl_id}/manage"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "a sibling agent must not delete another agent's template"
    );
}

// ── Deployment template variables (D44) ────────────────────────────────────

/// The variable reference panel's data source. Values are returned in the
/// clear to any authenticated caller — deliberately, since a template author
/// can recover them anyway (see the next test), which is precisely why nothing
/// secret may be configured under `OVERSLASH_TEMPLATE_VAR_`.
#[tokio::test]
async fn template_vars_endpoint_lists_the_deployments_variables() {
    let (pool, _fixtures) = common::test_pool_bootstrapped().await;
    let (base, client) = common::start_api_with_registry_vars(
        pool,
        None,
        overslash_core::template_vars::Vars::from_pairs([
            ("MAILBOX_HOST", "mailbox.dev.overslash.com"),
            ("METABASE_URL", "https://mb.example.com"),
        ]),
        |_| {},
    )
    .await;
    let (_org_id, _ident_id, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let vars: Value = client
        .get(format!("{base}/v1/templates/vars"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        vars,
        json!([
            { "name": "MAILBOX_HOST", "value": "mailbox.dev.overslash.com" },
            { "name": "METABASE_URL", "value": "https://mb.example.com" },
        ]),
        "sorted by name, prefix stripped"
    );

    // The endpoint is deployment-scoped, not a window onto the environment:
    // an unprefixed variable is not reachable through it.
    assert!(
        !vars.to_string().contains("DATABASE_URL"),
        "only OVERSLASH_TEMPLATE_VAR_* is exposed"
    );
}

/// An org-authored template resolves `${VAR}` the same way a shipped one does,
/// and the DB row keeps the reference unexpanded — so the same row follows
/// whichever deployment reads it instead of freezing the authoring one's host.
#[tokio::test]
async fn org_template_expands_vars_but_persists_the_reference() {
    let (pool, _fixtures) = common::test_pool_bootstrapped().await;
    let (base, client) = common::start_api_with_registry_vars(
        pool,
        None,
        overslash_core::template_vars::Vars::from_pairs([("TENANT_HOST", "api.tenant.example")]),
        |_| {},
    )
    .await;
    let (_org_id, _ident_id, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let yaml = format!(
        "openapi: 3.1.0
info:
  title: Varred
  key: varred
servers:
  - url: https://${{{var}}}
paths:
  /items:
    get:
      operationId: list_items
      summary: List items
      risk: read
",
        var = "TENANT_HOST"
    );

    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "openapi": yaml }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "org template with a var should register: {:?}",
        resp.text().await
    );

    let detail: Value = client
        .get(format!("{base}/v1/templates/varred"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        detail["hosts"],
        json!(["api.tenant.example"]),
        "the resolved template reports the expanded host"
    );
    assert!(
        detail["openapi"]
            .as_str()
            .expect("stored source returned")
            .contains("${TENANT_HOST}"),
        "the stored document must keep the reference, not the expansion: {}",
        detail["openapi"]
    );
}

/// A reference this deployment cannot resolve is a validation error, not a
/// silently empty host — the failure mode D44 exists to remove is a template
/// that quietly names the wrong place.
#[tokio::test]
async fn template_with_an_unset_var_is_rejected_at_validate() {
    let (pool, _fixtures) = common::test_pool_bootstrapped().await;
    let (base, client) = common::start_api_with_registry_vars(
        pool,
        None,
        overslash_core::template_vars::Vars::empty(),
        |_| {},
    )
    .await;
    let (_org_id, _ident_id, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let yaml = format!(
        "openapi: 3.1.0
info:
  title: Varred
  key: varred
servers:
  - url: https://${{{var}}}
paths:
  /items:
    get:
      operationId: list_items
      summary: List items
      risk: read
",
        var = "NOT_SET_ANYWHERE"
    );

    let report: Value = client
        .post(format!("{base}/v1/templates/validate"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .body(yaml)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(report["valid"], json!(false));
    let errors = report["errors"].as_array().expect("errors array");
    assert!(
        errors.iter().any(|e| e["code"] == "template_var_unset"),
        "expected template_var_unset, got {errors:?}"
    );
    // The message must name the env var an operator has to set, not just the
    // reference — the reader is usually deploying, not authoring.
    assert!(
        errors.iter().any(|e| e["message"]
            .as_str()
            .is_some_and(|m| m.contains("OVERSLASH_TEMPLATE_VAR_NOT_SET_ANYWHERE"))),
        "message should name the env var: {errors:?}"
    );
}
