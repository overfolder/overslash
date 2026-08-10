//! Integration tests for the template/service instance split.

use crate::common;

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
async fn test_list_templates_only_http_pseudo_service() {
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

    // Test registries use `with_builtins()` which only carries the synthetic
    // `http` pseudo-service (the Mode-A anchor — see DECISIONS.md D15). No
    // shipped YAML templates are loaded in tests, so the listing should
    // contain exactly that one entry.
    let keys: Vec<&str> = resp
        .iter()
        .filter_map(|v| v.get("key").and_then(|k| k.as_str()))
        .collect();
    assert_eq!(
        keys,
        vec!["http"],
        "test registry should expose only `http`"
    );
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
            "openapi": common::render_openapi(
                include_str!("fixtures/openapi/minimal.yaml.tmpl"),
                &[("key", "my-internal-api"), ("display_name", "My Internal API")],
            ),
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
    let (base, client, org_id, _ident_id, _api_key, admin_key) = setup(pool).await;

    // Enable user-level templates (gated by org setting)
    client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"user_template_policy": "full"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "openapi": common::minimal_openapi("my-personal-api"),
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
            "openapi": common::minimal_openapi("searchable-api"),
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
            "openapi": common::minimal_openapi("deletable-api"),
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
            "openapi": common::minimal_openapi("test-svc"),
            "user_level": false,
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
            "openapi": common::minimal_openapi("list-svc"),
            "user_level": false,
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
            "openapi": common::minimal_openapi("lifecycle-svc"),
            "user_level": false,
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
            "openapi": common::minimal_openapi("auto-name-svc"),
            "user_level": false,
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
async fn test_secret_name_rejected_on_oauth_template() {
    let pool = common::test_pool().await;
    let (base, client, _org_id, _ident_id, api_key, admin_key) = setup(pool).await;

    // Two org-level templates: one OAuth-only, one secret-only. The gate
    // should reject `secret_name` for the OAuth one and accept it for the
    // other.
    client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "openapi": common::render_openapi(
                include_str!("fixtures/openapi/oauth_google.yaml.tmpl"),
                &[("key", "oauth-svc"), ("display_name", "OAuth Svc")],
            ),
            "user_level": false,
        }))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "openapi": "openapi: 3.1.0\n\
                info:\n  title: Apikey Svc\n  key: apikey-svc\n\
                servers:\n  - url: https://apikey-svc.example.com\n\
                components:\n  securitySchemes:\n    token:\n      type: http\n      scheme: bearer\n      x-overslash-default_secret_name: apikey_svc_token\n\
                security:\n  - token: []\n\
                paths:\n  /items:\n    get:\n      operationId: list_items\n      summary: List items\n      risk: read\n",
            "user_level": false,
        }))
        .send()
        .await
        .unwrap();

    // Reject: `secret_name` on a create against an OAuth-only template.
    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "template_key": "oauth-svc",
            "name": "oauth-reject",
            "secret_name": "leftover-secret",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("does not use secret or MCP bearer auth"),
        "expected secret-auth error, got: {body}"
    );

    // Update path: clean OAuth instance, then try to set `secret_name` via PUT.
    let created: Value = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "template_key": "oauth-svc",
            "name": "oauth-clean",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap();

    let update = client
        .put(format!("{base}/v1/services/{id}/manage"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "secret_name": "foo" }))
        .send()
        .await
        .unwrap();
    assert_eq!(update.status(), 400);

    // Clearing `secret_name` (null) is always allowed, even on OAuth — callers
    // need a way to scrub stale values left over from before the gate landed.
    let clear = client
        .put(format!("{base}/v1/services/{id}/manage"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "secret_name": null }))
        .send()
        .await
        .unwrap();
    assert_eq!(clear.status(), 200);

    // Regression guard: the gate must NOT over-reject — secret-based templates
    // continue to accept `secret_name`.
    let ok = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "template_key": "apikey-svc",
            "name": "apikey-accepted",
            "secret_name": "apikey_svc_token",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
}

#[tokio::test]
async fn test_duplicate_instance_name_conflict() {
    let pool = common::test_pool().await;
    let (base, client, _org_id, _ident_id, api_key, admin_key) = setup(pool).await;

    client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "openapi": common::minimal_openapi("dup-svc"),
            "user_level": false,
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
            "openapi": include_str!("fixtures/openapi/actions_svc.yaml"),
            "user_level": false,
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
            "openapi": include_str!("fixtures/openapi/tmpl_actions.yaml"),
            "user_level": false,
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

/// The dashboard links each service-list row to `/services/<uuid>`. That URL
/// segment is forwarded verbatim into `GET /v1/services/{name}`, which must
/// resolve a UUID-shaped path identically to a name-shaped path. Two rows
/// with the same display name (e.g. user-level shadowing org-level) are the
/// motivating case — the name path silently picks one, while the id path
/// must address each instance unambiguously.
#[tokio::test]
async fn test_service_lookup_by_uuid_path() {
    let pool = common::test_pool().await;
    let (base, client, _org_id, _ident_id, api_key, admin_key) = setup(pool).await;

    client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "openapi": common::minimal_openapi("uuid-lookup-svc"),
            "user_level": false,
        }))
        .send()
        .await
        .unwrap();

    let create: Value = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({ "template_key": "uuid-lookup-svc", "status": "active" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = create["id"].as_str().unwrap();
    let name = create["name"].as_str().unwrap();

    let by_id: Value = client
        .get(format!("{base}/v1/services/{id}"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let by_name: Value = client
        .get(format!("{base}/v1/services/{name}"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(by_id["id"], by_name["id"]);
    assert_eq!(by_id["id"].as_str().unwrap(), id);

    // Sublist also accepts a UUID path (used when the dashboard refreshes
    // actions after navigating from the list).
    let actions_resp = client
        .get(format!("{base}/v1/services/{id}/actions"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(actions_resp.status(), 200);

    // Delete by UUID and confirm the row is gone.
    let del = client
        .delete(format!("{base}/v1/services/{id}"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(del.status(), 200);
    let after = client
        .get(format!("{base}/v1/services/{id}"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(after.status(), 404);
}

// -- Org-level create: group requirement --

/// Create an org-level template so the tests below have something to
/// instantiate. Returns nothing — the template key is the caller's to reuse.
async fn seed_org_template(base: &str, client: &Client, admin_key: &str, key: &str) {
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "openapi": common::minimal_openapi(key),
            "user_level": false,
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "template create failed: {}",
        resp.text().await.unwrap_or_default()
    );
}

#[tokio::test]
async fn org_level_create_requires_at_least_one_group() {
    let pool = common::test_pool().await;
    let (base, client, _org_id, _ident_id, _api_key, admin_key) = setup(pool).await;
    seed_org_template(&base, &client, &admin_key, "orphan-svc").await;

    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "template_key": "orphan-svc",
            "name": "orphan-svc",
            "user_level": false,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("at least one group"),
        "unexpected error body: {body:?}"
    );

    // Nothing was inserted: the same name is still free. A 409 here would mean
    // the rejected request left a row behind.
    let retry = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "template_key": "orphan-svc",
            "name": "orphan-svc",
            "user_level": false,
            "groups": common::everyone_grant(&base, &client, &admin_key).await,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(retry.status(), 200, "no row should have been created");
}

#[tokio::test]
async fn org_level_create_rejects_group_the_creator_is_not_in() {
    let pool = common::test_pool().await;
    let (base, client, _org_id, _ident_id, _api_key, admin_key) = setup(pool).await;
    seed_org_template(&base, &client, &admin_key, "outsider-svc").await;

    // A fresh group with no members — the creator is definitionally not in it.
    let group: Value = client
        .post(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "name": "Nobody", "description": "empty" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "template_key": "outsider-svc",
            "name": "outsider-svc",
            "user_level": false,
            "groups": [{ "group_id": group["id"], "access_level": "read" }],
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("member of at least one"),
        "unexpected error body: {body:?}"
    );
}

#[tokio::test]
async fn org_level_create_attaches_the_requested_grants() {
    let pool = common::test_pool().await;
    let (base, client, _org_id, _ident_id, _api_key, admin_key) = setup(pool).await;
    seed_org_template(&base, &client, &admin_key, "shared-svc").await;

    let everyone_id = common::everyone_group_id(&base, &client, &admin_key).await;
    let created: Value = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "template_key": "shared-svc",
            "name": "shared-svc",
            "user_level": false,
            "groups": [{
                "group_id": everyone_id.to_string(),
                "access_level": "read",
                "auto_approve_reads": true,
            }],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let svc_id = created["id"].as_str().expect("created service id");

    let groups: Vec<Value> = client
        .get(format!("{base}/v1/services/{svc_id}/groups"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let grant = groups
        .iter()
        .find(|g| g["group_id"].as_str() == Some(&everyone_id.to_string()))
        .expect("Everyone grant should exist");
    assert_eq!(grant["access_level"], "read");
    // The deprecated boolean still lands on exactly the `read` rung — it must
    // not silently promote to the grant's ceiling.
    assert_eq!(grant["auto_approve_level"], "read");
    assert_eq!(grant["auto_approve_reads"], true);
}

#[tokio::test]
async fn org_level_create_rejects_invalid_grant_shapes() {
    let pool = common::test_pool().await;
    let (base, client, _org_id, _ident_id, _api_key, admin_key) = setup(pool).await;
    seed_org_template(&base, &client, &admin_key, "picky-svc").await;
    let everyone_id = common::everyone_group_id(&base, &client, &admin_key).await;

    // Bad access level.
    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "template_key": "picky-svc",
            "name": "picky-svc",
            "user_level": false,
            "groups": [{ "group_id": everyone_id.to_string(), "access_level": "owner" }],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Same group twice — would trip the grants unique index after the insert.
    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "template_key": "picky-svc",
            "name": "picky-svc",
            "user_level": false,
            "groups": [
                { "group_id": everyone_id.to_string(), "access_level": "read" },
                { "group_id": everyone_id.to_string(), "access_level": "admin" },
            ],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("duplicate group"),
        "unexpected error body: {body:?}"
    );

    // Unknown group.
    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "template_key": "picky-svc",
            "name": "picky-svc",
            "user_level": false,
            "groups": [{ "group_id": Uuid::new_v4().to_string(), "access_level": "read" }],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // Auto-approval above the grant's own ceiling (D53). This path writes
    // `group_grants` without going through `POST /v1/groups/{id}/grants`, so
    // it has to enforce the same bound or it becomes a side door around it.
    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "template_key": "picky-svc",
            "name": "picky-svc",
            "user_level": false,
            "groups": [{
                "group_id": everyone_id.to_string(),
                "access_level": "read",
                "auto_approve_level": "admin",
            }],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("exceeds access_level"),
        "unexpected error body: {body:?}"
    );

    // An unknown rung is a 400 too, not a silent "none".
    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "template_key": "picky-svc",
            "name": "picky-svc",
            "user_level": false,
            "groups": [{
                "group_id": everyone_id.to_string(),
                "access_level": "admin",
                "auto_approve_level": "root",
            }],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn org_level_create_rejects_a_myself_group() {
    let pool = common::test_pool().await;
    let (base, client, _org_id, _ident_id, _api_key, admin_key) = setup(pool).await;
    seed_org_template(&base, &client, &admin_key, "selfish-svc").await;

    // A user-level create materializes the caller's Myself group on demand.
    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "template_key": "selfish-svc", "name": "mine" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let groups: Vec<Value> = client
        .get(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let self_group = groups
        .iter()
        .find(|g| g["system_kind"].as_str() == Some("self"))
        .expect("caller's Myself group should be listed");

    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "template_key": "selfish-svc",
            "name": "selfish-svc",
            "user_level": false,
            "groups": [{ "group_id": self_group["id"], "access_level": "admin" }],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("Myself groups"),
        "unexpected error body: {body:?}"
    );
}

#[tokio::test]
async fn user_level_create_still_needs_no_group() {
    let pool = common::test_pool().await;
    let (base, client, _org_id, _ident_id, api_key, admin_key) = setup(pool).await;
    seed_org_template(&base, &client, &admin_key, "personal-svc").await;

    let created: Value = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({ "template_key": "personal-svc", "name": "personal-svc" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let svc_id = created["id"].as_str().expect("created service id");

    // The Myself auto-grant is still the only grant it needs.
    let groups: Vec<Value> = client
        .get(format!("{base}/v1/services/{svc_id}/groups"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        groups
            .iter()
            .any(|g| g["system_kind"].as_str() == Some("self")),
        "user-level instance should carry its Myself grant: {groups:?}"
    );
}

#[tokio::test]
async fn non_admin_cannot_grant_groups_at_creation() {
    let pool = common::test_pool().await;
    let (base, client, org_id, _ident_id, _api_key, admin_key) = setup(pool).await;
    seed_org_template(&base, &client, &admin_key, "sneaky-svc").await;
    let everyone_id = common::everyone_group_id(&base, &client, &admin_key).await;

    // A plain user — `setup`'s own user sits in Admins, so its agent inherits
    // admin through the ceiling and wouldn't exercise the gate.
    let plain: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "name": "plain-user", "kind": "user" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "org_id": org_id,
            "identity_id": plain["id"],
            "name": "plain-key",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let plain_key = key_resp["key"].as_str().expect("plain user key");

    // Attaching a group is the sharing half of service management and stays
    // admin-only — otherwise the create path would be a side door around
    // `POST /v1/groups/{id}/grants`.
    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {plain_key}"))
        .json(&json!({
            "template_key": "sneaky-svc",
            "name": "sneaky-svc",
            "groups": [{ "group_id": everyone_id.to_string(), "access_level": "admin" }],
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn org_level_create_rolls_back_when_a_group_disappears() {
    let pool = common::test_pool().await;
    let (base, client, _org_id, _ident_id, _api_key, admin_key) = setup(pool.clone()).await;
    seed_org_template(&base, &client, &admin_key, "racy-svc").await;
    let everyone_id = common::everyone_group_id(&base, &client, &admin_key).await;

    // A second group the admin belongs to, deleted straight out from under the
    // create. Validation passed on it; the grant insert can't find it. There is
    // no transaction spanning the instance row and its grants, so the kernel
    // compensates by dropping the instance — the alternative is the orphaned,
    // unreachable org-level service this whole rule exists to prevent.
    let doomed: Value = client
        .post(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "name": "Doomed", "description": "" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let doomed_id: Uuid = doomed["id"].as_str().unwrap().parse().unwrap();

    sqlx::query!("DELETE FROM groups WHERE id = $1", doomed_id)
        .execute(&pool)
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "template_key": "racy-svc",
            "name": "racy-svc",
            "user_level": false,
            "groups": [
                { "group_id": everyone_id.to_string(), "access_level": "admin" },
                { "group_id": doomed_id.to_string(), "access_level": "read" },
            ],
        }))
        .send()
        .await
        .unwrap();
    // 404 from the pre-insert lookup, or 409 if the delete lands between
    // validation and the grant write. Either way nothing is left behind.
    assert!(
        resp.status() == 404 || resp.status() == 409,
        "unexpected status: {}",
        resp.status()
    );

    let left_behind =
        sqlx::query_scalar!("SELECT count(*) FROM service_instances WHERE name = 'racy-svc'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        left_behind,
        Some(0),
        "the rejected create left a row behind"
    );
}
