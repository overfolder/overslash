//! Integration tests for the template validation endpoint and the CRUD hook
//! that rejects broken templates at create/update time.

mod common;

use reqwest::Client;
use serde_json::{Value, json};
use uuid::Uuid;

fn auth(key: &str) -> (&'static str, String) {
    ("Authorization", format!("Bearer {key}"))
}

/// Spin up an API instance backed by the real services/ registry, bootstrap
/// an org + admin API key, and return the pieces tests need.
async fn bootstrap(pool: sqlx::PgPool) -> (String, Client, String) {
    let (base, client) = common::start_api_with_registry(pool, None).await;

    // Create org
    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "ValTest Org", "slug": format!("val-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();

    // Bootstrap key (first call on a fresh org creates an admin identity).
    let key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admin_key = key_resp["key"].as_str().unwrap().to_string();

    (base, client, admin_key)
}

const VALID_YAML: &str = r#"
key: test-svc
display_name: Test Service
hosts: [api.example.com]
auth:
  - type: api_key
    default_secret_name: svc_token
    injection:
      as: header
      header_name: Authorization
      prefix: "Bearer "
actions:
  list_items:
    method: GET
    path: /items
    description: List items
"#;

// ---------------------------------------------------------------------------
// POST /v1/templates/validate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn validate_accepts_valid_yaml() {
    let pool = common::test_pool().await;
    let (base, client, admin_key) = bootstrap(pool).await;

    let resp = client
        .post(format!("{base}/v1/templates/validate"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .header("content-type", "application/yaml")
        .body(VALID_YAML)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["valid"], true, "body: {body}");
    assert!(body["errors"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn validate_reports_yaml_parse_error_as_issue_not_400() {
    let pool = common::test_pool().await;
    let (base, client, admin_key) = bootstrap(pool).await;

    let resp = client
        .post(format!("{base}/v1/templates/validate"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .body("key: svc\n  bad_indent: :::")
        .send()
        .await
        .unwrap();
    // Parse failures are validation issues, not transport errors.
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["valid"], false);
    let errors = body["errors"].as_array().unwrap();
    assert!(errors.iter().any(|e| e["code"] == "yaml_parse"));
}

#[tokio::test]
async fn validate_reports_semantic_error() {
    let pool = common::test_pool().await;
    let (base, client, admin_key) = bootstrap(pool).await;

    // scope_param references a non-existent param.
    let broken = r#"
key: test-svc
display_name: Test
hosts: [api.example.com]
actions:
  get_item:
    method: GET
    path: /items/{id}
    description: "Get {id}"
    scope_param: missing
    params:
      id:
        type: string
        required: true
"#;

    let resp = client
        .post(format!("{base}/v1/templates/validate"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .body(broken)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["valid"], false);
    let errors = body["errors"].as_array().unwrap();
    assert!(
        errors.iter().any(|e| e["code"] == "unknown_scope_param"),
        "expected unknown_scope_param; body: {body}"
    );
}

#[tokio::test]
async fn validate_rejects_oversized_body() {
    let pool = common::test_pool().await;
    let (base, client, admin_key) = bootstrap(pool).await;

    // 600 KB — well above the 512 KB cap.
    let huge = "x".repeat(600 * 1024);

    let resp = client
        .post(format!("{base}/v1/templates/validate"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .body(huge)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn validate_requires_auth() {
    let pool = common::test_pool().await;
    let (base, client, _admin_key) = bootstrap(pool).await;

    let resp = client
        .post(format!("{base}/v1/templates/validate"))
        .body(VALID_YAML)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ---------------------------------------------------------------------------
// CRUD hook: create_template / update_template reject broken templates
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_template_rejects_broken_template() {
    let pool = common::test_pool().await;
    let (base, client, admin_key) = bootstrap(pool).await;

    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "key": "bad-api",
            "display_name": "Bad API",
            "hosts": ["api.example.com"],
            "actions": {
                "bad_action": {
                    // path references a param that doesn't exist
                    "method": "GET",
                    "path": "/items/{ghost}",
                    "description": "Get item",
                }
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "validation_failed");
    let errors = body["report"]["errors"].as_array().unwrap();
    assert!(errors.iter().any(|e| e["code"] == "unknown_path_param"));
}

#[tokio::test]
async fn create_template_accepts_valid_minimal_template() {
    // Regression: existing CRUD path must still work for a valid template.
    let pool = common::test_pool().await;
    let (base, client, admin_key) = bootstrap(pool).await;

    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "key": "good-api",
            "display_name": "Good API",
            "hosts": ["api.example.com"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["key"], "good-api");
}

#[tokio::test]
async fn update_template_rejects_broken_patch() {
    let pool = common::test_pool().await;
    let (base, client, admin_key) = bootstrap(pool).await;

    // Create a valid template first.
    let create: Value = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "key": "edit-api",
            "display_name": "Edit API",
            "hosts": ["api.example.com"],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = create["id"].as_str().unwrap();

    // Now try to patch actions with a broken action.
    let resp = client
        .put(format!("{base}/v1/templates/{id}/manage"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "actions": {
                "borked": {
                    "method": "SNOOZE",
                    "path": "/x",
                    "description": "nope",
                }
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "validation_failed");
    let errors = body["report"]["errors"].as_array().unwrap();
    assert!(errors.iter().any(|e| e["code"] == "invalid_http_method"));
}

#[tokio::test]
async fn update_template_allows_metadata_only_patch_on_valid_template() {
    // Regression: PUT {display_name} on a valid template still works and
    // re-validates the untouched fields against the current rule set.
    let pool = common::test_pool().await;
    let (base, client, admin_key) = bootstrap(pool).await;

    let create: Value = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "key": "meta-api",
            "display_name": "Meta API",
            "hosts": ["api.example.com"],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = create["id"].as_str().unwrap();

    let resp = client
        .put(format!("{base}/v1/templates/{id}/manage"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"display_name": "Meta API v2"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["display_name"], "Meta API v2");
}
