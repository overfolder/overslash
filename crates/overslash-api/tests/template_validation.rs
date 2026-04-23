//! Integration tests for the template validation endpoint and the CRUD hook
//! that rejects broken templates at create/update time.
//!
//! All requests use OpenAPI 3.1 YAML payloads with `x-overslash-*` vendor
//! extensions (plus aliases — see `overslash_core::openapi`).

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

const VALID_YAML: &str = include_str!("fixtures/openapi/test_service.yaml");

fn yaml_with_key(key: &str) -> String {
    let display_name = format!("Template for {key}");
    common::render_openapi(
        include_str!("fixtures/openapi/minimal.yaml.tmpl"),
        &[("key", key), ("display_name", &display_name)],
    )
}

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
        .body("openapi: 3.1.0\n  bad_indent: :::")
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

    let resp = client
        .post(format!("{base}/v1/templates/validate"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .body(include_str!("fixtures/openapi/unknown_scope_param.yaml"))
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

#[tokio::test]
async fn validate_reports_ambiguous_alias() {
    let pool = common::test_pool().await;
    let (base, client, admin_key) = bootstrap(pool).await;

    let resp = client
        .post(format!("{base}/v1/templates/validate"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .body(include_str!("fixtures/openapi/ambiguous_alias.yaml"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["valid"], false);
    assert!(
        body["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["code"] == "ambiguous_alias")
    );
}

// ---------------------------------------------------------------------------
// CRUD hook: create_template / update_template reject broken templates
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_template_rejects_broken_template() {
    let pool = common::test_pool().await;
    let (base, client, admin_key) = bootstrap(pool).await;

    // path references a param that doesn't exist
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "openapi": include_str!("fixtures/openapi/unknown_path_param.yaml"),
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
    let pool = common::test_pool().await;
    let (base, client, admin_key) = bootstrap(pool).await;

    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "openapi": yaml_with_key("good-api") }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["key"], "good-api");
}

#[tokio::test]
async fn update_template_rejects_broken_doc() {
    let pool = common::test_pool().await;
    let (base, client, admin_key) = bootstrap(pool).await;

    // Create a valid template first.
    let create: Value = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "openapi": yaml_with_key("edit-api") }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = create["id"].as_str().unwrap();

    // Now try to replace the doc with a broken one.
    let resp = client
        .put(format!("{base}/v1/templates/{id}/manage"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "openapi": include_str!("fixtures/openapi/invalid_risk.yaml"),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "validation_failed");
    let errors = body["report"]["errors"].as_array().unwrap();
    assert!(
        errors.iter().any(|e| e["code"] == "invalid_risk"),
        "body: {body}"
    );
}

#[tokio::test]
async fn update_template_allows_valid_full_replacement() {
    let pool = common::test_pool().await;
    let (base, client, admin_key) = bootstrap(pool).await;

    let create: Value = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "openapi": yaml_with_key("meta-api") }))
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
        .json(&json!({
            "openapi": include_str!("fixtures/openapi/meta_api_v2.yaml"),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["display_name"], "Meta API v2");
}

#[tokio::test]
async fn update_template_rejects_key_change() {
    let pool = common::test_pool().await;
    let (base, client, admin_key) = bootstrap(pool).await;

    let create: Value = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "openapi": yaml_with_key("orig-api") }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = create["id"].as_str().unwrap();

    // Attempt to renaming the key via update — should be rejected.
    let resp = client
        .put(format!("{base}/v1/templates/{id}/manage"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "openapi": yaml_with_key("renamed-api") }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}
