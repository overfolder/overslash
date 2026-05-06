//! Integration tests for the action-call path's typed auth-recovery
//! envelopes.
//!
//! Drives a `POST /v1/actions/call` against a known-broken auth state
//! and asserts the response shape:
//!
//! - `needs_authentication` — emitted when an action-shape call targets
//!   a service whose template declares OAuth and the caller has no
//!   connection for that provider. 401 with `{ error, service,
//!   service_instance_id, auth_url }`.
//!
//! `auth_url` must point at the gated
//! `{public_url}/connect-authorize?id=<flow>` shape.
//!
//! The `reauth_required` envelope (refresh-failed / no-refresh-token)
//! is exercised at unit-test level in `routes::actions::tests`
//! (`classify_oauth_*`) and by the live Mode-C path: any expired
//! instance-bound OAuth connection trips the same `oauth_error_to_app_error`
//! call site. Earlier Mode-B integration tests of this envelope were
//! removed alongside Mode B itself (see DECISIONS.md D14).
// Test setup writes oauth_provider rows directly (dynamic provider key) and
// uses sqlx::query directly for pool fixtures — both trip the workspace's
// disallowed-methods lint.
#![allow(clippy::disallowed_methods)]

mod common;

use axum::http::StatusCode;
use serde_json::{Value, json};

/// When the agent calls a service whose template declares
/// OAuth and the calling identity has no connection for that provider,
/// the action handler returns 401 `needs_authentication` with a
/// fresh-create gated `auth_url` and the resolved `service_instance_id`.
#[tokio::test]
async fn mode_c_no_connection_returns_needs_authentication() {
    let pool = common::test_pool().await;

    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", "x_test_client");
        std::env::set_var("OAUTH_X_CLIENT_SECRET", "x_test_secret");
    }

    // Use `start_api_with_registry` so the bundled `x` template is loaded
    // — the default `start_api` boots with an empty `ServiceRegistry` and
    // would 404 the create call below.
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (_org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Create an org-level service instance for the bundled `x` template.
    // No connection is bound — we want the recovery arm to fire.
    let create_resp = client
        .post(format!("{base}/v1/services"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({
            "template_key": "x",
            "name": "x",
            "user_level": false,
            "status": "active",
        }))
        .send()
        .await
        .unwrap();
    assert!(
        create_resp.status().is_success(),
        "service create failed: {} {:?}",
        create_resp.status(),
        create_resp.text().await
    );
    let svc: Value = create_resp.json().await.unwrap();
    let svc_id = svc["id"].as_str().unwrap().to_string();

    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "x:*:*"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&api_key).0, common::auth(&api_key).1)
        .json(&json!({
            "service": "x",
            "action": "get_me",
            "params": {},
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "expected 401 needs_authentication, got: {:?}",
        resp.text().await
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "needs_authentication");
    assert_eq!(body["service"], "x");
    let auth_url = body["auth_url"].as_str().unwrap();
    assert!(
        auth_url.contains("/connect-authorize?id="),
        "auth_url should be a gated link: {auth_url}"
    );
    // service_instance_id should round-trip when one was found.
    assert_eq!(body["service_instance_id"].as_str().unwrap(), svc_id);
}
