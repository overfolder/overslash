//! Integration tests for the `request_secret` platform kernel.
//!
//! `start_api_with_registry` loads `services/overslash.yaml`, so the
//! `request_secret` action is dispatched through the platform_target arm
//! in `routes/actions.rs`. These tests cover the kernel branches that the
//! happy-path puppet scenario doesn't reach with cargo coverage:
//! empty-name 400, unknown-identity 404, share-denial 403, org-key 400,
//! and the self-target 200.

#![allow(clippy::disallowed_methods)]

mod common;

use serde_json::{Value, json};
use uuid::Uuid;

async fn call(
    client: &reqwest::Client,
    base: &str,
    api_key: &str,
    body: Value,
) -> reqwest::Response {
    client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&body)
        .send()
        .await
        .unwrap()
}

async fn grant(
    client: &reqwest::Client,
    base: &str,
    admin_key: &str,
    identity_id: Uuid,
    pattern: &str,
) {
    let resp = client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "identity_id": identity_id,
            "action_pattern": pattern,
            "effect": "allow",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "grant failed");
}

/// Self-target happy path: agent with `request_secrets_own:*` mints a
/// provide URL for its own identity. Asserts the kernel returns 200 with
/// `request_id`, `provide_url`, and an `expires_at` in the future.
#[tokio::test]
async fn self_target_returns_provide_url() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool, None).await;
    let (_org, agent_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    grant(
        &client,
        &base,
        &admin_key,
        agent_id,
        "overslash:request_secrets_own:*",
    )
    .await;

    let resp = call(
        &client,
        &base,
        &agent_key,
        json!({
            "service": "overslash",
            "action": "request_secret",
            "params": { "secret_name": "openai_api_key" }
        }),
    )
    .await;

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");

    let inner: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let request_id = inner["request_id"].as_str().expect("request_id");
    assert!(request_id.starts_with("req_"));
    let provide_url = inner["provide_url"].as_str().expect("provide_url");
    assert!(provide_url.contains(request_id));
    assert!(provide_url.contains("token="));
    assert!(inner["expires_at"].is_string());
}

/// Empty `secret_name` is rejected at the kernel before any DB writes.
#[tokio::test]
async fn empty_secret_name_rejected() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool, None).await;
    let (_org, agent_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    grant(
        &client,
        &base,
        &admin_key,
        agent_id,
        "overslash:request_secrets_own:*",
    )
    .await;

    let resp = call(
        &client,
        &base,
        &agent_key,
        json!({
            "service": "overslash",
            "action": "request_secret",
            "params": { "secret_name": "  " }
        }),
    )
    .await;

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("secret_name"),
        "expected error to mention secret_name, got {body}"
    );
}

/// `identity_id` pointing at an unknown UUID returns a clean 404 instead of
/// hitting the DB FK with a confusing 500.
#[tokio::test]
async fn unknown_identity_returns_404() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool, None).await;
    let (_org, agent_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    grant(
        &client,
        &base,
        &admin_key,
        agent_id,
        "overslash:request_secrets_own:*",
    )
    .await;

    let phantom = Uuid::new_v4();
    let resp = call(
        &client,
        &base,
        &agent_key,
        json!({
            "service": "overslash",
            "action": "request_secret",
            "params": { "secret_name": "k", "identity_id": phantom }
        }),
    )
    .await;

    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

/// Non-admin agent targeting a sibling identity (not self, not a descendant)
/// gets the share-denial 403. The agent only holds `request_secrets_own:*`,
/// not `request_secrets_share`, and its OrgAcl access level lands at write.
#[tokio::test]
async fn share_target_denied_for_non_admin_agent() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool, None).await;
    let (_org, agent_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    grant(
        &client,
        &base,
        &admin_key,
        agent_id,
        "overslash:request_secrets_own:*",
    )
    .await;

    // Sibling user — direct child of admin, parallel branch from the agent's
    // ceiling user. Not a descendant of the agent and the agent is not its
    // ancestor.
    let sibling: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name": "sibling-user", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sibling_id: Uuid = sibling["id"].as_str().unwrap().parse().unwrap();

    let resp = call(
        &client,
        &base,
        &agent_key,
        json!({
            "service": "overslash",
            "action": "request_secret",
            "params": { "secret_name": "k", "identity_id": sibling_id }
        }),
    )
    .await;

    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .to_lowercase()
            .contains("request_secrets_share"),
        "expected request_secrets_share denial, got {body}"
    );
}

/// Org-level API keys (no identity binding) cannot mint a request — the
/// `secret_requests` row needs an identity. Surfacing this as a clean 400
/// keeps the failure mode out of the FK 500 path.
#[tokio::test]
async fn org_key_without_identity_rejected() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool, None).await;
    let (org_id, _agent_id, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Mint a fresh org-level (unbound) key. Admin level satisfies the YAML
    // anchor on the action without needing an explicit grant, so the kernel
    // is reached and the identity check is the first thing that fires.
    let key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"org_id": org_id, "name": "org-unbound"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let unbound_key = key_resp["key"].as_str().unwrap();

    let resp = call(
        &client,
        &base,
        unbound_key,
        json!({
            "service": "overslash",
            "action": "request_secret",
            "params": { "secret_name": "openai_api_key" }
        }),
    )
    .await;

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .to_lowercase()
            .contains("identity"),
        "expected identity-required error, got {body}"
    );
}
