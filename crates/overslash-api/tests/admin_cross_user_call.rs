//! Cross-user invocation by an org admin.
//!
//! When an admin selects another user's service in the dashboard's API
//! Explorer, the request carries the instance UUID alongside the name. The
//! backend resolves the instance org-scoped (not caller-shadowed), rebinds
//! the effective identity to the service owner so OAuth/secrets and the
//! permission chain anchor on the right user, and tags the audit row with
//! the admin as the impersonator.
//!
//! These tests pin the visible contract:
//!
//! 1. Admin can list actions for another user's service by **UUID**.
//! 2. Admin listing the same instance by **name** still 404s (name
//!    resolution stays caller-scoped — documented in
//!    `routes/services.rs::list_service_actions`).
//! 3. A non-admin caller passing another user's `service_id` to
//!    `/v1/actions/call` gets a clean 403 with an explanatory message
//!    (no leak of the resolver internals).
//! 4. An admin calling `/v1/actions/validate` with another user's
//!    `service_id` reaches the permission gate as the owner — i.e. the
//!    request gets past the impersonation guard and produces a normal
//!    validate envelope (not 403).

#![allow(clippy::disallowed_methods)]

mod common;

use axum::http::StatusCode;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

/// Sets up:
///   - bootstrap org + admin user identity flagged `is_org_admin = true`
///   - a separate user B with an identity-bound key
///   - a user-B-owned service instance from template `x`
///
/// Returns (base, client, pool, org_id, admin_key, user_b_id, svc_id, svc_name).
async fn setup_cross_user_instance() -> (
    String,
    reqwest::Client,
    PgPool,
    Uuid,
    String,
    Uuid,
    Uuid,
    String,
) {
    let pool = common::test_pool().await;
    // The `x` template is loaded by `start_api_with_registry`; the bare
    // `start_api` helper ships an empty registry, so the service-create
    // call would 404 with `template 'x' not found in any tier`.
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;

    // bootstrap_org_identity hands back the admin's *org-bound* key plus a
    // test-agent key under a test-user. The bootstrap path already creates
    // an identity named "admin" with `is_org_admin = true` — we just need
    // an identity-bound key for it because `/v1/actions/call` rejects
    // org-bound keys (callers must be a specific identity).
    let (org_id, _agent_id, _agent_key, org_key) =
        common::bootstrap_org_identity(&base, &client).await;
    let admin_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM identities WHERE org_id = $1 AND name = 'admin' LIMIT 1",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let admin_key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({
            "org_id": org_id,
            "identity_id": admin_id,
            "name": "admin-identity-key",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admin_key = admin_key_resp["key"].as_str().unwrap().to_string();

    // User B — distinct user identity that will own the instance.
    let user_b: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"name": "user-b", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_b_id: Uuid = user_b["id"].as_str().unwrap().parse().unwrap();

    let user_b_key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({
            "org_id": org_id,
            "identity_id": user_b_id,
            "name": "user-b-key",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_b_key = user_b_key_resp["key"].as_str().unwrap();

    let svc_name = format!("x_b_{}", Uuid::new_v4().simple());
    let svc_resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {user_b_key}"))
        .json(&json!({
            "template_key": "x",
            "name": svc_name,
            "user_level": true,
            "status": "active",
        }))
        .send()
        .await
        .unwrap();
    let status = svc_resp.status();
    let svc: Value = svc_resp.json().await.unwrap();
    let svc_id: Uuid = svc["id"]
        .as_str()
        .unwrap_or_else(|| panic!("service create failed status={status} body={svc:?}"))
        .parse()
        .unwrap();

    (
        base, client, pool, org_id, admin_key, user_b_id, svc_id, svc_name,
    )
}

#[tokio::test]
async fn admin_can_list_actions_for_other_users_instance_by_uuid() {
    let (base, client, _pool, _org_id, admin_key, _user_b_id, svc_id, _svc_name) =
        setup_cross_user_instance().await;

    let resp = client
        .get(format!("{base}/v1/services/{svc_id}/actions"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "admin GET by UUID should resolve org-scoped: {}",
        resp.text().await.unwrap()
    );
    let actions: Vec<Value> = resp.json().await.unwrap();
    assert!(
        actions.iter().any(|a| a["key"] == "get_me"),
        "expected the x template's get_me action in the response, got {actions:?}"
    );
}

#[tokio::test]
async fn admin_listing_other_users_instance_by_name_still_404s() {
    let (base, client, _pool, _org_id, admin_key, _user_b_id, _svc_id, svc_name) =
        setup_cross_user_instance().await;

    let resp = client
        .get(format!("{base}/v1/services/{svc_name}/actions"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();
    // Name lookup is intentionally caller-scoped: an admin's name resolution
    // does not shadow another user's instance. Callers that need to reach a
    // cross-user instance use the UUID path (the dashboard does this for
    // org-admin "Show all users' services" flows).
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "admin GET by name across owners stays 404 (use UUID): {}",
        resp.text().await.unwrap()
    );
}

#[tokio::test]
async fn non_admin_call_with_other_users_service_id_returns_403() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (org_id, _agent_id, agent_key, org_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // User B + B-owned instance via B's key (no admin flip — the calling
    // agent here is not an admin and must be refused on cross-user UUID).
    let user_b: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"name": "user-b", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_b_id: Uuid = user_b["id"].as_str().unwrap().parse().unwrap();
    let user_b_key: String = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({
            "org_id": org_id,
            "identity_id": user_b_id,
            "name": "user-b-key",
        }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["key"]
        .as_str()
        .unwrap()
        .to_string();
    let svc_name = format!("x_b_{}", Uuid::new_v4().simple());
    let svc: Value = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {user_b_key}"))
        .json(&json!({
            "template_key": "x",
            "name": svc_name,
            "user_level": true,
            "status": "active",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let svc_id: Uuid = svc["id"].as_str().unwrap().parse().unwrap();

    // The default bootstrap test-agent (under test-user, distinct from B) is
    // not an org admin. Passing B's instance UUID must be refused.
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": svc_name,
            "service_id": svc_id,
            "action": "get_me",
            "params": {},
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap();
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "non-admin cross-user service_id must 403, got {status}: {body}"
    );
    assert!(
        body.contains("org admin") || body.contains("owned by another user"),
        "403 body should be the cross-user message, got {body}"
    );
}

#[tokio::test]
async fn admin_validate_with_other_users_service_id_reaches_permission_gate() {
    let (base, client, _pool, _org_id, admin_key, _user_b_id, svc_id, svc_name) =
        setup_cross_user_instance().await;

    // /validate is cheap (no OAuth resolution, no upstream call). With the
    // admin impersonating user B as the effective identity, the request
    // gets past the cross-user guard and produces a normal validation
    // envelope. We assert 200 + an `ok` body — the exact `permission.status`
    // depends on B's groups (Myself grant is auto-created at instance
    // creation), so we just pin the success shape here.
    let resp = client
        .post(format!("{base}/v1/actions/validate"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "service": svc_name,
            "service_id": svc_id,
            "action": "get_me",
            "params": {},
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "admin validate cross-user should 200, got {status}: {body}"
    );
    assert_eq!(
        body["ok"], true,
        "validate envelope missing ok=true: {body}"
    );
    assert!(
        body.get("permission").is_some(),
        "validate envelope missing permission block: {body}"
    );
}
