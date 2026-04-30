//! Integration tests for `/v1/org-service-keys`.
//!
//! Covers:
//!   - First plain create auto-mints the shared `org-service` Agent and
//!     attaches it to the Admins group (one-time `org_service_agent.created`
//!     audit + per-call `api_key.created` with `bound_to_identity_id`).
//!   - Second create reuses the same Agent (no duplicate "agent created"
//!     audit).
//!   - Impersonation flow: the resulting key + `X-Overslash-As` reaches a
//!     non-admin endpoint; runtime audit captures BOTH the impersonator
//!     (org-service Agent) and the impersonated target (the admin user).
//!   - Non-admin caller → 403.
//!   - Revoke removes the key and authenticating with it returns 401.
//!   - Revoke on a key from another org → 404.
//!   - Revoke refuses to nuke a non-service (user-bound) key.

mod common;

use serde_json::{Value, json};
use uuid::Uuid;

/// Create org + bootstrap admin User + admin key. Returns
/// (base, client, org_id, admin_key, admin_user_id).
async fn setup() -> (String, reqwest::Client, Uuid, String, Uuid) {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "OrgSvcTest", "slug": format!("ostest-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();

    // Bootstrap path mints the first admin User and binds the key to it.
    let bootstrap: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "bootstrap-admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admin_key = bootstrap["key"].as_str().unwrap().to_string();
    let admin_user_id: Uuid = bootstrap["identity_id"].as_str().unwrap().parse().unwrap();

    (base, client, org_id, admin_key, admin_user_id)
}

#[tokio::test]
async fn first_create_mints_org_service_agent_and_audits_creation() {
    let (base, client, org_id, admin_key, admin_user_id) = setup().await;

    let resp: Value = client
        .post(format!("{base}/v1/org-service-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"org_id": org_id, "name": "ci-deploy"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let key = resp["key"].as_str().unwrap();
    assert!(key.starts_with("osk_"), "key should be osk_ prefixed");
    let agent_id: Uuid = resp["identity_id"].as_str().unwrap().parse().unwrap();
    let scopes: Vec<String> = resp["scopes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();
    assert!(scopes.contains(&"service".to_string()));
    assert!(!scopes.contains(&"impersonate".to_string()));

    // Identity row is an Agent, not a User.
    let identities: Vec<Value> = client
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_row = identities
        .iter()
        .find(|i| i["id"].as_str().unwrap() == agent_id.to_string())
        .expect("org-service agent should appear in /v1/identities");
    assert_eq!(agent_row["kind"].as_str().unwrap(), "agent");
    assert_eq!(agent_row["name"].as_str().unwrap(), "org-service");

    // Audit log should contain both the agent-creation row (with the human
    // minter as actor) and the api_key.created row (also human minter as
    // actor, with bound_to_identity_id pointing at the new agent).
    let audit: Vec<Value> = client
        .get(format!("{base}/v1/audit?limit=50"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let agent_created = audit
        .iter()
        .find(|r| r["action"] == "org_service_agent.created")
        .expect("missing org_service_agent.created audit");
    assert_eq!(
        agent_created["identity_id"].as_str().unwrap(),
        admin_user_id.to_string(),
        "minter should be the human admin"
    );
    assert_eq!(
        agent_created["resource_id"].as_str().unwrap(),
        agent_id.to_string()
    );

    let key_created = audit
        .iter()
        .find(|r| {
            r["action"] == "api_key.created"
                && r["detail"]["kind"].as_str() == Some("org_service_key")
        })
        .expect("missing api_key.created audit for the org-service key");
    assert_eq!(
        key_created["identity_id"].as_str().unwrap(),
        admin_user_id.to_string()
    );
    assert_eq!(
        key_created["detail"]["bound_to_identity_id"]
            .as_str()
            .unwrap(),
        agent_id.to_string()
    );
}

#[tokio::test]
async fn second_create_reuses_agent_without_duplicate_creation_audit() {
    let (base, client, org_id, admin_key, _) = setup().await;

    let first: Value = client
        .post(format!("{base}/v1/org-service-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"org_id": org_id, "name": "first"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id: Uuid = first["identity_id"].as_str().unwrap().parse().unwrap();

    let second: Value = client
        .post(format!("{base}/v1/org-service-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"org_id": org_id, "name": "second"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let second_agent_id: Uuid = second["identity_id"].as_str().unwrap().parse().unwrap();
    assert_eq!(
        agent_id, second_agent_id,
        "both keys must bind to the same agent"
    );

    let audit: Vec<Value> = client
        .get(format!("{base}/v1/audit?limit=50"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_created_count = audit
        .iter()
        .filter(|r| r["action"] == "org_service_agent.created")
        .count();
    assert_eq!(
        agent_created_count, 1,
        "agent creation should only audit on first mint"
    );
    let key_created_count = audit
        .iter()
        .filter(|r| {
            r["action"] == "api_key.created"
                && r["detail"]["kind"].as_str() == Some("org_service_key")
        })
        .count();
    assert_eq!(key_created_count, 2);
}

#[tokio::test]
async fn impersonation_key_succeeds_and_runtime_audit_captures_chain() {
    let (base, client, org_id, admin_key, admin_user_id) = setup().await;

    // Mint impersonation-capable service key.
    let resp: Value = client
        .post(format!("{base}/v1/org-service-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"org_id": org_id, "name": "imp-key", "allow_impersonate": true}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let imp_key = resp["key"].as_str().unwrap().to_string();
    let agent_id: Uuid = resp["identity_id"].as_str().unwrap().parse().unwrap();
    let scopes: Vec<String> = resp["scopes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();
    assert!(scopes.contains(&"impersonate".to_string()));

    // Use the impersonation key to act as the admin user and mint a new
    // service key. This goes through the OrgScope extractor on
    // /v1/org-service-keys, so the resulting api_key.created audit row
    // must carry both the impersonated identity and the impersonator.
    let create2: Value = client
        .post(format!("{base}/v1/org-service-keys"))
        .header("Authorization", format!("Bearer {imp_key}"))
        .header("X-Overslash-As", admin_user_id.to_string())
        .json(&json!({"org_id": org_id, "name": "via-impersonation"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let new_key_prefix = create2["key_prefix"].as_str().unwrap().to_string();

    // Pull audit and find the row matching the impersonated mint.
    let audit: Vec<Value> = client
        .get(format!("{base}/v1/audit?limit=50"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = audit
        .iter()
        .find(|r| {
            r["action"] == "api_key.created"
                && r["detail"]["key_prefix"].as_str() == Some(&new_key_prefix)
        })
        .expect("missing api_key.created audit row for the impersonated mint");

    // Effective identity (the impersonated target) is the admin user.
    assert_eq!(
        row["identity_id"].as_str().unwrap(),
        admin_user_id.to_string(),
        "audit identity_id must reflect the impersonated target"
    );
    // The org-service Agent (the actual key holder) is recorded as the
    // impersonator. This is the load-bearing chain link.
    assert_eq!(
        row["impersonated_by_identity_id"].as_str().unwrap(),
        agent_id.to_string(),
        "audit impersonated_by_identity_id must point at the org-service agent"
    );
}

#[tokio::test]
async fn non_admin_caller_is_rejected() {
    let (base, client, org_id, admin_key, _) = setup().await;

    // Create a non-admin user with their own key.
    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name": "regular-user", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id: Uuid = user["id"].as_str().unwrap().parse().unwrap();

    let user_key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"org_id": org_id, "identity_id": user_id, "name": "user-key"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_key = user_key_resp["key"].as_str().unwrap();

    let resp = client
        .post(format!("{base}/v1/org-service-keys"))
        .header("Authorization", format!("Bearer {user_key}"))
        .json(&json!({"org_id": org_id, "name": "should-fail"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        403,
        "non-admin must not be able to mint org service keys"
    );
}

#[tokio::test]
async fn revoke_disables_key_and_audits_revoker() {
    let (base, client, org_id, admin_key, admin_user_id) = setup().await;

    let resp: Value = client
        .post(format!("{base}/v1/org-service-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"org_id": org_id, "name": "to-revoke"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let key_id: Uuid = resp["id"].as_str().unwrap().parse().unwrap();
    let raw_key = resp["key"].as_str().unwrap().to_string();

    let revoke = client
        .post(format!("{base}/v1/org-service-keys/{key_id}/revoke"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(revoke.status().as_u16(), 204);

    // The revoked key no longer authenticates.
    let auth_with_revoked = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {raw_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(auth_with_revoked.status().as_u16(), 401);

    // The list endpoint no longer shows it.
    let list: Vec<Value> = client
        .get(format!("{base}/v1/org-service-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        !list
            .iter()
            .any(|r| r["id"].as_str().unwrap() == key_id.to_string()),
        "revoked key must not appear in list"
    );

    // Audit row records the human revoker.
    let audit: Vec<Value> = client
        .get(format!("{base}/v1/audit?limit=50"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let revoke_row = audit
        .iter()
        .find(|r| {
            r["action"] == "api_key.revoked"
                && r["resource_id"].as_str() == Some(&key_id.to_string())
        })
        .expect("missing api_key.revoked audit row");
    assert_eq!(
        revoke_row["identity_id"].as_str().unwrap(),
        admin_user_id.to_string()
    );
}

#[tokio::test]
async fn revoke_other_org_returns_not_found() {
    let (base_a, client, org_a_id, admin_key_a, _) = setup().await;
    // Reuse the same listener for org B so we don't fire up a second server.
    let _ = org_a_id;

    let org_b: Value = client
        .post(format!("{base_a}/v1/orgs"))
        .json(&json!({"name": "OrgB", "slug": format!("ostest-b-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_b_id: Uuid = org_b["id"].as_str().unwrap().parse().unwrap();
    let boot_b: Value = client
        .post(format!("{base_a}/v1/api-keys"))
        .json(&json!({"org_id": org_b_id, "name": "admin-b"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admin_key_b = boot_b["key"].as_str().unwrap().to_string();

    let key_b: Value = client
        .post(format!("{base_a}/v1/org-service-keys"))
        .header("Authorization", format!("Bearer {admin_key_b}"))
        .json(&json!({"org_id": org_b_id, "name": "b-key"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let b_key_id: Uuid = key_b["id"].as_str().unwrap().parse().unwrap();

    // Org A's admin must not be able to revoke a key from org B.
    let resp = client
        .post(format!("{base_a}/v1/org-service-keys/{b_key_id}/revoke"))
        .header("Authorization", format!("Bearer {admin_key_a}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404);
}

#[tokio::test]
async fn revoke_refuses_non_service_keys() {
    // The endpoint must not be a back door for nuking arbitrary user-bound
    // keys. Only keys carrying the "service" scope are reachable through it.
    let (base, client, org_id, admin_key, admin_user_id) = setup().await;

    // Mint a regular (non-service) personal API key for the admin user.
    let regular: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "org_id": org_id,
            "identity_id": admin_user_id,
            "name": "personal",
            "scopes": [],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let regular_id: Uuid = regular["id"].as_str().unwrap().parse().unwrap();

    let resp = client
        .post(format!("{base}/v1/org-service-keys/{regular_id}/revoke"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        404,
        "revoke must refuse non-service keys"
    );
}
