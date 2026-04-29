//! Integration tests for the Myself-group model that absorbed the former
//! "user-level service bypass". Covers the new owner-managed Myself grant
//! controls, the read-bypass that skips Layer 2 for owner reads on owned
//! services, the self-group guard that prevents cross-owner grants, and the
//! admin-share path that exposes a previously-personal service to other groups.
#![allow(clippy::disallowed_methods)]

mod common;

use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;

/// Bootstrap an org with an admin user, a regular user, and an agent under
/// that user. Returns (base, pool, admin_key, user_id, user_key, agent_id, agent_key).
async fn setup_org_with_user_and_agent()
-> (String, sqlx::PgPool, String, Uuid, String, Uuid, String) {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    // bootstrap_org_identity creates the org, an admin user, a "test-user", and
    // a "test-agent" under that user. We grab everything we need from there.
    let (org_id, agent_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Find the test-user (parent of the agent). We need its identity_id +
    // a user-bound API key for the cap/disable/delete/restore tests.
    let identities: Vec<Value> = client
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id: Uuid = identities
        .iter()
        .find(|i| i["kind"] == "user" && i["name"] == "test-user")
        .expect("test-user not found")["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    // Mint a user-bound key (for owner-managing-Myself flows).
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
    let user_key = user_key_resp["key"].as_str().unwrap().to_string();

    (
        base, pool, admin_key, user_id, user_key, agent_id, agent_key,
    )
}

/// Register a minimal HTTP template (org-tier, requires admin) and then
/// create a user-level instance owned by the user-bound key. The template
/// name doubles as the service name. Returns the service instance id.
async fn create_user_service(base: &str, admin_key: &str, user_key: &str, name: &str) -> Uuid {
    let client = reqwest::Client::new();
    client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "openapi": common::minimal_openapi(name),
            "user_level": false,
        }))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {user_key}"))
        .json(&json!({
            "template_key": name,
            "name": name,
            "user_level": true,
            "status": "active",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "create user service failed: {:?}",
        resp.text().await
    );
    let svc: Value = resp.json().await.unwrap();
    svc["id"].as_str().unwrap().parse().unwrap()
}

/// Find the Myself group for the given user via `?include_self=true`.
async fn find_self_group(base: &str, key: &str, owner: Uuid) -> Value {
    let client = reqwest::Client::new();
    let groups: Vec<Value> = client
        .get(format!("{base}/v1/groups?include_self=true"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    groups
        .into_iter()
        .find(|g| {
            g["system_kind"].as_str() == Some("self")
                && g["owner_identity_id"].as_str() == Some(&owner.to_string())
        })
        .expect("Myself group not found for user")
}

async fn list_self_grants(base: &str, key: &str, group_id: &str) -> Vec<Value> {
    let client = reqwest::Client::new();
    client
        .get(format!("{base}/v1/groups/{group_id}/grants"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn list_groups_hides_self_groups_by_default() {
    let (base, _pool, admin_key, user_id, _user_key, _agent_id, _agent_key) =
        setup_org_with_user_and_agent().await;
    let client = reqwest::Client::new();

    // Default listing: only Everyone + Admins (no Myself).
    let groups: Vec<Value> = client
        .get(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        groups
            .iter()
            .all(|g| g["system_kind"].as_str() != Some("self")),
        "Myself groups must not appear in default listing"
    );

    // Opt-in listing exposes them.
    let with_self = find_self_group(&base, &admin_key, user_id).await;
    assert_eq!(with_self["system_kind"], "self");
    assert_eq!(with_self["owner_identity_id"], user_id.to_string());
}

#[tokio::test]
async fn create_user_service_auto_grants_admin_to_self_group() {
    let (base, _pool, admin_key, user_id, user_key, _agent_id, _agent_key) =
        setup_org_with_user_and_agent().await;

    let svc_id = create_user_service(&base, &admin_key, &user_key, "alpha").await;

    let myself = find_self_group(&base, &user_key, user_id).await;
    let self_id = myself["id"].as_str().unwrap();
    let grants = list_self_grants(&base, &user_key, self_id).await;
    let grant = grants
        .iter()
        .find(|g| g["service_instance_id"].as_str() == Some(&svc_id.to_string()))
        .expect("grant on alpha must exist");
    assert_eq!(grant["access_level"], "admin");
    assert_eq!(grant["auto_approve_reads"], true);
}

#[tokio::test]
async fn owner_can_delete_and_re_add_self_grant() {
    let (base, _pool, admin_key, user_id, user_key, _agent_id, _agent_key) =
        setup_org_with_user_and_agent().await;
    let client = reqwest::Client::new();

    let svc_id = create_user_service(&base, &admin_key, &user_key, "beta").await;
    let myself = find_self_group(&base, &user_key, user_id).await;
    let self_id = myself["id"].as_str().unwrap();

    let grants = list_self_grants(&base, &user_key, self_id).await;
    let grant_id = grants
        .iter()
        .find(|g| g["service_instance_id"].as_str() == Some(&svc_id.to_string()))
        .expect("grant exists")["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Owner deletes their own Myself grant — must succeed (no lockout guard).
    let resp = client
        .delete(format!("{base}/v1/groups/{self_id}/grants/{grant_id}"))
        .header("Authorization", format!("Bearer {user_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);

    let grants = list_self_grants(&base, &user_key, self_id).await;
    assert!(
        grants
            .iter()
            .all(|g| g["service_instance_id"].as_str() != Some(&svc_id.to_string())),
        "grant should be gone"
    );

    // Owner re-adds via the standard grants endpoint (still allowed because
    // the service's owner_identity_id matches the Myself group owner).
    let resp = client
        .post(format!("{base}/v1/groups/{self_id}/grants"))
        .header("Authorization", format!("Bearer {user_key}"))
        .json(&json!({
            "service_instance_id": svc_id.to_string(),
            "access_level": "admin",
            "auto_approve_reads": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);
}

#[tokio::test]
async fn admin_can_share_owner_service_with_other_group() {
    let (base, _pool, admin_key, _user_id, user_key, _agent_id, _agent_key) =
        setup_org_with_user_and_agent().await;
    let client = reqwest::Client::new();

    // The user (test-user) creates a private service.
    let svc_id = create_user_service(&base, &admin_key, &user_key, "shared-thing").await;

    // Admin creates an Engineering group and grants the user-owned service.
    let group: Value = client
        .post(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name": "Engineering"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let eng_id = group["id"].as_str().unwrap();

    let resp = client
        .post(format!("{base}/v1/groups/{eng_id}/grants"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "service_instance_id": svc_id.to_string(),
            "access_level": "read",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "admin must be able to grant a user-owned service to a regular group: {:?}",
        resp.text().await
    );
}

#[tokio::test]
async fn admin_cannot_grant_alices_service_to_bobs_self_group() {
    let (base, _pool, admin_key, alice_id, alice_key, _agent_id, _agent_key) =
        setup_org_with_user_and_agent().await;
    let client = reqwest::Client::new();

    let svc_id = create_user_service(&base, &admin_key, &alice_key, "alice-private").await;

    // Mint a second user (bob) under the admin so we have a separate Myself.
    let bob: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name": "bob", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let bob_id: Uuid = bob["id"].as_str().unwrap().parse().unwrap();
    assert_ne!(bob_id, alice_id);

    let bob_self = find_self_group(&base, &admin_key, bob_id).await;
    let bob_self_id = bob_self["id"].as_str().unwrap();

    // Even an org admin must not be able to point bob's Myself at alice's service.
    let resp = client
        .post(format!("{base}/v1/groups/{bob_self_id}/grants"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "service_instance_id": svc_id.to_string(),
            "access_level": "admin",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "{:?}", resp.text().await);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap_or("").contains("Myself"),
        "expected Myself-guard error, got {body}"
    );
}

#[tokio::test]
async fn agent_read_on_owners_service_skips_layer_2() {
    let (base, pool, admin_key, _user_id, user_key, agent_id, agent_key) =
        setup_org_with_user_and_agent().await;
    let client = reqwest::Client::new();

    // Owner creates a personal service. Default Myself grant: admin + auto-approve-reads.
    create_user_service(&base, &admin_key, &user_key, "owners-svc").await;

    // Agent calls a read on that service. Read-bypass should skip Layer 2:
    // no permission rule written, no approval filed, the action runs.
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": "owners-svc",
            "action": "list_items",
            "params": {}
        }))
        .send()
        .await
        .unwrap();
    // Mock target may 404 the upstream call, but the gating decision is what
    // we care about here — anything other than 200 (called) or 502 (upstream
    // error after passing the gate) means the gate denied/queued.
    let status = resp.status();
    let body: Value = resp.json().await.unwrap();
    assert_ne!(
        body["status"].as_str(),
        Some("pending_approval"),
        "read on owner's service must NOT trigger approval (status={status}, body={body})"
    );

    // Verify no permission rule was created for the agent (the win this
    // refactor delivers: read-bypass leaves the agent's rule list clean).
    let count: i64 =
        sqlx::query("SELECT COUNT(*) AS c FROM permission_rules WHERE identity_id = $1")
            .bind(agent_id)
            .fetch_one(&pool)
            .await
            .unwrap()
            .get("c");
    assert_eq!(
        count, 0,
        "no permission_rules row should be created by a read-bypass call"
    );
}
