//! Integration tests for identity hierarchy, permission chain walk, and approval bubbling.
//!
//! Tests the full stack: API → chain walk → approval creation → resolution → rule grant.

mod common;

use reqwest::Client;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

/// Bootstrap org + user identity + org-level key. Returns (base_url, org_key, org_id, user_id).
///
/// The user identity is created with `can_create_sub=true` and `max_sub_depth=4` via direct SQL
/// update, since the flat identity creation path doesn't accept these fields.
async fn setup_org_with_user(pool: PgPool) -> (String, String, Uuid, Uuid) {
    let db = pool.clone();
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    // Create org
    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "HierarchyOrg", "slug": format!("hier-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();

    // Org-level API key
    let key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "org-admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_key = key_resp["key"].as_str().unwrap().to_string();

    // Create user identity (root of hierarchy) via API
    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({"name": "alice", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id: Uuid = user["id"].as_str().unwrap().parse().unwrap();

    // Enable hierarchy support on the user via direct SQL
    // (flat creation doesn't accept can_create_sub/max_sub_depth)
    sqlx::query("UPDATE identities SET can_create_sub = true, max_sub_depth = 4 WHERE id = $1")
        .bind(user_id)
        .execute(&db)
        .await
        .unwrap();

    (base, org_key, org_id, user_id)
}

/// Create an identity-bound API key and return it.
async fn create_api_key(
    client: &Client,
    base: &str,
    org_id: Uuid,
    identity_id: Uuid,
    name: &str,
) -> String {
    let resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "identity_id": identity_id, "name": name}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    resp["key"].as_str().unwrap().to_string()
}

/// Store a secret for an identity. Required so actions trigger the permission gate.
async fn store_secret(client: &Client, base: &str, key: &str, name: &str) {
    client
        .put(format!("{base}/v1/secrets/{name}"))
        .header(common::auth(key).0, common::auth(key).1)
        .json(&json!({"value": "test-secret"}))
        .send()
        .await
        .unwrap();
}

/// Execute an action and return the response.
async fn execute_action(
    client: &Client,
    base: &str,
    key: &str,
    target_url: &str,
) -> reqwest::Response {
    client
        .post(format!("{base}/v1/actions/execute"))
        .header(common::auth(key).0, common::auth(key).1)
        .json(&json!({
            "method": "GET",
            "url": target_url,
            "secrets": [{"name": "tk", "inject_as": "header", "header_name": "X-Auth"}]
        }))
        .send()
        .await
        .unwrap()
}

// ── Test 1: Create hierarchical identities with correct depth/owner ──────────

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_identity_hierarchy_creation(pool: PgPool) {
    let (base, org_key, _org_id, user_id) = setup_org_with_user(pool).await;
    let client = Client::new();

    // Create agent under user (depth=1)
    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({
            "name": "henry",
            "kind": "agent",
            "parent_id": user_id,
            "can_create_sub": true,
            "max_sub_depth": 3
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(agent["depth"], 1);
    assert_eq!(agent["kind"], "agent");
    assert_eq!(agent["parent_id"], user_id.to_string());
    assert_eq!(agent["owner_id"], user_id.to_string());
    let agent_id: Uuid = agent["id"].as_str().unwrap().parse().unwrap();

    // Create subagent under agent (depth=2)
    let subagent: Value = client
        .post(format!("{base}/v1/identities"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({
            "name": "researcher",
            "kind": "subagent",
            "parent_id": agent_id,
            "inherit_permissions": true
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(subagent["depth"], 2);
    assert_eq!(subagent["kind"], "subagent");
    assert_eq!(subagent["parent_id"], agent_id.to_string());
    assert_eq!(subagent["owner_id"], user_id.to_string());
    assert_eq!(subagent["inherit_permissions"], true);

    // List identities — verify all 3 are returned with hierarchy fields
    let list: Vec<Value> = client
        .get(format!("{base}/v1/identities"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(list.len(), 3);
    let depths: Vec<i64> = list.iter().map(|i| i["depth"].as_i64().unwrap()).collect();
    assert!(depths.contains(&0));
    assert!(depths.contains(&1));
    assert!(depths.contains(&2));
}

// ── Test 2: max_sub_depth enforcement ────────────────────────────────────────

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_max_sub_depth_enforcement(pool: PgPool) {
    let (base, org_key, _org_id, user_id) = setup_org_with_user(pool).await;
    let client = Client::new();

    // User has max_sub_depth=4, create agent at depth=1 with max_sub_depth=2
    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({
            "name": "limited-agent",
            "kind": "agent",
            "parent_id": user_id,
            "can_create_sub": true,
            "max_sub_depth": 2
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id: Uuid = agent["id"].as_str().unwrap().parse().unwrap();

    // Create subagent at depth=2 — within agent's max_sub_depth=2 ✓
    let sub: Value = client
        .post(format!("{base}/v1/identities"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({
            "name": "sub-ok",
            "kind": "subagent",
            "parent_id": agent_id,
            "can_create_sub": true
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(sub["depth"], 2);
    let sub_id: Uuid = sub["id"].as_str().unwrap().parse().unwrap();

    // Create sub-subagent at depth=3 — exceeds agent's max_sub_depth=2 ✗
    let resp = client
        .post(format!("{base}/v1/identities"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({
            "name": "sub-too-deep",
            "kind": "subagent",
            "parent_id": sub_id
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let err: Value = resp.json().await.unwrap();
    assert!(err["error"].as_str().unwrap().contains("max_sub_depth"));
}

// ── Test 3: can_create_sub=false prevents child creation ─────────────────────

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_can_create_sub_enforcement(pool: PgPool) {
    let (base, org_key, _org_id, user_id) = setup_org_with_user(pool).await;
    let client = Client::new();

    // Agent without can_create_sub
    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({
            "name": "no-children-agent",
            "kind": "agent",
            "parent_id": user_id,
            "can_create_sub": false
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id: Uuid = agent["id"].as_str().unwrap().parse().unwrap();

    // Try to create sub under it — should be forbidden
    let resp = client
        .post(format!("{base}/v1/identities"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({
            "name": "rejected-sub",
            "kind": "subagent",
            "parent_id": agent_id
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

// ── Test 4: Subagent gap → approval created → agent resolves ─────────────────

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_subagent_gap_agent_resolves(pool: PgPool) {
    let mock = common::start_mock().await;
    let (base, org_key, org_id, user_id) = setup_org_with_user(pool).await;
    let client = Client::new();

    // User → Agent → SubAgent
    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({
            "name": "henry",
            "kind": "agent",
            "parent_id": user_id,
            "can_create_sub": true
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id: Uuid = agent["id"].as_str().unwrap().parse().unwrap();

    let subagent: Value = client
        .post(format!("{base}/v1/identities"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({
            "name": "researcher",
            "kind": "subagent",
            "parent_id": agent_id
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let subagent_id: Uuid = subagent["id"].as_str().unwrap().parse().unwrap();

    // Give User and Agent allow rules so only SubAgent has a gap
    let agent_key = create_api_key(&client, &base, org_id, agent_id, "agent-key").await;
    let sub_key = create_api_key(&client, &base, org_id, subagent_id, "sub-key").await;

    // User: allow all
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({"identity_id": user_id, "action_pattern": "http:**", "effect": "allow"}))
        .send()
        .await
        .unwrap();

    // Agent: allow all
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({"identity_id": agent_id, "action_pattern": "http:**", "effect": "allow"}))
        .send()
        .await
        .unwrap();

    // SubAgent: NO rules → gap

    store_secret(&client, &base, &sub_key, "tk").await;

    // Execute as subagent — should get 202 pending_approval
    let resp = execute_action(&client, &base, &sub_key, &format!("http://{mock}/echo")).await;
    assert_eq!(resp.status(), 202);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "pending_approval");
    let approval_id = body["approval_id"].as_str().unwrap();

    // Verify gaps array contains gap at subagent level
    let gaps = body["gaps"].as_array().unwrap();
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0]["gap_identity_id"], subagent_id.to_string());
    let can_handle = gaps[0]["can_be_handled_by"].as_array().unwrap();
    assert!(can_handle.iter().any(|v| v == &json!(agent_id.to_string())));
    assert!(can_handle.iter().any(|v| v == &json!(user_id.to_string())));

    // Agent resolves the approval
    let resp = client
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header(common::auth(&agent_key).0, common::auth(&agent_key).1)
        .json(&json!({"decision": "allow"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.json::<Value>().await.unwrap()["status"], "allowed");
}

// ── Test 5: Self-approval is forbidden ───────────────────────────────────────

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_self_approval_forbidden(pool: PgPool) {
    let mock = common::start_mock().await;
    let (base, org_key, org_id, user_id) = setup_org_with_user(pool).await;
    let client = Client::new();

    // User → Agent (no rules → gap at agent)
    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({
            "name": "self-approver",
            "kind": "agent",
            "parent_id": user_id,
            "can_create_sub": true
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id: Uuid = agent["id"].as_str().unwrap().parse().unwrap();

    let agent_key = create_api_key(&client, &base, org_id, agent_id, "agent-key").await;

    // User has allow rules, agent does not
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({"identity_id": user_id, "action_pattern": "http:**", "effect": "allow"}))
        .send()
        .await
        .unwrap();

    store_secret(&client, &base, &agent_key, "tk").await;

    // Execute as agent → gap at agent → pending approval
    let resp = execute_action(&client, &base, &agent_key, &format!("http://{mock}/echo")).await;
    assert_eq!(resp.status(), 202);
    let approval_id = resp.json::<Value>().await.unwrap()["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Agent tries to resolve own approval → forbidden
    let resp = client
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header(common::auth(&agent_key).0, common::auth(&agent_key).1)
        .json(&json!({"decision": "allow"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

// ── Test 6: inherit_permissions skips level in chain walk ─────────────────────

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_inherit_permissions_allows_action(pool: PgPool) {
    let mock = common::start_mock().await;
    let (base, org_key, org_id, user_id) = setup_org_with_user(pool).await;
    let client = Client::new();

    // User → Agent(allow http:**) → SubAgent(inherit_permissions=true)
    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({
            "name": "henry",
            "kind": "agent",
            "parent_id": user_id,
            "can_create_sub": true
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id: Uuid = agent["id"].as_str().unwrap().parse().unwrap();

    let subagent: Value = client
        .post(format!("{base}/v1/identities"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({
            "name": "inheritor",
            "kind": "subagent",
            "parent_id": agent_id,
            "inherit_permissions": true
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let subagent_id: Uuid = subagent["id"].as_str().unwrap().parse().unwrap();

    let sub_key = create_api_key(&client, &base, org_id, subagent_id, "sub-key").await;

    // User and Agent both have allow rules
    for id in [user_id, agent_id] {
        client
            .post(format!("{base}/v1/permissions"))
            .header(common::auth(&org_key).0, common::auth(&org_key).1)
            .json(&json!({"identity_id": id, "action_pattern": "http:**", "effect": "allow"}))
            .send()
            .await
            .unwrap();
    }

    store_secret(&client, &base, &sub_key, "tk").await;

    // SubAgent inherits from Agent → should be allowed (200), not pending
    let resp = execute_action(&client, &base, &sub_key, &format!("http://{mock}/echo")).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.json::<Value>().await.unwrap()["status"], "executed");
}

// ── Test 7: Deny at any level blocks entire chain ────────────────────────────

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_deny_at_ancestor_blocks_descendant(pool: PgPool) {
    let mock = common::start_mock().await;
    let (base, org_key, org_id, user_id) = setup_org_with_user(pool).await;
    let client = Client::new();

    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({
            "name": "denied-agent",
            "kind": "agent",
            "parent_id": user_id,
            "can_create_sub": true
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id: Uuid = agent["id"].as_str().unwrap().parse().unwrap();

    let agent_key = create_api_key(&client, &base, org_id, agent_id, "agent-key").await;

    // User has DENY rule
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({"identity_id": user_id, "action_pattern": "http:**", "effect": "deny"}))
        .send()
        .await
        .unwrap();

    // Agent has ALLOW rule — but deny at user level should still block
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({"identity_id": agent_id, "action_pattern": "http:**", "effect": "allow"}))
        .send()
        .await
        .unwrap();

    store_secret(&client, &base, &agent_key, "tk").await;

    let resp = execute_action(&client, &base, &agent_key, &format!("http://{mock}/echo")).await;
    assert_eq!(resp.status(), 403);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "denied");
}

// ── Test 8: Approval scope filtering (actionable vs mine) ────────────────────

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_approval_scope_filtering(pool: PgPool) {
    let mock = common::start_mock().await;
    let (base, org_key, org_id, user_id) = setup_org_with_user(pool).await;
    let client = Client::new();

    // User → Agent → SubAgent (no rules → gap at subagent)
    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({
            "name": "henry",
            "kind": "agent",
            "parent_id": user_id,
            "can_create_sub": true
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id: Uuid = agent["id"].as_str().unwrap().parse().unwrap();

    let subagent: Value = client
        .post(format!("{base}/v1/identities"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({
            "name": "researcher",
            "kind": "subagent",
            "parent_id": agent_id
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let subagent_id: Uuid = subagent["id"].as_str().unwrap().parse().unwrap();

    let agent_key = create_api_key(&client, &base, org_id, agent_id, "agent-key").await;
    let sub_key = create_api_key(&client, &base, org_id, subagent_id, "sub-key").await;

    // User and Agent have allow rules, SubAgent does not
    for id in [user_id, agent_id] {
        client
            .post(format!("{base}/v1/permissions"))
            .header(common::auth(&org_key).0, common::auth(&org_key).1)
            .json(&json!({"identity_id": id, "action_pattern": "http:**", "effect": "allow"}))
            .send()
            .await
            .unwrap();
    }

    store_secret(&client, &base, &sub_key, "tk").await;

    // SubAgent executes → gap → pending approval
    let resp = execute_action(&client, &base, &sub_key, &format!("http://{mock}/echo")).await;
    assert_eq!(resp.status(), 202);

    // scope=mine as subagent → should see the approval
    let mine: Vec<Value> = client
        .get(format!("{base}/v1/approvals?scope=mine"))
        .header(common::auth(&sub_key).0, common::auth(&sub_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(mine.len(), 1);

    // scope=actionable as agent → should see it (agent is in can_be_handled_by)
    let actionable: Vec<Value> = client
        .get(format!("{base}/v1/approvals?scope=actionable"))
        .header(common::auth(&agent_key).0, common::auth(&agent_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(actionable.len(), 1);

    // scope=actionable as subagent → should see nothing (subagent can't resolve its own gap)
    let not_actionable: Vec<Value> = client
        .get(format!("{base}/v1/approvals?scope=actionable"))
        .header(common::auth(&sub_key).0, common::auth(&sub_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(not_actionable.len(), 0);
}

// ── Test 9: allow_remember with grant_to creates rule on target identity ─────

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_allow_remember_with_grant_to(pool: PgPool) {
    let mock = common::start_mock().await;
    let (base, org_key, org_id, user_id) = setup_org_with_user(pool).await;
    let client = Client::new();

    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({
            "name": "henry",
            "kind": "agent",
            "parent_id": user_id,
            "can_create_sub": true
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id: Uuid = agent["id"].as_str().unwrap().parse().unwrap();

    let subagent: Value = client
        .post(format!("{base}/v1/identities"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({
            "name": "researcher",
            "kind": "subagent",
            "parent_id": agent_id
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let subagent_id: Uuid = subagent["id"].as_str().unwrap().parse().unwrap();

    let user_key = create_api_key(&client, &base, org_id, user_id, "user-key").await;
    let sub_key = create_api_key(&client, &base, org_id, subagent_id, "sub-key").await;

    // User and Agent have rules, SubAgent does not
    for id in [user_id, agent_id] {
        client
            .post(format!("{base}/v1/permissions"))
            .header(common::auth(&org_key).0, common::auth(&org_key).1)
            .json(&json!({"identity_id": id, "action_pattern": "http:**", "effect": "allow"}))
            .send()
            .await
            .unwrap();
    }

    store_secret(&client, &base, &sub_key, "tk").await;

    // First execute → pending
    let resp = execute_action(&client, &base, &sub_key, &format!("http://{mock}/echo")).await;
    assert_eq!(resp.status(), 202);
    let approval_id = resp.json::<Value>().await.unwrap()["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    // User resolves with allow_remember + grant_to=subagent + expires_in=30d
    let resp = client
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header(common::auth(&user_key).0, common::auth(&user_key).1)
        .json(&json!({
            "decision": "allow_remember",
            "grant_to": subagent_id,
            "expires_in": "30d"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Second execute by subagent → should be auto-approved now (rule was created)
    let resp = execute_action(&client, &base, &sub_key, &format!("http://{mock}/echo")).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.json::<Value>().await.unwrap()["status"], "executed");
}

// ── Test 10: Flat identity backwards compatibility ───────────────────────────

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_flat_identity_backwards_compatible(pool: PgPool) {
    let mock = common::start_mock().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    // Use bootstrap_org_identity — creates flat identity (no parent)
    let (org_id, ident_id, api_key) = common::bootstrap_org_identity(&base, &client).await;
    let _ = (org_id, ident_id);

    store_secret(&client, &base, &api_key, "tk").await;

    // No permission rules → flat check → needs approval (202)
    let resp = execute_action(&client, &base, &api_key, &format!("http://{mock}/echo")).await;
    assert_eq!(resp.status(), 202);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "pending_approval");

    // gaps array should be empty for flat identities
    assert!(body.get("gaps").is_none() || body["gaps"].as_array().map_or(true, |a| a.is_empty()));
}

// ── Test 11: Webhook payload includes gap fields ─────────────────────────────

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_webhook_includes_gap_fields(pool: PgPool) {
    let mock = common::start_mock().await;
    let (base, org_key, org_id, user_id) = setup_org_with_user(pool).await;
    let client = Client::new();

    // Subscribe to approval events
    client
        .post(format!("{base}/v1/webhooks"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({
            "url": format!("http://{mock}/webhooks/receive"),
            "events": ["approval.created", "approval.resolved"]
        }))
        .send()
        .await
        .unwrap();

    // User → Agent (no rules → gap)
    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({
            "name": "henry",
            "kind": "agent",
            "parent_id": user_id,
            "can_create_sub": true
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id: Uuid = agent["id"].as_str().unwrap().parse().unwrap();

    let user_key = create_api_key(&client, &base, org_id, user_id, "user-key").await;
    let agent_key = create_api_key(&client, &base, org_id, agent_id, "agent-key").await;

    // User has allow, agent does not
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({"identity_id": user_id, "action_pattern": "http:**", "effect": "allow"}))
        .send()
        .await
        .unwrap();

    store_secret(&client, &base, &agent_key, "tk").await;

    // Agent executes → gap → pending approval
    let resp = execute_action(&client, &base, &agent_key, &format!("http://{mock}/echo")).await;
    assert_eq!(resp.status(), 202);
    let approval_id = resp.json::<Value>().await.unwrap()["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Wait for webhook delivery
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Check webhook payloads
    let webhooks: Value = client
        .get(format!("http://{mock}/webhooks/received"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let hooks = webhooks["webhooks"].as_array().unwrap();

    // Find approval.created webhook (payload has status=pending, gap_identity_id set)
    let created = hooks
        .iter()
        .find(|h| h["status"] == "pending" && !h["gap_identity_id"].is_null())
        .expect("approval.created webhook not received");
    assert_eq!(created["gap_identity_id"], agent_id.to_string());
    assert!(!created["can_be_handled_by"].as_array().unwrap().is_empty());

    // Now resolve and check approval.resolved webhook
    client
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header(common::auth(&user_key).0, common::auth(&user_key).1)
        .json(&json!({"decision": "allow"}))
        .send()
        .await
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let webhooks: Value = client
        .get(format!("http://{mock}/webhooks/received"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let hooks = webhooks["webhooks"].as_array().unwrap();

    let resolved = hooks
        .iter()
        .find(|h| h["status"] == "allowed" && !h["gap_identity_id"].is_null())
        .expect("approval.resolved webhook not received");
    assert_eq!(resolved["gap_identity_id"], agent_id.to_string());
}

// ── Test 12: Multiple gaps create multiple approvals ─────────────────────────

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_multiple_gaps_create_multiple_approvals(pool: PgPool) {
    let mock = common::start_mock().await;
    let (base, org_key, org_id, user_id) = setup_org_with_user(pool).await;
    let client = Client::new();

    // User(allow) → Agent(no rules, no inherit) → SubAgent(no rules, no inherit)
    // Gap at Agent + gap at SubAgent = 2 approvals
    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({
            "name": "henry",
            "kind": "agent",
            "parent_id": user_id,
            "can_create_sub": true
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id: Uuid = agent["id"].as_str().unwrap().parse().unwrap();

    let subagent: Value = client
        .post(format!("{base}/v1/identities"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({
            "name": "researcher",
            "kind": "subagent",
            "parent_id": agent_id
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let subagent_id: Uuid = subagent["id"].as_str().unwrap().parse().unwrap();

    let sub_key = create_api_key(&client, &base, org_id, subagent_id, "sub-key").await;

    // Only User has allow rules
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({"identity_id": user_id, "action_pattern": "http:**", "effect": "allow"}))
        .send()
        .await
        .unwrap();

    store_secret(&client, &base, &sub_key, "tk").await;

    // Execute → should detect 2 gaps
    let resp = execute_action(&client, &base, &sub_key, &format!("http://{mock}/echo")).await;
    assert_eq!(resp.status(), 202);

    let body: Value = resp.json().await.unwrap();
    let gaps = body["gaps"].as_array().unwrap();
    assert_eq!(gaps.len(), 2);

    // Verify both gap identities are present
    let gap_ids: Vec<&str> = gaps
        .iter()
        .map(|g| g["gap_identity_id"].as_str().unwrap())
        .collect();
    assert!(gap_ids.contains(&agent_id.to_string().as_str()));
    assert!(gap_ids.contains(&subagent_id.to_string().as_str()));
}

// ── Test 13: Cascading inheritance (SubAgent→Agent→User all covered) ─────────

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_cascading_inheritance(pool: PgPool) {
    let mock = common::start_mock().await;
    let (base, org_key, org_id, user_id) = setup_org_with_user(pool).await;
    let client = Client::new();

    // User(allow) → Agent(inherit) → SubAgent(inherit)
    // Both inherit so only User's rules matter
    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({
            "name": "henry",
            "kind": "agent",
            "parent_id": user_id,
            "inherit_permissions": true,
            "can_create_sub": true
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id: Uuid = agent["id"].as_str().unwrap().parse().unwrap();

    let subagent: Value = client
        .post(format!("{base}/v1/identities"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({
            "name": "researcher",
            "kind": "subagent",
            "parent_id": agent_id,
            "inherit_permissions": true
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let subagent_id: Uuid = subagent["id"].as_str().unwrap().parse().unwrap();

    let sub_key = create_api_key(&client, &base, org_id, subagent_id, "sub-key").await;

    // Only User has rules — Agent and SubAgent inherit
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&org_key).0, common::auth(&org_key).1)
        .json(&json!({"identity_id": user_id, "action_pattern": "http:**", "effect": "allow"}))
        .send()
        .await
        .unwrap();

    store_secret(&client, &base, &sub_key, "tk").await;

    // SubAgent executes → both levels inherit → User's rules cover → 200
    let resp = execute_action(&client, &base, &sub_key, &format!("http://{mock}/echo")).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.json::<Value>().await.unwrap()["status"], "executed");
}
