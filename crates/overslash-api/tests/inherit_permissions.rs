//! Tests for inherit_permissions dynamic resolution.
//!
//! When an identity has inherit_permissions=true, it dynamically inherits
//! permission rules from its parent (and transitively up the chain).

mod common;

use serde_json::{Value, json};
use uuid::Uuid;

/// Execute an action as the given identity. Returns HTTP status code.
async fn execute(base: &str, api_key: &str, mock_addr: std::net::SocketAddr) -> u16 {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "method": "POST",
            "url": format!("http://{mock_addr}/echo"),
            "headers": {"Content-Type": "application/json"},
            "body": "{}",
            "secrets": [{"name": "test_token", "inject_as": "header", "header_name": "X-Token"}]
        }))
        .send()
        .await
        .unwrap();
    resp.status().as_u16()
}

// ── Test 1: Parent rule + inherit=true → allowed ────────────────────

#[tokio::test]
async fn inherit_from_parent_allows() {
    let pool = common::test_pool().await;
    let (base, org_key, user_id, agent_id, agent_key, mock_addr) =
        setup_with_pool(pool.clone()).await;
    let client = reqwest::Client::new();

    // Enable inherit_permissions on agent
    overslash_db::repos::identity::set_inherit_permissions(&pool, agent_id, true)
        .await
        .unwrap();

    // Add allow rule on the USER (parent)
    let resp = client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({
            "identity_id": user_id,
            "action_pattern": "http:**",
            "effect": "allow"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Execute as agent — should inherit parent's rule → 200
    assert_eq!(execute(&base, &agent_key, mock_addr).await, 200);
}

// ── Test 2: No inheritance → needs approval ─────────────────────────

#[tokio::test]
async fn no_inherit_needs_approval() {
    let pool = common::test_pool().await;
    let (base, org_key, user_id, _agent_id, agent_key, mock_addr) =
        setup_with_pool(pool.clone()).await;
    let client = reqwest::Client::new();

    // inherit_permissions stays false (default)

    // Add allow rule on user
    client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({
            "identity_id": user_id,
            "action_pattern": "http:**",
            "effect": "allow"
        }))
        .send()
        .await
        .unwrap();

    // Execute as agent — no own rules, no inherit → 202
    assert_eq!(execute(&base, &agent_key, mock_addr).await, 202);
}

// ── Test 3: Dynamic — parent gains rule after child creation ────────

#[tokio::test]
async fn dynamic_parent_rule_addition() {
    let pool = common::test_pool().await;
    let (base, org_key, user_id, agent_id, agent_key, mock_addr) =
        setup_with_pool(pool.clone()).await;
    let client = reqwest::Client::new();

    // Enable inherit on agent BEFORE parent has any rules
    overslash_db::repos::identity::set_inherit_permissions(&pool, agent_id, true)
        .await
        .unwrap();

    // No rules yet → 202
    assert_eq!(execute(&base, &agent_key, mock_addr).await, 202);

    // Now add a rule to the parent
    client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({
            "identity_id": user_id,
            "action_pattern": "http:**",
            "effect": "allow"
        }))
        .send()
        .await
        .unwrap();

    // Execute again — dynamically picks up parent's new rule → 200
    assert_eq!(execute(&base, &agent_key, mock_addr).await, 200);
}

// ── Test 4: Revocation — parent rule deleted → child denied ─────────

#[tokio::test]
async fn revocation_removes_inherited_access() {
    let pool = common::test_pool().await;
    let (base, org_key, user_id, agent_id, agent_key, mock_addr) =
        setup_with_pool(pool.clone()).await;
    let client = reqwest::Client::new();

    overslash_db::repos::identity::set_inherit_permissions(&pool, agent_id, true)
        .await
        .unwrap();

    // Add rule on parent
    let resp: Value = client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({
            "identity_id": user_id,
            "action_pattern": "http:**",
            "effect": "allow"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rule_id = resp["id"].as_str().unwrap();

    // Allowed
    assert_eq!(execute(&base, &agent_key, mock_addr).await, 200);

    // Delete the parent's rule
    client
        .delete(format!("{base}/v1/permissions/{rule_id}"))
        .header("Authorization", format!("Bearer {org_key}"))
        .send()
        .await
        .unwrap();

    // Now needs approval — inherited rule is gone
    assert_eq!(execute(&base, &agent_key, mock_addr).await, 202);
}

// ── Test 5: Chain inheritance (user → agent → sub_agent) ────────────

#[tokio::test]
async fn chain_inheritance_through_multiple_levels() {
    let pool = common::test_pool().await;
    let (base, org_key, user_id, agent_id, _, mock_addr) = setup_with_pool(pool.clone()).await;
    let client = reqwest::Client::new();

    // Create sub_agent under agent
    let sub: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"name": "sub-bot", "kind": "sub_agent", "parent_id": agent_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sub_id: Uuid = sub["id"].as_str().unwrap().parse().unwrap();
    let org_id: Uuid = sub["org_id"].as_str().unwrap().parse().unwrap();

    // Sub-agent API key
    let key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "identity_id": sub_id, "name": "sub-key"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sub_key = key_resp["key"].as_str().unwrap().to_string();

    // Enable inherit on both agent AND sub_agent
    overslash_db::repos::identity::set_inherit_permissions(&pool, agent_id, true)
        .await
        .unwrap();
    overslash_db::repos::identity::set_inherit_permissions(&pool, sub_id, true)
        .await
        .unwrap();

    // Rule on USER only
    client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({
            "identity_id": user_id,
            "action_pattern": "http:**",
            "effect": "allow"
        }))
        .send()
        .await
        .unwrap();

    // Sub-agent should inherit through agent → user → 200
    assert_eq!(execute(&base, &sub_key, mock_addr).await, 200);
}

// ── Test 6: Chain break — middle identity has inherit=false ─────────

#[tokio::test]
async fn chain_break_stops_inheritance() {
    let pool = common::test_pool().await;
    let (base, org_key, user_id, agent_id, _, mock_addr) = setup_with_pool(pool.clone()).await;
    let client = reqwest::Client::new();

    // Create sub_agent
    let sub: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"name": "sub-bot", "kind": "sub_agent", "parent_id": agent_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sub_id: Uuid = sub["id"].as_str().unwrap().parse().unwrap();
    let org_id: Uuid = sub["org_id"].as_str().unwrap().parse().unwrap();

    let key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "identity_id": sub_id, "name": "sub-key"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sub_key = key_resp["key"].as_str().unwrap().to_string();

    // Agent has inherit=false (default), sub_agent has inherit=true
    // So sub_agent inherits from agent, but NOT from user.
    overslash_db::repos::identity::set_inherit_permissions(&pool, sub_id, true)
        .await
        .unwrap();

    // Rule on user only — sub_agent shouldn't reach it
    client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({
            "identity_id": user_id,
            "action_pattern": "http:**",
            "effect": "allow"
        }))
        .send()
        .await
        .unwrap();

    // Sub-agent inherits from agent (empty) but NOT from user → 202
    assert_eq!(execute(&base, &sub_key, mock_addr).await, 202);
}

// ── Test 7: Deny rule propagation ───────────────────────────────────

#[tokio::test]
async fn inherited_deny_rule_blocks() {
    let pool = common::test_pool().await;
    let (base, org_key, user_id, agent_id, agent_key, mock_addr) =
        setup_with_pool(pool.clone()).await;
    let client = reqwest::Client::new();

    overslash_db::repos::identity::set_inherit_permissions(&pool, agent_id, true)
        .await
        .unwrap();

    // Add allow rule on agent itself
    client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({
            "identity_id": agent_id,
            "action_pattern": "http:**",
            "effect": "allow"
        }))
        .send()
        .await
        .unwrap();

    // Add deny rule on user (parent)
    client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({
            "identity_id": user_id,
            "action_pattern": "http:POST:**",
            "effect": "deny"
        }))
        .send()
        .await
        .unwrap();

    // Deny from parent overrides allow from self → 403
    assert_eq!(execute(&base, &agent_key, mock_addr).await, 403);
}

// ── Shared setup that accepts a pool ────────────────────────────────

/// Like `setup()` but accepts a pool so tests can also use it directly for DB operations.
async fn setup_with_pool(
    pool: sqlx::PgPool,
) -> (String, String, Uuid, Uuid, String, std::net::SocketAddr) {
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let mock_addr = common::start_mock().await;

    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "InheritOrg", "slug": format!("inh-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();

    let org_key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "org-admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_api_key = org_key["key"].as_str().unwrap().to_string();

    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_api_key}"))
        .json(&json!({"name": "alice", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id: Uuid = user["id"].as_str().unwrap().parse().unwrap();

    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_api_key}"))
        .json(&json!({"name": "bot", "kind": "agent", "parent_id": user_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id: Uuid = agent["id"].as_str().unwrap().parse().unwrap();

    let key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "identity_id": agent_id, "name": "agent-key"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_api_key = key_resp["key"].as_str().unwrap().to_string();

    // Create secret to trigger permission gating
    client
        .put(format!("{base}/v1/secrets/test_token"))
        .header("Authorization", format!("Bearer {org_api_key}"))
        .json(&json!({"value": "secret123"}))
        .send()
        .await
        .unwrap();

    (
        base,
        org_api_key,
        user_id,
        agent_id,
        agent_api_key,
        mock_addr,
    )
}
