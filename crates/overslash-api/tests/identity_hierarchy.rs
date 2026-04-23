//! Tests for identity hierarchy: parent/child relationships, depth tracking, ancestor chains.

mod common;

use serde_json::{Value, json};

#[tokio::test]
async fn test_create_user_identity() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");

    // Create org + org-level key
    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "HierOrg", "slug": "hier-org"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id = org["id"].as_str().unwrap();

    let key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let api_key = key["key"].as_str().unwrap();

    // Create user — no parent, depth=0
    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "alice", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(user["kind"], "user");
    assert_eq!(user["depth"], 0);
    assert!(user["parent_id"].is_null());
    assert!(user["owner_id"].is_null());
    assert_eq!(user["inherit_permissions"], false);
}

#[tokio::test]
async fn test_create_agent_with_user_parent() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");

    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "HierOrg2", "slug": "hier-org-2"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id = org["id"].as_str().unwrap();

    let key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let api_key = key["key"].as_str().unwrap();

    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "alice", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = user["id"].as_str().unwrap();

    // Create agent with user parent
    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "henry", "kind": "agent", "parent_id": user_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(agent["kind"], "agent");
    assert_eq!(agent["depth"], 1);
    assert_eq!(agent["parent_id"], user_id);
    assert_eq!(agent["owner_id"], user_id);
}

#[tokio::test]
async fn test_create_agent_without_parent_fails() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");

    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "O", "slug": "no-parent-test"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id = org["id"].as_str().unwrap();

    let key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let api_key = key["key"].as_str().unwrap();

    let resp = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "orphan", "kind": "agent"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_create_agent_with_nonexistent_parent_fails() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");

    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "O", "slug": "bad-parent-test"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id = org["id"].as_str().unwrap();

    let key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let api_key = key["key"].as_str().unwrap();

    let resp = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "orphan", "kind": "agent", "parent_id": "00000000-0000-0000-0000-000000000000"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_create_agent_with_agent_parent_fails() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");

    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "O", "slug": "agent-parent-test"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id = org["id"].as_str().unwrap();

    let key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let api_key = key["key"].as_str().unwrap();

    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "alice", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = user["id"].as_str().unwrap();

    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "henry", "kind": "agent", "parent_id": user_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id = agent["id"].as_str().unwrap();

    // Agent with agent parent should fail (must be user)
    let resp = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "bad", "kind": "agent", "parent_id": agent_id}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_create_sub_agent() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");

    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "O", "slug": "sub-agent-test"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id = org["id"].as_str().unwrap();

    let key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let api_key = key["key"].as_str().unwrap();

    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "alice", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = user["id"].as_str().unwrap();

    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "henry", "kind": "agent", "parent_id": user_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id = agent["id"].as_str().unwrap();

    // Create sub_agent under agent
    let sub: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "researcher", "kind": "sub_agent", "parent_id": agent_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(sub["kind"], "sub_agent");
    assert_eq!(sub["depth"], 2);
    assert_eq!(sub["parent_id"], agent_id);
    assert_eq!(sub["owner_id"], user_id); // owner propagates from agent
}

#[tokio::test]
async fn test_create_sub_agent_with_user_parent_fails() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");

    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "O", "slug": "sub-user-fail"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id = org["id"].as_str().unwrap();

    let key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let api_key = key["key"].as_str().unwrap();

    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "alice", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = user["id"].as_str().unwrap();

    let resp = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "bad-sub", "kind": "sub_agent", "parent_id": user_id}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_create_user_with_parent_fails() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");

    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "O", "slug": "user-parent-fail"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id = org["id"].as_str().unwrap();

    let key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let api_key = key["key"].as_str().unwrap();

    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "alice", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = user["id"].as_str().unwrap();

    let resp = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "bob", "kind": "user", "parent_id": user_id}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_ancestor_chain() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");

    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "O", "slug": "ancestor-test"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id = org["id"].as_str().unwrap();

    let key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let api_key = key["key"].as_str().unwrap();

    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "alice", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = user["id"].as_str().unwrap();

    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "henry", "kind": "agent", "parent_id": user_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id = agent["id"].as_str().unwrap();

    let sub: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "researcher", "kind": "sub_agent", "parent_id": agent_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sub_id = sub["id"].as_str().unwrap();

    // Get ancestor chain from sub_agent
    let chain: Vec<Value> = client
        .get(format!("{base}/v1/identities/{sub_id}/chain"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(chain.len(), 3);
    assert_eq!(chain[0]["kind"], "user");
    assert_eq!(chain[0]["depth"], 0);
    assert_eq!(chain[1]["kind"], "agent");
    assert_eq!(chain[1]["depth"], 1);
    assert_eq!(chain[2]["kind"], "sub_agent");
    assert_eq!(chain[2]["depth"], 2);
}

#[tokio::test]
async fn test_list_children() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");

    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "O", "slug": "children-test"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id = org["id"].as_str().unwrap();

    let key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let api_key = key["key"].as_str().unwrap();

    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "alice", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = user["id"].as_str().unwrap();

    // Create two agents under user
    let _a1: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "agent1", "kind": "agent", "parent_id": user_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let _a2: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "agent2", "kind": "agent", "parent_id": user_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let children: Vec<Value> = client
        .get(format!("{base}/v1/identities/{user_id}/children"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(children.len(), 2);
    assert!(children.iter().all(|c| c["kind"] == "agent"));
}

#[tokio::test]
async fn test_delete_parent_cascades_children() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{base}");

    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "O", "slug": "cascade-test"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id = org["id"].as_str().unwrap();

    let key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let api_key = key["key"].as_str().unwrap();

    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "alice", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = user["id"].as_str().unwrap();

    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "henry", "kind": "agent", "parent_id": user_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id = agent["id"].as_str().unwrap();

    let _sub: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "researcher", "kind": "sub_agent", "parent_id": agent_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Delete agent — sub_agent should cascade
    overslash_db::OrgScope::new(org_id.parse().unwrap(), pool.clone())
        .delete_identity(agent_id.parse().unwrap())
        .await
        .unwrap();

    // List all identities — only user should remain
    let all: Vec<Value> = client
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Two users remain: the bootstrap admin (auto-created by the unauth
    // POST /v1/api-keys path) and "alice", the test's own user.
    assert_eq!(all.len(), 2);
    assert!(all.iter().all(|c| c["kind"] == "user"));
}

#[tokio::test]
async fn test_nested_sub_agents() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");

    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "O", "slug": "nested-sub-test"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id = org["id"].as_str().unwrap();

    let key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let api_key = key["key"].as_str().unwrap();

    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "alice", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = user["id"].as_str().unwrap();

    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "henry", "kind": "agent", "parent_id": user_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id = agent["id"].as_str().unwrap();

    let sub1: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "sub1", "kind": "sub_agent", "parent_id": agent_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sub1_id = sub1["id"].as_str().unwrap();

    // Sub-agent under sub-agent (depth=3)
    let sub2: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "sub2", "kind": "sub_agent", "parent_id": sub1_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(sub2["depth"], 3);
    assert_eq!(sub2["parent_id"], sub1_id);
    assert_eq!(sub2["owner_id"], user_id); // owner propagates through chain
}

// ─── PATCH / DELETE / filter coverage (PR #79) ────────────────────────────

async fn bootstrap_admin(client: &reqwest::Client, base: &str, slug: &str) -> String {
    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "T", "slug": slug}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id = org["id"].as_str().unwrap().to_string();
    let key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    key["key"].as_str().unwrap().to_string()
}

async fn create_identity_helper(
    client: &reqwest::Client,
    base: &str,
    api_key: &str,
    body: serde_json::Value,
) -> Value {
    client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn test_patch_rename_identity() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let api_key = bootstrap_admin(&client, &base, "patch-rename").await;

    let user = create_identity_helper(
        &client,
        &base,
        &api_key,
        json!({"name": "alice", "kind": "user"}),
    )
    .await;
    let id = user["id"].as_str().unwrap();

    let res = client
        .patch(format!("{base}/v1/identities/{id}"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "alice2"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["name"], "alice2");
}

#[tokio::test]
async fn test_patch_rename_empty_name_rejected() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let api_key = bootstrap_admin(&client, &base, "patch-rename-empty").await;

    let user = create_identity_helper(
        &client,
        &base,
        &api_key,
        json!({"name": "alice", "kind": "user"}),
    )
    .await;
    let id = user["id"].as_str().unwrap();

    let res = client
        .patch(format!("{base}/v1/identities/{id}"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "   "}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn test_patch_rename_trims_whitespace() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let api_key = bootstrap_admin(&client, &base, "patch-rename-trim").await;

    let user = create_identity_helper(
        &client,
        &base,
        &api_key,
        json!({"name": "alice", "kind": "user"}),
    )
    .await;
    let id = user["id"].as_str().unwrap();

    let res: Value = client
        .patch(format!("{base}/v1/identities/{id}"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "  alice2  "}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(res["name"], "alice2");
}

#[tokio::test]
async fn test_patch_move_user_rejected() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let api_key = bootstrap_admin(&client, &base, "patch-move-user").await;

    let user = create_identity_helper(
        &client,
        &base,
        &api_key,
        json!({"name": "alice", "kind": "user"}),
    )
    .await;
    let other = create_identity_helper(
        &client,
        &base,
        &api_key,
        json!({"name": "bob", "kind": "user"}),
    )
    .await;
    let id = user["id"].as_str().unwrap();
    let other_id = other["id"].as_str().unwrap();

    let res = client
        .patch(format!("{base}/v1/identities/{id}"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"parent_id": other_id}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn test_patch_move_agent_updates_descendants() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let api_key = bootstrap_admin(&client, &base, "patch-move-cascade").await;

    let alice = create_identity_helper(
        &client,
        &base,
        &api_key,
        json!({"name": "alice", "kind": "user"}),
    )
    .await;
    let bob = create_identity_helper(
        &client,
        &base,
        &api_key,
        json!({"name": "bob", "kind": "user"}),
    )
    .await;
    let alice_id = alice["id"].as_str().unwrap();
    let bob_id = bob["id"].as_str().unwrap();

    // Build alice → agent → sub → sub2
    let agent = create_identity_helper(
        &client,
        &base,
        &api_key,
        json!({"name": "henry", "kind": "agent", "parent_id": alice_id}),
    )
    .await;
    let agent_id = agent["id"].as_str().unwrap();
    let sub = create_identity_helper(
        &client,
        &base,
        &api_key,
        json!({"name": "s1", "kind": "sub_agent", "parent_id": agent_id}),
    )
    .await;
    let sub_id = sub["id"].as_str().unwrap();
    let sub2 = create_identity_helper(
        &client,
        &base,
        &api_key,
        json!({"name": "s2", "kind": "sub_agent", "parent_id": sub_id}),
    )
    .await;
    let sub2_id = sub2["id"].as_str().unwrap();

    assert_eq!(sub["owner_id"].as_str().unwrap(), alice_id);
    assert_eq!(sub2["owner_id"].as_str().unwrap(), alice_id);
    assert_eq!(sub2["depth"], 3);

    // Move agent under bob — descendants must be reparented (owner_id) and
    // keep their depth offsets (depth stays the same here since both users
    // are at depth 0).
    let moved = client
        .patch(format!("{base}/v1/identities/{agent_id}"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"parent_id": bob_id}))
        .send()
        .await
        .unwrap();
    assert_eq!(moved.status(), 200);
    let moved: Value = moved.json().await.unwrap();
    assert_eq!(moved["parent_id"].as_str().unwrap(), bob_id);
    assert_eq!(moved["owner_id"].as_str().unwrap(), bob_id);

    // Re-fetch descendants and verify owner_id was rewritten.
    let all: Vec<Value> = client
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let by_id = |target: &str| {
        all.iter()
            .find(|i| i["id"].as_str() == Some(target))
            .cloned()
            .unwrap()
    };
    assert_eq!(by_id(sub_id)["owner_id"].as_str().unwrap(), bob_id);
    assert_eq!(by_id(sub2_id)["owner_id"].as_str().unwrap(), bob_id);
    assert_eq!(by_id(sub2_id)["depth"], 3);
}

#[tokio::test]
async fn test_patch_move_cycle_rejected() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let api_key = bootstrap_admin(&client, &base, "patch-move-cycle").await;

    let user = create_identity_helper(
        &client,
        &base,
        &api_key,
        json!({"name": "alice", "kind": "user"}),
    )
    .await;
    let user_id = user["id"].as_str().unwrap();
    let agent = create_identity_helper(
        &client,
        &base,
        &api_key,
        json!({"name": "henry", "kind": "agent", "parent_id": user_id}),
    )
    .await;
    let agent_id = agent["id"].as_str().unwrap();
    let sub = create_identity_helper(
        &client,
        &base,
        &api_key,
        json!({"name": "s1", "kind": "sub_agent", "parent_id": agent_id}),
    )
    .await;
    let sub_id = sub["id"].as_str().unwrap();

    // Try to move sub under agent again — fine. Try to move agent under sub
    // (its own descendant) — must be rejected.
    let res = client
        .patch(format!("{base}/v1/identities/{agent_id}"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"parent_id": sub_id}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn test_patch_inherit_permissions_toggle() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let api_key = bootstrap_admin(&client, &base, "patch-inherit").await;

    let user = create_identity_helper(
        &client,
        &base,
        &api_key,
        json!({"name": "alice", "kind": "user"}),
    )
    .await;
    let user_id = user["id"].as_str().unwrap();
    let agent = create_identity_helper(
        &client,
        &base,
        &api_key,
        json!({"name": "henry", "kind": "agent", "parent_id": user_id}),
    )
    .await;
    let agent_id = agent["id"].as_str().unwrap();

    let res: Value = client
        .patch(format!("{base}/v1/identities/{agent_id}"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"inherit_permissions": true}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(res["inherit_permissions"], true);

    let res: Value = client
        .patch(format!("{base}/v1/identities/{agent_id}"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"inherit_permissions": false}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(res["inherit_permissions"], false);
}

#[tokio::test]
async fn test_delete_blocked_when_children_exist() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let api_key = bootstrap_admin(&client, &base, "delete-blocked").await;

    let user = create_identity_helper(
        &client,
        &base,
        &api_key,
        json!({"name": "alice", "kind": "user"}),
    )
    .await;
    let user_id = user["id"].as_str().unwrap();
    let _agent = create_identity_helper(
        &client,
        &base,
        &api_key,
        json!({"name": "henry", "kind": "agent", "parent_id": user_id}),
    )
    .await;

    let res = client
        .delete(format!("{base}/v1/identities/{user_id}"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 409);
}

#[tokio::test]
async fn test_delete_leaf_succeeds() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let api_key = bootstrap_admin(&client, &base, "delete-leaf").await;

    let user = create_identity_helper(
        &client,
        &base,
        &api_key,
        json!({"name": "alice", "kind": "user"}),
    )
    .await;
    let user_id = user["id"].as_str().unwrap();
    let agent = create_identity_helper(
        &client,
        &base,
        &api_key,
        json!({"name": "henry", "kind": "agent", "parent_id": user_id}),
    )
    .await;
    let agent_id = agent["id"].as_str().unwrap();

    let res = client
        .delete(format!("{base}/v1/identities/{agent_id}"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);

    // user is now a leaf and can be deleted
    let res = client
        .delete(format!("{base}/v1/identities/{user_id}"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);
}

#[tokio::test]
async fn test_approvals_filter_by_identity_cross_org_rejected() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");

    let key_a = bootstrap_admin(&client, &base, "approvals-org-a").await;
    let key_b = bootstrap_admin(&client, &base, "approvals-org-b").await;

    // identity in org A
    let user_a = create_identity_helper(
        &client,
        &base,
        &key_a,
        json!({"name": "alice", "kind": "user"}),
    )
    .await;
    let user_a_id = user_a["id"].as_str().unwrap();

    // org B caller asks for org A's identity → 404
    let res = client
        .get(format!("{base}/v1/approvals?identity_id={user_a_id}"))
        .header("Authorization", format!("Bearer {key_b}"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}

#[tokio::test]
async fn test_permissions_filter_by_identity_cross_org_rejected() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");

    let key_a = bootstrap_admin(&client, &base, "perms-org-a").await;
    let key_b = bootstrap_admin(&client, &base, "perms-org-b").await;

    let user_a = create_identity_helper(
        &client,
        &base,
        &key_a,
        json!({"name": "alice", "kind": "user"}),
    )
    .await;
    let user_a_id = user_a["id"].as_str().unwrap();

    let res = client
        .get(format!("{base}/v1/permissions?identity_id={user_a_id}"))
        .header("Authorization", format!("Bearer {key_b}"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}
