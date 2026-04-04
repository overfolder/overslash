//! Tests for identity hierarchy: parent/child relationships, depth tracking, ancestor chains.

mod common;

use serde_json::{Value, json};
use sqlx::PgPool;

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_create_user_identity(pool: PgPool) {
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

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_create_agent_with_user_parent(pool: PgPool) {
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

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_create_agent_without_parent_fails(pool: PgPool) {
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

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_create_agent_with_nonexistent_parent_fails(pool: PgPool) {
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

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_create_agent_with_agent_parent_fails(pool: PgPool) {
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

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_create_sub_agent(pool: PgPool) {
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

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_create_sub_agent_with_user_parent_fails(pool: PgPool) {
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

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_create_user_with_parent_fails(pool: PgPool) {
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

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_ancestor_chain(pool: PgPool) {
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

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_list_children(pool: PgPool) {
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

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_delete_parent_cascades_children(pool: PgPool) {
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
    overslash_db::repos::identity::delete(&pool, agent_id.parse().unwrap())
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

    assert_eq!(all.len(), 1);
    assert_eq!(all[0]["kind"], "user");
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_nested_sub_agents(pool: PgPool) {
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
