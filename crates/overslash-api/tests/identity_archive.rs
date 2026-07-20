//! Tests for the on-demand cascade-archive endpoint `POST /v1/identities/{id}/archive`.
//!
//! Covers: cascade over the descendant subtree, archived_count correctness,
//! key revocation + approval expiry, idempotent re-archive, any-kind archiving
//! (asymmetric with sub_agent-only restore), default/custom reason, 404 paths,
//! WriteAcl enforcement, and the `include_archived` filtering on the list +
//! children endpoints (default-exclude behavior).

#![allow(clippy::disallowed_methods)]

use crate::common;

use reqwest::Client;
use serde_json::{Value, json};
use uuid::Uuid;

/// Set up an org + unbound org admin key + user + agent. The unbound org key
/// carries write-level ACL (it resolves admin), matching the idle-cleanup
/// suite's use of it for `/restore`.
async fn setup_hierarchy(
    client: &Client,
    base: &str,
    slug: &str,
) -> (String, String, String, String) {
    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": format!("ArchiveOrg-{slug}"), "slug": slug}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id = org["id"].as_str().unwrap().to_string();

    let key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": &org_id, "name": "admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let api_key = key["key"].as_str().unwrap().to_string();

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
    let user_id = user["id"].as_str().unwrap().to_string();

    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": "bot", "kind": "agent", "parent_id": user_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id = agent["id"].as_str().unwrap().to_string();

    (org_id, api_key, user_id, agent_id)
}

async fn make_child(client: &Client, base: &str, key: &str, parent_id: &str, name: &str) -> Value {
    client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({"name": name, "kind": "sub_agent", "parent_id": parent_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn test_archive_cascades_over_subtree() {
    let pool = common::test_pool().await;
    let (base, client, _guard) = common::start_api_shared(pool.clone()).await;
    let base = format!("http://{base}");
    let (org_id, key, _user_id, agent_id) = setup_hierarchy(&client, &base, "cascade").await;
    let org_uuid: Uuid = org_id.parse().unwrap();

    // agent → sub → sub_sub
    let sub = make_child(&client, &base, &key, &agent_id, "sub").await;
    let sub_id = sub["id"].as_str().unwrap().to_string();
    let sub_sub = make_child(&client, &base, &key, &sub_id, "subsub").await;
    let sub_sub_id = sub_sub["id"].as_str().unwrap().to_string();

    // Archive the agent — should cascade to the whole subtree (agent + sub + sub_sub).
    let resp = client
        .post(format!("{base}/v1/identities/{agent_id}/archive"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["archived_count"], 3);
    assert_eq!(body["identity"]["id"], agent_id);
    assert!(body["identity"]["archived_at"].is_string());
    assert_eq!(body["identity"]["archived_reason"], "manual");

    // Every node in the subtree is archived in the DB.
    for id in [&agent_id, &sub_id, &sub_sub_id] {
        let uuid: Uuid = id.parse().unwrap();
        let row = overslash_db::repos::identity::get_by_id(&pool, org_uuid, uuid)
            .await
            .unwrap()
            .unwrap();
        assert!(row.archived_at.is_some(), "{id} should be archived");
    }

    // GET /v1/identities excludes archived by default; the user remains.
    let visible: Vec<Value> = client
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        visible.iter().all(|i| i["kind"] == "user"),
        "only the (live) user should remain visible, got: {visible:?}"
    );

    // ?include_archived=true returns the archived nodes again.
    let all: Vec<Value> = client
        .get(format!("{base}/v1/identities?include_archived=true"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(all.iter().any(|i| i["id"] == agent_id.as_str()));
    assert!(all.iter().any(|i| i["id"] == sub_sub_id.as_str()));
}

#[tokio::test]
async fn test_archive_children_endpoint_filtering() {
    let pool = common::test_pool().await;
    let (base, client, _guard) = common::start_api_shared(pool).await;
    let base = format!("http://{base}");
    let (_org_id, key, _user_id, agent_id) =
        setup_hierarchy(&client, &base, "children-filter").await;

    let sub = make_child(&client, &base, &key, &agent_id, "sub").await;
    let sub_id = sub["id"].as_str().unwrap().to_string();

    // Archive just the leaf sub-agent.
    let resp = client
        .post(format!("{base}/v1/identities/{sub_id}/archive"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Default: agent's children exclude the archived sub.
    let kids: Vec<Value> = client
        .get(format!("{base}/v1/identities/{agent_id}/children"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        kids.is_empty(),
        "archived child hidden by default, got: {kids:?}"
    );

    // include_archived=true reveals it.
    let kids_all: Vec<Value> = client
        .get(format!(
            "{base}/v1/identities/{agent_id}/children?include_archived=true"
        ))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(kids_all.len(), 1);
    assert_eq!(kids_all[0]["id"], sub_id);
}

#[tokio::test]
async fn test_archive_revokes_keys_and_expires_approvals() {
    let pool = common::test_pool().await;
    let (base, client, _guard) = common::start_api_shared(pool.clone()).await;
    let base = format!("http://{base}");
    let (org_id, key, _user_id, agent_id) = setup_hierarchy(&client, &base, "side-effects").await;
    let org_uuid: Uuid = org_id.parse().unwrap();

    let sub = make_child(&client, &base, &key, &agent_id, "withkeys").await;
    let sub_id: Uuid = sub["id"].as_str().unwrap().parse().unwrap();

    // Mint a key bound to the sub-agent.
    let sub_key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({"org_id": &org_id, "identity_id": sub_id, "name": "k"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let key_prefix = sub_key["key_prefix"].as_str().unwrap().to_string();

    // Create a pending approval bound to the sub-agent.
    let token = Uuid::new_v4().to_string();
    let scope = overslash_db::scopes::OrgScope::new(org_uuid, pool.clone());
    scope
        .create_approval(
            sub_id,
            sub_id,
            "test",
            None,
            None,
            None,
            &[],
            &token,
            time::OffsetDateTime::now_utc() + time::Duration::hours(2),
        )
        .await
        .unwrap();

    // Archive the sub-agent's parent (cascade reaches the sub-agent).
    let resp = client
        .post(format!("{base}/v1/identities/{agent_id}/archive"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Key revoked + tagged.
    let revoked: (Option<time::OffsetDateTime>, Option<String>) =
        sqlx::query_as("SELECT revoked_at, revoked_reason FROM api_keys WHERE key_prefix = $1")
            .bind(&key_prefix)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(revoked.0.is_some(), "key should be revoked");
    assert_eq!(revoked.1.as_deref(), Some("identity_archived"));

    // Approval expired.
    let approval = scope.get_approval_by_token(&token).await.unwrap().unwrap();
    assert_eq!(approval.status, "expired");
}

#[tokio::test]
async fn test_archive_is_idempotent() {
    let pool = common::test_pool().await;
    let (base, client, _guard) = common::start_api_shared(pool).await;
    let base = format!("http://{base}");
    let (_org_id, key, _user_id, agent_id) = setup_hierarchy(&client, &base, "idempotent").await;

    let sub = make_child(&client, &base, &key, &agent_id, "sub").await;
    let sub_id = sub["id"].as_str().unwrap().to_string();

    let first: Value = client
        .post(format!("{base}/v1/identities/{sub_id}/archive"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(first["archived_count"], 1);

    // Re-archive: still 200, but nothing newly archived.
    let resp = client
        .post(format!("{base}/v1/identities/{sub_id}/archive"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let second: Value = resp.json().await.unwrap();
    assert_eq!(second["archived_count"], 0);
    assert!(second["identity"]["archived_at"].is_string());
}

#[tokio::test]
async fn test_archive_accepts_any_kind() {
    // Unlike restore (sub_agent-only), archive accepts user/agent/sub_agent —
    // overfolder archives user identities on ghost-merge/delete.
    let pool = common::test_pool().await;
    let (base, client, _guard) = common::start_api_shared(pool).await;
    let base = format!("http://{base}");
    let (_org_id, key, user_id, agent_id) = setup_hierarchy(&client, &base, "any-kind").await;

    // Archive the agent (kind = agent).
    let resp = client
        .post(format!("{base}/v1/identities/{agent_id}/archive"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "archiving an agent must succeed");

    // Archive the user (kind = user) — cascade re-archives the already-archived
    // agent subtree (count 0 for those) but archives the user itself.
    let resp = client
        .post(format!("{base}/v1/identities/{user_id}/archive"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "archiving a user must succeed");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["identity"]["kind"], "user");
    assert_eq!(
        body["archived_count"], 1,
        "only the user was newly archived; the agent subtree was already archived"
    );
}

#[tokio::test]
async fn test_archive_default_and_custom_reason() {
    let pool = common::test_pool().await;
    let (base, client, _guard) = common::start_api_shared(pool).await;
    let base = format!("http://{base}");
    let (_org_id, key, _user_id, agent_id) = setup_hierarchy(&client, &base, "reason").await;

    let s1 = make_child(&client, &base, &key, &agent_id, "s1").await;
    let s1_id = s1["id"].as_str().unwrap().to_string();
    let s2 = make_child(&client, &base, &key, &agent_id, "s2").await;
    let s2_id = s2["id"].as_str().unwrap().to_string();

    // Bodyless POST → default reason "manual".
    let body: Value = client
        .post(format!("{base}/v1/identities/{s1_id}/archive"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["identity"]["archived_reason"], "manual");

    // Explicit reason is stored verbatim.
    let body: Value = client
        .post(format!("{base}/v1/identities/{s2_id}/archive"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({"reason": "ghost_merge"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["identity"]["archived_reason"], "ghost_merge");
}

#[tokio::test]
async fn test_archive_404_unknown_and_cross_tenant() {
    let pool = common::test_pool().await;
    let (base, client, _guard) = common::start_api_shared(pool).await;
    let base = format!("http://{base}");
    let (_org_a, key_a, _user_a, _agent_a) = setup_hierarchy(&client, &base, "arc-iso-a").await;
    let (_org_b, _key_b, _user_b, agent_b) = setup_hierarchy(&client, &base, "arc-iso-b").await;

    // Unknown id → 404.
    let bogus = Uuid::new_v4();
    let resp = client
        .post(format!("{base}/v1/identities/{bogus}/archive"))
        .header("Authorization", format!("Bearer {key_a}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // Cross-tenant id (org B's agent, org A's key) → 404.
    let resp = client
        .post(format!("{base}/v1/identities/{agent_b}/archive"))
        .header("Authorization", format!("Bearer {key_a}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_archive_requires_write_acl() {
    // A read-only caller must not be able to archive.
    let pool = common::test_pool().await;
    let (base, client, _guard) = common::start_api_shared(pool).await;
    let base = format!("http://{base}");
    let (org_id, org_key, _user_id, agent_id) = setup_hierarchy(&client, &base, "write-acl").await;

    // Build a read-only identity: own user, removed from Everyone, granted read
    // on the overslash service via a Viewers group.
    let groups: Vec<Value> = client
        .get(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {org_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let everyone_id = groups.iter().find(|g| g["name"] == "Everyone").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let ro_user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"name": "viewer", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ro_uid: Uuid = ro_user["id"].as_str().unwrap().parse().unwrap();

    let ro_key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"org_id": &org_id, "identity_id": ro_uid, "name": "ro-key"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ro_key = ro_key_resp["key"].as_str().unwrap().to_string();

    let overslash_svc: Value = client
        .get(format!("{base}/v1/services/overslash"))
        .header("Authorization", format!("Bearer {org_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let overslash_svc_id = overslash_svc["id"].as_str().unwrap().to_string();

    client
        .delete(format!("{base}/v1/groups/{everyone_id}/members/{ro_uid}"))
        .header("Authorization", format!("Bearer {org_key}"))
        .send()
        .await
        .unwrap();

    let viewers: Value = client
        .post(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"name": "Viewers"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let viewers_id = viewers["id"].as_str().unwrap().to_string();

    client
        .post(format!("{base}/v1/groups/{viewers_id}/grants"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"service_instance_id": overslash_svc_id, "access_level": "read"}))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/v1/groups/{viewers_id}/members"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"identity_id": ro_uid}))
        .send()
        .await
        .unwrap();

    // Read-only caller archiving → 403.
    let resp = client
        .post(format!("{base}/v1/identities/{agent_id}/archive"))
        .header("Authorization", format!("Bearer {ro_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Sanity: the same caller can still read.
    let resp = client
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {ro_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}
