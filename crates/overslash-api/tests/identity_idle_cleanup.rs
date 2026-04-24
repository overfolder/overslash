//! Tests for sub-agent idle cleanup with two-phase archive (SPEC §4).
//!
//! Covers: creation, last_active_at touching, archive pass, archive of API keys
//! and pending approvals, archived auth rejection, parent waits for live
//! children, restore (resurrects auto-revoked keys but not manually-revoked
//! ones), purge after retention, purge waits for children, multi-pass drain,
//! per-org config, users/agents never archived, validation bounds.

// Test setup needs dynamic SQL for forcing org config + last_active_at backdating.
#![allow(clippy::disallowed_methods)]

mod common;

use serde_json::{Value, json};
use uuid::Uuid;

/// Set up an org + admin api key + user + agent. Returns (org_id, admin_api_key, agent_id).
async fn setup_hierarchy(
    client: &reqwest::Client,
    base: &str,
    slug: &str,
) -> (String, String, String) {
    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": format!("IdleOrg-{slug}"), "slug": slug}))
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
    let user_id = user["id"].as_str().unwrap();

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

    (org_id, api_key, agent_id)
}

/// Create an api key bound to an identity, authenticated with the org admin key.
/// (Master gated key creation behind ACL admin in the org-acl PR.)
async fn make_sub_key(
    client: &reqwest::Client,
    base: &str,
    admin_key: &str,
    org_id: &str,
    identity_id: Uuid,
    name: &str,
) -> Value {
    client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "org_id": org_id,
            "identity_id": identity_id,
            "name": name,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn make_subagent(
    client: &reqwest::Client,
    base: &str,
    api_key: &str,
    parent_id: &str,
    name: &str,
) -> Value {
    client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"name": name, "kind": "sub_agent", "parent_id": parent_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// Force the org's idle timeout (and optionally retention) to a small value
/// directly via SQL. The HTTP endpoint enforces a 4h floor; tests need to
/// trigger archives in seconds, so they bypass it via SQL.
async fn force_org_config(pool: &sqlx::PgPool, org_id: Uuid, idle_secs: i32, retention_days: i32) {
    sqlx::query("UPDATE orgs SET subagent_idle_timeout_secs = $2, subagent_archive_retention_days = $3 WHERE id = $1")
        .bind(org_id)
        .bind(idle_secs)
        .bind(retention_days)
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_create_subagent_has_active_state() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (_org, api_key, agent_id) = setup_hierarchy(&client, &base, "create-active").await;

    let sub = make_subagent(&client, &base, &api_key, &agent_id, "fresh").await;

    assert_eq!(sub["kind"], "sub_agent");
    assert!(sub["last_active_at"].is_string());
    assert!(
        sub.get("archived_at").is_none() || sub["archived_at"].is_null(),
        "fresh sub-agent must not be archived"
    );
}

#[tokio::test]
async fn test_authenticated_request_touches_last_active_at() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{base}");
    let (org_id, admin_key, agent_id) = setup_hierarchy(&client, &base, "touch-active").await;

    let sub = make_subagent(&client, &base, &admin_key, &agent_id, "touchy").await;
    let sub_id: Uuid = sub["id"].as_str().unwrap().parse().unwrap();

    // Mint a key bound to the sub-agent
    let sub_key = make_sub_key(&client, &base, &admin_key, &org_id, sub_id, "sub-key").await;
    let sub_key_str = sub_key["key"].as_str().unwrap().to_string();

    // Push last_active_at into the past so we can detect a fresh touch
    sqlx::query("UPDATE identities SET last_active_at = now() - interval '1 hour' WHERE id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .unwrap();

    // Authenticated request — list identities — should bump last_active_at
    let resp = client
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {sub_key_str}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Spawned touch is fire-and-forget; allow it a moment.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let last_active: time::OffsetDateTime =
        sqlx::query_scalar("SELECT last_active_at FROM identities WHERE id = $1")
            .bind(sub_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let age = time::OffsetDateTime::now_utc() - last_active;
    assert!(
        age < time::Duration::seconds(10),
        "last_active_at should be fresh, was {age:?} ago"
    );
}

#[tokio::test]
async fn test_archive_pass_archives_idle_subagents() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{base}");
    let (org_id, admin_key, agent_id) = setup_hierarchy(&client, &base, "archive-pass").await;
    let org_uuid: Uuid = org_id.parse().unwrap();

    let sub = make_subagent(&client, &base, &admin_key, &agent_id, "idler").await;
    let sub_id: Uuid = sub["id"].as_str().unwrap().parse().unwrap();

    // Force a tiny idle timeout and push activity backward.
    force_org_config(&pool, org_uuid, 60, 30).await;
    sqlx::query("UPDATE identities SET last_active_at = now() - interval '2 hours' WHERE id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .unwrap();

    let archived = overslash_db::repos::identity::archive_idle_subagents(&pool)
        .await
        .unwrap();
    assert_eq!(archived, 1);

    let row = overslash_db::repos::identity::get_by_id(&pool, org_uuid, sub_id)
        .await
        .unwrap()
        .unwrap();
    assert!(row.archived_at.is_some());
    assert_eq!(row.archived_reason.as_deref(), Some("idle_timeout"));
}

#[tokio::test]
async fn test_archive_revokes_api_keys_and_expires_approvals() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{base}");
    let (org_id, admin_key, agent_id) =
        setup_hierarchy(&client, &base, "archive-side-effects").await;
    let org_uuid: Uuid = org_id.parse().unwrap();

    let sub = make_subagent(&client, &base, &admin_key, &agent_id, "with-keys").await;
    let sub_id: Uuid = sub["id"].as_str().unwrap().parse().unwrap();

    // Mint API key
    let sub_key = make_sub_key(&client, &base, &admin_key, &org_id, sub_id, "k").await;
    let key_prefix = sub_key["key_prefix"].as_str().unwrap().to_string();

    // Create a pending approval bound to the sub-agent
    let token = Uuid::new_v4().to_string();
    let test_scope = overslash_db::scopes::OrgScope::new(org_uuid, pool.clone());
    test_scope
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

    // Make idle and archive
    force_org_config(&pool, org_uuid, 60, 30).await;
    sqlx::query("UPDATE identities SET last_active_at = now() - interval '2 hours' WHERE id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .unwrap();
    overslash_db::repos::identity::archive_idle_subagents(&pool)
        .await
        .unwrap();

    // API key should be revoked AND tagged with revoked_reason
    let revoked: (Option<time::OffsetDateTime>, Option<String>) =
        sqlx::query_as("SELECT revoked_at, revoked_reason FROM api_keys WHERE key_prefix = $1")
            .bind(&key_prefix)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(revoked.0.is_some(), "key should be revoked");
    assert_eq!(revoked.1.as_deref(), Some("identity_archived"));

    // Lookup that excludes revoked → not found
    let found = overslash_db::SystemScope::new_internal(pool.clone())
        .find_api_key_by_prefix(&key_prefix)
        .await
        .unwrap();
    assert!(found.is_none(), "revoked key should not be findable");

    // Approval should be marked expired
    let approval = test_scope
        .get_approval_by_token(&token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(approval.status, "expired");
}

#[tokio::test]
async fn test_archived_identity_auth_rejected_with_403() {
    // Realistic flow: background loop archives a sub-agent and auto-revokes its
    // keys with reason='identity_archived'. The client's still-cached key should
    // get a clear 403 with restore hints, NOT a 401.
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{base}");
    let (org_id, admin_key, agent_id) = setup_hierarchy(&client, &base, "archived-auth").await;
    let org_uuid: Uuid = org_id.parse().unwrap();

    let sub = make_subagent(&client, &base, &admin_key, &agent_id, "doomed").await;
    let sub_id: Uuid = sub["id"].as_str().unwrap().parse().unwrap();

    let sub_key = make_sub_key(&client, &base, &admin_key, &org_id, sub_id, "k").await;
    let sub_key_str = sub_key["key"].as_str().unwrap().to_string();

    // Force idle and run the actual archive pass — this is the realistic path.
    force_org_config(&pool, org_uuid, 60, 30).await;
    sqlx::query("UPDATE identities SET last_active_at = now() - interval '2 hours' WHERE id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .unwrap();
    overslash_db::repos::identity::archive_idle_subagents(&pool)
        .await
        .unwrap();

    // Original key auto-revoked by archive → expect 403 with restore hints,
    // not a misleading 401.
    let resp = client
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {sub_key_str}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "identity_archived");
    assert_eq!(body["reason"], "idle_timeout");
    assert!(body["restorable_until"].is_string());
    // identity_id is included so clients don't have to track it themselves.
    assert_eq!(body["identity_id"].as_str().unwrap(), sub_id.to_string());
    // The hint embeds the actual UUID — no literal `{id}` placeholder.
    let hint = body["hint"].as_str().unwrap_or("");
    assert!(
        hint.contains(&sub_id.to_string()),
        "hint should embed the actual identity id, got: {hint}"
    );
    assert!(hint.contains("/restore"), "hint should mention restore");
    assert!(
        !hint.contains("{id}"),
        "hint must not contain literal {{id}} placeholder"
    );
}

#[tokio::test]
async fn test_cannot_restore_child_under_archived_parent() {
    // Regression: restoring a child under an archived parent would re-create
    // a live child, permanently blocking the parent from being purged.
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{base}");
    let (_org_id, admin_key, agent_id) =
        setup_hierarchy(&client, &base, "restore-under-archived").await;
    let org_uuid: Uuid = _org_id.parse().unwrap();

    // Build parent → child sub-agents.
    let parent_sub = make_subagent(&client, &base, &admin_key, &agent_id, "p").await;
    let parent_str = parent_sub["id"].as_str().unwrap().to_string();
    let parent_uuid: Uuid = parent_str.parse().unwrap();
    let child_sub = make_subagent(&client, &base, &admin_key, &parent_str, "c").await;
    let child_str = child_sub["id"].as_str().unwrap().to_string();
    let child_uuid: Uuid = child_str.parse().unwrap();

    // Archive child first (it has no children of its own), then archive parent.
    force_org_config(&pool, org_uuid, 60, 30).await;
    sqlx::query(
        "UPDATE identities SET last_active_at = now() - interval '2 hours' WHERE id = ANY($1)",
    )
    .bind(vec![parent_uuid, child_uuid])
    .execute(&pool)
    .await
    .unwrap();
    overslash_db::repos::identity::archive_idle_subagents(&pool)
        .await
        .unwrap(); // archives child (parent still has live child snapshot)
    overslash_db::repos::identity::archive_idle_subagents(&pool)
        .await
        .unwrap(); // archives parent

    // Restoring the child while parent is still archived must be rejected.
    let resp = client
        .post(format!("{base}/v1/identities/{child_str}/restore"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap_or("")
            .contains("parent is archived"),
        "error should mention archived parent, got: {body}"
    );

    // After restoring the parent, the child can be restored.
    let resp = client
        .post(format!("{base}/v1/identities/{parent_str}/restore"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = client
        .post(format!("{base}/v1/identities/{child_str}/restore"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_cannot_create_subagent_under_archived_parent() {
    // Regression: a child born under an archived parent would (a) be
    // immediately non-functional and (b) block the parent from ever being
    // purged because purge requires NO remaining children.
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{base}");
    let (org_id, admin_key, agent_id) =
        setup_hierarchy(&client, &base, "no-child-on-archived").await;
    let org_uuid: Uuid = org_id.parse().unwrap();

    let parent_sub = make_subagent(&client, &base, &admin_key, &agent_id, "p").await;
    let parent_id_str = parent_sub["id"].as_str().unwrap().to_string();
    let parent_uuid: Uuid = parent_id_str.parse().unwrap();

    // Archive the parent
    force_org_config(&pool, org_uuid, 60, 30).await;
    sqlx::query("UPDATE identities SET last_active_at = now() - interval '2 hours' WHERE id = $1")
        .bind(parent_uuid)
        .execute(&pool)
        .await
        .unwrap();
    overslash_db::repos::identity::archive_idle_subagents(&pool)
        .await
        .unwrap();

    // Try to create a sub-agent under the archived parent → 400
    let resp = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "name": "child",
            "kind": "sub_agent",
            "parent_id": parent_id_str
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap_or("").contains("archived"),
        "error should mention 'archived', got: {body}"
    );

    // After restore, creation should succeed.
    let resp = client
        .post(format!("{base}/v1/identities/{parent_id_str}/restore"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "name": "child",
            "kind": "sub_agent",
            "parent_id": parent_id_str
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

// (Removed) test_purged_identity_orphan_key_does_not_authenticate
// Migration 028 changed api_keys.identity_id from `ON DELETE SET NULL` to
// `ON DELETE CASCADE`, so the orphaned-NULL-identity scenario this test
// guarded against can no longer arise: when an identity is purged its api
// keys are deleted alongside it.

#[tokio::test]
async fn test_archived_identity_takes_precedence_over_key_expiry() {
    // Regression: a sub-agent whose API key has its own expires_at in the past
    // AND whose identity is archived should still see the actionable
    // 403 identity_archived (with restore hint), not 401 api_key_expired.
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{base}");
    let (org_id, admin_key, agent_id) =
        setup_hierarchy(&client, &base, "archived-vs-expired").await;
    let org_uuid: Uuid = org_id.parse().unwrap();

    let sub = make_subagent(&client, &base, &admin_key, &agent_id, "doomed").await;
    let sub_id: Uuid = sub["id"].as_str().unwrap().parse().unwrap();

    let sub_key = make_sub_key(&client, &base, &admin_key, &org_id, sub_id, "k").await;
    let key_id: Uuid = sub_key["id"].as_str().unwrap().parse().unwrap();
    let key_str = sub_key["key"].as_str().unwrap().to_string();

    // Set the key's own absolute expiry to the past
    sqlx::query("UPDATE api_keys SET expires_at = now() - interval '1 hour' WHERE id = $1")
        .bind(key_id)
        .execute(&pool)
        .await
        .unwrap();

    // Archive the identity
    force_org_config(&pool, org_uuid, 60, 30).await;
    sqlx::query("UPDATE identities SET last_active_at = now() - interval '2 hours' WHERE id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .unwrap();
    overslash_db::repos::identity::archive_idle_subagents(&pool)
        .await
        .unwrap();

    let resp = client
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {key_str}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "identity_archived");
}

#[tokio::test]
async fn test_archived_identity_resolves_for_rate_limit_charging() {
    // Sentry-flagged regression: the rate-limit middleware used find_by_prefix
    // (which excludes auto-revoked keys), so requests bound to archived
    // identities skipped rate limiting entirely — an attacker holding a stolen
    // key for an archived identity could hammer the gateway uncharged.
    //
    // This test pins the contract used by the middleware: after archive,
    // looking up the api_key by prefix with the inclusive variant must still
    // return a row whose identity_id is set, so the bucket can be charged
    // before auth eventually rejects with 403.
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{base}");
    let (org_id, admin_key, agent_id) = setup_hierarchy(&client, &base, "rl-archived").await;
    let org_uuid: Uuid = org_id.parse().unwrap();

    let sub = make_subagent(&client, &base, &admin_key, &agent_id, "doomed").await;
    let sub_id: Uuid = sub["id"].as_str().unwrap().parse().unwrap();
    let sub_key = make_sub_key(&client, &base, &admin_key, &org_id, sub_id, "k").await;
    let prefix = sub_key["key_prefix"].as_str().unwrap().to_string();

    // Archive the sub-agent — auto-revokes its API key with reason='identity_archived'.
    force_org_config(&pool, org_uuid, 60, 30).await;
    sqlx::query("UPDATE identities SET last_active_at = now() - interval '2 hours' WHERE id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .unwrap();
    overslash_db::repos::identity::archive_idle_subagents(&pool)
        .await
        .unwrap();

    // Pre-fix behavior: find_by_prefix filters out revoked keys → None.
    // The middleware would then skip rate limiting entirely.
    let exclusive = overslash_db::SystemScope::new_internal(pool.clone())
        .find_api_key_by_prefix(&prefix)
        .await
        .unwrap();
    assert!(
        exclusive.is_none(),
        "find_by_prefix must continue to hide revoked keys"
    );

    // Post-fix behavior: find_by_prefix_including_archived returns the row, so
    // the rate-limit middleware can charge the bucket on the resolved identity.
    let inclusive = overslash_db::SystemScope::new_internal(pool.clone())
        .find_api_key_by_prefix_including_archived(&prefix)
        .await
        .unwrap()
        .expect("auto-revoked key must be visible to the rate-limit lookup");
    assert_eq!(inclusive.identity_id, sub_id);
    assert!(inclusive.revoked_at.is_some());
    assert_eq!(
        inclusive.revoked_reason.as_deref(),
        Some("identity_archived")
    );
}

#[tokio::test]
async fn test_manually_revoked_key_returns_401_not_403() {
    // A manually-revoked key (revoked_reason IS NULL) on a healthy identity must
    // still return 401, not 403, because nothing about the identity is archived.
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{base}");
    let (org_id, admin_key, agent_id) = setup_hierarchy(&client, &base, "manual-revoke").await;

    let sub = make_subagent(&client, &base, &admin_key, &agent_id, "alive").await;
    let sub_id: Uuid = sub["id"].as_str().unwrap().parse().unwrap();

    let sub_key = make_sub_key(&client, &base, &admin_key, &org_id, sub_id, "k").await;
    let key_id: Uuid = sub_key["id"].as_str().unwrap().parse().unwrap();
    let key_str = sub_key["key"].as_str().unwrap().to_string();

    // Manual revoke: leaves revoked_reason NULL
    let org_uuid: Uuid = org_id.parse().unwrap();
    overslash_db::OrgScope::new(org_uuid, pool.clone())
        .revoke_api_key(key_id)
        .await
        .unwrap();

    let resp = client
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {key_str}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid api key");
}

#[tokio::test]
async fn test_parent_does_not_archive_while_child_alive() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{base}");
    let (org_id, admin_key, agent_id) = setup_hierarchy(&client, &base, "parent-waits").await;
    let org_uuid: Uuid = org_id.parse().unwrap();

    let parent_sub = make_subagent(&client, &base, &admin_key, &agent_id, "p").await;
    let parent_id_str = parent_sub["id"].as_str().unwrap().to_string();
    let parent_uuid: Uuid = parent_id_str.parse().unwrap();

    let child_sub = make_subagent(&client, &base, &admin_key, &parent_id_str, "c").await;
    let child_uuid: Uuid = child_sub["id"].as_str().unwrap().parse().unwrap();

    // Configure tiny idle timeout
    force_org_config(&pool, org_uuid, 60, 30).await;
    // Push parent idle but keep child fresh
    sqlx::query("UPDATE identities SET last_active_at = now() - interval '2 hours' WHERE id = $1")
        .bind(parent_uuid)
        .execute(&pool)
        .await
        .unwrap();

    let archived = overslash_db::repos::identity::archive_idle_subagents(&pool)
        .await
        .unwrap();
    assert_eq!(archived, 0, "parent must wait for child to drain first");

    let parent_row = overslash_db::repos::identity::get_by_id(&pool, org_uuid, parent_uuid)
        .await
        .unwrap()
        .unwrap();
    assert!(parent_row.archived_at.is_none());

    // Now make the child idle as well
    sqlx::query("UPDATE identities SET last_active_at = now() - interval '2 hours' WHERE id = $1")
        .bind(child_uuid)
        .execute(&pool)
        .await
        .unwrap();

    // Pass 1: child archives
    let archived = overslash_db::repos::identity::archive_idle_subagents(&pool)
        .await
        .unwrap();
    assert_eq!(archived, 1);
    let child_row = overslash_db::repos::identity::get_by_id(&pool, org_uuid, child_uuid)
        .await
        .unwrap()
        .unwrap();
    assert!(child_row.archived_at.is_some());
    let parent_row = overslash_db::repos::identity::get_by_id(&pool, org_uuid, parent_uuid)
        .await
        .unwrap()
        .unwrap();
    assert!(
        parent_row.archived_at.is_none(),
        "parent still alive after first pass — child became archived but archive_at filter checks NULL on child"
    );

    // Pass 2: parent archives now that child's archived_at IS NOT NULL
    let archived = overslash_db::repos::identity::archive_idle_subagents(&pool)
        .await
        .unwrap();
    assert_eq!(archived, 1);
    let parent_row = overslash_db::repos::identity::get_by_id(&pool, org_uuid, parent_uuid)
        .await
        .unwrap()
        .unwrap();
    assert!(parent_row.archived_at.is_some());
}

#[tokio::test]
async fn test_restore_resurrects_api_keys_but_not_manual_revokes() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{base}");
    let (org_id, admin_key, agent_id) = setup_hierarchy(&client, &base, "restore-keys").await;
    let org_uuid: Uuid = org_id.parse().unwrap();

    let sub = make_subagent(&client, &base, &admin_key, &agent_id, "renewable").await;
    let sub_id: Uuid = sub["id"].as_str().unwrap().parse().unwrap();

    // Auto-revoked key
    let auto_key = make_sub_key(&client, &base, &admin_key, &org_id, sub_id, "auto").await;
    let auto_prefix = auto_key["key_prefix"].as_str().unwrap().to_string();

    // Manually-revoked key (should NOT be resurrected)
    let manual_key = make_sub_key(&client, &base, &admin_key, &org_id, sub_id, "manual").await;
    let manual_id: Uuid = manual_key["id"].as_str().unwrap().parse().unwrap();
    let manual_prefix = manual_key["key_prefix"].as_str().unwrap().to_string();
    overslash_db::OrgScope::new(org_uuid, pool.clone())
        .revoke_api_key(manual_id)
        .await
        .unwrap();

    // Archive the identity
    force_org_config(&pool, org_uuid, 60, 30).await;
    sqlx::query("UPDATE identities SET last_active_at = now() - interval '2 hours' WHERE id = $1")
        .bind(sub_id)
        .execute(&pool)
        .await
        .unwrap();
    overslash_db::repos::identity::archive_idle_subagents(&pool)
        .await
        .unwrap();

    // Restore via the HTTP endpoint
    let resp = client
        .post(format!("{base}/v1/identities/{sub_id}/restore"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["api_keys_resurrected"], 1);
    assert!(
        body["identity"]["archived_at"].is_null() || body["identity"].get("archived_at").is_none()
    );

    // Auto key is back
    let auto = overslash_db::SystemScope::new_internal(pool.clone())
        .find_api_key_by_prefix(&auto_prefix)
        .await
        .unwrap();
    assert!(auto.is_some(), "auto-revoked key should be resurrected");

    // Manual key remains revoked
    let manual = overslash_db::SystemScope::new_internal(pool.clone())
        .find_api_key_by_prefix(&manual_prefix)
        .await
        .unwrap();
    assert!(
        manual.is_none(),
        "manually-revoked key must NOT be resurrected"
    );
}

#[tokio::test]
async fn test_restore_rejects_not_archived_and_past_retention() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{base}");
    let (org_id, admin_key, agent_id) = setup_hierarchy(&client, &base, "restore-edge").await;
    let org_uuid: Uuid = org_id.parse().unwrap();

    // Not archived → 400
    let sub = make_subagent(&client, &base, &admin_key, &agent_id, "alive").await;
    let sub_id = sub["id"].as_str().unwrap();
    let resp = client
        .post(format!("{base}/v1/identities/{sub_id}/restore"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Past retention → 409
    let sub2 = make_subagent(&client, &base, &admin_key, &agent_id, "ancient").await;
    let sub2_id: Uuid = sub2["id"].as_str().unwrap().parse().unwrap();
    force_org_config(&pool, org_uuid, 60, 1).await;
    sqlx::query("UPDATE identities SET archived_at = now() - interval '5 days', archived_reason = 'idle_timeout' WHERE id = $1")
        .bind(sub2_id)
        .execute(&pool)
        .await
        .unwrap();
    let resp = client
        .post(format!("{base}/v1/identities/{sub2_id}/restore"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);

    // Wrong kind → 400
    // (Try restoring the agent itself.)
    let resp = client
        .post(format!("{base}/v1/identities/{agent_id}/restore"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_purge_after_retention_and_skips_with_children() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{base}");
    let (org_id, admin_key, agent_id) = setup_hierarchy(&client, &base, "purge-pass").await;
    let org_uuid: Uuid = org_id.parse().unwrap();

    let parent_sub = make_subagent(&client, &base, &admin_key, &agent_id, "p").await;
    let parent_str = parent_sub["id"].as_str().unwrap().to_string();
    let parent_uuid: Uuid = parent_str.parse().unwrap();
    let child_sub = make_subagent(&client, &base, &admin_key, &parent_str, "c").await;
    let child_uuid: Uuid = child_sub["id"].as_str().unwrap().parse().unwrap();

    // Both archived, both past retention. But parent has a child row, so first
    // pass should only purge child; parent purges next pass.
    force_org_config(&pool, org_uuid, 60, 1).await;
    sqlx::query("UPDATE identities SET archived_at = now() - interval '5 days', archived_reason='idle_timeout' WHERE id = ANY($1)")
        .bind(vec![parent_uuid, child_uuid])
        .execute(&pool)
        .await
        .unwrap();

    let purged = overslash_db::repos::identity::purge_archived_subagents(&pool)
        .await
        .unwrap();
    assert_eq!(purged, 1, "first pass should only purge the leaf child");
    let parent_still = overslash_db::repos::identity::get_by_id(&pool, org_uuid, parent_uuid)
        .await
        .unwrap();
    assert!(parent_still.is_some(), "parent must still exist");
    let child_gone = overslash_db::repos::identity::get_by_id(&pool, org_uuid, child_uuid)
        .await
        .unwrap();
    assert!(child_gone.is_none());

    let purged = overslash_db::repos::identity::purge_archived_subagents(&pool)
        .await
        .unwrap();
    assert_eq!(purged, 1);
    let parent_gone = overslash_db::repos::identity::get_by_id(&pool, org_uuid, parent_uuid)
        .await
        .unwrap();
    assert!(parent_gone.is_none());
}

#[tokio::test]
async fn test_users_and_agents_never_archived() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{base}");
    let (org_id, _admin_key, agent_id) = setup_hierarchy(&client, &base, "users-immune").await;
    let org_uuid: Uuid = org_id.parse().unwrap();
    let agent_uuid: Uuid = agent_id.parse().unwrap();

    // Make the agent and user maximally idle and the org's idle timeout tiny.
    force_org_config(&pool, org_uuid, 60, 30).await;
    sqlx::query(
        "UPDATE identities SET last_active_at = now() - interval '30 days' WHERE org_id = $1",
    )
    .bind(org_uuid)
    .execute(&pool)
    .await
    .unwrap();

    let archived = overslash_db::repos::identity::archive_idle_subagents(&pool)
        .await
        .unwrap();
    assert_eq!(archived, 0, "no sub_agents present, nothing to archive");

    let agent_row = overslash_db::repos::identity::get_by_id(&pool, org_uuid, agent_uuid)
        .await
        .unwrap()
        .unwrap();
    assert!(agent_row.archived_at.is_none(), "agents must never archive");
}

#[tokio::test]
async fn test_per_org_idle_timeout_is_respected() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{base}");

    let (org_a, key_a, agent_a) = setup_hierarchy(&client, &base, "org-a").await;
    let (org_b, key_b, agent_b) = setup_hierarchy(&client, &base, "org-b").await;

    // Org A: aggressive (60s), Org B: lenient (1 day)
    force_org_config(&pool, org_a.parse().unwrap(), 60, 30).await;
    force_org_config(&pool, org_b.parse().unwrap(), 86_400, 30).await;

    let sub_a = make_subagent(&client, &base, &key_a, &agent_a, "a").await;
    let sub_b = make_subagent(&client, &base, &key_b, &agent_b, "b").await;
    let id_a: Uuid = sub_a["id"].as_str().unwrap().parse().unwrap();
    let id_b: Uuid = sub_b["id"].as_str().unwrap().parse().unwrap();

    // Both 30 minutes idle
    sqlx::query(
        "UPDATE identities SET last_active_at = now() - interval '30 minutes' WHERE id = ANY($1)",
    )
    .bind(vec![id_a, id_b])
    .execute(&pool)
    .await
    .unwrap();

    let archived = overslash_db::repos::identity::archive_idle_subagents(&pool)
        .await
        .unwrap();
    assert_eq!(
        archived, 1,
        "only the aggressive org's sub-agent should archive"
    );

    let row_a = overslash_db::repos::identity::get_by_id(&pool, org_a.parse().unwrap(), id_a)
        .await
        .unwrap()
        .unwrap();
    assert!(row_a.archived_at.is_some());
    let row_b = overslash_db::repos::identity::get_by_id(&pool, org_b.parse().unwrap(), id_b)
        .await
        .unwrap()
        .unwrap();
    assert!(row_b.archived_at.is_none());
}

#[tokio::test]
async fn test_subagent_cleanup_config_endpoint_validates_bounds() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (org_id, admin_key, _agent_id) = setup_hierarchy(&client, &base, "cfg-bounds").await;

    // Below floor (4h)
    let resp = client
        .patch(format!("{base}/v1/orgs/{org_id}/subagent-cleanup-config"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "subagent_idle_timeout_secs": 60,
            "subagent_archive_retention_days": 30
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Above ceiling (60d)
    let resp = client
        .patch(format!("{base}/v1/orgs/{org_id}/subagent-cleanup-config"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "subagent_idle_timeout_secs": 60 * 60 * 24 * 365,
            "subagent_archive_retention_days": 30
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Retention too long
    let resp = client
        .patch(format!("{base}/v1/orgs/{org_id}/subagent-cleanup-config"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "subagent_idle_timeout_secs": 4 * 60 * 60,
            "subagent_archive_retention_days": 365
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Retention below floor (0 days)
    let resp = client
        .patch(format!("{base}/v1/orgs/{org_id}/subagent-cleanup-config"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "subagent_idle_timeout_secs": 4 * 60 * 60,
            "subagent_archive_retention_days": 0
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Valid: 4h idle, 7 day retention
    let resp = client
        .patch(format!("{base}/v1/orgs/{org_id}/subagent-cleanup-config"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "subagent_idle_timeout_secs": 4 * 60 * 60,
            "subagent_archive_retention_days": 7
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["subagent_idle_timeout_secs"], 4 * 60 * 60);
    assert_eq!(body["subagent_archive_retention_days"], 7);
}

#[tokio::test]
async fn test_get_org_returns_cleanup_config_with_defaults() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (org_id, admin_key, _agent_id) = setup_hierarchy(&client, &base, "cfg-defaults").await;

    let resp = client
        .get(format!("{base}/v1/orgs/{org_id}"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    // Default sits at the floor (4h) so new orgs are within validation bounds.
    assert_eq!(body["subagent_idle_timeout_secs"], 4 * 60 * 60);
    assert_eq!(body["subagent_archive_retention_days"], 30);
}

#[tokio::test]
async fn test_get_org_blocks_cross_org_access() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (_org_a, key_a, _agent_a) = setup_hierarchy(&client, &base, "isolate-a").await;
    let (org_b, _key_b, _agent_b) = setup_hierarchy(&client, &base, "isolate-b").await;

    // org A admin tries to read org B
    let resp = client
        .get(format!("{base}/v1/orgs/{org_b}"))
        .header("Authorization", format!("Bearer {key_a}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_patch_subagent_cleanup_config_blocks_cross_org() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (_org_a, key_a, _agent_a) = setup_hierarchy(&client, &base, "patch-iso-a").await;
    let (org_b, _key_b, _agent_b) = setup_hierarchy(&client, &base, "patch-iso-b").await;

    // org A admin tries to mutate org B's cleanup config
    let resp = client
        .patch(format!("{base}/v1/orgs/{org_b}/subagent-cleanup-config"))
        .header("Authorization", format!("Bearer {key_a}"))
        .json(&json!({
            "subagent_idle_timeout_secs": 4 * 60 * 60,
            "subagent_archive_retention_days": 7
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_patch_org_with_no_fields_returns_400() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (org_id, admin_key, _agent_id) = setup_hierarchy(&client, &base, "patch-empty").await;

    // PATCH /v1/orgs/{id} currently has no patchable fields
    let resp = client
        .patch(format!("{base}/v1/orgs/{org_id}"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Cross-org guard fires before the no-fields check
    let (org_b, _key_b, _agent_b) = setup_hierarchy(&client, &base, "patch-empty-b").await;
    let resp = client
        .patch(format!("{base}/v1/orgs/{org_b}"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_restore_not_found_for_unknown_identity() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (_org, admin_key, _agent) = setup_hierarchy(&client, &base, "restore-404").await;

    let bogus = Uuid::new_v4();
    let resp = client
        .post(format!("{base}/v1/identities/{bogus}/restore"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}
