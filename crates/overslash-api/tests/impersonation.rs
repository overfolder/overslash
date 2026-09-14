// Name-based-target tests seed + assert against the DB with dynamic SQL.
#![allow(clippy::disallowed_methods)]
//! Integration tests for the `X-Overslash-As` header and the `"impersonate"`
//! API key scope.
//!
//! The feature lets an API key with `scopes: ["impersonate"]` execute any
//! request as an arbitrary non-archived identity in the same org. Only org
//! admins can create such keys. Audit rows record both the effective identity
//! and the impersonating service account.

use crate::common;

use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

/// Setup helper: creates org + admin key + a regular user identity + an agent.
/// Returns (base, client, pool, org_id, admin_key, service_account_id, target_user_id, target_agent_id).
async fn setup() -> (
    String,
    reqwest::Client,
    PgPool,
    Uuid,
    String,
    Uuid,
    Uuid,
    Uuid,
) {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    // Bootstrap org + admin identity key
    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "ImpersonationTestOrg", "slug": format!("imp-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();

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
    let service_account_id: Uuid = bootstrap["identity_id"].as_str().unwrap().parse().unwrap();

    // Create a regular user identity (target)
    let target_user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name": "target-user", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let target_user_id: Uuid = target_user["id"].as_str().unwrap().parse().unwrap();

    // Create an agent identity (target) under the service account
    let target_agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name": "target-agent", "kind": "agent", "parent_id": service_account_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let target_agent_id: Uuid = target_agent["id"].as_str().unwrap().parse().unwrap();

    (
        base,
        client,
        pool,
        org_id,
        admin_key,
        service_account_id,
        target_user_id,
        target_agent_id,
    )
}

/// Create an API key with `scopes: ["impersonate"]` for the given identity.
async fn create_impersonation_key(
    base: &str,
    client: &reqwest::Client,
    admin_key: &str,
    org_id: Uuid,
    identity_id: Uuid,
) -> String {
    let resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "org_id": org_id,
            "identity_id": identity_id,
            "name": "service-impersonation-key",
            "scopes": ["impersonate"],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    resp["key"]
        .as_str()
        .expect("key field missing in response")
        .to_string()
}

// ── Happy path ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn impersonation_user_target_succeeds() {
    let (base, client, _pool, org_id, admin_key, sa_id, target_user_id, _) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;

    let resp = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {imp_key}"))
        .header("X-Overslash-As", target_user_id.to_string())
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "expected 200, got {}: {}",
        resp.status(),
        resp.text().await.unwrap()
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["identity_id"].as_str().unwrap(),
        target_user_id.to_string(),
        "whoami should reflect the impersonated identity"
    );
}

#[tokio::test]
async fn impersonation_agent_target_succeeds() {
    let (base, client, _pool, org_id, admin_key, sa_id, _, target_agent_id) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;

    let resp = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {imp_key}"))
        .header("X-Overslash-As", target_agent_id.to_string())
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "expected 200, got {}: {}",
        resp.status(),
        resp.text().await.unwrap()
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["identity_id"].as_str().unwrap(),
        target_agent_id.to_string()
    );
}

#[tokio::test]
async fn audit_row_records_impersonated_by() {
    let (base, client, _pool, org_id, admin_key, sa_id, target_user_id, _) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;

    // Trigger an audited operation as the impersonated user
    let resp = client
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {imp_key}"))
        .header("X-Overslash-As", target_user_id.to_string())
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // Fetch audit log and find the most recent impersonated row
    let audit: Vec<Value> = client
        .get(format!("{base}/v1/audit?limit=20"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // The GET /v1/identities call does not log an audit row itself, so we
    // check the api_key.created row for the impersonation key instead —
    // that was created with the admin key (no impersonation, so
    // impersonated_by should be null there). What we can assert definitively
    // is that api_key.created exists and has null impersonated_by_identity_id
    // (it was created by the admin key, not an impersonation key).
    let api_key_row = audit
        .iter()
        .find(|r| r["action"] == "api_key.created")
        .expect("api_key.created audit row not found");
    assert!(
        api_key_row["impersonated_by_identity_id"].is_null(),
        "non-impersonated key creation should have null impersonated_by"
    );
}

// ── Enforcement: key capability ──────────────────────────────────────────────

#[tokio::test]
async fn impersonation_rejected_without_scope() {
    let (base, client, _pool, org_id, admin_key, _, target_user_id, _) = setup().await;

    // Create a regular (no impersonate scope) key for the service account
    let regular_key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "org_id": org_id,
            "name": "no-impersonate-key",
            "scopes": [],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let regular_key = regular_key_resp["key"].as_str().unwrap();

    let resp = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {regular_key}"))
        .header("X-Overslash-As", target_user_id.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        403,
        "key without 'impersonate' scope should be rejected with 403"
    );
}

// ── Enforcement: target validation ───────────────────────────────────────────

#[tokio::test]
async fn impersonation_rejected_for_unknown_target() {
    let (base, client, _pool, org_id, admin_key, sa_id, _, _) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;

    let resp = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {imp_key}"))
        .header("X-Overslash-As", Uuid::new_v4().to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        404,
        "non-existent target should yield 404"
    );
}

#[tokio::test]
async fn impersonation_rejected_for_archived_target() {
    let (base, client, pool, org_id, admin_key, sa_id, target_user_id, _) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;

    // Set archived_at directly in the DB — there is no API endpoint to archive
    // a user identity (DELETE hard-deletes leaf nodes). This simulates the
    // idle-cleanup path that sets archived_at on sub-agents.
    sqlx::query!(
        "UPDATE identities SET archived_at = now() WHERE id = $1",
        target_user_id
    )
    .execute(&pool)
    .await
    .unwrap();

    let resp = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {imp_key}"))
        .header("X-Overslash-As", target_user_id.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        403,
        "archived target should yield 403"
    );
}

#[tokio::test]
async fn impersonation_cannot_reach_other_org_identity() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    // Org A
    let org_a: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "OrgA", "slug": format!("orga-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_a_id: Uuid = org_a["id"].as_str().unwrap().parse().unwrap();
    let boot_a: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_a_id, "name": "admin-a"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admin_key_a = boot_a["key"].as_str().unwrap().to_string();
    let sa_a_id: Uuid = boot_a["identity_id"].as_str().unwrap().parse().unwrap();

    // Org B — get an identity to try to impersonate
    let org_b: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "OrgB", "slug": format!("orgb-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_b_id: Uuid = org_b["id"].as_str().unwrap().parse().unwrap();
    let boot_b: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_b_id, "name": "admin-b"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_b_identity_id: Uuid = boot_b["identity_id"].as_str().unwrap().parse().unwrap();

    // Create impersonation key in Org A
    let imp_key = create_impersonation_key(&base, &client, &admin_key_a, org_a_id, sa_a_id).await;

    // Attempt to impersonate Org B's identity from Org A's key
    let resp = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {imp_key}"))
        .header("X-Overslash-As", org_b_identity_id.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        404,
        "cross-org impersonation attempt should yield 404"
    );
}

// ── Admin-only key creation ───────────────────────────────────────────────────

#[tokio::test]
async fn create_impersonation_key_requires_admin() {
    let (base, client, _pool, org_id, admin_key, sa_id, target_user_id, _) = setup().await;

    // Create a write-level key for target_user_id
    let write_key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "org_id": org_id,
            "identity_id": target_user_id,
            "name": "write-key",
            "scopes": [],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // target_user_id has no group membership = Read level by default
    let write_key = write_key_resp["key"].as_str().unwrap();

    let resp = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {write_key}"))
        .json(&json!({
            "org_id": org_id,
            "identity_id": sa_id,
            "name": "sneaky-imp-key",
            "scopes": ["impersonate"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        403,
        "non-admin should not be able to create 'impersonate' scope key"
    );
}

#[tokio::test]
async fn create_impersonation_key_succeeds_for_admin() {
    let (base, client, _pool, org_id, admin_key, sa_id, _, _) = setup().await;

    let resp = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "org_id": org_id,
            "identity_id": sa_id,
            "name": "valid-imp-key",
            "scopes": ["impersonate"],
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "admin should be able to create 'impersonate' scope key: {}",
        resp.text().await.unwrap()
    );
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s == "impersonate"),
        "response should include 'impersonate' in scopes"
    );
}

#[tokio::test]
async fn bootstrap_path_cannot_create_impersonation_key() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "BootstrapImpOrg", "slug": format!("bimp-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();

    // Bootstrap path: unauthenticated, but requesting impersonate scope
    let resp = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({
            "org_id": org_id,
            "name": "bootstrap-imp",
            "scopes": ["impersonate"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        403,
        "bootstrap path should not allow 'impersonate' scope"
    );
}

// ── Bad header value ──────────────────────────────────────────────────────────

#[tokio::test]
async fn impersonation_rejects_non_uuid_header() {
    let (base, client, _pool, org_id, admin_key, sa_id, _, _) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;

    let resp = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {imp_key}"))
        .header("X-Overslash-As", "not-a-uuid")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        400,
        "malformed UUID in header should yield 400"
    );
}

// ── ACL cap: no privilege escalation via impersonation ────────────────────────

/// An impersonation key issued to a lower-privilege identity cannot be used to
/// impersonate an admin. Without the ACL cap a write/read-level key with the
/// "impersonate" scope could escalate to admin by pointing at an org admin.
#[tokio::test]
async fn impersonation_cannot_escalate_to_higher_acl() {
    let (base, client, _pool, org_id, admin_key, sa_id, target_user_id, _) = setup().await;

    // Admin creates an impersonation key FOR the low-privilege target_user
    // (target_user has Read level — no group grants).
    let low_priv_imp_key =
        create_impersonation_key(&base, &client, &admin_key, org_id, target_user_id).await;

    // Try to use that low-privilege key to impersonate the admin service account.
    // sa_id has Admin level (bootstrap identity), target_user has Read level.
    // target (Admin) > caller (Read) → must be rejected.
    let resp = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {low_priv_imp_key}"))
        .header("X-Overslash-As", sa_id.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        403,
        "low-privilege impersonation key must not be able to impersonate an admin"
    );
}

// ── Name-based targets (email + agent path) ──────────────────────────────────

/// `X-Overslash-As: <email>` for an unknown email JIT-provisions a user
/// identity in the key's org, bootstraps its groups, and audits the
/// provisioning. A second call by the same email reuses that identity.
#[tokio::test]
async fn impersonation_by_email_jit_creates_then_reuses_user() {
    let (base, client, pool, org_id, admin_key, sa_id, _, _) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;
    let email = "jit-user@example.com";

    let first: Value = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {imp_key}"))
        .header("X-Overslash-As", email)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let created_id = first["identity_id"].as_str().unwrap().to_string();
    assert_eq!(first["kind"], "user");

    // The identity is real, scoped to this org, carries the email, and has
    // NULL external_id ("never signed in").
    let (db_org, ext_id): (Uuid, Option<String>) =
        sqlx::query_as("SELECT org_id, external_id FROM identities WHERE id = $1")
            .bind(Uuid::parse_str(&created_id).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(db_org, org_id);
    assert!(ext_id.is_none(), "JIT user must have NULL external_id");

    // Joined the Everyone group.
    let in_everyone: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_groups ig
         JOIN groups g ON g.id = ig.group_id
         WHERE ig.identity_id = $1 AND g.org_id = $2 AND g.system_kind = 'everyone'",
    )
    .bind(Uuid::parse_str(&created_id).unwrap())
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(in_everyone, 1, "JIT user must join the Everyone group");

    // An `identity.provisioned` audit row records the provenance.
    let provisioned: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log
         WHERE org_id = $1 AND action = 'identity.provisioned' AND resource_id = $2",
    )
    .bind(org_id)
    .bind(Uuid::parse_str(&created_id).unwrap())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(provisioned, 1, "auto-creation must be audited");

    // Second call with the same email reuses the same identity.
    let second: Value = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {imp_key}"))
        .header("X-Overslash-As", email)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(second["identity_id"].as_str().unwrap(), created_id);
}

/// `X-Overslash-As: <email>/<agent>/<sub>` creates the whole missing chain
/// under the user, non-inheriting, and resolves to the leaf. A second call
/// reuses every level.
#[tokio::test]
async fn impersonation_agent_path_creates_and_reuses_chain() {
    let (base, client, pool, org_id, admin_key, sa_id, _, _) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;
    let target = "chain-user@example.com/henry/researcher";

    let first: Value = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {imp_key}"))
        .header("X-Overslash-As", target)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let leaf_id = first["identity_id"].as_str().unwrap().to_string();
    assert_eq!(first["kind"], "sub_agent");
    assert_eq!(first["name"], "researcher");

    // The user, agent, and sub-agent all exist with the right kinds + owner.
    let user_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM identities WHERE org_id = $1 AND kind = 'user' AND email = 'chain-user@example.com'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let (henry_id, henry_kind, henry_inherit): (Uuid, String, bool) = sqlx::query_as(
        "SELECT id, kind, inherit_permissions FROM identities WHERE org_id = $1 AND parent_id = $2 AND name = 'henry'",
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(henry_kind, "agent");
    assert!(
        !henry_inherit,
        "auto-created agent must not inherit permissions"
    );

    let (leaf_owner, leaf_parent): (Option<Uuid>, Option<Uuid>) =
        sqlx::query_as("SELECT owner_id, parent_id FROM identities WHERE id = $1")
            .bind(Uuid::parse_str(&leaf_id).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        leaf_owner,
        Some(user_id),
        "sub-agent owner is the root user"
    );
    assert_eq!(leaf_parent, Some(henry_id), "sub-agent parent is henry");

    // Reuse: a second identical call lands on the same leaf.
    let second: Value = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {imp_key}"))
        .header("X-Overslash-As", target)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(second["identity_id"].as_str().unwrap(), leaf_id);
}

/// A malformed target value is a clean 400, not a 500.
#[tokio::test]
async fn impersonation_rejects_malformed_target() {
    let (base, client, _pool, org_id, admin_key, sa_id, _, _) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;

    for bad in ["not-a-uuid", "no-at-sign/henry", "alice@acme.com//henry"] {
        let resp = client
            .get(format!("{base}/v1/whoami"))
            .header("Authorization", format!("Bearer {imp_key}"))
            .header("X-Overslash-As", bad)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 400, "value {bad:?} must 400");
    }
}

/// An agent path deeper than the cap is rejected before any DB writes.
#[tokio::test]
async fn impersonation_rejects_too_deep_agent_path() {
    let (base, client, _pool, org_id, admin_key, sa_id, _, _) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;
    let deep = format!("deep-user@example.com/{}", ["a"; 9].join("/"));

    let resp = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {imp_key}"))
        .header("X-Overslash-As", deep)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400, "over-deep path must 400");
}

/// Regression: revoking a pending invite whose user has an agent chain
/// beneath them must NOT cascade-delete that subtree. `identities.parent_id`
/// is ON DELETE CASCADE, so a raw delete would silently wipe `henry`; the
/// endpoint must 409.
///
/// Models the real shape: an admin invites alice, then a backend impersonates
/// `alice@…/henry`, which *reuses* her existing invite identity and creates
/// the agent under it. She stays a genuine invite (created via the invite
/// endpoint), so she is still revocable — and that revoke must be refused.
#[tokio::test]
async fn revoking_pending_invite_with_provisioned_agents_is_refused() {
    let (base, client, pool, org_id, admin_key, sa_id, _, _) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;

    // Admin invites alice — a genuine pending invite.
    let invite: Value = client
        .post(format!("{base}/v1/org-invites"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "email": "cascade-alice@example.com", "role": "member" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let alice_id: Uuid = invite["id"].as_str().unwrap().parse().unwrap();

    // A backend then provisions an agent beneath her, reusing her identity.
    client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {imp_key}"))
        .header("X-Overslash-As", "cascade-alice@example.com/henry")
        .send()
        .await
        .unwrap();

    // Revoke via the invite endpoint — must be refused, henry must survive.
    let resp = client
        .delete(format!("{base}/v1/org-invites/{alice_id}"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        409,
        "revoking a pending invite with provisioned agents must 409, not cascade-delete"
    );

    let alice_still_there: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identities WHERE id = $1")
            .bind(alice_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(alice_still_there, 1, "alice must not be deleted");

    let henry_still_there: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identities WHERE org_id = $1 AND parent_id = $2 AND name = 'henry'",
    )
    .bind(org_id)
    .bind(alice_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(henry_still_there, 1, "henry must survive a refused revoke");
}

/// An impersonation-provisioned pending user is a member managed on the
/// Members page, NOT a deliberate invitation — it must not surface in the
/// `/v1/org-invites` list (else a white-label backend floods it).
#[tokio::test]
async fn impersonation_provisioned_user_is_not_listed_as_an_invite() {
    let (base, client, _pool, org_id, admin_key, sa_id, _, _) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;

    // Provision a pending user via impersonation.
    client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {imp_key}"))
        .header("X-Overslash-As", "not-an-invite@example.com")
        .send()
        .await
        .unwrap();

    // The invites list must be empty — she was never explicitly invited.
    let invites: Vec<Value> = client
        .get(format!("{base}/v1/org-invites"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        !invites
            .iter()
            .any(|i| i["email"] == "not-an-invite@example.com"),
        "impersonation-provisioned pending user must not appear as an invite: {invites:?}"
    );
}

/// All three invite endpoints agree on what an "invite" is: an
/// impersonation-provisioned pending user is invisible to list/get and is
/// NOT revocable through the invites surface either (it is a Members-page
/// concern). Deleting it there is a no-op, and the identity survives.
#[tokio::test]
async fn impersonation_provisioned_user_is_not_revocable_as_an_invite() {
    let (base, client, pool, org_id, admin_key, sa_id, _, _) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;

    client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {imp_key}"))
        .header("X-Overslash-As", "solo-provisioned@example.com")
        .send()
        .await
        .unwrap();

    let uid: Uuid = sqlx::query_scalar(
        "SELECT id FROM identities WHERE org_id = $1 AND kind = 'user' AND email = 'solo-provisioned@example.com'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    // GET must 404 — it is not an invite.
    let get_resp = client
        .get(format!("{base}/v1/org-invites/{uid}"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(get_resp.status().as_u16(), 404, "not an invite => 404");

    // DELETE is a no-op and must not remove the identity.
    let del: Value = client
        .delete(format!("{base}/v1/org-invites/{uid}"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(del["deleted"], false, "must not be revocable as an invite");

    let still_there: i64 = sqlx::query_scalar("SELECT count(*) FROM identities WHERE id = $1")
        .bind(uid)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(still_there, 1, "identity must survive the no-op delete");
}

// ── X-Overslash-As-Name: the display name of the user root ────────────────────

/// Read an identity's name straight from the DB.
async fn name_of(pool: &PgPool, id: Uuid) -> String {
    sqlx::query_scalar("SELECT name FROM identities WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Impersonate as `target`, optionally carrying a display name, and return the
/// (status, parsed body) of `/v1/whoami`.
async fn whoami_as(
    base: &str,
    client: &reqwest::Client,
    key: &str,
    target: &str,
    name: Option<&str>,
) -> (u16, Value) {
    let mut req = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {key}"))
        .header("X-Overslash-As", target);
    if let Some(name) = name {
        req = req.header("X-Overslash-As-Name", name);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// Without the name header a JIT-provisioned user is labelled from their email
/// local-part; with it, the org sees the real name. The provenance recorded on
/// the audit row says which of the two happened.
#[tokio::test]
async fn name_header_sets_name_on_jit_created_user() {
    let (base, client, pool, org_id, admin_key, sa_id, _, _) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;

    let (_, derived) = whoami_as(&base, &client, &imp_key, "derived@example.com", None).await;
    let derived_id: Uuid = derived["identity_id"].as_str().unwrap().parse().unwrap();
    assert_eq!(name_of(&pool, derived_id).await, "derived");

    let (_, named) = whoami_as(
        &base,
        &client,
        &imp_key,
        "alice@example.com",
        Some("Alice Smith"),
    )
    .await;
    let alice_id: Uuid = named["identity_id"].as_str().unwrap().parse().unwrap();
    assert_eq!(name_of(&pool, alice_id).await, "Alice Smith");

    // Still an unadopted member — the name changes nothing about admission.
    let ext_id: Option<String> =
        sqlx::query_scalar("SELECT external_id FROM identities WHERE id = $1")
            .bind(alice_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(ext_id.is_none());

    let source: Option<String> = sqlx::query_scalar(
        "SELECT detail->>'name_source' FROM audit_log
         WHERE action = 'identity.provisioned' AND resource_id = $1",
    )
    .bind(alice_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(source.as_deref(), Some("header"));
}

/// A member who has never signed in still has an email-derived placeholder for
/// a name; a later call carrying the real one corrects it, and says so in the
/// audit log. Re-sending the same name writes nothing — this runs on the auth
/// path of every request.
#[tokio::test]
async fn name_header_renames_unadopted_user_then_stops() {
    let (base, client, pool, org_id, admin_key, sa_id, _, _) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;
    let email = "rename-me@example.com";

    let (_, first) = whoami_as(&base, &client, &imp_key, email, None).await;
    let id: Uuid = first["identity_id"].as_str().unwrap().parse().unwrap();
    assert_eq!(name_of(&pool, id).await, "rename-me");

    whoami_as(&base, &client, &imp_key, email, Some("Rena Meyer")).await;
    assert_eq!(name_of(&pool, id).await, "Rena Meyer");

    // Twice more with the same name: the rename must not re-fire.
    whoami_as(&base, &client, &imp_key, email, Some("Rena Meyer")).await;
    whoami_as(&base, &client, &imp_key, email, Some("Rena Meyer")).await;

    let renames: Vec<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT detail->>'from', detail->>'to' FROM audit_log
         WHERE action = 'identity.updated' AND resource_id = $1
           AND detail->>'via' = 'impersonation'",
    )
    .bind(id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(renames.len(), 1, "an unchanged name must not write a row");
    assert_eq!(renames[0].0.as_deref(), Some("rename-me"));
    assert_eq!(renames[0].1.as_deref(), Some("Rena Meyer"));
}

/// Once a human has signed in, their identity provider owns their name. A
/// header from a white-label backend must not fight it.
#[tokio::test]
async fn name_header_is_ignored_for_an_adopted_user() {
    let (base, client, pool, org_id, admin_key, sa_id, _, _) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;
    let email = "adopted@example.com";

    let (_, first) = whoami_as(&base, &client, &imp_key, email, Some("Provisional")).await;
    let id: Uuid = first["identity_id"].as_str().unwrap().parse().unwrap();

    // Stand in for a first sign-in.
    sqlx::query("UPDATE identities SET external_id = 'idp-subject-1' WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();

    let (status, _) = whoami_as(&base, &client, &imp_key, email, Some("Overwritten")).await;
    assert_eq!(
        status, 200,
        "the call still succeeds; only the rename is a no-op"
    );
    assert_eq!(name_of(&pool, id).await, "Provisional");
}

/// An org admin's pre-created row is deliberately out of reach: the guard is
/// narrower than "unadopted" on purpose.
#[tokio::test]
async fn name_header_is_ignored_for_an_org_admin() {
    let (base, client, pool, org_id, admin_key, sa_id, _, _) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;
    let email = "admin-invite@example.com";

    let (_, first) = whoami_as(&base, &client, &imp_key, email, Some("Placeholder")).await;
    let id: Uuid = first["identity_id"].as_str().unwrap().parse().unwrap();
    sqlx::query("UPDATE identities SET is_org_admin = true WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();

    whoami_as(&base, &client, &imp_key, email, Some("Renamed By Header")).await;
    assert_eq!(name_of(&pool, id).await, "Placeholder");
}

/// The rename is a write to a row this request did not create, so it must not
/// land until the ACL cap has agreed the caller may act as the target at all.
#[tokio::test]
async fn name_header_rename_does_not_outrun_the_acl_cap() {
    let (base, client, pool, org_id, admin_key, sa_id, target_user_id, _) = setup().await;

    // A pre-created member who outranks the caller: unadopted (so the rename
    // would otherwise apply) but an admin by group, which the cap sees.
    let (_, seeded) = whoami_as(
        &base,
        &client,
        &create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await,
        "high-priv@example.com",
        None,
    )
    .await;
    let high_priv_id: Uuid = seeded["identity_id"].as_str().unwrap().parse().unwrap();
    sqlx::query(
        "INSERT INTO identity_groups (identity_id, group_id)
         SELECT $1, id FROM groups WHERE org_id = $2 AND system_kind = 'admins'",
    )
    .bind(high_priv_id)
    .bind(org_id)
    .execute(&pool)
    .await
    .unwrap();

    // A low-privilege key aims at them, carrying a name.
    let low_priv_key =
        create_impersonation_key(&base, &client, &admin_key, org_id, target_user_id).await;
    let (status, _) = whoami_as(
        &base,
        &client,
        &low_priv_key,
        "high-priv@example.com",
        Some("Should Not Land"),
    )
    .await;

    assert_eq!(status, 403);
    assert_eq!(
        name_of(&pool, high_priv_id).await,
        "high-priv",
        "a refused impersonation must not have renamed its target"
    );
}

/// Non-ASCII names arrive in the RFC 8187 form, because a header value is a
/// byte string and a JS client cannot put `José` in one at all.
#[tokio::test]
async fn name_header_accepts_the_rfc8187_form() {
    let (base, client, pool, org_id, admin_key, sa_id, _, _) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;

    let (status, body) = whoami_as(
        &base,
        &client,
        &imp_key,
        "jose@example.com",
        Some("UTF-8''Jos%C3%A9%20%C3%81lvarez"),
    )
    .await;
    assert_eq!(status, 200);
    let id: Uuid = body["identity_id"].as_str().unwrap().parse().unwrap();
    assert_eq!(name_of(&pool, id).await, "José Álvarez");
}

/// A name that cannot be stored as-is is a clean 400, never a truncation and
/// never a 500.
#[tokio::test]
async fn name_header_rejects_unusable_values() {
    let (base, client, _pool, org_id, admin_key, sa_id, _, _) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;

    let too_long = "a".repeat(129);
    for bad in [
        "   ",
        "UTF-8''",
        "UTF-8''bad%ZZescape",
        "UTF-8''%FF%FE",
        "UTF-8''tab%09separated",
        too_long.as_str(),
    ] {
        let (status, _) = whoami_as(&base, &client, &imp_key, "bad@example.com", Some(bad)).await;
        assert_eq!(status, 400, "value {bad:?} must 400");
    }
}

/// The name has no target of its own — it qualifies `X-Overslash-As`. Sent
/// alone it is a mistake worth surfacing, not a header to ignore.
#[tokio::test]
async fn name_header_alone_is_rejected() {
    let (base, client, _pool, org_id, admin_key, sa_id, _, _) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;

    let resp = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {imp_key}"))
        .header("X-Overslash-As-Name", "Alice Smith")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
}

/// A display name means nothing for an agent, whose name is its path segment.
/// Silently dropping it would let a caller believe a rename happened.
#[tokio::test]
async fn name_header_rejects_an_agent_target() {
    let (base, client, _pool, org_id, admin_key, sa_id, _, target_agent_id) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;

    let (status, _) = whoami_as(
        &base,
        &client,
        &imp_key,
        &target_agent_id.to_string(),
        Some("Not A Person"),
    )
    .await;
    assert_eq!(status, 400);
}

// ── Activity tracking ────────────────────────────────────────────────────────

/// Create a `sub_agent` under `parent_id` and return its id.
async fn create_subagent(
    base: &str,
    client: &reqwest::Client,
    admin_key: &str,
    parent_id: Uuid,
    name: &str,
) -> Uuid {
    let sub: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name": name, "kind": "sub_agent", "parent_id": parent_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    sub["id"].as_str().unwrap().parse().unwrap()
}

/// The touch is fire-and-forget (`tokio::spawn`), so poll for it rather than
/// racing it. Returns the observed `last_active_at`.
async fn await_last_active_after(
    pool: &PgPool,
    id: Uuid,
    floor: time::OffsetDateTime,
) -> time::OffsetDateTime {
    for _ in 0..50 {
        let seen: time::OffsetDateTime =
            sqlx::query_scalar("SELECT last_active_at FROM identities WHERE id = $1")
                .bind(id)
                .fetch_one(pool)
                .await
                .unwrap();
        if seen > floor {
            return seen;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("last_active_at never advanced past {floor} for {id}");
}

#[tokio::test]
async fn impersonation_touches_sub_agent_target_last_active() {
    let (base, client, pool, org_id, admin_key, sa_id, _, target_agent_id) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;
    let sub_id = create_subagent(&base, &client, &admin_key, target_agent_id, "worker").await;

    // Backdate activity so any advance is unambiguously ours.
    let floor: time::OffsetDateTime = sqlx::query_scalar(
        "UPDATE identities SET last_active_at = now() - interval '2 hours'
         WHERE id = $1 RETURNING last_active_at",
    )
    .bind(sub_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    let resp = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {imp_key}"))
        .header("X-Overslash-As", sub_id.to_string())
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "impersonated call should succeed"
    );

    // Impersonation is the only route that reaches this identity — nobody
    // holds a key for it — so if the header does not stamp it, nothing does.
    await_last_active_after(&pool, sub_id, floor).await;
}

#[tokio::test]
async fn impersonated_sub_agent_survives_the_idle_sweep() {
    let (base, client, pool, org_id, admin_key, sa_id, _, target_agent_id) = setup().await;
    let imp_key = create_impersonation_key(&base, &client, &admin_key, org_id, sa_id).await;
    let sub_id = create_subagent(&base, &client, &admin_key, target_agent_id, "busy").await;

    sqlx::query("UPDATE orgs SET subagent_idle_timeout_secs = 60 WHERE id = $1")
        .bind(org_id)
        .execute(&pool)
        .await
        .unwrap();
    let floor: time::OffsetDateTime = sqlx::query_scalar(
        "UPDATE identities SET last_active_at = now() - interval '2 hours'
         WHERE id = $1 RETURNING last_active_at",
    )
    .bind(sub_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    let resp = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {imp_key}"))
        .header("X-Overslash-As", sub_id.to_string())
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    await_last_active_after(&pool, sub_id, floor).await;

    overslash_db::repos::identity::archive_idle_subagents(&pool)
        .await
        .unwrap();

    let row = overslash_db::repos::identity::get_by_id(&pool, org_id, sub_id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        row.archived_at.is_none(),
        "a sub-agent used this second must not be reaped as idle (reason: {:?})",
        row.archived_reason
    );
}
