//! Authorization for service management (delete/update).
//!
//! `create_service` is gated by `WriteAcl`, so service delete/update must be
//! symmetric: a Write-level member may manage a service it owns. It may also
//! manage a service owned by an identity it is an ancestor of — the parent→child
//! ceiling allowance that lets a user manage its own agents'/sub-agents'
//! services (the dashboard runs as the user identity). The allowance is
//! one-directional: an agent cannot reach up to its owner-user's or a sibling's
//! service, and org-level (`owner_identity_id IS NULL`) services still require
//! Admin. See `routes/services.rs` + `caller_may_manage_owned`.

// Seeds service instances + asserts via direct SQL.
#![allow(clippy::disallowed_methods)]

mod common;

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// Seed a service instance owned by `owner` (`None` = org-level). `is_system`
/// cannot be set through `POST /v1/services`, so system rows are seeded here
/// directly, mirroring migration 023's bootstrap INSERT.
async fn seed_service_instance(
    pool: &PgPool,
    org_id: Uuid,
    owner: Option<Uuid>,
    name: &str,
    is_system: bool,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO service_instances \
         (org_id, owner_identity_id, name, template_source, template_key, status, is_system) \
         VALUES ($1, $2, $3, 'global', $3, 'active', $4) RETURNING id",
    )
    .bind(org_id)
    .bind(owner)
    .bind(name)
    .bind(is_system)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn service_count(pool: &PgPool, id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM service_instances WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Create an `agent`/`sub_agent` identity under `parent_id` and mint an API key
/// bound to it. Returns `(identity_id, api_key)`. Uses `org_key` (org-bound) for
/// the privileged creation calls.
async fn create_child_identity(
    base: &str,
    client: &reqwest::Client,
    org_key: &str,
    org_id: Uuid,
    kind: &str,
    parent_id: Uuid,
    name: &str,
) -> (Uuid, String) {
    let ident: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&serde_json::json!({ "name": name, "kind": kind, "parent_id": parent_id }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id: Uuid = ident["id"]
        .as_str()
        .unwrap_or_else(|| panic!("identity create failed: {ident}"))
        .parse()
        .unwrap();

    let key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&serde_json::json!({ "org_id": org_id, "identity_id": id, "name": format!("{name}-key") }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let key = key_resp["key"].as_str().unwrap().to_string();
    (id, key)
}

/// (f) The parent→child ceiling allowance: the owning **user** may delete a
/// service owned by one of its **agents** (the dashboard's core use case).
#[tokio::test]
async fn user_deletes_agent_owned_service() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    // Agent owned by the write-user.
    let (agent_id, _agent_key) = create_child_identity(
        &base,
        &client,
        &fx.org_key,
        fx.org_id,
        "agent",
        fx.user_ids[1],
        "svc-agent",
    )
    .await;
    let svc = seed_service_instance(&pool, fx.org_id, Some(agent_id), "agent-svc", false).await;

    // The parent user deletes it with its own (write-level) key.
    let resp = client
        .delete(format!("{base}/v1/services/{svc}"))
        .header("Authorization", format!("Bearer {}", fx.write_key))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "a user may delete a service owned by its agent"
    );
    assert_eq!(service_count(&pool, svc).await, 0, "service must be gone");
}

/// (g) Allowance reaches transitively: the user may delete a service owned by a
/// **sub_agent** two levels down.
#[tokio::test]
async fn user_deletes_sub_agent_owned_service() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let (agent_id, _) = create_child_identity(
        &base,
        &client,
        &fx.org_key,
        fx.org_id,
        "agent",
        fx.user_ids[1],
        "mid-agent",
    )
    .await;
    let (sub_id, _) = create_child_identity(
        &base,
        &client,
        &fx.org_key,
        fx.org_id,
        "sub_agent",
        agent_id,
        "leaf-sub",
    )
    .await;
    let svc = seed_service_instance(&pool, fx.org_id, Some(sub_id), "sub-svc", false).await;

    let resp = client
        .delete(format!("{base}/v1/services/{svc}"))
        .header("Authorization", format!("Bearer {}", fx.write_key))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "a user may delete a service owned by its sub_agent"
    );
    assert_eq!(service_count(&pool, svc).await, 0, "service must be gone");
}

/// (h) Status-change parity for the allowance: the user may archive its agent's
/// service (same gate as delete).
#[tokio::test]
async fn user_updates_status_of_agent_owned_service() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let (agent_id, _) = create_child_identity(
        &base,
        &client,
        &fx.org_key,
        fx.org_id,
        "agent",
        fx.user_ids[1],
        "status-agent",
    )
    .await;
    let svc =
        seed_service_instance(&pool, fx.org_id, Some(agent_id), "agent-status-svc", false).await;

    let resp = client
        .patch(format!("{base}/v1/services/{svc}/status"))
        .header("Authorization", format!("Bearer {}", fx.write_key))
        .json(&serde_json::json!({ "status": "archived" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "a user may change status of a service owned by its agent"
    );
}

/// (i) One-directional: an **agent** may NOT delete a service owned by its
/// **owner-user** (child→parent is not allowed).
#[tokio::test]
async fn agent_cannot_delete_owner_users_service() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let (_agent_id, agent_key) = create_child_identity(
        &base,
        &client,
        &fx.org_key,
        fx.org_id,
        "agent",
        fx.user_ids[1],
        "upward-agent",
    )
    .await;
    // Service owned by the parent user.
    let svc =
        seed_service_instance(&pool, fx.org_id, Some(fx.user_ids[1]), "parent-svc", false).await;

    let resp = client
        .delete(format!("{base}/v1/services/{svc}"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "an agent must not reach up to its owner-user's service"
    );
    assert_eq!(service_count(&pool, svc).await, 1, "service must survive");
}

/// (j) One-directional: a **sibling** agent may NOT delete another agent's
/// service (no lateral reach).
#[tokio::test]
async fn sibling_agent_cannot_delete_agent_owned_service() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let (_a_id, a_key) = create_child_identity(
        &base,
        &client,
        &fx.org_key,
        fx.org_id,
        "agent",
        fx.user_ids[1],
        "sibling-a",
    )
    .await;
    let (b_id, _b_key) = create_child_identity(
        &base,
        &client,
        &fx.org_key,
        fx.org_id,
        "agent",
        fx.user_ids[1],
        "sibling-b",
    )
    .await;
    let svc = seed_service_instance(&pool, fx.org_id, Some(b_id), "sibling-b-svc", false).await;

    let resp = client
        .delete(format!("{base}/v1/services/{svc}"))
        .header("Authorization", format!("Bearer {a_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "a sibling agent must not delete another agent's service"
    );
    assert_eq!(service_count(&pool, svc).await, 1, "service must survive");
}

/// (a) A Write member may delete a service it owns.
#[tokio::test]
async fn write_member_deletes_own_service() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    // write-user (user_ids[1]) owns it.
    let svc = seed_service_instance(&pool, fx.org_id, Some(fx.user_ids[1]), "own-svc", false).await;

    let resp = client
        .delete(format!("{base}/v1/services/{svc}"))
        .header("Authorization", format!("Bearer {}", fx.write_key))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "owner delete at Write level must succeed"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["deleted"], true);
    assert_eq!(service_count(&pool, svc).await, 0, "service must be gone");
}

/// (b) A Write member may NOT delete another identity's service without Admin.
#[tokio::test]
async fn write_member_cannot_delete_other_identitys_service() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    // readonly-user (user_ids[2]) owns it; write-user tries to delete.
    let svc =
        seed_service_instance(&pool, fx.org_id, Some(fx.user_ids[2]), "other-svc", false).await;

    let resp = client
        .delete(format!("{base}/v1/services/{svc}"))
        .header("Authorization", format!("Bearer {}", fx.write_key))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "non-owner delete without admin must be forbidden"
    );
    assert_eq!(service_count(&pool, svc).await, 1, "service must survive");
}

/// (c) A Write member may NOT delete an org-level (owner NULL) service without Admin.
#[tokio::test]
async fn write_member_cannot_delete_org_level_service() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let svc = seed_service_instance(&pool, fx.org_id, None, "org-svc", false).await;

    let resp = client
        .delete(format!("{base}/v1/services/{svc}"))
        .header("Authorization", format!("Bearer {}", fx.write_key))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "org-level delete without admin must be forbidden"
    );
    assert_eq!(service_count(&pool, svc).await, 1, "service must survive");
}

/// (d) A system service can never be deleted, even by its owner — the
/// `is_system` guard runs before the ownership check.
#[tokio::test]
async fn cannot_delete_system_service() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    // Owned by the write-user, so ownership would otherwise permit it.
    let svc = seed_service_instance(&pool, fx.org_id, Some(fx.user_ids[1]), "sys-svc", true).await;

    let resp = client
        .delete(format!("{base}/v1/services/{svc}"))
        .header("Authorization", format!("Bearer {}", fx.write_key))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "system service delete must be rejected");
    assert_eq!(service_count(&pool, svc).await, 1, "service must survive");
}

/// (e) An org admin may delete any service in the org.
#[tokio::test]
async fn admin_deletes_any_service() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    // Owned by another identity + an org-level one; admin deletes both.
    let owned =
        seed_service_instance(&pool, fx.org_id, Some(fx.user_ids[2]), "admin-owned", false).await;
    let org_level = seed_service_instance(&pool, fx.org_id, None, "admin-org", false).await;

    for svc in [owned, org_level] {
        let resp = client
            .delete(format!("{base}/v1/services/{svc}"))
            .header("Authorization", format!("Bearer {}", fx.admin_key))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "admin delete must succeed");
        assert_eq!(service_count(&pool, svc).await, 0, "service must be gone");
    }
}

/// Update parity: a Write member cannot change another identity's service
/// status without Admin (same gate as delete).
#[tokio::test]
async fn write_member_cannot_update_status_of_other_identitys_service() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let svc =
        seed_service_instance(&pool, fx.org_id, Some(fx.user_ids[2]), "status-svc", false).await;

    let resp = client
        .patch(format!("{base}/v1/services/{svc}/status"))
        .header("Authorization", format!("Bearer {}", fx.write_key))
        .json(&serde_json::json!({ "status": "archived" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "non-owner status change without admin must be forbidden"
    );
}
