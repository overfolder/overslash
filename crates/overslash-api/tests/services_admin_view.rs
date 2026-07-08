//! Authorization for service management (delete/update).
//!
//! `create_service` is gated by `WriteAcl`, so service delete/update must be
//! symmetric: a Write-level member may manage a service it owns, but managing
//! another identity's service — or an org-level (`owner_identity_id IS NULL`)
//! service — still requires Admin. This is a strict per-row ownership check
//! (NOT a ceiling/family check). See `routes/services.rs`.

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
