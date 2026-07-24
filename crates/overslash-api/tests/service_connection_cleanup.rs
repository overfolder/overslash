//! Connection auto-cleanup on service deletion.
//!
//! Deleting a service instance also deletes the OAuth connection it was bound
//! to, but only when all three hold: the caller did not pass
//! `keep_connection=true`, the connection is not marked `keep`, and no other
//! service instance (any status) still references it. See `routes/services.rs`
//! (`delete_service` / `cleanup_orphaned_connection`).

// Seeds services + connections + asserts via direct SQL.
#![allow(clippy::disallowed_methods)]

use crate::common;

use overslash_core::crypto;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// Seed an OAuth connection owned by `identity_id`, optionally marked `keep`.
async fn seed_connection(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    provider_key: &str,
    keep: bool,
) -> Uuid {
    let enc_key = crypto::Keyring::test();
    let access = crypto::encrypt(&enc_key, b"mock_access_token").unwrap();
    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO connections (org_id, identity_id, provider_key,
         encrypted_access_token, account_email, is_default, keep)
         VALUES ($1, $2, $3, $4, $5, true, $6) RETURNING id",
    )
    .bind(org_id)
    .bind(identity_id)
    .bind(provider_key)
    .bind(&access)
    .bind(format!("{provider_key}@x"))
    .bind(keep)
    .fetch_one(pool)
    .await
    .unwrap();
    row.0
}

/// Seed a service instance, optionally bound to `connection_id` and with a
/// given status (`active` / `draft` / `archived`).
async fn seed_service(
    pool: &PgPool,
    org_id: Uuid,
    owner: Uuid,
    name: &str,
    connection_id: Option<Uuid>,
    status: &str,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO service_instances \
         (org_id, owner_identity_id, name, template_source, template_key, status, connection_id) \
         VALUES ($1, $2, $3, 'global', $3, $5, $4) RETURNING id",
    )
    .bind(org_id)
    .bind(owner)
    .bind(name)
    .bind(connection_id)
    .bind(status)
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

async fn connection_count(pool: &PgPool, id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM connections WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Default: deleting the only service bound to a connection deletes the
/// connection too.
#[tokio::test]
async fn default_deletes_orphaned_connection() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let conn = seed_connection(&pool, fx.org_id, fx.user_ids[0], "google", false).await;
    let svc = seed_service(
        &pool,
        fx.org_id,
        fx.user_ids[0],
        "svc",
        Some(conn),
        "active",
    )
    .await;

    let resp = client
        .delete(format!("{base}/v1/services/{svc}"))
        .header("Authorization", format!("Bearer {}", fx.admin_key))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["deleted"], true);
    assert_eq!(body["connection_deleted"], true);
    assert_eq!(service_count(&pool, svc).await, 0);
    assert_eq!(
        connection_count(&pool, conn).await,
        0,
        "orphaned connection must be deleted"
    );
}

/// `keep_connection=true` preserves the connection.
#[tokio::test]
async fn keep_connection_query_preserves() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let conn = seed_connection(&pool, fx.org_id, fx.user_ids[0], "google", false).await;
    let svc = seed_service(
        &pool,
        fx.org_id,
        fx.user_ids[0],
        "svc",
        Some(conn),
        "active",
    )
    .await;

    let resp = client
        .delete(format!("{base}/v1/services/{svc}?keep_connection=true"))
        .header("Authorization", format!("Bearer {}", fx.admin_key))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["connection_deleted"], false);
    assert_eq!(
        connection_count(&pool, conn).await,
        1,
        "connection must survive"
    );
}

/// A connection marked `keep` is preserved even without the query opt-out.
#[tokio::test]
async fn keep_flag_preserves() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let conn = seed_connection(&pool, fx.org_id, fx.user_ids[0], "google", true).await;
    let svc = seed_service(
        &pool,
        fx.org_id,
        fx.user_ids[0],
        "svc",
        Some(conn),
        "active",
    )
    .await;

    let resp = client
        .delete(format!("{base}/v1/services/{svc}"))
        .header("Authorization", format!("Bearer {}", fx.admin_key))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["connection_deleted"], false);
    assert_eq!(
        connection_count(&pool, conn).await,
        1,
        "kept connection must survive"
    );
}

/// A connection still referenced by another service (even a draft) is
/// preserved.
#[tokio::test]
async fn still_referenced_preserves() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let conn = seed_connection(&pool, fx.org_id, fx.user_ids[0], "google", false).await;
    let svc = seed_service(
        &pool,
        fx.org_id,
        fx.user_ids[0],
        "svc-a",
        Some(conn),
        "active",
    )
    .await;
    // A second, draft-status service also bound to the same connection.
    let _other = seed_service(
        &pool,
        fx.org_id,
        fx.user_ids[0],
        "svc-b",
        Some(conn),
        "draft",
    )
    .await;

    let resp = client
        .delete(format!("{base}/v1/services/{svc}"))
        .header("Authorization", format!("Bearer {}", fx.admin_key))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["connection_deleted"], false);
    assert_eq!(
        connection_count(&pool, conn).await,
        1,
        "connection still used by another service must survive"
    );
}

/// A service with no bound connection deletes cleanly (no cascade).
#[tokio::test]
async fn no_connection_is_noop() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let svc = seed_service(&pool, fx.org_id, fx.user_ids[0], "svc", None, "active").await;

    let resp = client
        .delete(format!("{base}/v1/services/{svc}"))
        .header("Authorization", format!("Bearer {}", fx.admin_key))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["deleted"], true);
    assert_eq!(body["connection_deleted"], false);
    assert_eq!(service_count(&pool, svc).await, 0);
}

/// The `keep` toggle endpoint updates the flag, reflected in the detail view.
#[tokio::test]
async fn keep_toggle_endpoint() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let conn = seed_connection(&pool, fx.org_id, fx.user_ids[0], "google", false).await;

    let resp = client
        .post(format!("{base}/v1/connections/{conn}/keep"))
        .header("Authorization", format!("Bearer {}", fx.admin_key))
        .json(&serde_json::json!({ "keep": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["keep"], true);

    let detail: Value = client
        .get(format!("{base}/v1/connections/{conn}"))
        .header("Authorization", format!("Bearer {}", fx.admin_key))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["keep"], true);
}
