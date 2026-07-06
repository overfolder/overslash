//! Admin-only "show all users' connections" view + full management.
//!
//! Mirrors the services `include_user_level` admin view, but for OAuth
//! connections. An org admin (the `is_org_admin` flag, not the Admins group /
//! `overslash` ACL) can:
//!   - list every user's connections via `?include_user_level=true`,
//!   - open, delete, and set-default another user's connection.
//!
//! Non-admins get only their own rows (the flag is silently ignored) and a 404
//! on another user's connection. See `routes/connections.rs`.

// Seeds connections + asserts via direct SQL.
#![allow(clippy::disallowed_methods)]

mod common;

use overslash_core::crypto;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// Seed an OAuth connection owned by `identity_id`. `is_default` controls the
/// per-(identity, provider) default flag — pass `false` for the second account
/// of a provider so the partial unique index isn't violated.
async fn seed_connection(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    provider_key: &str,
    account_email: &str,
    is_default: bool,
) -> Uuid {
    let enc_key = crypto::Keyring::test();
    let access = crypto::encrypt(&enc_key, b"mock_access_token").unwrap();
    let expires_at = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let scopes: Vec<String> = vec!["read".to_string()];
    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO connections (org_id, identity_id, provider_key,
         encrypted_access_token, token_expires_at, scopes, account_email, is_default)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
    )
    .bind(org_id)
    .bind(identity_id)
    .bind(provider_key)
    .bind(&access)
    .bind(expires_at)
    .bind(scopes)
    .bind(account_email)
    .bind(is_default)
    .fetch_one(pool)
    .await
    .unwrap();
    row.0
}

async fn make_org_admin(pool: &PgPool, identity_id: Uuid) {
    sqlx::query!(
        "UPDATE identities SET is_org_admin = true WHERE id = $1",
        identity_id,
    )
    .execute(pool)
    .await
    .unwrap();
}

/// A flag-only org admin passing `?include_user_level=true` sees every user's
/// connections, each carrying the correct `owner_identity_id`.
#[tokio::test]
async fn admin_sees_all_users_connections_with_flag() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let admin_conn =
        seed_connection(&pool, fx.org_id, fx.user_ids[0], "google", "admin@x", true).await;
    let write_conn =
        seed_connection(&pool, fx.org_id, fx.user_ids[1], "github", "write@x", true).await;
    make_org_admin(&pool, fx.user_ids[0]).await;

    let resp = client
        .get(format!("{base}/v1/connections?include_user_level=true"))
        .header("Authorization", format!("Bearer {}", fx.admin_key))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let conns: Vec<Value> = resp.json().await.unwrap();
    let ids: Vec<&str> = conns.iter().filter_map(|c| c["id"].as_str()).collect();
    assert!(
        ids.contains(&admin_conn.to_string().as_str())
            && ids.contains(&write_conn.to_string().as_str()),
        "admin must see both users' connections (got: {ids:?})"
    );

    // owner_identity_id is surfaced and correct for the other user's row.
    let write_row = conns
        .iter()
        .find(|c| c["id"].as_str() == Some(write_conn.to_string().as_str()))
        .unwrap();
    assert_eq!(
        write_row["owner_identity_id"].as_str().unwrap(),
        fx.user_ids[1].to_string(),
        "owner_identity_id must point at the connection's owner"
    );
}

/// `?include_user_level=true` is silently ignored for non-admins — write-user
/// sees only their own connection, not the admin-user's.
#[tokio::test]
async fn non_admin_include_user_level_silently_ignored() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let admin_conn =
        seed_connection(&pool, fx.org_id, fx.user_ids[0], "google", "admin@x", true).await;
    let write_conn =
        seed_connection(&pool, fx.org_id, fx.user_ids[1], "github", "write@x", true).await;

    let resp = client
        .get(format!("{base}/v1/connections?include_user_level=true"))
        .header("Authorization", format!("Bearer {}", fx.write_key))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let conns: Vec<Value> = resp.json().await.unwrap();
    let ids: Vec<&str> = conns.iter().filter_map(|c| c["id"].as_str()).collect();
    assert!(
        ids.contains(&write_conn.to_string().as_str()),
        "write-user must see their own connection (got: {ids:?})"
    );
    assert!(
        !ids.contains(&admin_conn.to_string().as_str()),
        "non-admin must not see another user's connection even with the flag (got: {ids:?})"
    );
}

/// An org admin can open another user's connection detail; a non-admin
/// non-owner gets a 404 (the row stays invisible).
#[tokio::test]
async fn admin_can_get_another_users_connection_detail() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let write_conn =
        seed_connection(&pool, fx.org_id, fx.user_ids[1], "github", "write@x", true).await;
    make_org_admin(&pool, fx.user_ids[0]).await;

    let resp = client
        .get(format!("{base}/v1/connections/{write_conn}"))
        .header("Authorization", format!("Bearer {}", fx.admin_key))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "admin must read another user's connection"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["provider_key"], "github");

    // read-user is not an admin and doesn't own it.
    let resp = client
        .get(format!("{base}/v1/connections/{write_conn}"))
        .header("Authorization", format!("Bearer {}", fx.read_key))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "non-admin non-owner must get 404");
}

/// An org admin can delete another user's connection; a non-admin non-owner
/// cannot (the row survives).
#[tokio::test]
async fn admin_can_delete_another_users_connection() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let write_conn =
        seed_connection(&pool, fx.org_id, fx.user_ids[1], "github", "write@x", true).await;
    make_org_admin(&pool, fx.user_ids[0]).await;

    let resp = client
        .delete(format!("{base}/v1/connections/{write_conn}"))
        .header("Authorization", format!("Bearer {}", fx.admin_key))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["deleted"], true, "admin delete must report deleted");

    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM connections WHERE id = $1")
        .bind(write_conn)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining, 0, "connection must be gone");
}

/// A non-admin cannot delete a connection they don't own — the call reports
/// `deleted: false` and the row survives.
#[tokio::test]
async fn non_admin_cannot_delete_another_users_connection() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    // read-user owns it; write-user (not admin) tries to delete.
    let read_conn =
        seed_connection(&pool, fx.org_id, fx.user_ids[2], "github", "read@x", true).await;

    let resp = client
        .delete(format!("{base}/v1/connections/{read_conn}"))
        .header("Authorization", format!("Bearer {}", fx.write_key))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["deleted"], false,
        "non-admin must not delete others' rows"
    );

    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM connections WHERE id = $1")
        .bind(read_conn)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining, 1, "connection must survive");
}

/// `?owner_identity_id=<other>` lets an org admin list a specific user's
/// connections (e.g. the owner of a service they're viewing) — only that
/// owner's rows, not the admin's own and not the whole org.
#[tokio::test]
async fn admin_owner_scoped_lists_only_that_owner() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let admin_conn =
        seed_connection(&pool, fx.org_id, fx.user_ids[0], "google", "admin@x", true).await;
    let write_conn =
        seed_connection(&pool, fx.org_id, fx.user_ids[1], "github", "write@x", true).await;
    let read_conn =
        seed_connection(&pool, fx.org_id, fx.user_ids[2], "github", "read@x", true).await;
    make_org_admin(&pool, fx.user_ids[0]).await;

    let resp = client
        .get(format!(
            "{base}/v1/connections?owner_identity_id={}",
            fx.user_ids[1]
        ))
        .header("Authorization", format!("Bearer {}", fx.admin_key))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let conns: Vec<Value> = resp.json().await.unwrap();
    let ids: Vec<&str> = conns.iter().filter_map(|c| c["id"].as_str()).collect();
    assert!(
        ids.contains(&write_conn.to_string().as_str()),
        "must see the target owner's connection (got: {ids:?})"
    );
    assert!(
        !ids.contains(&admin_conn.to_string().as_str())
            && !ids.contains(&read_conn.to_string().as_str()),
        "must see ONLY the target owner's rows (got: {ids:?})"
    );
}

/// A non-admin passing `?owner_identity_id=<other>` is silently downgraded to
/// their own connections (same contract as `include_user_level`, no 403).
#[tokio::test]
async fn non_admin_owner_scoped_downgrades_to_own() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let admin_conn =
        seed_connection(&pool, fx.org_id, fx.user_ids[0], "google", "admin@x", true).await;
    let write_conn =
        seed_connection(&pool, fx.org_id, fx.user_ids[1], "github", "write@x", true).await;

    // write-user (non-admin) asks for the admin-user's connections.
    let resp = client
        .get(format!(
            "{base}/v1/connections?owner_identity_id={}",
            fx.user_ids[0]
        ))
        .header("Authorization", format!("Bearer {}", fx.write_key))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let conns: Vec<Value> = resp.json().await.unwrap();
    let ids: Vec<&str> = conns.iter().filter_map(|c| c["id"].as_str()).collect();
    assert!(
        ids.contains(&write_conn.to_string().as_str())
            && !ids.contains(&admin_conn.to_string().as_str()),
        "non-admin must fall back to their own rows only (got: {ids:?})"
    );
}

/// `?owner_identity_id=<self>` is always allowed and returns the caller's own
/// connections — the common case for a user viewing their own service.
#[tokio::test]
async fn owner_scoped_self_returns_own() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let write_conn =
        seed_connection(&pool, fx.org_id, fx.user_ids[1], "github", "write@x", true).await;

    let resp = client
        .get(format!(
            "{base}/v1/connections?owner_identity_id={}",
            fx.user_ids[1]
        ))
        .header("Authorization", format!("Bearer {}", fx.write_key))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let conns: Vec<Value> = resp.json().await.unwrap();
    let ids: Vec<&str> = conns.iter().filter_map(|c| c["id"].as_str()).collect();
    assert!(
        ids.contains(&write_conn.to_string().as_str()),
        "self owner scope must return own connections (got: {ids:?})"
    );
}

/// An org admin promoting another user's connection demotes the sibling within
/// the **owner's** (identity, provider), not the admin's.
#[tokio::test]
async fn admin_set_default_demotes_within_owner_identity() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    // write-user has two github connections; the first is the current default.
    let first = seed_connection(
        &pool,
        fx.org_id,
        fx.user_ids[1],
        "github",
        "write-a@x",
        true,
    )
    .await;
    let second = seed_connection(
        &pool,
        fx.org_id,
        fx.user_ids[1],
        "github",
        "write-b@x",
        false,
    )
    .await;
    make_org_admin(&pool, fx.user_ids[0]).await;

    let resp = client
        .post(format!("{base}/v1/connections/{second}/set_default"))
        .header("Authorization", format!("Bearer {}", fx.admin_key))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "admin set_default on another user's conn"
    );

    let first_default: bool =
        sqlx::query_scalar("SELECT is_default FROM connections WHERE id = $1")
            .bind(first)
            .fetch_one(&pool)
            .await
            .unwrap();
    let second_default: bool =
        sqlx::query_scalar("SELECT is_default FROM connections WHERE id = $1")
            .bind(second)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!first_default, "the prior default must be demoted");
    assert!(second_default, "the promoted connection must be default");
}
