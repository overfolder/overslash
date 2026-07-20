//! Migration 086 — re-point agent-level OAuth connections to the owner identity.
//!
//! Storage complement to D22 (see `owner_scoped_connections.rs`). Connections
//! used to bind to the calling agent; the read path resolves them at the owner,
//! so legacy agent-bound rows were invisible and caused reauth loops. The
//! migration re-points every agent/sub_agent connection to its owner user,
//! collapsing duplicates:
//!   - owner wins: drop an agent row when the owner already holds one for the
//!     same (provider, account_email);
//!   - agent-vs-agent: among the rest, keep only the most recent per
//!     (owner, provider, account_email);
//!   - re-point the survivors and re-establish one default per (identity, provider).
//!
//! This test seeds legacy agent-bound rows directly (bypassing the new
//! owner-binding write path) and runs the real `086_*.up.sql` against them.

// Seeds rows via direct SQL.
#![allow(clippy::disallowed_methods)]

use crate::common;

use overslash_core::crypto;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// The exact migration this test exercises.
const MIGRATION_086: &str =
    include_str!("../../overslash-db/migrations/086_connection_owner_identity.up.sql");

/// Seed one connection row with explicit `account_email`, `is_default`, and
/// `created_at` (so "most recent wins" is deterministic). Returns its id.
#[allow(clippy::too_many_arguments)]
async fn seed(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    provider_key: &str,
    account_email: &str,
    is_default: bool,
    created_at: OffsetDateTime,
) -> Uuid {
    let enc_key = crypto::Keyring::test();
    let access = crypto::encrypt(&enc_key, b"mock_access_token").unwrap();
    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO connections (org_id, identity_id, provider_key,
         encrypted_access_token, token_expires_at, scopes, account_email,
         is_default, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id",
    )
    .bind(org_id)
    .bind(identity_id)
    .bind(provider_key)
    .bind(&access)
    .bind(OffsetDateTime::now_utc() + time::Duration::hours(1))
    .bind(Vec::<String>::new())
    .bind(account_email)
    .bind(is_default)
    .bind(created_at)
    .fetch_one(pool)
    .await
    .unwrap();
    row.0
}

async fn count_for(pool: &PgPool, identity_id: Uuid) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM connections WHERE identity_id = $1")
        .bind(identity_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn exists(pool: &PgPool, id: Uuid) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM connections WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
        == 1
}

/// Full scenario: owner-wins delete, agent-vs-agent collapse (most recent wins),
/// re-point, and exactly one default per (identity, provider) after the move.
#[tokio::test]
async fn migration_collapses_agent_rows_into_owner() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    // `bootstrap_org_identity` makes the agent a child of "test-user" with
    // owner_id pointing at that user — exactly what the migration walks.
    let (org_id, agent_id, _key, _admin_key) = common::bootstrap_org_identity(&base, &client).await;
    let owner_id = common::owner_user_id(&pool, org_id).await;

    let t = |h: i64| OffsetDateTime::now_utc() - time::Duration::hours(h);

    // Owner already holds a google connection for owned@example.com.
    let owner_owned = seed(
        &pool,
        org_id,
        owner_id,
        "google",
        "owned@example.com",
        true,
        t(10),
    )
    .await;

    // Agent rows. The unique index allows only one is_default per
    // (agent, google), so only the first is_default=true.
    // owned@example.com on the agent — owner already has it → both deleted.
    let agent_owned_a = seed(
        &pool,
        org_id,
        agent_id,
        "google",
        "owned@example.com",
        true,
        t(9),
    )
    .await;
    let agent_owned_b = seed(
        &pool,
        org_id,
        agent_id,
        "google",
        "owned@example.com",
        false,
        t(8),
    )
    .await;
    // dupe@example.com ×2 — no owner row → collapse to the most recent (t=4).
    let dupe_old = seed(
        &pool,
        org_id,
        agent_id,
        "google",
        "dupe@example.com",
        false,
        t(6),
    )
    .await;
    let dupe_new = seed(
        &pool,
        org_id,
        agent_id,
        "google",
        "dupe@example.com",
        false,
        t(4),
    )
    .await;
    // solo@example.com — unique, simply re-pointed.
    let solo = seed(
        &pool,
        org_id,
        agent_id,
        "google",
        "solo@example.com",
        false,
        t(2),
    )
    .await;

    sqlx::raw_sql(MIGRATION_086).execute(&pool).await.unwrap();

    // No connection remains on the agent — they all moved or were deleted.
    assert_eq!(
        count_for(&pool, agent_id).await,
        0,
        "agent must retain no connections"
    );

    // Owner-wins: the agent's owned@example.com rows are gone; the owner's kept.
    assert!(
        exists(&pool, owner_owned).await,
        "owner's pre-existing row survives"
    );
    assert!(
        !exists(&pool, agent_owned_a).await,
        "agent owned-dupe deleted (owner wins)"
    );
    assert!(
        !exists(&pool, agent_owned_b).await,
        "agent owned-dupe deleted (owner wins)"
    );

    // Agent-vs-agent collapse: most recent dupe survives, older one gone.
    assert!(exists(&pool, dupe_new).await, "most-recent dupe survives");
    assert!(!exists(&pool, dupe_old).await, "older dupe collapsed");

    // Solo re-pointed.
    assert!(exists(&pool, solo).await, "solo row survives");

    // Owner now holds exactly three google connections: owned, dupe(new), solo.
    let owner_google = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM connections WHERE identity_id = $1 AND provider_key = 'google'",
    )
    .bind(owner_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(owner_google, 3, "owner holds owned + dupe(new) + solo");

    // Exactly one default per (owner, google) — the unique index invariant holds.
    let defaults = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM connections
         WHERE identity_id = $1 AND provider_key = 'google' AND is_default",
    )
    .bind(owner_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(defaults, 1, "exactly one default for (owner, google)");

    // The surviving rows really are owned by the owner identity.
    for id in [dupe_new, solo] {
        let owner =
            sqlx::query_scalar::<_, Uuid>("SELECT identity_id FROM connections WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            owner, owner_id,
            "re-pointed row {id} must belong to the owner"
        );
    }
}
