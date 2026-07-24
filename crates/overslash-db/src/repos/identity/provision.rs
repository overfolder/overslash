use sqlx::PgPool;
use uuid::Uuid;

use super::{IdentityRow, find_child_by_name, find_user_by_email_in_org};

/// Serialize the get-or-create paths below on `(org_id, key)`.
///
/// `identities` has no unique index on `(org_id, email)` (dropped by
/// migration 043) or on `(org_id, parent_id, name)` — names and emails are
/// deliberately non-unique — so two concurrent first-calls naming the same
/// target would each miss the lookup and each insert. A transaction-scoped
/// advisory lock is the cheapest fix that needs no schema change: it is
/// released on commit or rollback, so a panicking request cannot strand it.
async fn lock_identity_key(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: Uuid,
    key: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        format!("identity:{org_id}:{key}"),
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Resolve a live user identity by email in this org, creating it when
/// absent. Returns `(row, created)` so the caller can decide whether to log
/// provisioning audit and run the new-member bootstrap.
///
/// The created row deliberately has `external_id = NULL`: that is what marks
/// a person who belongs to the org but has never completed a sign-in, and it
/// is the hook the login path adopts by email.
pub async fn get_or_create_user_by_email(
    pool: &PgPool,
    org_id: Uuid,
    email: &str,
    name: &str,
    metadata: serde_json::Value,
) -> Result<(IdentityRow, bool), sqlx::Error> {
    if let Some(existing) = find_user_by_email_in_org(pool, org_id, email).await? {
        return Ok((existing, false));
    }

    let mut tx = pool.begin().await?;
    lock_identity_key(&mut tx, org_id, &format!("email:{}", email.to_lowercase())).await?;

    // Re-check under the lock: the request that beat us here committed its
    // insert before releasing it, so this now sees the winner's row.
    let existing = sqlx::query_as!(
        IdentityRow,
        "SELECT id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at
         FROM identities
         WHERE org_id = $1 AND kind = 'user' AND lower(email) = lower($2)
           AND archived_at IS NULL
         ORDER BY created_at ASC
         LIMIT 1",
        org_id,
        email,
    )
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(row) = existing {
        tx.commit().await?;
        return Ok((row, false));
    }

    let row = sqlx::query_as!(
        IdentityRow,
        "INSERT INTO identities (org_id, name, kind, email, metadata, auto_call_on_approve)
         VALUES ($1, $2, 'user', lower($3), $4, (SELECT NOT default_deferred_execution FROM orgs WHERE id = $1))
         RETURNING id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at",
        org_id,
        name,
        email,
        metadata,
    )
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((row, true))
}

/// Resolve a live child identity by name under `parent_id`, creating it when
/// absent. Returns `(row, created)`.
///
/// `inherit_permissions` is always `false` on the created row: an inheriting
/// child never gates, so a header-driven creation path must not mint one.
#[allow(clippy::too_many_arguments)]
pub async fn get_or_create_child(
    pool: &PgPool,
    org_id: Uuid,
    parent_id: Uuid,
    name: &str,
    kind: &str,
    depth: i32,
    owner_id: Uuid,
    metadata: serde_json::Value,
) -> Result<(IdentityRow, bool), sqlx::Error> {
    if let Some(existing) = find_child_by_name(pool, org_id, parent_id, name).await? {
        return Ok((existing, false));
    }

    let mut tx = pool.begin().await?;
    lock_identity_key(&mut tx, org_id, &format!("child:{parent_id}:{name}")).await?;

    let existing = sqlx::query_as!(
        IdentityRow,
        "SELECT id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at
         FROM identities
         WHERE org_id = $1 AND parent_id = $2 AND name = $3 AND archived_at IS NULL
         ORDER BY created_at ASC
         LIMIT 1",
        org_id,
        parent_id,
        name,
    )
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(row) = existing {
        tx.commit().await?;
        return Ok((row, false));
    }

    let row = sqlx::query_as!(
        IdentityRow,
        "INSERT INTO identities (org_id, name, kind, parent_id, depth, owner_id, inherit_permissions, metadata, auto_call_on_approve)
         VALUES ($1, $2, $3, $4, $5, $6, false, $7, (SELECT NOT default_deferred_execution FROM orgs WHERE id = $1))
         RETURNING id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at",
        org_id,
        name,
        kind,
        parent_id,
        depth,
        owner_id,
        metadata,
    )
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((row, true))
}
