use sqlx::PgPool;
use uuid::Uuid;

use super::IdentityRow;

/// Point a user identity at the IdP subject that just authenticated as it.
/// Used by the adopt-by-email login branch to convert a pre-created identity
/// (`external_id IS NULL` — "invited, never signed in") into a live one, and
/// to re-point an existing member who signs in through a second IdP.
///
/// The `(org_id, external_id)` unique constraint makes a collision here a
/// database error rather than a silent takeover; the caller surfaces it.
pub async fn set_external_id(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
    external_id: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE identities SET external_id = $3, updated_at = now()
         WHERE id = $1 AND org_id = $2",
        id,
        org_id,
        external_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Update an identity's profile (name, metadata) on subsequent login.
pub async fn update_profile(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
    name: &str,
    metadata: serde_json::Value,
) -> Result<Option<IdentityRow>, sqlx::Error> {
    sqlx::query_as!(
        IdentityRow,
        "UPDATE identities SET name = $3, metadata = $4, updated_at = now()
         WHERE id = $1 AND org_id = $2
         RETURNING id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at",
        id,
        org_id,
        name,
        metadata,
    )
    .fetch_optional(pool)
    .await
}

/// Refresh the display name of a user identity that has never signed in,
/// returning the previous name when a row actually changed.
///
/// Every part of the `WHERE` is load-bearing:
/// - `external_id IS NULL` — the row is still a pre-created member. Once a
///   human has signed in, the IdP profile owns the name (see `update_profile`,
///   which the login path calls) and header traffic must not fight it.
/// - `is_org_admin = false` — an admin's pending row is deliberately not
///   renameable this way; the blast radius of getting it wrong is larger and
///   the value of getting it right is smaller.
/// - `name <> $3` — this runs on the auth hot path. Steady-state traffic that
///   keeps sending the same name must not write a row per request.
///
/// The old name is read under the row lock before the update so the caller can
/// audit the transition; reading it back from a `RETURNING` subquery would see
/// the value we just wrote.
pub async fn rename_if_unadopted(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
    name: &str,
) -> Result<Option<String>, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let previous = sqlx::query_scalar!(
        "SELECT name FROM identities
         WHERE id = $1 AND org_id = $2 AND kind = 'user'
           AND external_id IS NULL AND is_org_admin = false
           AND archived_at IS NULL AND name <> $3
         FOR UPDATE",
        id,
        org_id,
        name,
    )
    .fetch_optional(&mut *tx)
    .await?;

    let Some(previous) = previous else {
        tx.commit().await?;
        return Ok(None);
    };

    sqlx::query!(
        "UPDATE identities SET name = $3, updated_at = now()
         WHERE id = $1 AND org_id = $2",
        id,
        org_id,
        name,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(previous))
}

/// Toggle the `is_org_admin` flag on a User identity. The DB CHECK constraint
/// rejects the call if `id` is not a User. Also keeps the `Admins` system group
/// membership in sync so the group-grant ACL path stays consistent with the
/// Attach (or detach) this identity's human pointer. Used by the multi-org
/// provisioning path when an existing identity needs to be promoted from
/// the legacy NULL-user_id shape. Writes are scoped by `(id, org_id)` to
/// avoid cross-tenant drift.
pub async fn set_user_id(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
    user_id: Option<Uuid>,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE identities SET user_id = $3, updated_at = now()
         WHERE id = $1 AND org_id = $2",
        id,
        org_id,
        user_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Toggle the per-agent `auto_call_on_approve` flag. Default for new
/// identities is TRUE; flipping to FALSE puts the agent in "deferred
/// execution" mode where the resolver/agent must call `POST
/// /v1/approvals/{id}/call` explicitly after approve.
pub async fn set_auto_call_on_approve(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
    value: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE identities SET auto_call_on_approve = $3, updated_at = now()
         WHERE id = $1 AND org_id = $2",
        id,
        org_id,
        value,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn set_inherit_permissions(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
    inherit: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE identities SET inherit_permissions = $3, updated_at = now()
         WHERE id = $1 AND org_id = $2",
        id,
        org_id,
        inherit,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}
