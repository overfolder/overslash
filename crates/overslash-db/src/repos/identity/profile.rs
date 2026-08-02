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
