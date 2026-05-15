//! `org_invites` — admin-curated `(email, role)` allowlist used by the
//! Overslash-managed sign-in flow. When `orgs.allow_overslash_managed_signin`
//! is true, the post-OAuth callback admits a user only if their verified
//! email matches a pending invite for the org. See migration 066 and
//! `docs/design/multi_org_auth.md`.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct OrgInviteRow {
    pub id: Uuid,
    pub org_id: Uuid,
    /// Always lower-cased — the DB CHECK enforces it and lookups use
    /// `lower($1)` so callers can pass any casing safely.
    pub email: String,
    /// `'admin'` or `'member'`. Enforced by a DB CHECK matching
    /// `user_org_memberships.role_check`.
    pub role: String,
    /// Identity that minted the invite. NULL'd on identity deletion so the
    /// audit trail survives admin offboarding.
    pub invited_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
    pub accepted_at: Option<OffsetDateTime>,
    pub accepted_by_user_id: Option<Uuid>,
}

/// Insert a new pending invite. The `(org_id, email)` partial unique index
/// guards against two pending invites for the same person — bubble that up
/// as `sqlx::Error::Database(is_unique_violation())` and let the handler
/// turn it into a 409.
pub(crate) async fn create(
    pool: &PgPool,
    org_id: Uuid,
    email: &str,
    role: &str,
    invited_by: Option<Uuid>,
) -> Result<OrgInviteRow, sqlx::Error> {
    sqlx::query_as!(
        OrgInviteRow,
        "INSERT INTO org_invites (org_id, email, role, invited_by)
         VALUES ($1, lower($2), $3, $4)
         RETURNING id, org_id, email, role, invited_by, created_at, accepted_at, accepted_by_user_id",
        org_id,
        email,
        role,
        invited_by,
    )
    .fetch_one(pool)
    .await
}

pub(crate) async fn get_by_id(
    pool: &PgPool,
    id: Uuid,
    org_id: Uuid,
) -> Result<Option<OrgInviteRow>, sqlx::Error> {
    sqlx::query_as!(
        OrgInviteRow,
        "SELECT id, org_id, email, role, invited_by, created_at, accepted_at, accepted_by_user_id
         FROM org_invites WHERE id = $1 AND org_id = $2",
        id,
        org_id,
    )
    .fetch_optional(pool)
    .await
}

pub(crate) async fn list_by_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<OrgInviteRow>, sqlx::Error> {
    sqlx::query_as!(
        OrgInviteRow,
        "SELECT id, org_id, email, role, invited_by, created_at, accepted_at, accepted_by_user_id
         FROM org_invites WHERE org_id = $1 ORDER BY created_at DESC",
        org_id,
    )
    .fetch_all(pool)
    .await
}

/// Find the pending invite for `(org_id, lower(email))`. Returns `None` if
/// no row exists or if the only row is already accepted — the caller is
/// expected to reject the login in either case.
pub async fn find_pending(
    pool: &PgPool,
    org_id: Uuid,
    email: &str,
) -> Result<Option<OrgInviteRow>, sqlx::Error> {
    sqlx::query_as!(
        OrgInviteRow,
        "SELECT id, org_id, email, role, invited_by, created_at, accepted_at, accepted_by_user_id
         FROM org_invites
         WHERE org_id = $1 AND email = lower($2) AND accepted_at IS NULL",
        org_id,
        email,
    )
    .fetch_optional(pool)
    .await
}

/// Mark an invite accepted. Idempotent: any row already accepted is
/// left untouched (the WHERE clause requires `accepted_at IS NULL`),
/// so a concurrent caller that lost the race just returns `Ok(false)`
/// without an error.
pub async fn mark_accepted(pool: &PgPool, id: Uuid, user_id: Uuid) -> Result<bool, sqlx::Error> {
    let res = sqlx::query!(
        "UPDATE org_invites
         SET accepted_at = now(), accepted_by_user_id = $2
         WHERE id = $1 AND accepted_at IS NULL",
        id,
        user_id,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Revoke a pending invite. Accepted invites are kept for the audit trail —
/// `accepted_at IS NULL` is the gate.
pub(crate) async fn delete_pending(
    pool: &PgPool,
    id: Uuid,
    org_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query!(
        "DELETE FROM org_invites
         WHERE id = $1 AND org_id = $2 AND accepted_at IS NULL",
        id,
        org_id,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}
