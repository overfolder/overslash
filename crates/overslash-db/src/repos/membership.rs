//! `user_org_memberships` — links `users` to `orgs` with a role. This is the
//! check that gates access to any org; identities-per-org follow from it.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct MembershipRow {
    pub user_id: Uuid,
    pub org_id: Uuid,
    /// `'admin'` or `'member'` — enforced by a DB CHECK.
    pub role: String,
    /// `true` for the one membership created by `POST /v1/orgs` when a user
    /// creates a corp org. Persists as a breakglass admin after the org
    /// configures its IdP (see `docs/design/multi_org_auth.md`).
    pub is_bootstrap: bool,
    pub created_at: OffsetDateTime,
}

pub const ROLE_ADMIN: &str = "admin";
pub const ROLE_MEMBER: &str = "member";

pub async fn find(
    pool: &PgPool,
    user_id: Uuid,
    org_id: Uuid,
) -> Result<Option<MembershipRow>, sqlx::Error> {
    sqlx::query_as!(
        MembershipRow,
        "SELECT user_id, org_id, role, is_bootstrap, created_at
         FROM user_org_memberships WHERE user_id = $1 AND org_id = $2",
        user_id,
        org_id,
    )
    .fetch_optional(pool)
    .await
}

pub async fn list_for_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<MembershipRow>, sqlx::Error> {
    sqlx::query_as!(
        MembershipRow,
        "SELECT user_id, org_id, role, is_bootstrap, created_at
         FROM user_org_memberships WHERE user_id = $1 ORDER BY created_at ASC",
        user_id,
    )
    .fetch_all(pool)
    .await
}

pub async fn list_for_org(pool: &PgPool, org_id: Uuid) -> Result<Vec<MembershipRow>, sqlx::Error> {
    sqlx::query_as!(
        MembershipRow,
        "SELECT user_id, org_id, role, is_bootstrap, created_at
         FROM user_org_memberships WHERE org_id = $1 ORDER BY created_at ASC",
        org_id,
    )
    .fetch_all(pool)
    .await
}

pub async fn create(
    pool: &PgPool,
    user_id: Uuid,
    org_id: Uuid,
    role: &str,
    is_bootstrap: bool,
) -> Result<MembershipRow, sqlx::Error> {
    sqlx::query_as!(
        MembershipRow,
        "INSERT INTO user_org_memberships (user_id, org_id, role, is_bootstrap)
         VALUES ($1, $2, $3, $4)
         RETURNING user_id, org_id, role, is_bootstrap, created_at",
        user_id,
        org_id,
        role,
        is_bootstrap,
    )
    .fetch_one(pool)
    .await
}

pub async fn delete(pool: &PgPool, user_id: Uuid, org_id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "DELETE FROM user_org_memberships WHERE user_id = $1 AND org_id = $2",
        user_id,
        org_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}
