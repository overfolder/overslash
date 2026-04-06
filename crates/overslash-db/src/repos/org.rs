use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct OrgRow {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub subagent_idle_timeout_secs: i32,
    pub subagent_archive_retention_days: i32,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

pub async fn create(pool: &PgPool, name: &str, slug: &str) -> Result<OrgRow, sqlx::Error> {
    sqlx::query_as!(
        OrgRow,
        "INSERT INTO orgs (name, slug) VALUES ($1, $2)
         RETURNING id, name, slug, subagent_idle_timeout_secs, subagent_archive_retention_days, created_at, updated_at",
        name,
        slug,
    )
    .fetch_one(pool)
    .await
}

pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<OrgRow>, sqlx::Error> {
    sqlx::query_as!(
        OrgRow,
        "SELECT id, name, slug, subagent_idle_timeout_secs, subagent_archive_retention_days, created_at, updated_at
         FROM orgs WHERE id = $1",
        id,
    )
    .fetch_optional(pool)
    .await
}

pub async fn get_by_slug(pool: &PgPool, slug: &str) -> Result<Option<OrgRow>, sqlx::Error> {
    sqlx::query_as!(
        OrgRow,
        "SELECT id, name, slug, subagent_idle_timeout_secs, subagent_archive_retention_days, created_at, updated_at
         FROM orgs WHERE slug = $1",
        slug,
    )
    .fetch_optional(pool)
    .await
}

/// Update an org's sub-agent cleanup configuration. Bounds validated by caller.
pub async fn update_subagent_cleanup_config(
    pool: &PgPool,
    id: Uuid,
    idle_timeout_secs: i32,
    archive_retention_days: i32,
) -> Result<Option<OrgRow>, sqlx::Error> {
    sqlx::query_as!(
        OrgRow,
        "UPDATE orgs
         SET subagent_idle_timeout_secs = $2,
             subagent_archive_retention_days = $3,
             updated_at = now()
         WHERE id = $1
         RETURNING id, name, slug, subagent_idle_timeout_secs, subagent_archive_retention_days, created_at, updated_at",
        id,
        idle_timeout_secs,
        archive_retention_days,
    )
    .fetch_optional(pool)
    .await
}
