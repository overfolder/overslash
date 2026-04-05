use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct OrgRow {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub allow_user_templates: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

pub async fn create(pool: &PgPool, name: &str, slug: &str) -> Result<OrgRow, sqlx::Error> {
    sqlx::query_as!(
        OrgRow,
        "INSERT INTO orgs (name, slug) VALUES ($1, $2)
         RETURNING id, name, slug, allow_user_templates, created_at, updated_at",
        name,
        slug,
    )
    .fetch_one(pool)
    .await
}

pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<OrgRow>, sqlx::Error> {
    sqlx::query_as!(
        OrgRow,
        "SELECT id, name, slug, allow_user_templates, created_at, updated_at FROM orgs WHERE id = $1",
        id,
    )
    .fetch_optional(pool)
    .await
}

pub async fn get_by_slug(pool: &PgPool, slug: &str) -> Result<Option<OrgRow>, sqlx::Error> {
    sqlx::query_as!(
        OrgRow,
        "SELECT id, name, slug, allow_user_templates, created_at, updated_at FROM orgs WHERE slug = $1",
        slug,
    )
    .fetch_optional(pool)
    .await
}

pub async fn update(
    pool: &PgPool,
    id: Uuid,
    name: &str,
    allow_user_templates: bool,
) -> Result<Option<OrgRow>, sqlx::Error> {
    sqlx::query_as!(
        OrgRow,
        "UPDATE orgs SET name = $2, allow_user_templates = $3, updated_at = now()
         WHERE id = $1
         RETURNING id, name, slug, allow_user_templates, created_at, updated_at",
        id,
        name,
        allow_user_templates,
    )
    .fetch_optional(pool)
    .await
}
