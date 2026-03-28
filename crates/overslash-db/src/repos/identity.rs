use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct IdentityRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub name: String,
    pub kind: String,
    pub external_id: Option<String>,
    pub email: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

pub async fn create(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
    kind: &str,
    external_id: Option<&str>,
) -> Result<IdentityRow, sqlx::Error> {
    sqlx::query_as::<_, IdentityRow>(
        "INSERT INTO identities (org_id, name, kind, external_id) VALUES ($1, $2, $3, $4)
         RETURNING id, org_id, name, kind, external_id, email, metadata, created_at, updated_at",
    )
    .bind(org_id)
    .bind(name)
    .bind(kind)
    .bind(external_id)
    .fetch_one(pool)
    .await
}

pub async fn create_with_email(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
    kind: &str,
    external_id: Option<&str>,
    email: Option<&str>,
    metadata: serde_json::Value,
) -> Result<IdentityRow, sqlx::Error> {
    sqlx::query_as::<_, IdentityRow>(
        "INSERT INTO identities (org_id, name, kind, external_id, email, metadata)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, org_id, name, kind, external_id, email, metadata, created_at, updated_at",
    )
    .bind(org_id)
    .bind(name)
    .bind(kind)
    .bind(external_id)
    .bind(email)
    .bind(metadata)
    .fetch_one(pool)
    .await
}

pub async fn find_by_email(pool: &PgPool, email: &str) -> Result<Option<IdentityRow>, sqlx::Error> {
    sqlx::query_as::<_, IdentityRow>(
        "SELECT id, org_id, name, kind, external_id, email, metadata, created_at, updated_at
         FROM identities WHERE email = $1 AND kind = 'user'",
    )
    .bind(email)
    .fetch_optional(pool)
    .await
}

pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<IdentityRow>, sqlx::Error> {
    sqlx::query_as::<_, IdentityRow>(
        "SELECT id, org_id, name, kind, external_id, email, metadata, created_at, updated_at FROM identities WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn list_by_org(pool: &PgPool, org_id: Uuid) -> Result<Vec<IdentityRow>, sqlx::Error> {
    sqlx::query_as::<_, IdentityRow>(
        "SELECT id, org_id, name, kind, external_id, email, metadata, created_at, updated_at FROM identities WHERE org_id = $1 ORDER BY created_at",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await
}

pub async fn delete(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM identities WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}
