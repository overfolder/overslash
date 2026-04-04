use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct ApiKeyRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub identity_id: Option<Uuid>,
    pub name: String,
    pub key_hash: String,
    pub key_prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<OffsetDateTime>,
    pub last_used_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

pub async fn create(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Option<Uuid>,
    name: &str,
    key_hash: &str,
    key_prefix: &str,
    scopes: &[String],
) -> Result<ApiKeyRow, sqlx::Error> {
    sqlx::query_as!(
        ApiKeyRow,
        "INSERT INTO api_keys (org_id, identity_id, name, key_hash, key_prefix, scopes)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, org_id, identity_id, name, key_hash, key_prefix, scopes, expires_at, last_used_at, revoked_at, created_at",
        org_id,
        identity_id,
        name,
        key_hash,
        key_prefix,
        scopes,
    )
    .fetch_one(pool)
    .await
}

pub async fn find_by_prefix(pool: &PgPool, prefix: &str) -> Result<Option<ApiKeyRow>, sqlx::Error> {
    sqlx::query_as!(
        ApiKeyRow,
        "SELECT id, org_id, identity_id, name, key_hash, key_prefix, scopes, expires_at, last_used_at, revoked_at, created_at
         FROM api_keys WHERE key_prefix = $1 AND revoked_at IS NULL",
        prefix,
    )
    .fetch_optional(pool)
    .await
}

pub async fn touch_last_used(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!("UPDATE api_keys SET last_used_at = now() WHERE id = $1", id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_by_org(pool: &PgPool, org_id: Uuid) -> Result<Vec<ApiKeyRow>, sqlx::Error> {
    sqlx::query_as!(
        ApiKeyRow,
        "SELECT id, org_id, identity_id, name, key_hash, key_prefix, scopes, expires_at, last_used_at, revoked_at, created_at
         FROM api_keys WHERE org_id = $1 AND revoked_at IS NULL ORDER BY created_at",
        org_id,
    )
    .fetch_all(pool)
    .await
}

pub async fn revoke(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE api_keys SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
        id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}
