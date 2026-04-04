use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct SecretRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub name: String,
    pub current_version: i32,
    pub deleted_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, sqlx::FromRow)]
pub struct SecretVersionRow {
    pub id: Uuid,
    pub secret_id: Uuid,
    pub version: i32,
    pub encrypted_value: Vec<u8>,
    pub created_at: OffsetDateTime,
    pub created_by: Option<Uuid>,
}

/// Store or update a secret. Creates a new version each time.
pub async fn put(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
    encrypted_value: &[u8],
    created_by: Option<Uuid>,
) -> Result<(SecretRow, SecretVersionRow), sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Upsert the secret row
    let secret = sqlx::query_as!(
        SecretRow,
        "INSERT INTO secrets (org_id, name) VALUES ($1, $2)
         ON CONFLICT (org_id, name) DO UPDATE SET
           current_version = secrets.current_version + 1,
           updated_at = now(),
           deleted_at = NULL
         RETURNING id, org_id, name, current_version, deleted_at, created_at, updated_at",
        org_id,
        name,
    )
    .fetch_one(&mut *tx)
    .await?;

    // Insert the version
    let version = sqlx::query_as!(
        SecretVersionRow,
        "INSERT INTO secret_versions (secret_id, version, encrypted_value, created_by)
         VALUES ($1, $2, $3, $4)
         RETURNING id, secret_id, version, encrypted_value, created_at, created_by",
        secret.id,
        secret.current_version,
        encrypted_value,
        created_by,
    )
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok((secret, version))
}

pub async fn get_by_name(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
) -> Result<Option<SecretRow>, sqlx::Error> {
    sqlx::query_as!(
        SecretRow,
        "SELECT id, org_id, name, current_version, deleted_at, created_at, updated_at
         FROM secrets WHERE org_id = $1 AND name = $2 AND deleted_at IS NULL",
        org_id,
        name,
    )
    .fetch_optional(pool)
    .await
}

pub async fn get_current_value(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
) -> Result<Option<SecretVersionRow>, sqlx::Error> {
    sqlx::query_as!(
        SecretVersionRow,
        "SELECT sv.id, sv.secret_id, sv.version, sv.encrypted_value, sv.created_at, sv.created_by
         FROM secret_versions sv
         JOIN secrets s ON sv.secret_id = s.id
         WHERE s.org_id = $1 AND s.name = $2 AND s.deleted_at IS NULL AND sv.version = s.current_version",
        org_id,
        name,
    )
    .fetch_optional(pool)
    .await
}

pub async fn list_by_org(pool: &PgPool, org_id: Uuid) -> Result<Vec<SecretRow>, sqlx::Error> {
    sqlx::query_as!(
        SecretRow,
        "SELECT id, org_id, name, current_version, deleted_at, created_at, updated_at
         FROM secrets WHERE org_id = $1 AND deleted_at IS NULL ORDER BY name",
        org_id,
    )
    .fetch_all(pool)
    .await
}

pub async fn soft_delete(pool: &PgPool, org_id: Uuid, name: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE secrets SET deleted_at = now() WHERE org_id = $1 AND name = $2 AND deleted_at IS NULL",
        org_id,
        name,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}
