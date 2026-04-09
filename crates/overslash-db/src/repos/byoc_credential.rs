use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct ByocCredentialRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub provider_key: String,
    pub encrypted_client_id: Vec<u8>,
    pub encrypted_client_secret: Vec<u8>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

pub struct CreateByocCredential<'a> {
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub provider_key: &'a str,
    pub encrypted_client_id: &'a [u8],
    pub encrypted_client_secret: &'a [u8],
}

pub(crate) async fn create(
    pool: &PgPool,
    input: &CreateByocCredential<'_>,
) -> Result<ByocCredentialRow, sqlx::Error> {
    sqlx::query_as!(
        ByocCredentialRow,
        "INSERT INTO byoc_credentials (org_id, identity_id, provider_key,
         encrypted_client_id, encrypted_client_secret)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, org_id, identity_id, provider_key,
                   encrypted_client_id, encrypted_client_secret, created_at, updated_at",
        input.org_id,
        input.identity_id,
        input.provider_key,
        input.encrypted_client_id,
        input.encrypted_client_secret,
    )
    .fetch_one(pool)
    .await
}

pub(crate) async fn get_by_id(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<ByocCredentialRow>, sqlx::Error> {
    sqlx::query_as!(
        ByocCredentialRow,
        "SELECT id, org_id, identity_id, provider_key,
                encrypted_client_id, encrypted_client_secret, created_at, updated_at
         FROM byoc_credentials WHERE id = $1",
        id,
    )
    .fetch_optional(pool)
    .await
}

pub(crate) async fn list_by_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<ByocCredentialRow>, sqlx::Error> {
    sqlx::query_as!(
        ByocCredentialRow,
        "SELECT id, org_id, identity_id, provider_key,
                encrypted_client_id, encrypted_client_secret, created_at, updated_at
         FROM byoc_credentials WHERE org_id = $1 ORDER BY created_at DESC",
        org_id,
    )
    .fetch_all(pool)
    .await
}

pub(crate) async fn delete_by_org(
    pool: &PgPool,
    id: Uuid,
    org_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "DELETE FROM byoc_credentials WHERE id = $1 AND org_id = $2",
        id,
        org_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Resolve BYOC credential for a given org + identity + provider.
/// BYOC credentials are always identity-bound (org-level/NULL identity rows
/// were removed in migration 028).
pub(crate) async fn resolve(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    provider_key: &str,
) -> Result<Option<ByocCredentialRow>, sqlx::Error> {
    sqlx::query_as!(
        ByocCredentialRow,
        "SELECT id, org_id, identity_id, provider_key,
                encrypted_client_id, encrypted_client_secret, created_at, updated_at
         FROM byoc_credentials
         WHERE org_id = $1 AND provider_key = $3 AND identity_id = $2
         LIMIT 1",
        org_id,
        identity_id,
        provider_key,
    )
    .fetch_optional(pool)
    .await
}
