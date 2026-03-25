use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct ConnectionRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub provider_key: String,
    pub encrypted_access_token: Vec<u8>,
    pub encrypted_refresh_token: Option<Vec<u8>>,
    pub token_expires_at: Option<OffsetDateTime>,
    pub scopes: Vec<String>,
    pub account_email: Option<String>,
    pub byoc_credential_id: Option<Uuid>,
    pub is_default: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

pub struct CreateConnection<'a> {
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub provider_key: &'a str,
    pub encrypted_access_token: &'a [u8],
    pub encrypted_refresh_token: Option<&'a [u8]>,
    pub token_expires_at: Option<OffsetDateTime>,
    pub scopes: &'a [String],
    pub account_email: Option<&'a str>,
}

pub async fn create(
    pool: &PgPool,
    input: &CreateConnection<'_>,
) -> Result<ConnectionRow, sqlx::Error> {
    sqlx::query_as::<_, ConnectionRow>(
        "INSERT INTO connections (org_id, identity_id, provider_key, encrypted_access_token,
         encrypted_refresh_token, token_expires_at, scopes, account_email)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING id, org_id, identity_id, provider_key, encrypted_access_token,
                   encrypted_refresh_token, token_expires_at, scopes, account_email,
                   byoc_credential_id, is_default, created_at, updated_at",
    )
    .bind(input.org_id)
    .bind(input.identity_id)
    .bind(input.provider_key)
    .bind(input.encrypted_access_token)
    .bind(input.encrypted_refresh_token)
    .bind(input.token_expires_at)
    .bind(input.scopes)
    .bind(input.account_email)
    .fetch_one(pool)
    .await
}

pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<ConnectionRow>, sqlx::Error> {
    sqlx::query_as::<_, ConnectionRow>(
        "SELECT id, org_id, identity_id, provider_key, encrypted_access_token,
                encrypted_refresh_token, token_expires_at, scopes, account_email,
                byoc_credential_id, is_default, created_at, updated_at
         FROM connections WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// Find a connection by identity and provider (for auto-resolve).
pub async fn find_by_provider(
    pool: &PgPool,
    identity_id: Uuid,
    provider_key: &str,
) -> Result<Option<ConnectionRow>, sqlx::Error> {
    sqlx::query_as::<_, ConnectionRow>(
        "SELECT id, org_id, identity_id, provider_key, encrypted_access_token,
                encrypted_refresh_token, token_expires_at, scopes, account_email,
                byoc_credential_id, is_default, created_at, updated_at
         FROM connections WHERE identity_id = $1 AND provider_key = $2
         ORDER BY is_default DESC, created_at DESC LIMIT 1",
    )
    .bind(identity_id)
    .bind(provider_key)
    .fetch_optional(pool)
    .await
}

pub async fn list_by_identity(
    pool: &PgPool,
    identity_id: Uuid,
) -> Result<Vec<ConnectionRow>, sqlx::Error> {
    sqlx::query_as::<_, ConnectionRow>(
        "SELECT id, org_id, identity_id, provider_key, encrypted_access_token,
                encrypted_refresh_token, token_expires_at, scopes, account_email,
                byoc_credential_id, is_default, created_at, updated_at
         FROM connections WHERE identity_id = $1 ORDER BY created_at DESC",
    )
    .bind(identity_id)
    .fetch_all(pool)
    .await
}

pub async fn update_tokens(
    pool: &PgPool,
    id: Uuid,
    encrypted_access_token: &[u8],
    encrypted_refresh_token: Option<&[u8]>,
    token_expires_at: Option<OffsetDateTime>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE connections SET encrypted_access_token = $2, encrypted_refresh_token = $3,
         token_expires_at = $4, updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(encrypted_access_token)
    .bind(encrypted_refresh_token)
    .bind(token_expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM connections WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

/// Delete scoped to org — for org-admin keys.
pub async fn delete_by_org(pool: &PgPool, id: Uuid, org_id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM connections WHERE id = $1 AND org_id = $2")
        .bind(id)
        .bind(org_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

/// Delete scoped to identity — for user/agent keys (can only delete own connections).
pub async fn delete_by_identity(
    pool: &PgPool,
    id: Uuid,
    identity_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM connections WHERE id = $1 AND identity_id = $2")
        .bind(id)
        .bind(identity_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}
