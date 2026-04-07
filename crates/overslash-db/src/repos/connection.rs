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

super::impl_org_owned!(ConnectionRow);

pub struct CreateConnection<'a> {
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub provider_key: &'a str,
    pub encrypted_access_token: &'a [u8],
    pub encrypted_refresh_token: Option<&'a [u8]>,
    pub token_expires_at: Option<OffsetDateTime>,
    pub scopes: &'a [String],
    pub account_email: Option<&'a str>,
    pub byoc_credential_id: Option<Uuid>,
}

pub(crate) async fn create(
    pool: &PgPool,
    input: &CreateConnection<'_>,
) -> Result<ConnectionRow, sqlx::Error> {
    sqlx::query_as!(
        ConnectionRow,
        "INSERT INTO connections (org_id, identity_id, provider_key, encrypted_access_token,
         encrypted_refresh_token, token_expires_at, scopes, account_email, byoc_credential_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING id, org_id, identity_id, provider_key, encrypted_access_token,
                   encrypted_refresh_token, token_expires_at, scopes, account_email,
                   byoc_credential_id, is_default, created_at, updated_at",
        input.org_id,
        input.identity_id,
        input.provider_key,
        input.encrypted_access_token,
        input.encrypted_refresh_token as Option<&[u8]>,
        input.token_expires_at,
        input.scopes,
        input.account_email,
        input.byoc_credential_id,
    )
    .fetch_one(pool)
    .await
}

/// Org-bounded `get_by_id`. The `(id, org_id)` double-key turns a forged
/// id from another tenant into a `None` at the SQL boundary.
pub(crate) async fn get_by_id(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
) -> Result<Option<ConnectionRow>, sqlx::Error> {
    sqlx::query_as!(
        ConnectionRow,
        "SELECT id, org_id, identity_id, provider_key, encrypted_access_token,
                encrypted_refresh_token, token_expires_at, scopes, account_email,
                byoc_credential_id, is_default, created_at, updated_at
         FROM connections WHERE id = $1 AND org_id = $2",
        id,
        org_id,
    )
    .fetch_optional(pool)
    .await
}

/// Update the access/refresh token for a connection, scoped to its org.
/// Used by the OAuth refresh path.
pub(crate) async fn update_tokens(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
    encrypted_access_token: &[u8],
    encrypted_refresh_token: Option<&[u8]>,
    token_expires_at: Option<OffsetDateTime>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE connections SET encrypted_access_token = $3, encrypted_refresh_token = $4,
         token_expires_at = $5, updated_at = now() WHERE id = $1 AND org_id = $2",
        id,
        org_id,
        encrypted_access_token,
        encrypted_refresh_token as Option<&[u8]>,
        token_expires_at,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Delete a connection scoped to org — for org-admin.
pub(crate) async fn delete_by_org(
    pool: &PgPool,
    id: Uuid,
    org_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "DELETE FROM connections WHERE id = $1 AND org_id = $2",
        id,
        org_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}
