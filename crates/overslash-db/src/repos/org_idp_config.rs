use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct OrgIdpConfigRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub provider_key: String,
    pub encrypted_client_id: Vec<u8>,
    pub encrypted_client_secret: Vec<u8>,
    pub enabled: bool,
    pub allowed_email_domains: Vec<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

pub(crate) async fn create(
    pool: &PgPool,
    org_id: Uuid,
    provider_key: &str,
    encrypted_client_id: &[u8],
    encrypted_client_secret: &[u8],
    enabled: bool,
    allowed_email_domains: &[String],
) -> Result<OrgIdpConfigRow, sqlx::Error> {
    sqlx::query_as!(
        OrgIdpConfigRow,
        "INSERT INTO org_idp_configs (org_id, provider_key, encrypted_client_id, encrypted_client_secret, enabled, allowed_email_domains)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, org_id, provider_key, encrypted_client_id, encrypted_client_secret, enabled, allowed_email_domains, created_at, updated_at",
        org_id,
        provider_key,
        encrypted_client_id,
        encrypted_client_secret,
        enabled,
        allowed_email_domains,
    )
    .fetch_one(pool)
    .await
}

pub(crate) async fn get_by_id(
    pool: &PgPool,
    id: Uuid,
    org_id: Uuid,
) -> Result<Option<OrgIdpConfigRow>, sqlx::Error> {
    sqlx::query_as!(
        OrgIdpConfigRow,
        "SELECT id, org_id, provider_key, encrypted_client_id, encrypted_client_secret, enabled, allowed_email_domains, created_at, updated_at
         FROM org_idp_configs WHERE id = $1 AND org_id = $2",
        id,
        org_id,
    )
    .fetch_optional(pool)
    .await
}

pub(crate) async fn get_by_org_and_provider(
    pool: &PgPool,
    org_id: Uuid,
    provider_key: &str,
) -> Result<Option<OrgIdpConfigRow>, sqlx::Error> {
    sqlx::query_as!(
        OrgIdpConfigRow,
        "SELECT id, org_id, provider_key, encrypted_client_id, encrypted_client_secret, enabled, allowed_email_domains, created_at, updated_at
         FROM org_idp_configs WHERE org_id = $1 AND provider_key = $2",
        org_id,
        provider_key,
    )
    .fetch_optional(pool)
    .await
}

pub(crate) async fn list_by_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<OrgIdpConfigRow>, sqlx::Error> {
    sqlx::query_as!(
        OrgIdpConfigRow,
        "SELECT id, org_id, provider_key, encrypted_client_id, encrypted_client_secret, enabled, allowed_email_domains, created_at, updated_at
         FROM org_idp_configs WHERE org_id = $1 ORDER BY created_at",
        org_id,
    )
    .fetch_all(pool)
    .await
}

pub(crate) async fn list_enabled_by_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<OrgIdpConfigRow>, sqlx::Error> {
    sqlx::query_as!(
        OrgIdpConfigRow,
        "SELECT id, org_id, provider_key, encrypted_client_id, encrypted_client_secret, enabled, allowed_email_domains, created_at, updated_at
         FROM org_idp_configs WHERE org_id = $1 AND enabled = true ORDER BY created_at",
        org_id,
    )
    .fetch_all(pool)
    .await
}

/// Find org IdP configs whose allowed_email_domains contain the given domain.
pub(crate) async fn find_by_email_domain(
    pool: &PgPool,
    domain: &str,
) -> Result<Vec<OrgIdpConfigRow>, sqlx::Error> {
    sqlx::query_as!(
        OrgIdpConfigRow,
        "SELECT id, org_id, provider_key, encrypted_client_id, encrypted_client_secret, enabled, allowed_email_domains, created_at, updated_at
         FROM org_idp_configs WHERE $1 = ANY(allowed_email_domains) AND enabled = true
         ORDER BY created_at",
        domain,
    )
    .fetch_all(pool)
    .await
}

pub(crate) async fn update(
    pool: &PgPool,
    id: Uuid,
    org_id: Uuid,
    encrypted_client_id: Option<&[u8]>,
    encrypted_client_secret: Option<&[u8]>,
    enabled: Option<bool>,
    allowed_email_domains: Option<&[String]>,
) -> Result<Option<OrgIdpConfigRow>, sqlx::Error> {
    sqlx::query_as!(
        OrgIdpConfigRow,
        "UPDATE org_idp_configs SET
            encrypted_client_id = COALESCE($3, encrypted_client_id),
            encrypted_client_secret = COALESCE($4, encrypted_client_secret),
            enabled = COALESCE($5, enabled),
            allowed_email_domains = COALESCE($6, allowed_email_domains),
            updated_at = now()
         WHERE id = $1 AND org_id = $2
         RETURNING id, org_id, provider_key, encrypted_client_id, encrypted_client_secret, enabled, allowed_email_domains, created_at, updated_at",
        id,
        org_id,
        encrypted_client_id,
        encrypted_client_secret,
        enabled,
        allowed_email_domains,
    )
    .fetch_optional(pool)
    .await
}

pub(crate) async fn delete(pool: &PgPool, id: Uuid, org_id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "DELETE FROM org_idp_configs WHERE id = $1 AND org_id = $2",
        id,
        org_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}
