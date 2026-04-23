use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct OrgIdpConfigRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub provider_key: String,
    /// NULL when the config defers to org-level OAuth App Credentials
    /// (org secrets `OAUTH_{PROVIDER}_CLIENT_ID/SECRET`). The DB CHECK
    /// enforces that both columns are NULL together or both are non-NULL.
    pub encrypted_client_id: Option<Vec<u8>>,
    pub encrypted_client_secret: Option<Vec<u8>>,
    pub enabled: bool,
    pub allowed_email_domains: Vec<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

pub(crate) async fn create(
    pool: &PgPool,
    org_id: Uuid,
    provider_key: &str,
    encrypted_client_id: Option<&[u8]>,
    encrypted_client_secret: Option<&[u8]>,
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

/// How to treat the client_id / client_secret columns on an update.
///
/// A tri-state: leave unchanged, set to specific dedicated values, or clear
/// (switch to org-level OAuth App Credentials).
pub enum CredentialsUpdate<'a> {
    Unchanged,
    SetDedicated {
        encrypted_client_id: &'a [u8],
        encrypted_client_secret: &'a [u8],
    },
    UseOrgCredentials,
}

pub(crate) async fn update(
    pool: &PgPool,
    id: Uuid,
    org_id: Uuid,
    creds: CredentialsUpdate<'_>,
    enabled: Option<bool>,
    allowed_email_domains: Option<&[String]>,
) -> Result<Option<OrgIdpConfigRow>, sqlx::Error> {
    // Encode the tri-state into two parallel columns:
    //   force_set: explicit overwrite happens (NULL when Unchanged)
    //   new_id/secret: new values when SetDedicated, NULL when UseOrgCredentials
    let (force_set, new_id, new_secret): (bool, Option<&[u8]>, Option<&[u8]>) = match creds {
        CredentialsUpdate::Unchanged => (false, None, None),
        CredentialsUpdate::SetDedicated {
            encrypted_client_id,
            encrypted_client_secret,
        } => (
            true,
            Some(encrypted_client_id),
            Some(encrypted_client_secret),
        ),
        CredentialsUpdate::UseOrgCredentials => (true, None, None),
    };

    sqlx::query_as!(
        OrgIdpConfigRow,
        "UPDATE org_idp_configs SET
            encrypted_client_id = CASE WHEN $3 THEN $4 ELSE encrypted_client_id END,
            encrypted_client_secret = CASE WHEN $3 THEN $5 ELSE encrypted_client_secret END,
            enabled = COALESCE($6, enabled),
            allowed_email_domains = COALESCE($7, allowed_email_domains),
            updated_at = now()
         WHERE id = $1 AND org_id = $2
         RETURNING id, org_id, provider_key, encrypted_client_id, encrypted_client_secret, enabled, allowed_email_domains, created_at, updated_at",
        id,
        org_id,
        force_set,
        new_id,
        new_secret,
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
