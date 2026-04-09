use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// Reason an API key was auto-revoked. Manually-revoked keys leave this NULL.
pub(crate) const REVOKED_REASON_IDENTITY_ARCHIVED: &str = "identity_archived";

#[derive(Debug, sqlx::FromRow)]
pub struct ApiKeyRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub name: String,
    pub key_hash: String,
    pub key_prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<OffsetDateTime>,
    pub last_used_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
    pub revoked_reason: Option<String>,
    pub created_at: OffsetDateTime,
}

pub(crate) async fn create(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    name: &str,
    key_hash: &str,
    key_prefix: &str,
    scopes: &[String],
) -> Result<ApiKeyRow, sqlx::Error> {
    sqlx::query_as!(
        ApiKeyRow,
        "INSERT INTO api_keys (org_id, identity_id, name, key_hash, key_prefix, scopes)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, org_id, identity_id, name, key_hash, key_prefix, scopes, expires_at, last_used_at, revoked_at, revoked_reason, created_at",
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

pub(crate) async fn find_by_prefix(
    pool: &PgPool,
    prefix: &str,
) -> Result<Option<ApiKeyRow>, sqlx::Error> {
    sqlx::query_as!(
        ApiKeyRow,
        "SELECT id, org_id, identity_id, name, key_hash, key_prefix, scopes, expires_at, last_used_at, revoked_at, revoked_reason, created_at
         FROM api_keys WHERE key_prefix = $1 AND revoked_at IS NULL",
        prefix,
    )
    .fetch_optional(pool)
    .await
}

/// Lookup variant used by the auth middleware that ALSO returns keys auto-revoked
/// because the bound identity was archived. This lets the middleware produce a
/// `403 identity_archived` (with restore hint) instead of the misleading
/// `401 invalid api key` that `find_by_prefix` would return.
///
/// Manually-revoked keys (revoked_reason IS NULL or anything other than the
/// archive sentinel) remain hidden — those are genuinely invalid.
pub(crate) async fn find_by_prefix_including_archived(
    pool: &PgPool,
    prefix: &str,
) -> Result<Option<ApiKeyRow>, sqlx::Error> {
    sqlx::query_as!(
        ApiKeyRow,
        "SELECT id, org_id, identity_id, name, key_hash, key_prefix, scopes, expires_at, last_used_at, revoked_at, revoked_reason, created_at
         FROM api_keys
         WHERE key_prefix = $1
           AND (revoked_at IS NULL OR revoked_reason = $2)",
        prefix,
        REVOKED_REASON_IDENTITY_ARCHIVED,
    )
    .fetch_optional(pool)
    .await
}

pub(crate) async fn list_by_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<ApiKeyRow>, sqlx::Error> {
    sqlx::query_as!(
        ApiKeyRow,
        "SELECT id, org_id, identity_id, name, key_hash, key_prefix, scopes, expires_at, last_used_at, revoked_at, revoked_reason, created_at
         FROM api_keys WHERE org_id = $1 AND revoked_at IS NULL ORDER BY created_at",
        org_id,
    )
    .fetch_all(pool)
    .await
}

pub(crate) async fn count_by_org(pool: &PgPool, org_id: Uuid) -> Result<i64, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT COUNT(*) AS count FROM api_keys WHERE org_id = $1 AND revoked_at IS NULL",
        org_id,
    )
    .fetch_one(pool)
    .await?;
    Ok(row.count.unwrap_or(0))
}

/// Bulk-revoke all active API keys belonging to the given identity IDs,
/// tagging them with `revoked_reason` so they can be later resurrected by `restore`.
pub(crate) async fn revoke_by_identity_ids_with_reason<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    ids: &[Uuid],
    reason: &str,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE api_keys SET revoked_at = now(), revoked_reason = $2
         WHERE identity_id = ANY($1) AND revoked_at IS NULL",
        ids,
        reason,
    )
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}

/// Resurrect API keys that were auto-revoked for the given reason on this identity.
/// Manually-revoked keys (revoked_reason IS NULL or different) are left untouched.
pub(crate) async fn unrevoke_by_identity_id_and_reason<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    identity_id: Uuid,
    reason: &str,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE api_keys SET revoked_at = NULL, revoked_reason = NULL
         WHERE identity_id = $1 AND revoked_reason = $2",
        identity_id,
        reason,
    )
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}
