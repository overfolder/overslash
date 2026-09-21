use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct SecretRequestRow {
    pub id: String,
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub secret_name: String,
    pub requested_by: Uuid,
    pub reason: Option<String>,
    pub token_hash: Vec<u8>,
    pub expires_at: OffsetDateTime,
    pub fulfilled_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    /// Captured at mint time from the org's `allow_unsigned_secret_provide`
    /// setting. When true, the public `submit_provide` handler requires a
    /// same-org `oss_session` cookie — anonymous signed-URL submission alone
    /// is rejected. Forward-only: flipping the org setting does not mutate
    /// this row.
    pub require_user_session: bool,
    /// Service instance this request provisions a credential for, when the
    /// request was minted as part of setting one up. `None` is a plain secret
    /// request: a vault name and nothing else.
    pub service_instance_id: Option<Uuid>,
    /// The template securityScheme slot key to bind on fulfilment. Validated
    /// against the template at *mint* time, by the caller that held
    /// `manage_services_own`; fulfilment carries only a capability token and
    /// re-derives nothing. Always `Some` exactly when `service_instance_id`
    /// is — the `secret_requests_service_binding_complete` check enforces it.
    pub credential_key: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub async fn create(
    pool: &PgPool,
    id: &str,
    org_id: Uuid,
    identity_id: Uuid,
    secret_name: &str,
    requested_by: Uuid,
    reason: Option<&str>,
    token_hash: &[u8],
    expires_at: OffsetDateTime,
    require_user_session: bool,
    service_instance_id: Option<Uuid>,
    credential_key: Option<&str>,
) -> Result<SecretRequestRow, sqlx::Error> {
    sqlx::query_as!(
        SecretRequestRow,
        "INSERT INTO secret_requests (id, org_id, identity_id, secret_name, requested_by, reason, token_hash, expires_at, require_user_session, service_instance_id, credential_key)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         RETURNING id, org_id, identity_id, secret_name, requested_by, reason, token_hash, expires_at, fulfilled_at, created_at, require_user_session, service_instance_id, credential_key",
        id,
        org_id,
        identity_id,
        secret_name,
        requested_by,
        reason,
        token_hash,
        expires_at,
        require_user_session,
        service_instance_id,
        credential_key,
    )
    .fetch_one(pool)
    .await
}

pub async fn get(pool: &PgPool, id: &str) -> Result<Option<SecretRequestRow>, sqlx::Error> {
    sqlx::query_as!(
        SecretRequestRow,
        "SELECT id, org_id, identity_id, secret_name, requested_by, reason, token_hash, expires_at, fulfilled_at, created_at, require_user_session, service_instance_id, credential_key
         FROM secret_requests WHERE id = $1",
        id,
    )
    .fetch_optional(pool)
    .await
}

/// Atomically mark fulfilled. Returns false if already fulfilled.
pub async fn mark_fulfilled(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
    let r = sqlx::query!(
        "UPDATE secret_requests SET fulfilled_at = now() WHERE id = $1 AND fulfilled_at IS NULL",
        id,
    )
    .execute(pool)
    .await?;
    Ok(r.rows_affected() > 0)
}

/// Every identity that minted a setup link for this instance.
///
/// "Who is blocked on this service going live." The rows survive fulfilment —
/// [`mark_fulfilled`] stamps a timestamp rather than deleting — so this keeps
/// answering after the credential has landed, which is when the answer is
/// wanted. Reads `idx_secret_requests_service` (migration 118).
pub async fn setup_requesters(
    pool: &PgPool,
    service_instance_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar!(
        "SELECT DISTINCT requested_by FROM secret_requests WHERE service_instance_id = $1",
        service_instance_id,
    )
    .fetch_all(pool)
    .await
}
