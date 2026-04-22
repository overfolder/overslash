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
    // COALESCE preserves the existing refresh_token when the caller passes
    // None. Google (and other OAuth2 providers) routinely omit the
    // refresh_token from refresh responses — only the initial code exchange
    // and re-consent flows mint one. Unconditionally writing $4 would wipe
    // the stored refresh_token on the first refresh, leaving the connection
    // unable to refresh ever again.
    sqlx::query!(
        "UPDATE connections SET encrypted_access_token = $3,
         encrypted_refresh_token = COALESCE($4, encrypted_refresh_token),
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

/// Update tokens *and* scopes in place, scoped to an org. Used by the
/// incremental-scope upgrade flow: an existing connection re-runs OAuth and
/// the callback needs to broaden both tokens (the old access token is
/// invalidated by provider semantics when re-authorizing) and the granted
/// scope set — without minting a new row, which would orphan any services
/// already pointing at the existing `connection_id`.
/// Update tokens, scopes, and optionally account_email in place, scoped to an
/// org. `account_email` is only written when `Some` — passing `None` leaves
/// the existing value intact, so a transient userinfo-endpoint failure on an
/// upgrade callback doesn't clobber an already-populated label.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn update_tokens_and_scopes(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
    encrypted_access_token: &[u8],
    encrypted_refresh_token: Option<&[u8]>,
    token_expires_at: Option<OffsetDateTime>,
    scopes: &[String],
    account_email: Option<&str>,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE connections SET encrypted_access_token = $3,
         encrypted_refresh_token = COALESCE($4, encrypted_refresh_token),
         token_expires_at = $5, scopes = $6,
         account_email = COALESCE($7, account_email), updated_at = now()
         WHERE id = $1 AND org_id = $2",
        id,
        org_id,
        encrypted_access_token,
        encrypted_refresh_token as Option<&[u8]>,
        token_expires_at,
        scopes,
        account_email,
    )
    .execute(pool)
    .await?;
    // Callers distinguish "connection was deleted between fetch and update"
    // from a normal success so the OAuth callback can surface an error
    // instead of telling the user their scope upgrade succeeded against a
    // row that no longer exists.
    Ok(result.rows_affected() > 0)
}

/// Batch fetch connections by ids, scoped to an org. Returned in arbitrary
/// order; callers should index by `id`. Used by the dashboard's services list
/// to avoid an N+1 lookup when classifying each service's credential health.
pub(crate) async fn get_by_ids(
    pool: &PgPool,
    org_id: Uuid,
    ids: &[Uuid],
) -> Result<Vec<ConnectionRow>, sqlx::Error> {
    if ids.is_empty() {
        return Ok(vec![]);
    }
    sqlx::query_as!(
        ConnectionRow,
        "SELECT id, org_id, identity_id, provider_key, encrypted_access_token,
                encrypted_refresh_token, token_expires_at, scopes, account_email,
                byoc_credential_id, is_default, created_at, updated_at
         FROM connections WHERE org_id = $1 AND id = ANY($2)",
        org_id,
        ids,
    )
    .fetch_all(pool)
    .await
}

/// Returns which (owner_identity_id, template_key) pairs currently point at
/// each of the given connections. Keyed by connection id. Used by the
/// dashboard's "pick a free connection" heuristic — if a connection is already
/// bound to a service using template `T`, we prefer to reuse it for a different
/// template rather than paper over the first.
pub(crate) async fn usage_by_template(
    pool: &PgPool,
    org_id: Uuid,
    connection_ids: &[Uuid],
) -> Result<Vec<(Uuid, String)>, sqlx::Error> {
    if connection_ids.is_empty() {
        return Ok(vec![]);
    }
    let rows = sqlx::query!(
        "SELECT connection_id AS \"connection_id!: Uuid\", template_key
         FROM service_instances
         WHERE org_id = $1 AND connection_id = ANY($2) AND status = 'active'",
        org_id,
        connection_ids,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| (r.connection_id, r.template_key))
        .collect())
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
