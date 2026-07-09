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
    /// Granted OAuth scopes. `None` means *unknown* (a token import that didn't
    /// declare them) — the action scope-gate treats unknown as covering
    /// everything (benefit of the doubt). `Some(vec)` is the known granted set
    /// (possibly empty); orchestrated connections always record this from the
    /// token response.
    pub scopes: Option<Vec<String>>,
    pub account_email: Option<String>,
    pub byoc_credential_id: Option<Uuid>,
    pub is_default: bool,
    /// When true, this connection is preserved (never auto-deleted) when a
    /// service instance bound to it is deleted, regardless of reference count.
    pub keep: bool,
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
    /// `None` stores SQL NULL — "scopes unknown" (see [`ConnectionRow::scopes`]).
    pub scopes: Option<&'a [String]>,
    pub account_email: Option<&'a str>,
    pub byoc_credential_id: Option<Uuid>,
}

pub(crate) async fn create(
    pool: &PgPool,
    input: &CreateConnection<'_>,
) -> Result<ConnectionRow, sqlx::Error> {
    create_with(pool, input).await
}

/// Executor-generic variant of [`create`], so the insert can run inside a
/// caller-supplied transaction (e.g. the atomic `create_connection_and_pin`
/// flow that binds the new connection to service instances in one commit).
pub(crate) async fn create_with<'e, E>(
    executor: E,
    input: &CreateConnection<'_>,
) -> Result<ConnectionRow, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    // `is_default` is computed, not defaulted: a new connection becomes the
    // provider default only when the identity has none yet. The column's
    // `DEFAULT true` (migration 009) predates the single-default invariant
    // (migration 075) — inserting a second account for a provider that already
    // has a default would otherwise hit `is_default = true` and violate the
    // partial unique index `idx_connections_one_default`, breaking the
    // multi-account-per-provider flow this very value supports.
    sqlx::query_as!(
        ConnectionRow,
        "INSERT INTO connections (org_id, identity_id, provider_key, encrypted_access_token,
         encrypted_refresh_token, token_expires_at, scopes, account_email, byoc_credential_id,
         is_default)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
                 NOT EXISTS (
                     SELECT 1 FROM connections
                     WHERE identity_id = $2 AND provider_key = $3 AND is_default
                 ))
         RETURNING id, org_id, identity_id, provider_key, encrypted_access_token,
                   encrypted_refresh_token, token_expires_at, scopes, account_email,
                   byoc_credential_id, is_default, keep, created_at, updated_at",
        input.org_id,
        input.identity_id,
        input.provider_key,
        input.encrypted_access_token,
        input.encrypted_refresh_token as Option<&[u8]>,
        input.token_expires_at,
        input.scopes as Option<&[String]>,
        input.account_email,
        input.byoc_credential_id,
    )
    .fetch_one(executor)
    .await
}

/// Find the connection a token import should update in place, scoped to an
/// (org, identity, provider). When `account_email` is given the match is keyed
/// on it (multi-account: a partner can vault several accounts of one provider
/// for the same user); otherwise the identity's default-most connection for the
/// provider is returned. `None` means "no existing connection — create one".
///
/// This is what keeps re-import idempotent: a white-label connection is
/// re-imported whenever the partner re-runs its OAuth dance, so without an
/// in-place update each cycle would accrete a duplicate row.
pub(crate) async fn find_for_import(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    provider_key: &str,
    account_email: Option<&str>,
) -> Result<Option<ConnectionRow>, sqlx::Error> {
    sqlx::query_as!(
        ConnectionRow,
        // `scopes AS "scopes?"`: force the nullable override — a single-table
        // SELECT trips a sqlx-macro quirk that decodes the nullable `scopes`
        // (migration 083) as non-`Option` and panics on a NULL. See `get_by_id`.
        "SELECT id, org_id, identity_id, provider_key, encrypted_access_token,
                encrypted_refresh_token, token_expires_at, scopes AS \"scopes?: Vec<String>\",
                account_email, byoc_credential_id, is_default, keep, created_at, updated_at
         FROM connections
         WHERE org_id = $1 AND identity_id = $2 AND provider_key = $3
           AND ($4::text IS NULL OR account_email IS NOT DISTINCT FROM $4)
         ORDER BY is_default DESC, created_at DESC
         LIMIT 1",
        org_id,
        identity_id,
        provider_key,
        account_email,
    )
    .fetch_optional(pool)
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
        // `scopes` is nullable (migration 083). The single-table SELECT trips a
        // sqlx-macro nullability quirk that decodes it as non-`Option` and panics
        // on a NULL (an import that didn't declare scopes), so force the override
        // explicitly. See `scopes/user_connections.rs` (its JOIN sidesteps this).
        "SELECT id, org_id, identity_id, provider_key, encrypted_access_token,
                encrypted_refresh_token, token_expires_at, scopes AS \"scopes?: Vec<String>\",
                account_email, byoc_credential_id, is_default, keep, created_at, updated_at
         FROM connections WHERE id = $1 AND org_id = $2",
        id,
        org_id,
    )
    .fetch_optional(pool)
    .await
}

/// List every connection in an org, across all identities. Powers the
/// dashboard's admin-only "show all users' connections" view — the per-user
/// listing lives on `UserScope::list_my_connections`. Ordered newest-first to
/// match that per-user query.
pub(crate) async fn list_all_in_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<ConnectionRow>, sqlx::Error> {
    sqlx::query_as!(
        ConnectionRow,
        // `scopes AS "scopes?"`: force the nullable override (see `get_by_id`).
        "SELECT id, org_id, identity_id, provider_key, encrypted_access_token,
                encrypted_refresh_token, token_expires_at, scopes AS \"scopes?: Vec<String>\",
                account_email, byoc_credential_id, is_default, keep, created_at, updated_at
         FROM connections WHERE org_id = $1 ORDER BY created_at DESC",
        org_id,
    )
    .fetch_all(pool)
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
    scopes: Option<&[String]>,
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
        scopes as Option<&[String]>,
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
        // `scopes AS "scopes?"`: force the nullable override (see `get_by_id`).
        "SELECT id, org_id, identity_id, provider_key, encrypted_access_token,
                encrypted_refresh_token, token_expires_at, scopes AS \"scopes?: Vec<String>\",
                account_email, byoc_credential_id, is_default, keep, created_at, updated_at
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

/// Service instances (id, name, template_key) actively bound to a single
/// connection, scoped to its org. Powers the connection-detail "Used by" list,
/// which links each row to `/services/{name}`. Distinct from
/// [`usage_by_template`], which returns only template keys for the list view's
/// reuse heuristic — the detail page needs the instance id and name too.
pub(crate) async fn usage_instances_by_connection(
    pool: &PgPool,
    org_id: Uuid,
    connection_id: Uuid,
) -> Result<Vec<(Uuid, String, String)>, sqlx::Error> {
    let rows = sqlx::query!(
        "SELECT id, name, template_key
         FROM service_instances
         WHERE org_id = $1 AND connection_id = $2 AND status = 'active'
         ORDER BY name",
        org_id,
        connection_id,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| (r.id, r.name, r.template_key))
        .collect())
}

/// Promote one connection to be the default for its (identity, provider),
/// demoting any sibling that held the flag. Scoped to both org and identity so
/// a forged id from another tenant or another user is a no-op. Returns `false`
/// when the target row doesn't exist / isn't owned by the identity.
///
/// Runs in a transaction with "demote siblings, then promote target" ordering
/// so the partial unique index `idx_connections_one_default` (one default per
/// identity+provider) is never transiently violated mid-statement.
pub(crate) async fn set_default(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Demote every connection sharing this connection's (identity, provider).
    // The subquery also enforces org + identity ownership of the target id, so
    // a foreign id selects no provider_key and demotes nothing.
    sqlx::query!(
        "UPDATE connections SET is_default = false, updated_at = now()
         WHERE org_id = $1 AND identity_id = $2
           AND provider_key = (
               SELECT provider_key FROM connections
               WHERE id = $3 AND org_id = $1 AND identity_id = $2
           )",
        org_id,
        identity_id,
        id,
    )
    .execute(&mut *tx)
    .await?;

    let promoted = sqlx::query!(
        "UPDATE connections SET is_default = true, updated_at = now()
         WHERE id = $1 AND org_id = $2 AND identity_id = $3",
        id,
        org_id,
        identity_id,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(promoted.rows_affected() > 0)
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

/// Atomically delete a connection for the service-deletion auto-cleanup, but
/// only when it is eligible: not marked `keep` and referenced by no service
/// instance in the org (across *all* statuses — draft/active/archived, so a
/// non-active bound service is never orphaned). Returns whether it deleted.
///
/// The reference check (`NOT EXISTS`) and the delete are a **single** statement
/// on purpose. A two-step "check `has_any_binding`, then `delete`" leaves a
/// TOCTOU window where a concurrent request binds a new service to this
/// connection after the check passes but before the delete — the
/// `ON DELETE SET NULL` FK would then silently null that fresh binding. As one
/// statement, the delete's exclusive row lock and the FK `KEY SHARE` lock a
/// concurrent bind takes on this row serialize the two, closing the window.
pub(crate) async fn delete_if_orphaned(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "DELETE FROM connections c
         WHERE c.id = $1 AND c.org_id = $2 AND c.keep = false
           AND NOT EXISTS (
               SELECT 1 FROM service_instances si WHERE si.connection_id = c.id
           )",
        id,
        org_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Set (or clear) the `keep` preserve flag on a connection, scoped to its org.
/// Returns `false` when the id isn't in this org.
pub(crate) async fn set_keep(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
    keep: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE connections SET keep = $3, updated_at = now()
         WHERE id = $1 AND org_id = $2",
        id,
        org_id,
        keep,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}
