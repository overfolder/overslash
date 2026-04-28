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
    /// The identity of the *human* who actually provisioned this value on
    /// the standalone `/secrets/provide` page, captured from a same-org
    /// session cookie. Distinct from `created_by` (the target identity that
    /// owns the secret slot). NULL for anonymous URL fulfillment and for
    /// API-driven writes (where `created_by` already names the caller).
    pub provisioned_by_user_id: Option<Uuid>,
}

/// Store or update a secret. Creates a new version each time.
pub(crate) async fn put(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
    encrypted_value: &[u8],
    created_by: Option<Uuid>,
    provisioned_by_user_id: Option<Uuid>,
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
        "INSERT INTO secret_versions (secret_id, version, encrypted_value, created_by, provisioned_by_user_id)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, secret_id, version, encrypted_value, created_at, created_by, provisioned_by_user_id",
        secret.id,
        secret.current_version,
        encrypted_value,
        created_by,
        provisioned_by_user_id,
    )
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok((secret, version))
}

pub(crate) async fn get_by_name(
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

pub(crate) async fn get_current_value(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
) -> Result<Option<SecretVersionRow>, sqlx::Error> {
    sqlx::query_as!(
        SecretVersionRow,
        "SELECT sv.id, sv.secret_id, sv.version, sv.encrypted_value, sv.created_at, sv.created_by, sv.provisioned_by_user_id
         FROM secret_versions sv
         JOIN secrets s ON sv.secret_id = s.id
         WHERE s.org_id = $1 AND s.name = $2 AND s.deleted_at IS NULL AND sv.version = s.current_version",
        org_id,
        name,
    )
    .fetch_optional(pool)
    .await
}

pub(crate) async fn list_by_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<SecretRow>, sqlx::Error> {
    sqlx::query_as!(
        SecretRow,
        "SELECT id, org_id, name, current_version, deleted_at, created_at, updated_at
         FROM secrets WHERE org_id = $1 AND deleted_at IS NULL ORDER BY name",
        org_id,
    )
    .fetch_all(pool)
    .await
}

/// List secrets visible to a non-admin user — i.e. secrets whose original
/// creator (version 1's `created_by`) sits in this user's subtree
/// (the user themselves, or any agent/sub-agent whose `owner_id` is the
/// user). SPEC §6.
pub(crate) async fn list_visible_to_user(
    pool: &PgPool,
    org_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<SecretRow>, sqlx::Error> {
    sqlx::query_as!(
        SecretRow,
        "SELECT s.id, s.org_id, s.name, s.current_version, s.deleted_at, s.created_at, s.updated_at
         FROM secrets s
         WHERE s.org_id = $1 AND s.deleted_at IS NULL
         AND EXISTS (
           SELECT 1 FROM secret_versions sv
           JOIN identities i ON i.id = sv.created_by
           WHERE sv.secret_id = s.id AND sv.version = 1
           AND (
             (i.kind = 'user' AND i.id = $2)
             OR (i.kind IN ('agent','sub_agent') AND i.owner_id = $2)
           )
         )
         ORDER BY s.name",
        org_id,
        user_id,
    )
    .fetch_all(pool)
    .await
}

/// True if the secret's slot owner (version 1 creator's ceiling user) is
/// `user_id`. Used to gate detail/reveal/restore/delete for non-admins.
pub(crate) async fn is_visible_to_user(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
    user_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT 1 AS exists FROM secrets s
         WHERE s.org_id = $1 AND s.name = $2 AND s.deleted_at IS NULL
         AND EXISTS (
           SELECT 1 FROM secret_versions sv
           JOIN identities i ON i.id = sv.created_by
           WHERE sv.secret_id = s.id AND sv.version = 1
           AND (
             (i.kind = 'user' AND i.id = $3)
             OR (i.kind IN ('agent','sub_agent') AND i.owner_id = $3)
           )
         )
         LIMIT 1",
        org_id,
        name,
        user_id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

pub(crate) async fn soft_delete(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE secrets SET deleted_at = now() WHERE org_id = $1 AND name = $2 AND deleted_at IS NULL",
        org_id,
        name,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// List every version of a secret, newest first. Returns metadata only —
/// `encrypted_value` is omitted to avoid pulling ciphertext into list views.
pub(crate) async fn list_versions(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
) -> Result<Vec<SecretVersionMeta>, sqlx::Error> {
    sqlx::query_as!(
        SecretVersionMeta,
        "SELECT sv.version, sv.created_at, sv.created_by, sv.provisioned_by_user_id
         FROM secret_versions sv
         JOIN secrets s ON sv.secret_id = s.id
         WHERE s.org_id = $1 AND s.name = $2 AND s.deleted_at IS NULL
         ORDER BY sv.version DESC",
        org_id,
        name,
    )
    .fetch_all(pool)
    .await
}

/// Fetch a specific version's encrypted value. Returns None if either the
/// secret or the version is missing.
pub(crate) async fn get_value_at_version(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
    version: i32,
) -> Result<Option<SecretVersionRow>, sqlx::Error> {
    sqlx::query_as!(
        SecretVersionRow,
        "SELECT sv.id, sv.secret_id, sv.version, sv.encrypted_value, sv.created_at, sv.created_by, sv.provisioned_by_user_id
         FROM secret_versions sv
         JOIN secrets s ON sv.secret_id = s.id
         WHERE s.org_id = $1 AND s.name = $2 AND s.deleted_at IS NULL AND sv.version = $3",
        org_id,
        name,
        version,
    )
    .fetch_optional(pool)
    .await
}

/// Return the `created_by` of the *first* version of a secret. The original
/// creator owns the slot — later versions written by other agents under the
/// same user don't transfer ownership.
pub(crate) async fn first_version_creator(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT sv.created_by
         FROM secret_versions sv
         JOIN secrets s ON sv.secret_id = s.id
         WHERE s.org_id = $1 AND s.name = $2 AND s.deleted_at IS NULL
         ORDER BY sv.version ASC
         LIMIT 1",
        org_id,
        name,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|r| r.created_by))
}

#[derive(Debug, sqlx::FromRow)]
pub struct SecretVersionMeta {
    pub version: i32,
    pub created_at: OffsetDateTime,
    pub created_by: Option<Uuid>,
    pub provisioned_by_user_id: Option<Uuid>,
}

/// Service instances that reference this secret name. Archived rows are
/// included with their status so the dashboard can render them as
/// stale references rather than hiding them — flipping a service back to
/// `active` is one click and keeping it in the list helps users notice
/// that the rotation matters.
pub(crate) async fn list_services_using_secret(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
) -> Result<Vec<ServiceUsingSecret>, sqlx::Error> {
    sqlx::query_as!(
        ServiceUsingSecret,
        "SELECT id, name, status
         FROM service_instances
         WHERE org_id = $1 AND secret_name = $2
         ORDER BY name",
        org_id,
        name,
    )
    .fetch_all(pool)
    .await
}

#[derive(Debug, sqlx::FromRow)]
pub struct ServiceUsingSecret {
    pub id: Uuid,
    pub name: String,
    pub status: String,
}

/// Atomically put multiple secrets in one transaction. Each entry
/// creates a new version of the corresponding secret. All writes
/// commit together or none do — useful when a logical resource
/// (e.g. an OAuth App Credential pair) spans two secret names.
pub(crate) async fn put_many(
    pool: &PgPool,
    org_id: Uuid,
    entries: &[(&str, &[u8])],
    created_by: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    for (name, encrypted_value) in entries {
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

        sqlx::query!(
            "INSERT INTO secret_versions (secret_id, version, encrypted_value, created_by, provisioned_by_user_id)
             VALUES ($1, $2, $3, $4, NULL)",
            secret.id,
            secret.current_version,
            encrypted_value,
            created_by,
        )
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Atomically soft-delete a set of secrets in one transaction.
///
/// Returns the total number of rows affected. If any DELETE fails the
/// whole transaction rolls back and none of the secrets are marked as
/// deleted — callers don't have to reason about partial state.
pub(crate) async fn soft_delete_many(
    pool: &PgPool,
    org_id: Uuid,
    names: &[&str],
) -> Result<u64, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let mut total: u64 = 0;
    for name in names {
        let result = sqlx::query!(
            "UPDATE secrets SET deleted_at = now() WHERE org_id = $1 AND name = $2 AND deleted_at IS NULL",
            org_id,
            name,
        )
        .execute(&mut *tx)
        .await?;
        total += result.rows_affected();
    }
    tx.commit().await?;
    Ok(total)
}
