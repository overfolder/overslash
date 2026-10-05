use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct SecretRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub name: String,
    pub current_version: i32,
    /// The namespace: the owning user identity, or NULL for the org-wide
    /// vault. Part of the unique key `(org_id, owner_identity_id, name)`.
    pub owner_identity_id: Option<Uuid>,
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

/// Store or update a secret in namespace `owner_identity_id` (NULL = org
/// vault). Creates a new version each time.
pub(crate) async fn put(
    pool: &PgPool,
    org_id: Uuid,
    owner_identity_id: Option<Uuid>,
    name: &str,
    encrypted_value: &[u8],
    created_by: Option<Uuid>,
    provisioned_by_user_id: Option<Uuid>,
) -> Result<(SecretRow, SecretVersionRow), sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Upsert the secret row
    let secret = sqlx::query_as!(
        SecretRow,
        "INSERT INTO secrets (org_id, name, owner_identity_id) VALUES ($1, $2, $3)
         ON CONFLICT (org_id, owner_identity_id, name) DO UPDATE SET
           current_version = secrets.current_version + 1,
           updated_at = now(),
           deleted_at = NULL
         RETURNING id, org_id, name, current_version, owner_identity_id, deleted_at, created_at, updated_at",
        org_id,
        name,
        owner_identity_id,
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
    owner_identity_id: Option<Uuid>,
    name: &str,
) -> Result<Option<SecretRow>, sqlx::Error> {
    sqlx::query_as!(
        SecretRow,
        "SELECT id, org_id, name, current_version, owner_identity_id, deleted_at, created_at, updated_at
         FROM secrets WHERE org_id = $1 AND owner_identity_id IS NOT DISTINCT FROM $3 AND name = $2 AND deleted_at IS NULL",
        org_id,
        name,
        owner_identity_id,
    )
    .fetch_optional(pool)
    .await
}

pub(crate) async fn get_current_value(
    pool: &PgPool,
    org_id: Uuid,
    owner_identity_id: Option<Uuid>,
    name: &str,
) -> Result<Option<SecretVersionRow>, sqlx::Error> {
    sqlx::query_as!(
        SecretVersionRow,
        "SELECT sv.id, sv.secret_id, sv.version, sv.encrypted_value, sv.created_at, sv.created_by, sv.provisioned_by_user_id
         FROM secret_versions sv
         JOIN secrets s ON sv.secret_id = s.id
         WHERE s.org_id = $1 AND s.owner_identity_id IS NOT DISTINCT FROM $3 AND s.name = $2 AND s.deleted_at IS NULL AND sv.version = s.current_version",
        org_id,
        name,
        owner_identity_id,
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
        "SELECT id, org_id, name, current_version, owner_identity_id, deleted_at, created_at, updated_at
         FROM secrets WHERE org_id = $1 AND deleted_at IS NULL ORDER BY name",
        org_id,
    )
    .fetch_all(pool)
    .await
}

/// List live secrets in one namespace (`owner_identity_id`, NULL = org vault).
pub(crate) async fn list_in_namespace(
    pool: &PgPool,
    org_id: Uuid,
    owner_identity_id: Option<Uuid>,
) -> Result<Vec<SecretRow>, sqlx::Error> {
    sqlx::query_as!(
        SecretRow,
        "SELECT id, org_id, name, current_version, owner_identity_id, deleted_at, created_at, updated_at
         FROM secrets
         WHERE org_id = $1 AND owner_identity_id IS NOT DISTINCT FROM $2 AND deleted_at IS NULL
         ORDER BY name",
        org_id,
        owner_identity_id,
    )
    .fetch_all(pool)
    .await
}

pub(crate) async fn soft_delete(
    pool: &PgPool,
    org_id: Uuid,
    owner_identity_id: Option<Uuid>,
    name: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE secrets SET deleted_at = now() WHERE org_id = $1 AND owner_identity_id IS NOT DISTINCT FROM $3 AND name = $2 AND deleted_at IS NULL",
        org_id,
        name,
        owner_identity_id,
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
    owner_identity_id: Option<Uuid>,
    name: &str,
) -> Result<Vec<SecretVersionMeta>, sqlx::Error> {
    sqlx::query_as!(
        SecretVersionMeta,
        "SELECT sv.version, sv.created_at, sv.created_by, sv.provisioned_by_user_id
         FROM secret_versions sv
         JOIN secrets s ON sv.secret_id = s.id
         WHERE s.org_id = $1 AND s.owner_identity_id IS NOT DISTINCT FROM $3 AND s.name = $2 AND s.deleted_at IS NULL
         ORDER BY sv.version DESC",
        org_id,
        name,
        owner_identity_id,
    )
    .fetch_all(pool)
    .await
}

/// Fetch a specific version's encrypted value. Returns None if either the
/// secret or the version is missing.
pub(crate) async fn get_value_at_version(
    pool: &PgPool,
    org_id: Uuid,
    owner_identity_id: Option<Uuid>,
    name: &str,
    version: i32,
) -> Result<Option<SecretVersionRow>, sqlx::Error> {
    sqlx::query_as!(
        SecretVersionRow,
        "SELECT sv.id, sv.secret_id, sv.version, sv.encrypted_value, sv.created_at, sv.created_by, sv.provisioned_by_user_id
         FROM secret_versions sv
         JOIN secrets s ON sv.secret_id = s.id
         WHERE s.org_id = $1 AND s.owner_identity_id IS NOT DISTINCT FROM $4 AND s.name = $2 AND s.deleted_at IS NULL AND sv.version = $3",
        org_id,
        name,
        version,
        owner_identity_id,
    )
    .fetch_optional(pool)
    .await
}

#[derive(Debug, sqlx::FromRow)]
pub struct SecretVersionMeta {
    pub version: i32,
    pub created_at: OffsetDateTime,
    pub created_by: Option<Uuid>,
    pub provisioned_by_user_id: Option<Uuid>,
}

/// Service instances that reference this secret path. Archived rows are
/// included with their status so the dashboard can render them as
/// stale references rather than hiding them — flipping a service back to
/// `active` is one click and keeping it in the list helps users notice
/// that the rotation matters.
pub(crate) async fn list_services_using_secret(
    pool: &PgPool,
    org_id: Uuid,
    path: &str,
) -> Result<Vec<ServiceUsingSecret>, sqlx::Error> {
    // A secret is "used" when the legacy scalar names it OR any per-scheme
    // binding in the `credentials` map does. Both hold canonical secret
    // paths (migration 133), so an exact match only finds bindings into
    // this secret's own namespace. Org-source overrides and multi-instance-
    // scheme bindings never mirror into the scalar, so the jsonb match is
    // load-bearing, not belt-and-braces.
    sqlx::query_as!(
        ServiceUsingSecret,
        "SELECT id, name, status
         FROM service_instances
         WHERE org_id = $1 AND (
             secret_name = $2
             OR EXISTS (
                 SELECT 1 FROM jsonb_each_text(credentials) kv WHERE kv.value = $2
             )
         )
         ORDER BY name",
        org_id,
        path,
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
    owner_identity_id: Option<Uuid>,
    entries: &[(&str, &[u8])],
    created_by: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    for (name, encrypted_value) in entries {
        let secret = sqlx::query_as!(
            SecretRow,
            "INSERT INTO secrets (org_id, name, owner_identity_id) VALUES ($1, $2, $3)
             ON CONFLICT (org_id, owner_identity_id, name) DO UPDATE SET
               current_version = secrets.current_version + 1,
               updated_at = now(),
               deleted_at = NULL
             RETURNING id, org_id, name, current_version, owner_identity_id, deleted_at, created_at, updated_at",
            org_id,
            name,
            owner_identity_id,
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
    owner_identity_id: Option<Uuid>,
    names: &[&str],
) -> Result<u64, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let mut total: u64 = 0;
    for name in names {
        let result = sqlx::query!(
            "UPDATE secrets SET deleted_at = now() WHERE org_id = $1 AND owner_identity_id IS NOT DISTINCT FROM $3 AND name = $2 AND deleted_at IS NULL",
            org_id,
            name,
            owner_identity_id,
        )
        .execute(&mut *tx)
        .await?;
        total += result.rows_affected();
    }
    tx.commit().await?;
    Ok(total)
}
