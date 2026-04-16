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
