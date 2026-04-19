use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct ServiceTemplateRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub owner_identity_id: Option<Uuid>,
    pub key: String,
    pub display_name: String,
    pub description: String,
    pub category: String,
    pub hosts: Vec<String>,
    /// Full OpenAPI 3.1 document (with `x-overslash-*` extensions), canonical
    /// source of truth for the template. The scalar fields above are
    /// denormalized at write time for fast listing.
    pub openapi: serde_json::Value,
    /// `'draft'` rows are the in-progress output of `POST /v1/templates/import`;
    /// they are invisible to the runtime registry and all public listing
    /// queries filter them out. `'active'` rows are the regular published
    /// templates.
    pub status: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

pub struct CreateServiceTemplate<'a> {
    pub org_id: Uuid,
    pub owner_identity_id: Option<Uuid>,
    pub key: &'a str,
    pub display_name: &'a str,
    pub description: &'a str,
    pub category: &'a str,
    pub hosts: &'a [String],
    pub openapi: serde_json::Value,
    /// Defaults to `'active'` when creating a new template directly. Imports
    /// pass `'draft'` to park the row until the user promotes it.
    pub status: &'a str,
}

pub struct UpdateServiceTemplate<'a> {
    pub display_name: Option<&'a str>,
    pub description: Option<&'a str>,
    pub category: Option<&'a str>,
    pub hosts: Option<&'a [String]>,
    pub openapi: Option<serde_json::Value>,
    pub key: Option<&'a str>,
}

pub async fn create(
    pool: &PgPool,
    input: &CreateServiceTemplate<'_>,
) -> Result<ServiceTemplateRow, sqlx::Error> {
    sqlx::query_as!(
        ServiceTemplateRow,
        "INSERT INTO service_templates (org_id, owner_identity_id, key, display_name, description, \
         category, hosts, openapi, status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         RETURNING id, org_id, owner_identity_id, key, display_name, description, \
         category, hosts, openapi, status, created_at, updated_at",
        input.org_id,
        input.owner_identity_id,
        input.key,
        input.display_name,
        input.description,
        input.category,
        input.hosts,
        input.openapi,
        input.status,
    )
    .fetch_one(pool)
    .await
}

pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<ServiceTemplateRow>, sqlx::Error> {
    sqlx::query_as!(
        ServiceTemplateRow,
        "SELECT id, org_id, owner_identity_id, key, display_name, description, \
         category, hosts, openapi, status, created_at, updated_at \
         FROM service_templates WHERE id = $1",
        id,
    )
    .fetch_optional(pool)
    .await
}

/// Look up an active template by key within a specific tier (org or user).
/// Draft rows are intentionally excluded — they are not reachable via the
/// runtime/public lookup surface.
pub async fn get_by_key(
    pool: &PgPool,
    org_id: Uuid,
    owner_identity_id: Option<Uuid>,
    key: &str,
) -> Result<Option<ServiceTemplateRow>, sqlx::Error> {
    sqlx::query_as!(
        ServiceTemplateRow,
        "SELECT id, org_id, owner_identity_id, key, display_name, description, \
         category, hosts, openapi, status, created_at, updated_at \
         FROM service_templates \
         WHERE org_id = $1 AND owner_identity_id IS NOT DISTINCT FROM $2 AND key = $3 \
           AND status = 'active'",
        org_id,
        owner_identity_id,
        key,
    )
    .fetch_optional(pool)
    .await
}

/// List active org-level templates (owner_identity_id IS NULL).
pub async fn list_by_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<ServiceTemplateRow>, sqlx::Error> {
    sqlx::query_as!(
        ServiceTemplateRow,
        "SELECT id, org_id, owner_identity_id, key, display_name, description, \
         category, hosts, openapi, status, created_at, updated_at \
         FROM service_templates \
         WHERE org_id = $1 AND owner_identity_id IS NULL AND status = 'active' ORDER BY key",
        org_id,
    )
    .fetch_all(pool)
    .await
}

/// List active user-level templates for a specific identity.
pub async fn list_by_user(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
) -> Result<Vec<ServiceTemplateRow>, sqlx::Error> {
    sqlx::query_as!(
        ServiceTemplateRow,
        "SELECT id, org_id, owner_identity_id, key, display_name, description, \
         category, hosts, openapi, status, created_at, updated_at \
         FROM service_templates \
         WHERE org_id = $1 AND owner_identity_id = $2 AND status = 'active' ORDER BY key",
        org_id,
        identity_id,
    )
    .fetch_all(pool)
    .await
}

/// List all active templates available to a caller: org-level + user-level
/// for the given identity.
pub async fn list_available(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Option<Uuid>,
) -> Result<Vec<ServiceTemplateRow>, sqlx::Error> {
    sqlx::query_as!(
        ServiceTemplateRow,
        "SELECT id, org_id, owner_identity_id, key, display_name, description, \
         category, hosts, openapi, status, created_at, updated_at \
         FROM service_templates \
         WHERE org_id = $1 AND (owner_identity_id IS NULL OR owner_identity_id = $2) \
           AND status = 'active' \
         ORDER BY key",
        org_id,
        identity_id,
    )
    .fetch_all(pool)
    .await
}

/// List ALL active templates in an org (org-level + all users'), for admin
/// compliance view.
pub async fn list_all_by_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<ServiceTemplateRow>, sqlx::Error> {
    sqlx::query_as!(
        ServiceTemplateRow,
        "SELECT id, org_id, owner_identity_id, key, display_name, description, \
         category, hosts, openapi, status, created_at, updated_at \
         FROM service_templates \
         WHERE org_id = $1 AND status = 'active' ORDER BY key",
        org_id,
    )
    .fetch_all(pool)
    .await
}

/// List drafts owned by a specific identity (user-level drafts only). Use
/// this for non-admin callers — they only see their own user drafts, never
/// org-level ones. Admins call [`list_all_drafts_in_org`] instead.
pub async fn list_user_drafts(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
) -> Result<Vec<ServiceTemplateRow>, sqlx::Error> {
    sqlx::query_as!(
        ServiceTemplateRow,
        "SELECT id, org_id, owner_identity_id, key, display_name, description, \
         category, hosts, openapi, status, created_at, updated_at \
         FROM service_templates \
         WHERE org_id = $1 AND status = 'draft' AND owner_identity_id = $2 \
         ORDER BY updated_at DESC",
        org_id,
        identity_id,
    )
    .fetch_all(pool)
    .await
}

/// Admin-only: list every draft in the org, across all owners. Mirrors
/// `list_all_by_org` but filtered to `status='draft'`. Routes MUST gate this
/// on admin access before calling.
pub async fn list_all_drafts_in_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<ServiceTemplateRow>, sqlx::Error> {
    sqlx::query_as!(
        ServiceTemplateRow,
        "SELECT id, org_id, owner_identity_id, key, display_name, description, \
         category, hosts, openapi, status, created_at, updated_at \
         FROM service_templates \
         WHERE org_id = $1 AND status = 'draft' \
         ORDER BY updated_at DESC",
        org_id,
    )
    .fetch_all(pool)
    .await
}

pub async fn update(
    pool: &PgPool,
    id: Uuid,
    input: &UpdateServiceTemplate<'_>,
) -> Result<Option<ServiceTemplateRow>, sqlx::Error> {
    sqlx::query_as!(
        ServiceTemplateRow,
        "UPDATE service_templates SET \
         display_name = COALESCE($2, display_name), \
         description = COALESCE($3, description), \
         category = COALESCE($4, category), \
         hosts = COALESCE($5, hosts), \
         openapi = COALESCE($6, openapi), \
         key = COALESCE($7, key), \
         updated_at = now() \
         WHERE id = $1 \
         RETURNING id, org_id, owner_identity_id, key, display_name, description, \
         category, hosts, openapi, status, created_at, updated_at",
        id,
        input.display_name,
        input.description,
        input.category,
        input.hosts as Option<&[String]>,
        input.openapi.clone() as Option<serde_json::Value>,
        input.key,
    )
    .fetch_optional(pool)
    .await
}

/// Flip a draft row to `'active'`. No-op on rows already `'active'`.
/// Returns the row on success, or `None` if the row does not exist.
/// The caller is expected to have validated the row shape and checked for
/// key collisions before calling this.
pub async fn promote_draft(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<ServiceTemplateRow>, sqlx::Error> {
    sqlx::query_as!(
        ServiceTemplateRow,
        "UPDATE service_templates SET status = 'active', updated_at = now() \
         WHERE id = $1 AND status = 'draft' \
         RETURNING id, org_id, owner_identity_id, key, display_name, description, \
         category, hosts, openapi, status, created_at, updated_at",
        id,
    )
    .fetch_optional(pool)
    .await
}

pub async fn delete(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!("DELETE FROM service_templates WHERE id = $1", id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}
