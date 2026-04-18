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
}

pub struct UpdateServiceTemplate<'a> {
    pub display_name: Option<&'a str>,
    pub description: Option<&'a str>,
    pub category: Option<&'a str>,
    pub hosts: Option<&'a [String]>,
    pub openapi: Option<serde_json::Value>,
}

pub async fn create(
    pool: &PgPool,
    input: &CreateServiceTemplate<'_>,
) -> Result<ServiceTemplateRow, sqlx::Error> {
    sqlx::query_as!(
        ServiceTemplateRow,
        "INSERT INTO service_templates (org_id, owner_identity_id, key, display_name, description, \
         category, hosts, openapi) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         RETURNING id, org_id, owner_identity_id, key, display_name, description, \
         category, hosts, openapi, created_at, updated_at",
        input.org_id,
        input.owner_identity_id,
        input.key,
        input.display_name,
        input.description,
        input.category,
        input.hosts,
        input.openapi,
    )
    .fetch_one(pool)
    .await
}

pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<ServiceTemplateRow>, sqlx::Error> {
    sqlx::query_as!(
        ServiceTemplateRow,
        "SELECT id, org_id, owner_identity_id, key, display_name, description, \
         category, hosts, openapi, created_at, updated_at \
         FROM service_templates WHERE id = $1",
        id,
    )
    .fetch_optional(pool)
    .await
}

/// Look up a template by key within a specific tier (org or user).
pub async fn get_by_key(
    pool: &PgPool,
    org_id: Uuid,
    owner_identity_id: Option<Uuid>,
    key: &str,
) -> Result<Option<ServiceTemplateRow>, sqlx::Error> {
    sqlx::query_as!(
        ServiceTemplateRow,
        "SELECT id, org_id, owner_identity_id, key, display_name, description, \
         category, hosts, openapi, created_at, updated_at \
         FROM service_templates \
         WHERE org_id = $1 AND owner_identity_id IS NOT DISTINCT FROM $2 AND key = $3",
        org_id,
        owner_identity_id,
        key,
    )
    .fetch_optional(pool)
    .await
}

/// List org-level templates (owner_identity_id IS NULL).
pub async fn list_by_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<ServiceTemplateRow>, sqlx::Error> {
    sqlx::query_as!(
        ServiceTemplateRow,
        "SELECT id, org_id, owner_identity_id, key, display_name, description, \
         category, hosts, openapi, created_at, updated_at \
         FROM service_templates \
         WHERE org_id = $1 AND owner_identity_id IS NULL ORDER BY key",
        org_id,
    )
    .fetch_all(pool)
    .await
}

/// List user-level templates for a specific identity.
pub async fn list_by_user(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
) -> Result<Vec<ServiceTemplateRow>, sqlx::Error> {
    sqlx::query_as!(
        ServiceTemplateRow,
        "SELECT id, org_id, owner_identity_id, key, display_name, description, \
         category, hosts, openapi, created_at, updated_at \
         FROM service_templates \
         WHERE org_id = $1 AND owner_identity_id = $2 ORDER BY key",
        org_id,
        identity_id,
    )
    .fetch_all(pool)
    .await
}

/// List all templates available to a caller: org-level + user-level for the given identity.
pub async fn list_available(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Option<Uuid>,
) -> Result<Vec<ServiceTemplateRow>, sqlx::Error> {
    sqlx::query_as!(
        ServiceTemplateRow,
        "SELECT id, org_id, owner_identity_id, key, display_name, description, \
         category, hosts, openapi, created_at, updated_at \
         FROM service_templates \
         WHERE org_id = $1 AND (owner_identity_id IS NULL OR owner_identity_id = $2) \
         ORDER BY key",
        org_id,
        identity_id,
    )
    .fetch_all(pool)
    .await
}

/// List ALL templates in an org (org-level + all users'), for admin compliance view.
pub async fn list_all_by_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<ServiceTemplateRow>, sqlx::Error> {
    sqlx::query_as!(
        ServiceTemplateRow,
        "SELECT id, org_id, owner_identity_id, key, display_name, description, \
         category, hosts, openapi, created_at, updated_at \
         FROM service_templates \
         WHERE org_id = $1 ORDER BY key",
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
         updated_at = now() \
         WHERE id = $1 \
         RETURNING id, org_id, owner_identity_id, key, display_name, description, \
         category, hosts, openapi, created_at, updated_at",
        id,
        input.display_name,
        input.description,
        input.category,
        input.hosts as Option<&[String]>,
        input.openapi.clone() as Option<serde_json::Value>,
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
