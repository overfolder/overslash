use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct ServiceInstanceRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub owner_identity_id: Option<Uuid>,
    pub name: String,
    pub template_source: String,
    pub template_key: String,
    pub template_id: Option<Uuid>,
    pub connection_id: Option<Uuid>,
    pub secret_name: Option<String>,
    pub status: String,
    pub is_system: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

crate::repos::impl_org_owned!(ServiceInstanceRow);

pub struct CreateServiceInstance<'a> {
    pub org_id: Uuid,
    pub owner_identity_id: Option<Uuid>,
    pub name: &'a str,
    pub template_source: &'a str,
    pub template_key: &'a str,
    pub template_id: Option<Uuid>,
    pub connection_id: Option<Uuid>,
    pub secret_name: Option<&'a str>,
    pub status: &'a str,
}

pub struct UpdateServiceInstance<'a> {
    pub name: Option<&'a str>,
    pub connection_id: Option<Option<Uuid>>,
    pub secret_name: Option<Option<&'a str>>,
}

pub(crate) async fn create(
    pool: &PgPool,
    input: &CreateServiceInstance<'_>,
) -> Result<ServiceInstanceRow, sqlx::Error> {
    sqlx::query_as!(
        ServiceInstanceRow,
        "INSERT INTO service_instances (org_id, owner_identity_id, name, template_source, \
         template_key, template_id, connection_id, secret_name, status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         RETURNING id, org_id, owner_identity_id, name, template_source, template_key, \
         template_id, connection_id, secret_name, status, is_system, created_at, updated_at",
        input.org_id,
        input.owner_identity_id,
        input.name,
        input.template_source,
        input.template_key,
        input.template_id,
        input.connection_id,
        input.secret_name,
        input.status,
    )
    .fetch_one(pool)
    .await
}

/// Look up a service instance by id, scoped to an org.
///
/// Double-key lookup: a row id belonging to a different org returns `None`.
pub(crate) async fn get_by_id(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
) -> Result<Option<ServiceInstanceRow>, sqlx::Error> {
    sqlx::query_as!(
        ServiceInstanceRow,
        "SELECT id, org_id, owner_identity_id, name, template_source, template_key, \
         template_id, connection_id, secret_name, status, is_system, created_at, updated_at \
         FROM service_instances WHERE id = $1 AND org_id = $2",
        id,
        org_id,
    )
    .fetch_optional(pool)
    .await
}

/// Get a service instance by name within a specific scope (org or user).
pub(crate) async fn get_by_name(
    pool: &PgPool,
    org_id: Uuid,
    owner_identity_id: Option<Uuid>,
    name: &str,
) -> Result<Option<ServiceInstanceRow>, sqlx::Error> {
    sqlx::query_as!(
        ServiceInstanceRow,
        "SELECT id, org_id, owner_identity_id, name, template_source, template_key, \
         template_id, connection_id, secret_name, status, is_system, created_at, updated_at \
         FROM service_instances \
         WHERE org_id = $1 AND owner_identity_id IS NOT DISTINCT FROM $2 AND name = $3",
        org_id,
        owner_identity_id,
        name,
    )
    .fetch_optional(pool)
    .await
}

/// Resolve a service instance by name using user-shadows-org semantics.
///
/// - `org/name` prefix forces org scope (ignores user instances)
/// - Plain `name` tries user scope first, then org scope
///
/// Only returns active instances by default (for execution). Use `get_by_name` for any status.
pub(crate) async fn resolve_by_name(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Option<Uuid>,
    raw_name: &str,
) -> Result<Option<ServiceInstanceRow>, sqlx::Error> {
    // Parse "org/" prefix
    if let Some(name) = raw_name.strip_prefix("org/") {
        // Explicit org scope
        return sqlx::query_as!(
            ServiceInstanceRow,
            "SELECT id, org_id, owner_identity_id, name, template_source, template_key, \
             template_id, connection_id, secret_name, status, is_system, created_at, updated_at \
             FROM service_instances \
             WHERE org_id = $1 AND owner_identity_id IS NULL AND name = $2 AND status = 'active'",
            org_id,
            name,
        )
        .fetch_optional(pool)
        .await;
    }

    // User-shadows-org: try user scope first
    if let Some(identity_id) = identity_id {
        let user_instance = sqlx::query_as!(
            ServiceInstanceRow,
            "SELECT id, org_id, owner_identity_id, name, template_source, template_key, \
             template_id, connection_id, secret_name, status, is_system, created_at, updated_at \
             FROM service_instances \
             WHERE org_id = $1 AND owner_identity_id = $2 AND name = $3 AND status = 'active'",
            org_id,
            identity_id,
            raw_name,
        )
        .fetch_optional(pool)
        .await?;
        if user_instance.is_some() {
            return Ok(user_instance);
        }
    }

    // Fall through to org scope
    sqlx::query_as!(
        ServiceInstanceRow,
        "SELECT id, org_id, owner_identity_id, name, template_source, template_key, \
         template_id, connection_id, secret_name, status, is_system, created_at, updated_at \
         FROM service_instances \
         WHERE org_id = $1 AND owner_identity_id IS NULL AND name = $2 AND status = 'active'",
        org_id,
        raw_name,
    )
    .fetch_optional(pool)
    .await
}

/// Resolve a service instance by name with the same user-shadows-org semantics
/// as [`resolve_by_name`], but without filtering by status. Used by the dashboard
/// detail view, which must be able to inspect draft and archived instances.
pub async fn resolve_by_name_any_status(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Option<Uuid>,
    raw_name: &str,
) -> Result<Option<ServiceInstanceRow>, sqlx::Error> {
    if let Some(name) = raw_name.strip_prefix("org/") {
        return sqlx::query_as!(
            ServiceInstanceRow,
            "SELECT id, org_id, owner_identity_id, name, template_source, template_key, \
             template_id, connection_id, secret_name, status, is_system, created_at, updated_at \
             FROM service_instances \
             WHERE org_id = $1 AND owner_identity_id IS NULL AND name = $2",
            org_id,
            name,
        )
        .fetch_optional(pool)
        .await;
    }

    if let Some(identity_id) = identity_id {
        let user_instance = sqlx::query_as!(
            ServiceInstanceRow,
            "SELECT id, org_id, owner_identity_id, name, template_source, template_key, \
             template_id, connection_id, secret_name, status, is_system, created_at, updated_at \
             FROM service_instances \
             WHERE org_id = $1 AND owner_identity_id = $2 AND name = $3",
            org_id,
            identity_id,
            raw_name,
        )
        .fetch_optional(pool)
        .await?;
        if user_instance.is_some() {
            return Ok(user_instance);
        }
    }

    sqlx::query_as!(
        ServiceInstanceRow,
        "SELECT id, org_id, owner_identity_id, name, template_source, template_key, \
         template_id, connection_id, secret_name, status, is_system, created_at, updated_at \
         FROM service_instances \
         WHERE org_id = $1 AND owner_identity_id IS NULL AND name = $2",
        org_id,
        raw_name,
    )
    .fetch_optional(pool)
    .await
}

/// List org-level instances.
pub(crate) async fn list_by_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<ServiceInstanceRow>, sqlx::Error> {
    sqlx::query_as!(
        ServiceInstanceRow,
        "SELECT id, org_id, owner_identity_id, name, template_source, template_key, \
         template_id, connection_id, secret_name, status, is_system, created_at, updated_at \
         FROM service_instances \
         WHERE org_id = $1 AND owner_identity_id IS NULL ORDER BY name",
        org_id,
    )
    .fetch_all(pool)
    .await
}

/// List user-level instances for a specific identity.
pub(crate) async fn list_by_user(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
) -> Result<Vec<ServiceInstanceRow>, sqlx::Error> {
    sqlx::query_as!(
        ServiceInstanceRow,
        "SELECT id, org_id, owner_identity_id, name, template_source, template_key, \
         template_id, connection_id, secret_name, status, is_system, created_at, updated_at \
         FROM service_instances \
         WHERE org_id = $1 AND owner_identity_id = $2 ORDER BY name",
        org_id,
        identity_id,
    )
    .fetch_all(pool)
    .await
}

/// List all instances available to a caller: user's + org's.
pub(crate) async fn list_available(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Option<Uuid>,
) -> Result<Vec<ServiceInstanceRow>, sqlx::Error> {
    sqlx::query_as!(
        ServiceInstanceRow,
        "SELECT id, org_id, owner_identity_id, name, template_source, template_key, \
         template_id, connection_id, secret_name, status, is_system, created_at, updated_at \
         FROM service_instances \
         WHERE org_id = $1 AND (owner_identity_id IS NULL OR owner_identity_id = $2) \
         ORDER BY name",
        org_id,
        identity_id,
    )
    .fetch_all(pool)
    .await
}

/// List services visible to a user, filtered by group membership.
/// User-owned services are always visible. Org-level services are filtered
/// by the `visible_service_ids` set (derived from group grants).
/// If `visible_service_ids` is `None`, no group filtering is applied (backward compat).
pub(crate) async fn list_available_with_groups(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Option<Uuid>,
    visible_service_ids: Option<&[Uuid]>,
) -> Result<Vec<ServiceInstanceRow>, sqlx::Error> {
    match visible_service_ids {
        Some(ids) => {
            sqlx::query_as!(
                ServiceInstanceRow,
                "SELECT id, org_id, owner_identity_id, name, template_source, template_key, \
                 template_id, connection_id, secret_name, status, is_system, created_at, updated_at \
                 FROM service_instances \
                 WHERE org_id = $1 AND (owner_identity_id = $2 OR id = ANY($3)) \
                 ORDER BY name",
                org_id,
                identity_id,
                ids,
            )
            .fetch_all(pool)
            .await
        }
        None => list_available(pool, org_id, identity_id).await,
    }
}

/// Update lifecycle status, scoped to an org.
///
/// Double-key
/// update: a row id from another org returns `None` and mutates nothing.
pub(crate) async fn update_status(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
    status: &str,
) -> Result<Option<ServiceInstanceRow>, sqlx::Error> {
    sqlx::query_as!(
        ServiceInstanceRow,
        "UPDATE service_instances SET status = $3, updated_at = now() \
         WHERE id = $1 AND org_id = $2 \
         RETURNING id, org_id, owner_identity_id, name, template_source, template_key, \
         template_id, connection_id, secret_name, status, is_system, created_at, updated_at",
        id,
        org_id,
        status,
    )
    .fetch_optional(pool)
    .await
}

/// Update mutable fields, scoped to an org.
///
/// Double-key
/// update: a row id from another org returns `None` and mutates nothing.
pub(crate) async fn update(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
    input: &UpdateServiceInstance<'_>,
) -> Result<Option<ServiceInstanceRow>, sqlx::Error> {
    // Build dynamic update — only set fields that are Some
    let update_conn = input.connection_id.is_some();
    let conn_id = input.connection_id.flatten();
    let update_secret = input.secret_name.is_some();
    let secret = input.secret_name.flatten();

    sqlx::query_as!(
        ServiceInstanceRow,
        "UPDATE service_instances SET \
         name = COALESCE($3, name), \
         connection_id = CASE WHEN $4 THEN $5 ELSE connection_id END, \
         secret_name = CASE WHEN $6 THEN $7 ELSE secret_name END, \
         updated_at = now() \
         WHERE id = $1 AND org_id = $2 \
         RETURNING id, org_id, owner_identity_id, name, template_source, template_key, \
         template_id, connection_id, secret_name, status, is_system, created_at, updated_at",
        id,
        org_id,
        input.name,
        update_conn,
        conn_id,
        update_secret,
        secret,
    )
    .fetch_optional(pool)
    .await
}

/// Delete a service instance, scoped to an org.
///
/// Double-key
/// delete: a row id from another org returns `false` and deletes nothing.
pub(crate) async fn delete(pool: &PgPool, org_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "DELETE FROM service_instances WHERE id = $1 AND org_id = $2",
        id,
        org_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}
