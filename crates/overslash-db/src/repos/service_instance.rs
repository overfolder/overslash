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
    /// Per-instance MCP server URL. Overrides the template's `mcp.url` at
    /// execution time. Required when the template declares no default URL.
    pub url: Option<String>,
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
    /// Per-instance MCP URL override. See `ServiceInstanceRow::url`.
    pub url: Option<&'a str>,
    pub status: &'a str,
}

pub struct UpdateServiceInstance<'a> {
    pub name: Option<&'a str>,
    pub connection_id: Option<Option<Uuid>>,
    pub secret_name: Option<Option<&'a str>>,
    /// Outer `Some` = field is present in the request (update it);
    /// inner `Option` = nullable value (set to NULL when `None`).
    pub url: Option<Option<&'a str>>,
}

pub(crate) async fn create(
    pool: &PgPool,
    input: &CreateServiceInstance<'_>,
) -> Result<ServiceInstanceRow, sqlx::Error> {
    sqlx::query_as!(
        ServiceInstanceRow,
        "INSERT INTO service_instances (org_id, owner_identity_id, name, template_source, \
         template_key, template_id, connection_id, secret_name, url, status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
         RETURNING id, org_id, owner_identity_id, name, template_source, template_key, \
         template_id, connection_id, secret_name, url, status, is_system, created_at, updated_at",
        input.org_id,
        input.owner_identity_id,
        input.name,
        input.template_source,
        input.template_key,
        input.template_id,
        input.connection_id,
        input.secret_name,
        input.url,
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
         template_id, connection_id, secret_name, url, status, is_system, created_at, updated_at \
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
         template_id, connection_id, secret_name, url, status, is_system, created_at, updated_at \
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
/// Resolution order (each layer is org-scoped; only active instances are returned):
/// 1. `org/name` prefix forces org scope, ignoring all user-level instances.
/// 2. Caller-owned instance (`owner_identity_id = identity_id`).
/// 3. Ceiling-user-owned instance (`owner_identity_id = ceiling_user_id`) — services the
///    agent's owner user has created are always reachable by the agent, regardless of
///    group membership.
/// 4. Org-level instance (`owner_identity_id IS NULL`).
///
/// Use `get_by_name` for any-status lookups.
pub(crate) async fn resolve_by_name(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Option<Uuid>,
    ceiling_user_id: Option<Uuid>,
    raw_name: &str,
) -> Result<Option<ServiceInstanceRow>, sqlx::Error> {
    // Parse "org/" prefix
    if let Some(name) = raw_name.strip_prefix("org/") {
        // Explicit org scope
        return sqlx::query_as!(
            ServiceInstanceRow,
            "SELECT id, org_id, owner_identity_id, name, template_source, template_key, \
             template_id, connection_id, secret_name, url, status, is_system, created_at, updated_at \
             FROM service_instances \
             WHERE org_id = $1 AND owner_identity_id IS NULL AND name = $2 AND status = 'active'",
            org_id,
            name,
        )
        .fetch_optional(pool)
        .await;
    }

    // Caller-owned wins first (agent-specific instance).
    if let Some(identity_id) = identity_id {
        let caller_instance = sqlx::query_as!(
            ServiceInstanceRow,
            "SELECT id, org_id, owner_identity_id, name, template_source, template_key, \
             template_id, connection_id, secret_name, url, status, is_system, created_at, updated_at \
             FROM service_instances \
             WHERE org_id = $1 AND owner_identity_id = $2 AND name = $3 AND status = 'active'",
            org_id,
            identity_id,
            raw_name,
        )
        .fetch_optional(pool)
        .await?;
        if caller_instance.is_some() {
            return Ok(caller_instance);
        }
    }

    // Ceiling-user-owned (user-level shared with all agents in their chain).
    if let Some(user_id) = ceiling_user_id
        && Some(user_id) != identity_id
    {
        let user_instance = sqlx::query_as!(
            ServiceInstanceRow,
            "SELECT id, org_id, owner_identity_id, name, template_source, template_key, \
             template_id, connection_id, secret_name, url, status, is_system, created_at, updated_at \
             FROM service_instances \
             WHERE org_id = $1 AND owner_identity_id = $2 AND name = $3 AND status = 'active'",
            org_id,
            user_id,
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
         template_id, connection_id, secret_name, url, status, is_system, created_at, updated_at \
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
    ceiling_user_id: Option<Uuid>,
    raw_name: &str,
) -> Result<Option<ServiceInstanceRow>, sqlx::Error> {
    if let Some(name) = raw_name.strip_prefix("org/") {
        return sqlx::query_as!(
            ServiceInstanceRow,
            "SELECT id, org_id, owner_identity_id, name, template_source, template_key, \
             template_id, connection_id, secret_name, url, status, is_system, created_at, updated_at \
             FROM service_instances \
             WHERE org_id = $1 AND owner_identity_id IS NULL AND name = $2",
            org_id,
            name,
        )
        .fetch_optional(pool)
        .await;
    }

    if let Some(identity_id) = identity_id {
        let caller_instance = sqlx::query_as!(
            ServiceInstanceRow,
            "SELECT id, org_id, owner_identity_id, name, template_source, template_key, \
             template_id, connection_id, secret_name, url, status, is_system, created_at, updated_at \
             FROM service_instances \
             WHERE org_id = $1 AND owner_identity_id = $2 AND name = $3",
            org_id,
            identity_id,
            raw_name,
        )
        .fetch_optional(pool)
        .await?;
        if caller_instance.is_some() {
            return Ok(caller_instance);
        }
    }

    if let Some(user_id) = ceiling_user_id
        && Some(user_id) != identity_id
    {
        let user_instance = sqlx::query_as!(
            ServiceInstanceRow,
            "SELECT id, org_id, owner_identity_id, name, template_source, template_key, \
             template_id, connection_id, secret_name, url, status, is_system, created_at, updated_at \
             FROM service_instances \
             WHERE org_id = $1 AND owner_identity_id = $2 AND name = $3",
            org_id,
            user_id,
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
         template_id, connection_id, secret_name, url, status, is_system, created_at, updated_at \
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
         template_id, connection_id, secret_name, url, status, is_system, created_at, updated_at \
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
         template_id, connection_id, secret_name, url, status, is_system, created_at, updated_at \
         FROM service_instances \
         WHERE org_id = $1 AND owner_identity_id = $2 ORDER BY name",
        org_id,
        identity_id,
    )
    .fetch_all(pool)
    .await
}

/// List all instances available to a caller: org-level + caller-owned + ceiling-user-owned.
///
/// `ceiling_user_id` is the caller's owner user (same as `identity_id` when the caller is
/// a user). Passing `None` yields the non-identity bound set (org-level only). Services
/// owned by the ceiling user are always included, guaranteeing a user and their agents
/// see every service the user has created regardless of group membership.
pub(crate) async fn list_available(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Option<Uuid>,
    ceiling_user_id: Option<Uuid>,
) -> Result<Vec<ServiceInstanceRow>, sqlx::Error> {
    sqlx::query_as!(
        ServiceInstanceRow,
        "SELECT id, org_id, owner_identity_id, name, template_source, template_key, \
         template_id, connection_id, secret_name, url, status, is_system, created_at, updated_at \
         FROM service_instances \
         WHERE org_id = $1 \
           AND (owner_identity_id IS NULL \
                OR owner_identity_id = $2 \
                OR owner_identity_id = $3) \
         ORDER BY name",
        org_id,
        identity_id,
        ceiling_user_id,
    )
    .fetch_all(pool)
    .await
}

/// List services visible to a caller, filtered by group membership.
///
/// Visibility flows entirely through `visible_service_ids` (the set of service
/// instance ids the caller's ceiling-user has access to via group grants — including
/// the auto-managed Myself group, which carries grants on services the user owns).
/// Pass `None` to skip group filtering — used for org-level API keys and the legacy
/// no-identity path.
pub(crate) async fn list_available_with_groups(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Option<Uuid>,
    ceiling_user_id: Option<Uuid>,
    visible_service_ids: Option<&[Uuid]>,
) -> Result<Vec<ServiceInstanceRow>, sqlx::Error> {
    match visible_service_ids {
        Some(ids) => {
            sqlx::query_as!(
                ServiceInstanceRow,
                "SELECT id, org_id, owner_identity_id, name, template_source, template_key, \
                 template_id, connection_id, secret_name, url, status, is_system, created_at, updated_at \
                 FROM service_instances \
                 WHERE org_id = $1 AND id = ANY($2) \
                 ORDER BY name",
                org_id,
                ids,
            )
            .fetch_all(pool)
            .await
        }
        None => list_available(pool, org_id, identity_id, ceiling_user_id).await,
    }
}

/// List every service instance in an org, regardless of owner or group grants.
///
/// Used by the dashboard's admin "view all users' services" affordance. The route
/// layer is responsible for gating this on `is_org_admin`.
pub(crate) async fn list_all_in_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<ServiceInstanceRow>, sqlx::Error> {
    sqlx::query_as!(
        ServiceInstanceRow,
        "SELECT id, org_id, owner_identity_id, name, template_source, template_key, \
         template_id, connection_id, secret_name, url, status, is_system, created_at, updated_at \
         FROM service_instances \
         WHERE org_id = $1 \
         ORDER BY name",
        org_id,
    )
    .fetch_all(pool)
    .await
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
         template_id, connection_id, secret_name, url, status, is_system, created_at, updated_at",
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
    let update_url = input.url.is_some();
    let url = input.url.flatten();

    sqlx::query_as!(
        ServiceInstanceRow,
        "UPDATE service_instances SET \
         name = COALESCE($3, name), \
         connection_id = CASE WHEN $4 THEN $5 ELSE connection_id END, \
         secret_name = CASE WHEN $6 THEN $7 ELSE secret_name END, \
         url = CASE WHEN $8 THEN $9 ELSE url END, \
         updated_at = now() \
         WHERE id = $1 AND org_id = $2 \
         RETURNING id, org_id, owner_identity_id, name, template_source, template_key, \
         template_id, connection_id, secret_name, url, status, is_system, created_at, updated_at",
        id,
        org_id,
        input.name,
        update_conn,
        conn_id,
        update_secret,
        secret,
        update_url,
        url,
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
