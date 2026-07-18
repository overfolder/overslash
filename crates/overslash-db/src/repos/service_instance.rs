use std::collections::BTreeMap;

use sqlx::PgPool;
use sqlx::types::Json;
use time::OffsetDateTime;
use uuid::Uuid;

/// Per-scheme credential bindings: securityScheme key → secret NAME in the
/// org vault. Values are vault references by construction, never secret
/// values. Typed at the DB boundary so callers never touch raw jsonb.
pub type CredentialsMap = BTreeMap<String, String>;

/// Per-instance non-secret param values: param name → value. The counterpart
/// to `CredentialsMap` — that one holds vault *references*, this one holds
/// ordinary values that vary per deployment (an IMAP host, a region, a tenant
/// id) rather than per template.
///
/// Values are stored as strings even for numeric params: they arrive from a
/// text input in the dashboard, and the existing action-arg coercion layer
/// already turns `"993"` into an integer against the param's declared schema
/// before validation. Keeping one representation here avoids a second,
/// subtly-different coercion path. See migration 102.
pub type ConfigMap = BTreeMap<String, String>;

#[derive(Debug, Clone, sqlx::FromRow)]
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
    /// Per-scheme secret bindings keyed by the template's securityScheme key
    /// (e.g. `{"gateway": "my_gateway_key", "mailbox": "my_mailbox_login"}`).
    /// An empty map falls back to the legacy scalar `secret_name` for the
    /// template's sole instance-source scheme. See migration 100.
    pub credentials: Json<CredentialsMap>,
    /// Per-instance non-secret param values, keyed by param name (e.g.
    /// `{"X-Mailbox-Imap": "mail.example.com:993"}`). Only params the template
    /// marks `x-overslash-instance-config` may appear. Merged under the
    /// caller's args at execution time. See migration 102.
    pub config: Json<ConfigMap>,
    /// Per-instance MCP server URL. Overrides the template's `mcp.url` at
    /// execution time. Required when the template declares no default URL.
    pub url: Option<String>,
    /// When `false`, an instance with no explicit `connection_id` must NOT fall
    /// back to the identity's default connection for the provider at execution
    /// time — it requires an explicit binding. Defaults to `true` (legacy
    /// fallback behavior). See migration 090.
    pub use_default_connection: bool,
    pub status: String,
    pub is_system: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    /// MCP tools/list result for this instance, populated by
    /// `POST /v1/services/{id}/mcp/resync`. `None` = never resynced (distinct
    /// from an empty list). Each element is `{name, description, input_schema,
    /// output_schema}`. Overlaid on the template's authored `tools:` at read
    /// time (authored wins field-by-field). See migration 101.
    pub discovered_tools: Option<Json<Vec<serde_json::Value>>>,
    /// When the instance was last resynced (RFC3339 surfaced to the UI).
    pub discovered_at: Option<OffsetDateTime>,
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
    /// Per-scheme secret bindings. See `ServiceInstanceRow::credentials`.
    pub credentials: &'a CredentialsMap,
    /// Per-instance non-secret param values. See `ServiceInstanceRow::config`.
    pub config: &'a ConfigMap,
    /// Per-instance MCP URL override. See `ServiceInstanceRow::url`.
    pub url: Option<&'a str>,
    /// See `ServiceInstanceRow::use_default_connection`. Defaults to `true` at
    /// the API layer when the caller omits it.
    pub use_default_connection: bool,
    pub status: &'a str,
}

pub struct UpdateServiceInstance<'a> {
    pub name: Option<&'a str>,
    pub connection_id: Option<Option<Uuid>>,
    pub secret_name: Option<Option<&'a str>>,
    /// `Some` = whole-map replace (an empty map clears every binding);
    /// `None` = leave unchanged. See `ServiceInstanceRow::credentials`.
    pub credentials: Option<&'a CredentialsMap>,
    /// `Some` = whole-map replace (an empty map clears every value);
    /// `None` = leave unchanged. See `ServiceInstanceRow::config`.
    pub config: Option<&'a ConfigMap>,
    /// Outer `Some` = field is present in the request (update it);
    /// inner `Option` = nullable value (set to NULL when `None`).
    pub url: Option<Option<&'a str>>,
    /// `Some` = update the flag; `None` = leave unchanged.
    pub use_default_connection: Option<bool>,
}

pub(crate) async fn create(
    pool: &PgPool,
    input: &CreateServiceInstance<'_>,
) -> Result<ServiceInstanceRow, sqlx::Error> {
    sqlx::query_as!(
        ServiceInstanceRow,
        "INSERT INTO service_instances (org_id, owner_identity_id, name, template_source, \
         template_key, template_id, connection_id, secret_name, credentials, config, url, use_default_connection, status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
         RETURNING id, org_id, owner_identity_id, name, template_source, template_key, \
         template_id, connection_id, secret_name, credentials as \"credentials: Json<CredentialsMap>\", config as \"config: Json<ConfigMap>\", url, use_default_connection, status, is_system, created_at, updated_at, discovered_tools as \"discovered_tools?: Json<Vec<serde_json::Value>>\", discovered_at",
        input.org_id,
        input.owner_identity_id,
        input.name,
        input.template_source,
        input.template_key,
        input.template_id,
        input.connection_id,
        input.secret_name,
        Json(input.credentials) as _,
        Json(input.config) as _,
        input.url,
        input.use_default_connection,
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
    get_by_id_with(pool, org_id, id).await
}

/// Executor-generic variant of [`get_by_id`], so the lookup can run inside a
/// caller-supplied transaction (the atomic connection-pin flow validates
/// ownership in the same tx as the bind).
pub(crate) async fn get_by_id_with<'e, E>(
    executor: E,
    org_id: Uuid,
    id: Uuid,
) -> Result<Option<ServiceInstanceRow>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as!(
        ServiceInstanceRow,
        "SELECT id, org_id, owner_identity_id, name, template_source, template_key, \
         template_id, connection_id, secret_name, credentials as \"credentials: Json<CredentialsMap>\", config as \"config: Json<ConfigMap>\", url, use_default_connection, status, is_system, created_at, updated_at, discovered_tools as \"discovered_tools?: Json<Vec<serde_json::Value>>\", discovered_at \
         FROM service_instances WHERE id = $1 AND org_id = $2",
        id,
        org_id,
    )
    .fetch_optional(executor)
    .await
}

/// Bind (or rebind) a service instance to a connection, scoped to an org.
/// Executor-generic so it can participate in the atomic connection-pin
/// transaction. Returns the updated row, or `None` if the id belongs to
/// another org / was deleted. Ownership validation is the caller's job.
pub(crate) async fn bind_connection_with<'e, E>(
    executor: E,
    org_id: Uuid,
    id: Uuid,
    connection_id: Uuid,
) -> Result<Option<ServiceInstanceRow>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as!(
        ServiceInstanceRow,
        "UPDATE service_instances SET connection_id = $3, updated_at = now() \
         WHERE id = $1 AND org_id = $2 \
         RETURNING id, org_id, owner_identity_id, name, template_source, template_key, \
         template_id, connection_id, secret_name, credentials as \"credentials: Json<CredentialsMap>\", config as \"config: Json<ConfigMap>\", url, use_default_connection, status, is_system, created_at, updated_at, discovered_tools as \"discovered_tools?: Json<Vec<serde_json::Value>>\", discovered_at",
        id,
        org_id,
        connection_id,
    )
    .fetch_optional(executor)
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
         template_id, connection_id, secret_name, credentials as \"credentials: Json<CredentialsMap>\", config as \"config: Json<ConfigMap>\", url, use_default_connection, status, is_system, created_at, updated_at, discovered_tools as \"discovered_tools?: Json<Vec<serde_json::Value>>\", discovered_at \
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
/// 5. Group-granted instance — the ceiling user has a group grant covering this instance
///    by name. Consistent with the visibility `search` returns via `get_visible_service_ids`.
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
             template_id, connection_id, secret_name, credentials as \"credentials: Json<CredentialsMap>\", config as \"config: Json<ConfigMap>\", url, use_default_connection, status, is_system, created_at, updated_at, discovered_tools as \"discovered_tools?: Json<Vec<serde_json::Value>>\", discovered_at \
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
             template_id, connection_id, secret_name, credentials as \"credentials: Json<CredentialsMap>\", config as \"config: Json<ConfigMap>\", url, use_default_connection, status, is_system, created_at, updated_at, discovered_tools as \"discovered_tools?: Json<Vec<serde_json::Value>>\", discovered_at \
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
             template_id, connection_id, secret_name, credentials as \"credentials: Json<CredentialsMap>\", config as \"config: Json<ConfigMap>\", url, use_default_connection, status, is_system, created_at, updated_at, discovered_tools as \"discovered_tools?: Json<Vec<serde_json::Value>>\", discovered_at \
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

    // Org-level instance (no owner).
    let org_instance = sqlx::query_as!(
        ServiceInstanceRow,
        "SELECT id, org_id, owner_identity_id, name, template_source, template_key, \
         template_id, connection_id, secret_name, credentials as \"credentials: Json<CredentialsMap>\", config as \"config: Json<ConfigMap>\", url, use_default_connection, status, is_system, created_at, updated_at, discovered_tools as \"discovered_tools?: Json<Vec<serde_json::Value>>\", discovered_at \
         FROM service_instances \
         WHERE org_id = $1 AND owner_identity_id IS NULL AND name = $2 AND status = 'active'",
        org_id,
        raw_name,
    )
    .fetch_optional(pool)
    .await?;
    if org_instance.is_some() {
        return Ok(org_instance);
    }

    // Group-granted: the ceiling user has a group grant for this instance.
    // Mirrors the join used by `get_visible_service_ids` so an instance
    // visible via search is also callable by name.
    if let Some(user_id) = ceiling_user_id {
        return sqlx::query_as!(
            ServiceInstanceRow,
            "SELECT si.id, si.org_id, si.owner_identity_id, si.name, si.template_source, si.template_key, \
             si.template_id, si.connection_id, si.secret_name, si.credentials as \"credentials: Json<CredentialsMap>\", si.config as \"config: Json<ConfigMap>\", si.url, si.use_default_connection, \
             si.status, si.is_system, si.created_at, si.updated_at, \
             si.discovered_tools as \"discovered_tools?: Json<Vec<serde_json::Value>>\", si.discovered_at \
             FROM service_instances si \
             WHERE si.org_id = $1 AND si.name = $2 AND si.status = 'active' \
               AND EXISTS ( \
                 SELECT 1 FROM group_grants gg \
                 JOIN identity_groups ig ON ig.group_id = gg.group_id \
                 JOIN identities i ON i.id = ig.identity_id \
                 JOIN groups g ON g.id = gg.group_id \
                 WHERE ig.identity_id = $3 \
                   AND gg.service_instance_id = si.id \
                   AND i.org_id = $1 \
                   AND g.org_id = $1 \
               )",
            org_id,
            raw_name,
            user_id,
        )
        .fetch_optional(pool)
        .await;
    }

    Ok(None)
}

/// Resolve a service instance by name with the same user-shadows-org semantics
/// as [`resolve_by_name`] — including the group-granted fallback (step 5) —
/// but without filtering by status. Used by the dashboard detail view, which
/// must be able to inspect draft and archived instances.
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
             template_id, connection_id, secret_name, credentials as \"credentials: Json<CredentialsMap>\", config as \"config: Json<ConfigMap>\", url, use_default_connection, status, is_system, created_at, updated_at, discovered_tools as \"discovered_tools?: Json<Vec<serde_json::Value>>\", discovered_at \
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
             template_id, connection_id, secret_name, credentials as \"credentials: Json<CredentialsMap>\", config as \"config: Json<ConfigMap>\", url, use_default_connection, status, is_system, created_at, updated_at, discovered_tools as \"discovered_tools?: Json<Vec<serde_json::Value>>\", discovered_at \
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
             template_id, connection_id, secret_name, credentials as \"credentials: Json<CredentialsMap>\", config as \"config: Json<ConfigMap>\", url, use_default_connection, status, is_system, created_at, updated_at, discovered_tools as \"discovered_tools?: Json<Vec<serde_json::Value>>\", discovered_at \
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

    let org_instance = sqlx::query_as!(
        ServiceInstanceRow,
        "SELECT id, org_id, owner_identity_id, name, template_source, template_key, \
         template_id, connection_id, secret_name, credentials as \"credentials: Json<CredentialsMap>\", config as \"config: Json<ConfigMap>\", url, use_default_connection, status, is_system, created_at, updated_at, discovered_tools as \"discovered_tools?: Json<Vec<serde_json::Value>>\", discovered_at \
         FROM service_instances \
         WHERE org_id = $1 AND owner_identity_id IS NULL AND name = $2",
        org_id,
        raw_name,
    )
    .fetch_optional(pool)
    .await?;
    if org_instance.is_some() {
        return Ok(org_instance);
    }

    // Group-granted: same visibility logic as resolve_by_name step 5.
    if let Some(user_id) = ceiling_user_id {
        return sqlx::query_as!(
            ServiceInstanceRow,
            "SELECT si.id, si.org_id, si.owner_identity_id, si.name, si.template_source, si.template_key, \
             si.template_id, si.connection_id, si.secret_name, si.credentials as \"credentials: Json<CredentialsMap>\", si.config as \"config: Json<ConfigMap>\", si.url, si.use_default_connection, \
             si.status, si.is_system, si.created_at, si.updated_at, \
             si.discovered_tools as \"discovered_tools?: Json<Vec<serde_json::Value>>\", si.discovered_at \
             FROM service_instances si \
             WHERE si.org_id = $1 AND si.name = $2 \
               AND EXISTS ( \
                 SELECT 1 FROM group_grants gg \
                 JOIN identity_groups ig ON ig.group_id = gg.group_id \
                 JOIN identities i ON i.id = ig.identity_id \
                 JOIN groups g ON g.id = gg.group_id \
                 WHERE ig.identity_id = $3 \
                   AND gg.service_instance_id = si.id \
                   AND i.org_id = $1 \
                   AND g.org_id = $1 \
               )",
            org_id,
            raw_name,
            user_id,
        )
        .fetch_optional(pool)
        .await;
    }

    Ok(None)
}

/// List org-level instances.
pub(crate) async fn list_by_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<ServiceInstanceRow>, sqlx::Error> {
    sqlx::query_as!(
        ServiceInstanceRow,
        "SELECT id, org_id, owner_identity_id, name, template_source, template_key, \
         template_id, connection_id, secret_name, credentials as \"credentials: Json<CredentialsMap>\", config as \"config: Json<ConfigMap>\", url, use_default_connection, status, is_system, created_at, updated_at, discovered_tools as \"discovered_tools?: Json<Vec<serde_json::Value>>\", discovered_at \
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
         template_id, connection_id, secret_name, credentials as \"credentials: Json<CredentialsMap>\", config as \"config: Json<ConfigMap>\", url, use_default_connection, status, is_system, created_at, updated_at, discovered_tools as \"discovered_tools?: Json<Vec<serde_json::Value>>\", discovered_at \
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
         template_id, connection_id, secret_name, credentials as \"credentials: Json<CredentialsMap>\", config as \"config: Json<ConfigMap>\", url, use_default_connection, status, is_system, created_at, updated_at, discovered_tools as \"discovered_tools?: Json<Vec<serde_json::Value>>\", discovered_at \
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
                 template_id, connection_id, secret_name, credentials as \"credentials: Json<CredentialsMap>\", config as \"config: Json<ConfigMap>\", url, use_default_connection, status, is_system, created_at, updated_at, discovered_tools as \"discovered_tools?: Json<Vec<serde_json::Value>>\", discovered_at \
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
         template_id, connection_id, secret_name, credentials as \"credentials: Json<CredentialsMap>\", config as \"config: Json<ConfigMap>\", url, use_default_connection, status, is_system, created_at, updated_at, discovered_tools as \"discovered_tools?: Json<Vec<serde_json::Value>>\", discovered_at \
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
         template_id, connection_id, secret_name, credentials as \"credentials: Json<CredentialsMap>\", config as \"config: Json<ConfigMap>\", url, use_default_connection, status, is_system, created_at, updated_at, discovered_tools as \"discovered_tools?: Json<Vec<serde_json::Value>>\", discovered_at",
        id,
        org_id,
        status,
    )
    .fetch_optional(pool)
    .await
}

/// Overwrite the MCP discovery result for an instance, scoped to an org.
///
/// Narrow writer (kept separate from [`update`], which is the user-facing
/// instance edit) used by the MCP resync route. Last write wins — every
/// resync replaces `discovered_tools` wholesale. Double-key: a row id from
/// another org mutates nothing and returns `false`.
pub(crate) async fn update_discovered_tools(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
    tools: &[serde_json::Value],
    at: OffsetDateTime,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE service_instances \
         SET discovered_tools = $3, discovered_at = $4, updated_at = now() \
         WHERE id = $1 AND org_id = $2",
        id,
        org_id,
        Json(tools) as _,
        at,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
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
    let update_creds = input.credentials.is_some();
    let empty_creds = CredentialsMap::new();
    let creds = input.credentials.unwrap_or(&empty_creds);
    let update_config = input.config.is_some();
    let empty_config = ConfigMap::new();
    let config = input.config.unwrap_or(&empty_config);
    let update_url = input.url.is_some();
    let url = input.url.flatten();
    let update_udc = input.use_default_connection.is_some();
    let udc = input.use_default_connection.unwrap_or(true);

    sqlx::query_as!(
        ServiceInstanceRow,
        "UPDATE service_instances SET \
         name = COALESCE($3, name), \
         connection_id = CASE WHEN $4 THEN $5 ELSE connection_id END, \
         secret_name = CASE WHEN $6 THEN $7 ELSE secret_name END, \
         credentials = CASE WHEN $8 THEN $9 ELSE credentials END, \
         config = CASE WHEN $10 THEN $11 ELSE config END, \
         url = CASE WHEN $12 THEN $13 ELSE url END, \
         use_default_connection = CASE WHEN $14 THEN $15 ELSE use_default_connection END, \
         updated_at = now() \
         WHERE id = $1 AND org_id = $2 \
         RETURNING id, org_id, owner_identity_id, name, template_source, template_key, \
         template_id, connection_id, secret_name, credentials as \"credentials: Json<CredentialsMap>\", config as \"config: Json<ConfigMap>\", url, use_default_connection, status, is_system, created_at, updated_at, discovered_tools as \"discovered_tools?: Json<Vec<serde_json::Value>>\", discovered_at",
        id,
        org_id,
        input.name,
        update_conn,
        conn_id,
        update_secret,
        secret,
        update_creds,
        Json(creds) as _,
        update_config,
        Json(config) as _,
        update_url,
        url,
        update_udc,
        udc,
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
