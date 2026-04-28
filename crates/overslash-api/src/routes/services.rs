use std::collections::HashMap;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, patch, put},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::repos::group::ServiceGroupRow;
use overslash_db::repos::service_instance::{
    CreateServiceInstance, ServiceInstanceRow, UpdateServiceInstance,
};
use overslash_db::scopes::OrgScope;

use super::util::fmt_time;
use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, AuthContext, WriteAcl},
    services::group_ceiling,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/services", get(list_services).post(create_service))
        .route(
            "/v1/services/{name}",
            get(get_service).delete(delete_service),
        )
        .route("/v1/services/{name}/actions", get(list_service_actions))
        .route("/v1/services/{id}/manage", put(update_service))
        .route("/v1/services/{id}/status", patch(update_service_status))
        .route("/v1/services/{id}/groups", get(list_service_groups))
}

// -- Response types --

#[derive(Serialize)]
struct ServiceInstanceSummary {
    id: Uuid,
    name: String,
    template_source: String,
    template_key: String,
    status: String,
    is_system: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_identity_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    connection_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_name: Option<String>,
    /// Per-instance MCP server URL override. Overrides the template's `mcp.url`.
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    /// Groups that grant access to this service instance. Empty when the
    /// service is not assigned to any group.
    #[serde(default)]
    groups: Vec<ServiceGroupRef>,
    /// Derived from the bound connection's granted scopes vs. the template's
    /// per-action `required_scopes`. See [`CredentialsStatus`] for the values.
    #[serde(skip_serializing_if = "Option::is_none")]
    credentials_status: Option<CredentialsStatus>,
}

#[derive(Serialize, Clone)]
struct ServiceGroupRef {
    grant_id: Uuid,
    group_id: Uuid,
    group_name: String,
    access_level: String,
    auto_approve_reads: bool,
}

impl From<ServiceGroupRow> for ServiceGroupRef {
    fn from(r: ServiceGroupRow) -> Self {
        Self {
            grant_id: r.grant_id,
            group_id: r.group_id,
            group_name: r.group_name,
            access_level: r.access_level,
            auto_approve_reads: r.auto_approve_reads,
        }
    }
}

#[derive(Serialize)]
struct ServiceInstanceDetail {
    id: Uuid,
    org_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_identity_id: Option<Uuid>,
    name: String,
    template_source: String,
    template_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    template_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    connection_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_name: Option<String>,
    /// Per-instance MCP server URL override.
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    status: String,
    is_system: bool,
    created_at: String,
    updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    credentials_status: Option<CredentialsStatus>,
}

/// Derived credential-health state for an OAuth-backed service instance.
///
/// Computed by walking the template's actions and comparing each action's
/// `required_scopes` against the bound connection's granted scopes:
///
/// - `Ok` — at least one action is fully covered by the connection's scopes
///   (or the template declares no `required_scopes`).
/// - `PartiallyDegraded` — some actions fully covered, some not. Individual
///   calls will 403 with `missing_scopes` but the service itself is still
///   usable for the actions it covers.
/// - `NeedsReconnect` — every action declares `required_scopes` that the
///   connection does not satisfy. No call will succeed without a scope
///   upgrade — this is the "new state" surfaced in the dashboard so the
///   user isn't left guessing why everything 403s.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum CredentialsStatus {
    Ok,
    PartiallyDegraded,
    NeedsReconnect,
}

// -- Request types --

#[derive(Deserialize)]
struct CreateServiceRequest {
    template_key: String,
    /// Defaults to template_key if not provided.
    name: Option<String>,
    connection_id: Option<Uuid>,
    secret_name: Option<String>,
    /// Per-instance MCP server URL. Required when the template declares no
    /// default `mcp.url`; optional otherwise (overrides the template default).
    url: Option<String>,
    /// Defaults to "active".
    #[serde(default = "default_status")]
    status: String,
    /// If true, create as user-level (requires identity-bound key). Default: true when key is identity-bound.
    user_level: Option<bool>,
    /// Create the service instance owned by this user identity instead of the
    /// calling agent. Caller must be the user itself or an agent whose owner
    /// is this user. Overrides `user_level` when both are set.
    #[serde(default)]
    on_behalf_of: Option<Uuid>,
}

fn default_status() -> String {
    "active".into()
}

#[derive(Deserialize)]
struct UpdateServiceRequest {
    name: Option<String>,
    connection_id: Option<Option<Uuid>>,
    secret_name: Option<Option<String>>,
    /// Update the per-instance MCP URL. `null` clears it (falls back to template default).
    url: Option<Option<String>>,
}

#[derive(Deserialize)]
struct UpdateStatusRequest {
    status: String,
}

// -- Handlers --

/// List service instances available to the caller (user's + org's), filtered by group membership.
async fn list_services(
    State(state): State<AppState>,
    auth: AuthContext,
    scope: OrgScope,
) -> Result<Json<Vec<ServiceInstanceSummary>>> {
    // Org-level API keys (no identity) bypass group filtering — they see everything.
    // Otherwise resolve the ceiling user (self for users, owner for agents) and apply
    // group-based visibility.
    let (ceiling_user_id, visible_ids) = if let Some(identity_id) = auth.identity_id {
        let ceiling_user_id = group_ceiling::resolve_ceiling_user_id(&scope, identity_id).await?;

        // System groups (Everyone, Admins) don't count for visibility filtering.
        // Only user-created groups trigger filtering, matching group_ceiling::load_ceiling.
        let groups = scope.list_groups_for_identity(ceiling_user_id).await?;
        let has_user_groups = groups.iter().any(|g| !g.is_system);
        let visible_ids = if !has_user_groups {
            None // no user groups = permissive (backward compat)
        } else {
            Some(scope.get_visible_service_ids(ceiling_user_id).await?)
        };
        (Some(ceiling_user_id), visible_ids)
    } else {
        (None, None) // org-level key — permissive
    };

    let rows = scope
        .list_available_service_instances_with_groups(
            auth.identity_id,
            ceiling_user_id,
            visible_ids.as_deref(),
        )
        .await?;

    // Batch-load the group assignments for the returned service ids so the UI
    // can render a Groups column without an N+1 follow-up.
    let service_ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let grants = scope.list_groups_for_services(&service_ids).await?;
    let mut groups_by_service: HashMap<Uuid, Vec<ServiceGroupRef>> = HashMap::new();
    for g in grants {
        groups_by_service
            .entry(g.service_instance_id)
            .or_default()
            .push(g.into());
    }

    // Pre-load connections and templates in bulk so we don't issue an
    // N-per-row burst of lookups while computing credentials_status. The
    // dashboard's services list page calls this on every visit.
    let connection_ids: Vec<Uuid> = rows.iter().filter_map(|r| r.connection_id).collect();
    let connections_by_id = scope.get_connections_by_ids(&connection_ids).await?;

    // Template lookup must use the *service's owner* identity, not the
    // caller's — user-tier templates are scoped to the creator, so using
    // `auth.identity_id` would miss templates owned by another user whose
    // service the caller can see via group membership. Cache by
    // (owner_identity_id, template_key) so we still fold duplicates.
    let mut templates: std::collections::HashMap<
        (Option<Uuid>, String),
        overslash_core::types::ServiceDefinition,
    > = std::collections::HashMap::new();
    for row in &rows {
        let key = (row.owner_identity_id, row.template_key.clone());
        if templates.contains_key(&key) {
            continue;
        }
        if let Ok(tpl) = crate::routes::templates::resolve_template_definition(
            &state,
            row.org_id,
            row.owner_identity_id,
            &row.template_key,
        )
        .await
        {
            templates.insert(key, tpl);
        }
    }

    let services = rows
        .into_iter()
        .map(|row| {
            let tpl_key = (row.owner_identity_id, row.template_key.clone());
            let credentials_status = row
                .connection_id
                .and_then(|cid| connections_by_id.get(&cid))
                .zip(templates.get(&tpl_key))
                .and_then(|(conn, tpl)| classify_scopes(&conn.scopes, tpl));
            let groups = groups_by_service.remove(&row.id).unwrap_or_default();
            let mut summary = row_to_summary(row, groups);
            summary.credentials_status = credentials_status;
            summary
        })
        .collect();
    Ok(Json(services))
}

/// List the groups that grant access to a single service instance.
///
/// Read access matches the sibling `GET /v1/groups/{id}/grants` endpoint,
/// which the project already treats as org-readable — any authenticated
/// caller can enumerate which groups grant what. Mutations (`add_grant`,
/// `remove_grant`) remain admin-only.
async fn list_service_groups(
    _: AuthContext,
    scope: OrgScope,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<ServiceGroupRef>>> {
    // Confirm the service exists in this org before returning the grant list.
    // An id from another tenant returns None here and we surface 404.
    let instance = scope
        .get_service_instance(id)
        .await?
        .ok_or_else(|| AppError::NotFound("service instance not found".into()))?;
    let grants = scope.list_groups_for_service(instance.id).await?;
    Ok(Json(grants.into_iter().map(Into::into).collect()))
}

#[derive(Deserialize, Default)]
struct GetServiceQuery {
    /// When true, also resolve draft and archived instances. Used by the
    /// dashboard's detail view; execution callers leave this off so the
    /// active-only contract is preserved.
    #[serde(default)]
    include_inactive: bool,
}

/// Get a service instance by name using user-shadows-org resolution.
///
/// By default only resolves active instances (execution semantics). Pass
/// `?include_inactive=true` to also resolve draft and archived rows.
async fn get_service(
    State(state): State<AppState>,
    auth: AuthContext,
    scope: OrgScope,
    Path(name): Path<String>,
    Query(q): Query<GetServiceQuery>,
) -> Result<Json<ServiceInstanceDetail>> {
    // Accept either a UUID or a name. Callers that already have the id should
    // pass it to avoid the user-shadows-org name resolution semantics.
    let row = if let Ok(uuid) = name.parse::<Uuid>() {
        scope.get_service_instance(uuid).await?
    } else {
        let ceiling = group_ceiling::resolve_ceiling_user_id_opt(&scope, auth.identity_id).await?;
        if q.include_inactive {
            scope
                .resolve_service_instance_by_name_any_status(auth.identity_id, ceiling, &name)
                .await?
        } else {
            scope
                .resolve_service_instance_by_name(auth.identity_id, ceiling, &name)
                .await?
        }
    }
    .ok_or_else(|| AppError::NotFound(format!("service '{name}' not found")))?;
    // Template resolution uses the service's owner — not the caller — so
    // user-tier templates owned by another user (reachable via groups) still
    // resolve from their correct tier.
    let credentials_status =
        compute_credentials_status(&state, &scope, &row, row.owner_identity_id).await;
    let mut detail = row_to_detail(row);
    detail.credentials_status = credentials_status;
    Ok(Json(detail))
}

/// Create a new service instance from a template.
async fn create_service(
    State(state): State<AppState>,
    WriteAcl(acl): WriteAcl,
    scope: OrgScope,
    Json(req): Json<CreateServiceRequest>,
) -> Result<Json<ServiceInstanceDetail>> {
    let auth = acl;
    let name = req.name.as_deref().unwrap_or(&req.template_key);

    // Determine the owning identity:
    //   - on_behalf_of: validate against the caller's owner chain, use the user
    //   - else: fall back to the legacy `user_level` flag (defaults true when
    //     the key is identity-bound)
    let owner_identity_id = if req.on_behalf_of.is_some() {
        group_ceiling::resolve_owner_identity(&scope, auth.identity_id, req.on_behalf_of).await?
    } else {
        let user_level = req.user_level.unwrap_or(auth.identity_id.is_some());
        if user_level {
            Some(auth.identity_id.ok_or_else(|| {
                AppError::BadRequest("user-level services require an identity-bound API key".into())
            })?)
        } else {
            None
        }
    };

    // Resolve the template to determine its source tier. User-tier templates
    // are scoped to the creator, so when `on_behalf_of` redirects ownership
    // to a user the caller is acting for, the lookup must use the owner's
    // identity — not the caller agent's.
    let template_lookup_identity = owner_identity_id.or(auth.identity_id);
    let (template_source, template_id) = resolve_template_source(
        &state,
        auth.org_id,
        template_lookup_identity,
        &req.template_key,
    )
    .await?;

    // Validate status
    if !["draft", "active", "archived"].contains(&req.status.as_str()) {
        return Err(AppError::BadRequest(format!(
            "invalid status '{}'; must be draft, active, or archived",
            req.status
        )));
    }

    // If the caller pinned a specific connection, assert it actually belongs
    // to this service's owner and targets the same OAuth provider the
    // template is built for. Without this check, a stale/wrong id silently
    // passes through to `service_instances.connection_id` and then surfaces
    // much later as an opaque execution failure ("action didn't auth").
    if let Some(connection_id) = req.connection_id {
        // Connections are always identity-owned (schema: `identity_id NOT
        // NULL`). An org-level service has no identity to compare against,
        // so we reject a pinned `connection_id` up front — otherwise a user
        // setting `user_level: false` could attach their personal connection
        // to a shared org service, creating a lifecycle + security mismatch.
        let expected_owner = owner_identity_id.ok_or_else(|| {
            AppError::BadRequest(
                "org-level services cannot pin a connection_id (connections are identity-owned)"
                    .into(),
            )
        })?;

        let connection = scope
            .get_connection(connection_id)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("connection '{connection_id}' not found")))?;

        if connection.identity_id != expected_owner {
            return Err(AppError::Forbidden(
                "connection belongs to another identity".into(),
            ));
        }

        let template_def = crate::routes::templates::resolve_template_definition(
            &state,
            auth.org_id,
            template_lookup_identity,
            &req.template_key,
        )
        .await?;
        let expected_provider = template_def.auth.iter().find_map(|a| match a {
            overslash_core::types::ServiceAuth::OAuth { provider, .. } => Some(provider.clone()),
            _ => None,
        });
        match expected_provider {
            Some(tpl_provider) if tpl_provider != connection.provider_key => {
                return Err(AppError::BadRequest(format!(
                    "connection_provider_mismatch: template '{}' uses '{}' but connection is for '{}'",
                    req.template_key, tpl_provider, connection.provider_key
                )));
            }
            None => {
                return Err(AppError::BadRequest(format!(
                    "connection_provider_mismatch: template '{}' does not use OAuth",
                    req.template_key
                )));
            }
            _ => {}
        }
    }

    // Validate secret_name and url against template requirements.
    // We fetch the template definition once here for all checks.
    {
        let template_def = crate::routes::templates::resolve_template_definition(
            &state,
            auth.org_id,
            template_lookup_identity,
            &req.template_key,
        )
        .await?;

        let is_mcp = template_def.runtime == overslash_core::types::Runtime::Mcp;
        let mcp_auth = template_def.mcp.as_ref().map(|m| &m.auth);
        let is_mcp_bearer = matches!(
            mcp_auth,
            Some(overslash_core::types::McpAuth::Bearer { .. })
        );
        let mcp_bearer_has_default_secret = matches!(
            mcp_auth,
            Some(overslash_core::types::McpAuth::Bearer {
                secret_name: Some(_)
            })
        );
        let mcp_has_default_url = template_def
            .mcp
            .as_ref()
            .and_then(|m| m.url.as_ref())
            .is_some();

        // `secret_name` is valid when: (1) template declares ApiKey auth, OR
        // (2) template is MCP with bearer auth. For OAuth-only HTTP templates
        // a secret_name would silently create a dead value — reject it.
        if req.secret_name.as_deref().is_some_and(|s| !s.is_empty()) {
            let has_api_key = template_def
                .auth
                .iter()
                .any(|a| matches!(a, overslash_core::types::ServiceAuth::ApiKey { .. }));
            if !has_api_key && !is_mcp_bearer {
                return Err(AppError::BadRequest(format!(
                    "template '{}' does not use api key or MCP bearer auth",
                    req.template_key
                )));
            }
        }

        // MCP templates with no default URL require one from the request.
        if is_mcp && !mcp_has_default_url {
            let provided = req.url.as_deref().is_some_and(|u| !u.is_empty());
            if !provided {
                return Err(AppError::BadRequest(format!(
                    "template '{}' has no default MCP URL; provide `url` in the request",
                    req.template_key
                )));
            }
        }

        // MCP bearer templates with no default secret_name require one from the request.
        if is_mcp && is_mcp_bearer && !mcp_bearer_has_default_secret {
            let provided = req.secret_name.as_deref().is_some_and(|s| !s.is_empty());
            if !provided {
                return Err(AppError::BadRequest(format!(
                    "template '{}' MCP bearer auth has no default secret_name; provide `secret_name` in the request",
                    req.template_key
                )));
            }
        }

        // Validate URL format when provided.
        if let Some(url) = req.url.as_deref() {
            if !url.is_empty() && !url.starts_with("http://") && !url.starts_with("https://") {
                return Err(AppError::BadRequest(
                    "`url` must start with http:// or https://".into(),
                ));
            }
        }
    }

    let input = CreateServiceInstance {
        org_id: auth.org_id,
        owner_identity_id,
        name,
        template_source: &template_source,
        template_key: &req.template_key,
        template_id,
        connection_id: req.connection_id,
        secret_name: req.secret_name.as_deref(),
        url: req.url.as_deref(),
        status: &req.status,
    };

    let row = scope.create_service_instance(input).await.map_err(|e| {
        if let sqlx::Error::Database(ref db_err) = e {
            if db_err.constraint().is_some() {
                return AppError::Conflict(format!("service '{name}' already exists"));
            }
        }
        AppError::Database(e)
    })?;

    // Match get/list semantics: newly-created services also carry the
    // derived `credentials_status` so clients don't need a second round-trip
    // to discover a bound connection is missing required scopes.
    let credentials_status =
        compute_credentials_status(&state, &scope, &row, row.owner_identity_id).await;
    let mut detail = row_to_detail(row);
    detail.credentials_status = credentials_status;
    Ok(Json(detail))
}

/// Update a service instance by id.
async fn update_service(
    State(state): State<AppState>,
    AdminAcl(auth): AdminAcl,
    scope: OrgScope,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateServiceRequest>,
) -> Result<Json<ServiceInstanceDetail>> {
    // Org-scoped lookup — a foreign id returns None at the SQL boundary.
    let existing = scope
        .get_service_instance(id)
        .await?
        .ok_or_else(|| AppError::NotFound("service instance not found".into()))?;
    if existing.is_system {
        return Err(AppError::BadRequest("cannot modify system service".into()));
    }

    // Block setting a non-empty `secret_name` on templates without ApiKey or MCP bearer auth.
    // Clearing via Some(None) or Some("") is always allowed.
    if let Some(Some(ref new_secret)) = req.secret_name {
        if !new_secret.is_empty() {
            let template_lookup_identity = existing.owner_identity_id.or(auth.identity_id);
            let template_def = crate::routes::templates::resolve_template_definition(
                &state,
                auth.org_id,
                template_lookup_identity,
                &existing.template_key,
            )
            .await?;
            let has_api_key = template_def
                .auth
                .iter()
                .any(|a| matches!(a, overslash_core::types::ServiceAuth::ApiKey { .. }));
            let is_mcp_bearer = matches!(
                template_def.mcp.as_ref().map(|m| &m.auth),
                Some(overslash_core::types::McpAuth::Bearer { .. })
            );
            if !has_api_key && !is_mcp_bearer {
                return Err(AppError::BadRequest(format!(
                    "template '{}' does not use api key or MCP bearer auth",
                    existing.template_key
                )));
            }
        }
    }

    // Validate URL format when provided.
    if let Some(Some(ref url)) = req.url {
        if !url.is_empty() && !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(AppError::BadRequest(
                "`url` must start with http:// or https://".into(),
            ));
        }
    }

    let input = UpdateServiceInstance {
        name: req.name.as_deref(),
        connection_id: req.connection_id,
        secret_name: req.secret_name.as_ref().map(|o| o.as_deref()),
        url: req.url.as_ref().map(|o| o.as_deref()),
    };

    let row = scope
        .update_service_instance(id, &input)
        .await?
        .ok_or_else(|| AppError::NotFound("service instance not found".into()))?;
    Ok(Json(row_to_detail(row)))
}

/// Update service instance lifecycle status.
async fn update_service_status(
    _: AdminAcl,
    scope: OrgScope,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateStatusRequest>,
) -> Result<Json<ServiceInstanceDetail>> {
    let existing = scope
        .get_service_instance(id)
        .await?
        .ok_or_else(|| AppError::NotFound("service instance not found".into()))?;
    if existing.is_system {
        return Err(AppError::BadRequest("cannot modify system service".into()));
    }

    if !["draft", "active", "archived"].contains(&req.status.as_str()) {
        return Err(AppError::BadRequest(format!(
            "invalid status '{}'; must be draft, active, or archived",
            req.status
        )));
    }

    let row = scope
        .update_service_instance_status(id, &req.status)
        .await?
        .ok_or_else(|| AppError::NotFound("service instance not found".into()))?;
    Ok(Json(row_to_detail(row)))
}

/// Delete a service instance.
async fn delete_service(
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let auth = acl;
    // Resolve by name (or id) to get the row; both lookups are org-scoped
    // at the SQL boundary, so a foreign id returns None → 404.
    // Destructive op: intentionally do NOT reach up to the ceiling user for
    // name resolution. An agent with AdminAcl must not be able to target its
    // owner user's services via the shadowing lookup; callers that really
    // mean to delete a parent-owned service can address it by UUID.
    let instance = if let Ok(uuid) = name.parse::<Uuid>() {
        scope
            .get_service_instance(uuid)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("service '{name}' not found")))?
    } else {
        scope
            .resolve_service_instance_by_name_any_status(auth.identity_id, None, &name)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("service '{name}' not found")))?
    };

    // Prevent deletion of system services (overslash)
    if instance.is_system {
        return Err(AppError::BadRequest("cannot delete system service".into()));
    }

    let deleted = scope.delete_service_instance(instance.id).await?;
    if !deleted {
        return Err(AppError::NotFound("service instance not found".into()));
    }
    Ok(Json(serde_json::json!({ "deleted": true })))
}

/// List actions for a service instance (delegates to the underlying template).
async fn list_service_actions(
    State(state): State<AppState>,
    auth: AuthContext,
    scope: OrgScope,
    Path(name): Path<String>,
) -> Result<Json<Vec<super::templates::ActionSummary>>> {
    // Accept either a UUID or a name (any status — dashboard inspection of
    // draft/archived must also work).
    let instance = if let Ok(uuid) = name.parse::<Uuid>() {
        scope.get_service_instance(uuid).await?
    } else {
        let ceiling = group_ceiling::resolve_ceiling_user_id_opt(&scope, auth.identity_id).await?;
        scope
            .resolve_service_instance_by_name_any_status(auth.identity_id, ceiling, &name)
            .await?
    }
    .ok_or_else(|| AppError::NotFound(format!("service '{name}' not found")))?;

    super::templates::resolve_template_actions(&state, &auth, &instance.template_key)
        .await
        .map(Json)
}

// -- Helpers --

fn row_to_summary(row: ServiceInstanceRow, groups: Vec<ServiceGroupRef>) -> ServiceInstanceSummary {
    ServiceInstanceSummary {
        id: row.id,
        name: row.name,
        template_source: row.template_source,
        template_key: row.template_key,
        status: row.status,
        is_system: row.is_system,
        owner_identity_id: row.owner_identity_id,
        connection_id: row.connection_id,
        secret_name: row.secret_name,
        url: row.url,
        groups,
        credentials_status: None,
    }
}

fn row_to_detail(row: ServiceInstanceRow) -> ServiceInstanceDetail {
    ServiceInstanceDetail {
        id: row.id,
        org_id: row.org_id,
        owner_identity_id: row.owner_identity_id,
        name: row.name,
        template_source: row.template_source,
        template_key: row.template_key,
        template_id: row.template_id,
        connection_id: row.connection_id,
        secret_name: row.secret_name,
        url: row.url,
        status: row.status,
        is_system: row.is_system,
        created_at: fmt_time(row.created_at),
        updated_at: fmt_time(row.updated_at),
        credentials_status: None,
    }
}

/// Compute the credential-health state for a service instance by comparing
/// each action's `required_scopes` against the bound connection's granted
/// scopes. Returns `None` when the service has no connection to evaluate —
/// the existing "needs setup" badge covers that case. See
/// [`CredentialsStatus`] for the meaning of each variant.
/// `template_owner` is the identity whose template tier is consulted — for
/// user-tier templates this MUST be the service's `owner_identity_id`, not
/// the caller, so a caller reaching another user's service via groups can
/// still resolve a user-tier template owned by someone else.
async fn compute_credentials_status(
    state: &AppState,
    scope: &OrgScope,
    row: &ServiceInstanceRow,
    template_owner: Option<Uuid>,
) -> Option<CredentialsStatus> {
    let conn_id = row.connection_id?;
    let connection = scope.get_connection(conn_id).await.ok().flatten()?;
    let template = crate::routes::templates::resolve_template_definition(
        state,
        row.org_id,
        template_owner,
        &row.template_key,
    )
    .await
    .ok()?;
    classify_scopes(&connection.scopes, &template)
}

/// Pure classifier — no DB, no state. Compares a connection's granted scopes
/// against a template's per-action `required_scopes` and returns `None` when
/// the template has no OAuth auth scheme (nothing to classify), otherwise the
/// health variant. Extracted out of [`compute_credentials_status`] so the
/// bulk path in [`list_services`] can reuse it against cached lookups and so
/// it can be unit-tested without spinning up an API.
fn classify_scopes(
    granted_scopes: &[String],
    template: &overslash_core::types::ServiceDefinition,
) -> Option<CredentialsStatus> {
    if !template
        .auth
        .iter()
        .any(|a| matches!(a, overslash_core::types::ServiceAuth::OAuth { .. }))
    {
        return None;
    }
    let granted: std::collections::HashSet<&str> =
        granted_scopes.iter().map(String::as_str).collect();

    let mut any_ok = false;
    let mut any_gap = false;
    for action in template.actions.values() {
        if action.required_scopes.is_empty() {
            // Actions without declared required_scopes inherit the service-
            // level superset — they always "work" from the gate's standpoint.
            any_ok = true;
            continue;
        }
        let covered = action
            .required_scopes
            .iter()
            .all(|s| granted.contains(s.as_str()));
        if covered {
            any_ok = true;
        } else {
            any_gap = true;
        }
    }

    Some(match (any_ok, any_gap) {
        (false, true) => CredentialsStatus::NeedsReconnect,
        (true, true) => CredentialsStatus::PartiallyDegraded,
        _ => CredentialsStatus::Ok,
    })
}

/// Determine the template source tier and optional DB template id for a given key.
async fn resolve_template_source(
    state: &AppState,
    org_id: Uuid,
    identity_id: Option<Uuid>,
    key: &str,
) -> Result<(String, Option<Uuid>)> {
    use overslash_db::repos::service_template;

    // Try user tier
    if let Some(identity_id) = identity_id {
        if let Some(t) =
            service_template::get_by_key(&state.db, org_id, Some(identity_id), key).await?
        {
            return Ok(("user".into(), Some(t.id)));
        }
    }

    // Try org tier
    if let Some(t) = service_template::get_by_key(&state.db, org_id, None, key).await? {
        return Ok(("org".into(), Some(t.id)));
    }

    // Try global
    if state.registry.get(key).is_some() {
        return Ok(("global".into(), None));
    }

    Err(AppError::NotFound(format!(
        "template '{key}' not found in any tier"
    )))
}

#[cfg(test)]
mod classify_scopes_tests {
    use super::*;
    use overslash_core::types::{
        Risk, ServiceAction, ServiceAuth, ServiceDefinition, TokenInjection,
    };
    use std::collections::HashMap;

    fn oauth_template(actions: Vec<(&str, Vec<&str>)>) -> ServiceDefinition {
        let mut map = HashMap::new();
        for (key, required) in actions {
            map.insert(
                key.to_string(),
                ServiceAction {
                    method: "GET".into(),
                    path: "/".into(),
                    description: String::new(),
                    risk: Risk::Read,
                    response_type: None,
                    params: HashMap::new(),
                    scope_param: None,
                    required_scopes: required.iter().map(|s| s.to_string()).collect(),
                    permission: None,
                    disclose: Vec::new(),
                    redact: Vec::new(),
                    mcp_tool: None,
                    output_schema: None,
                    disabled: false,
                },
            );
        }
        ServiceDefinition {
            key: "t".into(),
            display_name: "T".into(),
            description: None,
            hosts: vec![],
            category: None,
            auth: vec![ServiceAuth::OAuth {
                provider: "google".into(),
                scopes: vec![],
                token_injection: TokenInjection {
                    inject_as: "header".into(),
                    header_name: Some("Authorization".into()),
                    query_param: None,
                    prefix: Some("Bearer ".into()),
                },
            }],
            actions: map,
            runtime: overslash_core::types::Runtime::Http,
            mcp: None,
        }
    }

    fn scopes(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn none_when_template_has_no_oauth() {
        let tpl = ServiceDefinition {
            key: "t".into(),
            display_name: "T".into(),
            description: None,
            hosts: vec![],
            category: None,
            auth: vec![],
            actions: HashMap::new(),
            runtime: overslash_core::types::Runtime::Http,
            mcp: None,
        };
        assert!(classify_scopes(&scopes(&["x"]), &tpl).is_none());
    }

    #[test]
    fn ok_when_connection_covers_every_action() {
        let tpl = oauth_template(vec![("a", vec!["s1"]), ("b", vec!["s2"])]);
        assert!(matches!(
            classify_scopes(&scopes(&["s1", "s2"]), &tpl),
            Some(CredentialsStatus::Ok)
        ));
    }

    #[test]
    fn ok_when_template_declares_no_required_scopes() {
        // Matches the pre-PR behavior for templates that haven't adopted
        // `required_scopes` yet — their actions count as "ok" by default.
        let tpl = oauth_template(vec![("a", vec![]), ("b", vec![])]);
        assert!(matches!(
            classify_scopes(&scopes(&[]), &tpl),
            Some(CredentialsStatus::Ok)
        ));
    }

    #[test]
    fn partially_degraded_when_some_actions_covered() {
        let tpl = oauth_template(vec![("a", vec!["s1"]), ("b", vec!["s2"])]);
        assert!(matches!(
            classify_scopes(&scopes(&["s1"]), &tpl),
            Some(CredentialsStatus::PartiallyDegraded)
        ));
    }

    #[test]
    fn needs_reconnect_when_no_action_covered() {
        let tpl = oauth_template(vec![("a", vec!["s1"]), ("b", vec!["s2"])]);
        assert!(matches!(
            classify_scopes(&scopes(&["other"]), &tpl),
            Some(CredentialsStatus::NeedsReconnect)
        ));
    }
}
