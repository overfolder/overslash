use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, patch, put},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::repos::service_instance::{
    CreateServiceInstance, ServiceInstanceRow, UpdateServiceInstance,
};
use overslash_db::scopes::OrgScope;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, AuthContext, WriteAcl},
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
}

// -- Response types --

#[derive(Serialize)]
struct ServiceInstanceSummary {
    id: Uuid,
    name: String,
    template_source: String,
    template_key: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_identity_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    connection_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_name: Option<String>,
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
    status: String,
    is_system: bool,
    created_at: String,
    updated_at: String,
}

// -- Request types --

#[derive(Deserialize)]
struct CreateServiceRequest {
    template_key: String,
    /// Defaults to template_key if not provided.
    name: Option<String>,
    connection_id: Option<Uuid>,
    secret_name: Option<String>,
    /// Defaults to "active".
    #[serde(default = "default_status")]
    status: String,
    /// If true, create as user-level (requires identity-bound key). Default: true when key is identity-bound.
    user_level: Option<bool>,
}

fn default_status() -> String {
    "active".into()
}

#[derive(Deserialize)]
struct UpdateServiceRequest {
    name: Option<String>,
    connection_id: Option<Option<Uuid>>,
    secret_name: Option<Option<String>>,
}

#[derive(Deserialize)]
struct UpdateStatusRequest {
    status: String,
}

// -- Handlers --

/// List service instances available to the caller (user's + org's), filtered by group membership.
async fn list_services(
    State(_state): State<AppState>,
    auth: AuthContext,
    scope: OrgScope,
) -> Result<Json<Vec<ServiceInstanceSummary>>> {
    // Org-level API keys (no identity) bypass group filtering — they see everything.
    // Otherwise resolve the ceiling user (self for users, owner for agents) and apply
    // group-based visibility.
    let visible_ids = if let Some(identity_id) = auth.identity_id {
        let ceiling_user_id =
            crate::services::group_ceiling::resolve_ceiling_user_id(&scope, identity_id).await?;

        // System groups (Everyone, Admins) don't count for visibility filtering.
        // Only user-created groups trigger filtering, matching group_ceiling::load_ceiling.
        let groups = scope.list_groups_for_identity(ceiling_user_id).await?;
        let has_user_groups = groups.iter().any(|g| !g.is_system);
        if !has_user_groups {
            None // no user groups = permissive (backward compat)
        } else {
            Some(scope.get_visible_service_ids(ceiling_user_id).await?)
        }
    } else {
        None // org-level key — permissive
    };

    let rows = scope
        .list_available_service_instances_with_groups(auth.identity_id, visible_ids.as_deref())
        .await?;

    let services = rows.into_iter().map(row_to_summary).collect();
    Ok(Json(services))
}

/// Get a service instance by name using user-shadows-org resolution.
async fn get_service(
    auth: AuthContext,
    scope: OrgScope,
    Path(name): Path<String>,
) -> Result<Json<ServiceInstanceDetail>> {
    // Use the any-status resolver so the dashboard can view draft and archived
    // instances. resolve_by_name filters to active and is reserved for execution.
    let row = scope
        .resolve_service_instance_by_name_any_status(auth.identity_id, &name)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("service '{name}' not found")))?;
    Ok(Json(row_to_detail(row)))
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

    // Determine if user-level or org-level
    let user_level = req.user_level.unwrap_or(auth.identity_id.is_some());
    let owner_identity_id = if user_level {
        Some(auth.identity_id.ok_or_else(|| {
            AppError::BadRequest("user-level services require an identity-bound API key".into())
        })?)
    } else {
        None
    };

    // Resolve the template to determine its source tier
    let (template_source, template_id) =
        resolve_template_source(&state, auth.org_id, auth.identity_id, &req.template_key).await?;

    // Validate status
    if !["draft", "active", "archived"].contains(&req.status.as_str()) {
        return Err(AppError::BadRequest(format!(
            "invalid status '{}'; must be draft, active, or archived",
            req.status
        )));
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

    Ok(Json(row_to_detail(row)))
}

/// Update a service instance by id.
async fn update_service(
    _: AdminAcl,
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

    let input = UpdateServiceInstance {
        name: req.name.as_deref(),
        connection_id: req.connection_id,
        secret_name: req.secret_name.as_ref().map(|o| o.as_deref()),
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
    let instance = if let Ok(uuid) = name.parse::<Uuid>() {
        scope
            .get_service_instance(uuid)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("service '{name}' not found")))?
    } else {
        scope
            .resolve_service_instance_by_name_any_status(auth.identity_id, &name)
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
    // Resolve the instance to get the template key (any status — dashboard
    // inspection of draft/archived must also work).
    let instance = scope
        .resolve_service_instance_by_name_any_status(auth.identity_id, &name)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("service '{name}' not found")))?;

    super::templates::resolve_template_actions(&state, &auth, &instance.template_key)
        .await
        .map(Json)
}

// -- Helpers --

fn row_to_summary(row: ServiceInstanceRow) -> ServiceInstanceSummary {
    ServiceInstanceSummary {
        id: row.id,
        name: row.name,
        template_source: row.template_source,
        template_key: row.template_key,
        status: row.status,
        owner_identity_id: row.owner_identity_id,
        connection_id: row.connection_id,
        secret_name: row.secret_name,
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
        status: row.status,
        is_system: row.is_system,
        created_at: row
            .created_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
        updated_at: row
            .updated_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
    }
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
