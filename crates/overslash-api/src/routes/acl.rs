use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{delete, get, put},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_core::types::acl::{AclAction, AclResourceType};
use overslash_db::repos::audit::{self, AuditEntry};

use crate::{
    AppState,
    acl::require_permission,
    error::{AppError, Result},
    extractors::{AuthContext, ClientIp},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/acl/roles", get(list_roles).post(create_role))
        .route(
            "/v1/acl/roles/{id}",
            get(get_role).put(update_role).delete(delete_role),
        )
        .route("/v1/acl/roles/{id}/grants", put(set_grants))
        .route(
            "/v1/acl/assignments",
            get(list_assignments).post(create_assignment),
        )
        .route("/v1/acl/assignments/{id}", delete(revoke_assignment))
        .route("/v1/acl/me", get(my_permissions))
        .route("/v1/acl/status", get(acl_status))
}

// --- Response types ---

#[derive(Serialize)]
struct RoleResponse {
    id: Uuid,
    org_id: Uuid,
    name: String,
    slug: String,
    description: String,
    is_builtin: bool,
    grants: Option<Vec<GrantResponse>>,
    created_at: String,
    updated_at: String,
}

#[derive(Serialize)]
struct GrantResponse {
    id: Uuid,
    resource_type: String,
    action: String,
}

#[derive(Serialize)]
struct AssignmentResponse {
    id: Uuid,
    org_id: Uuid,
    identity_id: Uuid,
    role_id: Uuid,
    assigned_by: Option<Uuid>,
    created_at: String,
}

#[derive(Serialize)]
struct PermissionsResponse {
    identity_id: Uuid,
    permissions: Vec<PermissionEntry>,
    is_admin: bool,
}

#[derive(Serialize)]
struct PermissionEntry {
    resource_type: String,
    action: String,
}

#[derive(Serialize)]
struct AclStatusResponse {
    has_admin: bool,
    admin_count: usize,
    admin_identities: Vec<AdminInfo>,
}

#[derive(Serialize)]
struct AdminInfo {
    identity_id: Uuid,
}

// --- Request types ---

#[derive(Deserialize)]
struct CreateRoleRequest {
    name: String,
    slug: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize)]
struct UpdateRoleRequest {
    name: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize)]
struct SetGrantsRequest {
    grants: Vec<GrantInput>,
}

#[derive(Deserialize)]
struct GrantInput {
    resource_type: String,
    action: String,
}

#[derive(Deserialize)]
struct CreateAssignmentRequest {
    identity_id: Uuid,
    role_id: Uuid,
}

// --- Handlers ---

async fn list_roles(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<Vec<RoleResponse>>> {
    require_permission(&state.db, auth.identity_id, AclResourceType::Acl, AclAction::Read).await?;

    let roles = overslash_db::repos::acl::list_roles_by_org(&state.db, auth.org_id).await?;
    Ok(Json(
        roles
            .into_iter()
            .map(|r| RoleResponse {
                id: r.id,
                org_id: r.org_id,
                name: r.name,
                slug: r.slug,
                description: r.description,
                is_builtin: r.is_builtin,
                grants: None,
                created_at: r.created_at.to_string(),
                updated_at: r.updated_at.to_string(),
            })
            .collect(),
    ))
}

async fn create_role(
    State(state): State<AppState>,
    auth: AuthContext,
    ip: ClientIp,
    Json(req): Json<CreateRoleRequest>,
) -> Result<Json<RoleResponse>> {
    require_permission(&state.db, auth.identity_id, AclResourceType::Acl, AclAction::Manage).await?;

    let role = overslash_db::repos::acl::create_role(
        &state.db,
        auth.org_id,
        &req.name,
        &req.slug,
        &req.description,
        false,
    )
    .await?;

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "acl_role.created",
            resource_type: Some("acl_role"),
            resource_id: Some(role.id),
            detail: serde_json::json!({ "name": &role.name, "slug": &role.slug }),
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(Json(RoleResponse {
        id: role.id,
        org_id: role.org_id,
        name: role.name,
        slug: role.slug,
        description: role.description,
        is_builtin: role.is_builtin,
        grants: None,
        created_at: role.created_at.to_string(),
        updated_at: role.updated_at.to_string(),
    }))
}

async fn get_role(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<RoleResponse>> {
    require_permission(&state.db, auth.identity_id, AclResourceType::Acl, AclAction::Read).await?;

    let role = overslash_db::repos::acl::get_role(&state.db, id, auth.org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("role not found".into()))?;

    let grants = overslash_db::repos::acl::list_grants_by_role(&state.db, id).await?;

    Ok(Json(RoleResponse {
        id: role.id,
        org_id: role.org_id,
        name: role.name,
        slug: role.slug,
        description: role.description,
        is_builtin: role.is_builtin,
        grants: Some(
            grants
                .into_iter()
                .map(|g| GrantResponse {
                    id: g.id,
                    resource_type: g.resource_type,
                    action: g.action,
                })
                .collect(),
        ),
        created_at: role.created_at.to_string(),
        updated_at: role.updated_at.to_string(),
    }))
}

async fn update_role(
    State(state): State<AppState>,
    auth: AuthContext,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateRoleRequest>,
) -> Result<Json<RoleResponse>> {
    require_permission(&state.db, auth.identity_id, AclResourceType::Acl, AclAction::Manage).await?;

    let role = overslash_db::repos::acl::update_role(
        &state.db,
        id,
        auth.org_id,
        &req.name,
        &req.description,
    )
    .await?
    .ok_or_else(|| {
        AppError::BadRequest("role not found or is built-in".into())
    })?;

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "acl_role.updated",
            resource_type: Some("acl_role"),
            resource_id: Some(role.id),
            detail: serde_json::json!({ "name": &role.name }),
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(Json(RoleResponse {
        id: role.id,
        org_id: role.org_id,
        name: role.name,
        slug: role.slug,
        description: role.description,
        is_builtin: role.is_builtin,
        grants: None,
        created_at: role.created_at.to_string(),
        updated_at: role.updated_at.to_string(),
    }))
}

async fn delete_role(
    State(state): State<AppState>,
    auth: AuthContext,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    require_permission(&state.db, auth.identity_id, AclResourceType::Acl, AclAction::Manage).await?;

    let deleted = overslash_db::repos::acl::delete_role(&state.db, id, auth.org_id).await?;

    if !deleted {
        return Err(AppError::BadRequest(
            "role not found or is built-in".into(),
        ));
    }

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "acl_role.deleted",
            resource_type: Some("acl_role"),
            resource_id: Some(id),
            detail: serde_json::json!({}),
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(Json(serde_json::json!({ "deleted": true })))
}

async fn set_grants(
    State(state): State<AppState>,
    auth: AuthContext,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<SetGrantsRequest>,
) -> Result<Json<Vec<GrantResponse>>> {
    require_permission(&state.db, auth.identity_id, AclResourceType::Acl, AclAction::Manage).await?;

    // Verify role exists and belongs to org
    let role = overslash_db::repos::acl::get_role(&state.db, id, auth.org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("role not found".into()))?;

    if role.is_builtin {
        return Err(AppError::BadRequest(
            "cannot modify grants on built-in roles".into(),
        ));
    }

    // Validate grant inputs
    for g in &req.grants {
        g.resource_type
            .parse::<AclResourceType>()
            .map_err(|e| AppError::BadRequest(e))?;
        g.action
            .parse::<AclAction>()
            .map_err(|e| AppError::BadRequest(e))?;
    }

    let grant_pairs: Vec<(String, String)> = req
        .grants
        .into_iter()
        .map(|g| (g.resource_type, g.action))
        .collect();

    let grants = overslash_db::repos::acl::set_grants(&state.db, id, &grant_pairs).await?;

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "acl_role.grants_updated",
            resource_type: Some("acl_role"),
            resource_id: Some(id),
            detail: serde_json::json!({ "grant_count": grants.len() }),
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(Json(
        grants
            .into_iter()
            .map(|g| GrantResponse {
                id: g.id,
                resource_type: g.resource_type,
                action: g.action,
            })
            .collect(),
    ))
}

async fn list_assignments(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<Vec<AssignmentResponse>>> {
    require_permission(&state.db, auth.identity_id, AclResourceType::Acl, AclAction::Read).await?;

    let assignments =
        overslash_db::repos::acl::list_assignments_by_org(&state.db, auth.org_id).await?;
    Ok(Json(
        assignments
            .into_iter()
            .map(|a| AssignmentResponse {
                id: a.id,
                org_id: a.org_id,
                identity_id: a.identity_id,
                role_id: a.role_id,
                assigned_by: a.assigned_by,
                created_at: a.created_at.to_string(),
            })
            .collect(),
    ))
}

async fn create_assignment(
    State(state): State<AppState>,
    auth: AuthContext,
    ip: ClientIp,
    Json(req): Json<CreateAssignmentRequest>,
) -> Result<Json<AssignmentResponse>> {
    require_permission(&state.db, auth.identity_id, AclResourceType::Acl, AclAction::Manage).await?;

    // Verify role belongs to this org
    overslash_db::repos::acl::get_role(&state.db, req.role_id, auth.org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("role not found".into()))?;

    let assignment = overslash_db::repos::acl::assign_role(
        &state.db,
        auth.org_id,
        req.identity_id,
        req.role_id,
        auth.identity_id,
    )
    .await?;

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "acl_assignment.created",
            resource_type: Some("acl_assignment"),
            resource_id: Some(assignment.id),
            detail: serde_json::json!({
                "target_identity_id": req.identity_id,
                "role_id": req.role_id,
            }),
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(Json(AssignmentResponse {
        id: assignment.id,
        org_id: assignment.org_id,
        identity_id: assignment.identity_id,
        role_id: assignment.role_id,
        assigned_by: assignment.assigned_by,
        created_at: assignment.created_at.to_string(),
    }))
}

async fn revoke_assignment(
    State(state): State<AppState>,
    auth: AuthContext,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    require_permission(&state.db, auth.identity_id, AclResourceType::Acl, AclAction::Manage).await?;

    let deleted =
        overslash_db::repos::acl::revoke_assignment(&state.db, id, auth.org_id).await?;

    if deleted {
        let _ = audit::log(
            &state.db,
            &AuditEntry {
                org_id: auth.org_id,
                identity_id: auth.identity_id,
                action: "acl_assignment.revoked",
                resource_type: Some("acl_assignment"),
                resource_id: Some(id),
                detail: serde_json::json!({}),
                ip_address: ip.0.as_deref(),
            },
        )
        .await;
    }

    Ok(Json(serde_json::json!({ "deleted": deleted })))
}

async fn my_permissions(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<PermissionsResponse>> {
    let identity_id = auth
        .identity_id
        .ok_or_else(|| AppError::BadRequest("no identity on this key".into()))?;

    let permissions =
        overslash_db::repos::acl::effective_permissions(&state.db, identity_id).await?;

    let is_admin = overslash_db::repos::acl::is_org_admin(&state.db, identity_id).await?;

    Ok(Json(PermissionsResponse {
        identity_id,
        permissions: permissions
            .into_iter()
            .map(|(rt, action)| PermissionEntry {
                resource_type: rt,
                action,
            })
            .collect(),
        is_admin,
    }))
}

async fn acl_status(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<AclStatusResponse>> {
    require_permission(&state.db, auth.identity_id, AclResourceType::Acl, AclAction::Read).await?;

    let has_admin = overslash_db::repos::acl::has_any_admin(&state.db, auth.org_id).await?;

    // Get all admin identity IDs
    let assignments =
        overslash_db::repos::acl::list_assignments_by_org(&state.db, auth.org_id).await?;
    let roles = overslash_db::repos::acl::list_roles_by_org(&state.db, auth.org_id).await?;
    let admin_role_id = roles.iter().find(|r| r.slug == "org-admin").map(|r| r.id);

    let admin_identities: Vec<AdminInfo> = if let Some(admin_role_id) = admin_role_id {
        assignments
            .iter()
            .filter(|a| a.role_id == admin_role_id)
            .map(|a| AdminInfo {
                identity_id: a.identity_id,
            })
            .collect()
    } else {
        Vec::new()
    };

    Ok(Json(AclStatusResponse {
        has_admin,
        admin_count: admin_identities.len(),
        admin_identities,
    }))
}
