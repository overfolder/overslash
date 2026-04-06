use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::repos::audit::{self, AuditEntry};
use overslash_db::repos::group;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, AuthContext, ClientIp},
    ownership::require_org_owned,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/groups", post(create_group).get(list_groups))
        .route(
            "/v1/groups/{id}",
            get(get_group).put(update_group).delete(delete_group),
        )
        .route("/v1/groups/{id}/grants", post(add_grant).get(list_grants))
        .route("/v1/groups/{id}/grants/{grant_id}", delete(remove_grant))
        .route(
            "/v1/groups/{id}/members",
            post(assign_identity).get(list_members),
        )
        .route(
            "/v1/groups/{id}/members/{identity_id}",
            delete(unassign_identity),
        )
}

// ── Request types ────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CreateGroupRequest {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    allow_raw_http: bool,
}

#[derive(Deserialize)]
struct UpdateGroupRequest {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    allow_raw_http: bool,
}

#[derive(Deserialize)]
struct AddGrantRequest {
    service_instance_id: Uuid,
    access_level: String,
    #[serde(default)]
    auto_approve_reads: bool,
}

#[derive(Deserialize)]
struct AssignIdentityRequest {
    identity_id: Uuid,
}

// ── Response types ───────────────────────────────────────────────────

#[derive(Serialize)]
struct GroupResponse {
    id: Uuid,
    org_id: Uuid,
    name: String,
    description: String,
    allow_raw_http: bool,
    is_system: bool,
    created_at: String,
    updated_at: String,
}

impl From<group::GroupRow> for GroupResponse {
    fn from(r: group::GroupRow) -> Self {
        Self {
            id: r.id,
            org_id: r.org_id,
            name: r.name,
            description: r.description,
            allow_raw_http: r.allow_raw_http,
            is_system: r.is_system,
            created_at: r.created_at.to_string(),
            updated_at: r.updated_at.to_string(),
        }
    }
}

#[derive(Serialize)]
struct GroupGrantResponse {
    id: Uuid,
    group_id: Uuid,
    service_instance_id: Uuid,
    service_name: String,
    access_level: String,
    auto_approve_reads: bool,
    created_at: String,
}

#[derive(Serialize)]
struct MemberResponse {
    identity_id: Uuid,
    group_id: Uuid,
    assigned_at: String,
}

// ── Handlers ─────────────────────────────────────────────────────────

async fn create_group(
    State(state): State<AppState>,
    AdminAcl(acl): AdminAcl,
    ip: ClientIp,
    Json(req): Json<CreateGroupRequest>,
) -> Result<Json<GroupResponse>> {
    let auth = acl;
    let row = group::create(
        &state.db,
        auth.org_id,
        &req.name,
        &req.description,
        req.allow_raw_http,
    )
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db_err) if db_err.constraint() == Some("groups_org_id_name_key") => {
            AppError::Conflict(format!("group '{}' already exists", req.name))
        }
        _ => AppError::Database(e),
    })?;

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "group.created",
            resource_type: Some("group"),
            resource_id: Some(row.id),
            detail: serde_json::json!({
                "name": &row.name,
                "allow_raw_http": row.allow_raw_http,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(Json(GroupResponse::from(row)))
}

async fn list_groups(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<Vec<GroupResponse>>> {
    let rows = group::list_by_org(&state.db, auth.org_id).await?;
    Ok(Json(rows.into_iter().map(GroupResponse::from).collect()))
}

async fn get_group(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<GroupResponse>> {
    let row = require_org_owned(group::get_by_id(&state.db, id).await?, auth.org_id, "group")?;
    Ok(Json(GroupResponse::from(row)))
}

async fn update_group(
    State(state): State<AppState>,
    AdminAcl(acl): AdminAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateGroupRequest>,
) -> Result<Json<GroupResponse>> {
    let auth = acl;
    // Prevent renaming or modifying system groups (Everyone, Admins).
    // Renaming would break the new-user auto-join and last-admin protection
    // which look up groups by name.
    let existing = require_org_owned(group::get_by_id(&state.db, id).await?, auth.org_id, "group")?;
    if existing.is_system {
        return Err(AppError::BadRequest("cannot modify system group".into()));
    }

    let row = group::update(
        &state.db,
        id,
        auth.org_id,
        &req.name,
        &req.description,
        req.allow_raw_http,
    )
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db_err) if db_err.constraint() == Some("groups_org_id_name_key") => {
            AppError::Conflict(format!("group '{}' already exists", req.name))
        }
        _ => AppError::Database(e),
    })?
    .ok_or_else(|| AppError::NotFound("group not found".into()))?;

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "group.updated",
            resource_type: Some("group"),
            resource_id: Some(row.id),
            detail: serde_json::json!({
                "name": &row.name,
                "allow_raw_http": row.allow_raw_http,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(Json(GroupResponse::from(row)))
}

async fn delete_group(
    State(state): State<AppState>,
    AdminAcl(acl): AdminAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let auth = acl;
    // Prevent deletion of system groups (Everyone, Admins)
    let grp = require_org_owned(group::get_by_id(&state.db, id).await?, auth.org_id, "group")?;
    if grp.is_system {
        return Err(AppError::BadRequest("cannot delete system group".into()));
    }

    let deleted = group::delete(&state.db, id, auth.org_id).await?;

    if deleted {
        let _ = audit::log(
            &state.db,
            &AuditEntry {
                org_id: auth.org_id,
                identity_id: auth.identity_id,
                action: "group.deleted",
                resource_type: Some("group"),
                resource_id: Some(id),
                detail: serde_json::json!({}),
                description: None,
                ip_address: ip.0.as_deref(),
            },
        )
        .await;
    }

    Ok(Json(serde_json::json!({ "deleted": deleted })))
}

// ── Grant handlers ───────────────────────────────────────────────────

async fn add_grant(
    State(state): State<AppState>,
    AdminAcl(acl): AdminAcl,
    ip: ClientIp,
    Path(group_id): Path<Uuid>,
    Json(req): Json<AddGrantRequest>,
) -> Result<Json<GroupGrantResponse>> {
    let auth = acl;
    // Validate access_level
    if !matches!(req.access_level.as_str(), "read" | "write" | "admin") {
        return Err(AppError::BadRequest(format!(
            "invalid access_level '{}': must be read, write, or admin",
            req.access_level
        )));
    }

    // Verify group exists and belongs to org
    require_org_owned(
        group::get_by_id(&state.db, group_id).await?,
        auth.org_id,
        "group",
    )?;

    // Verify service instance exists, belongs to org, and is org-level
    let svc = overslash_db::repos::service_instance::get_by_id(&state.db, req.service_instance_id)
        .await?
        .ok_or_else(|| AppError::NotFound("service instance not found".into()))?;
    if svc.org_id != auth.org_id {
        return Err(AppError::NotFound("service instance not found".into()));
    }
    if svc.owner_identity_id.is_some() {
        return Err(AppError::BadRequest(
            "only org-level service instances can be granted to groups".into(),
        ));
    }

    let grant_row = group::add_grant(
        &state.db,
        group_id,
        req.service_instance_id,
        &req.access_level,
        req.auto_approve_reads,
    )
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db_err)
            if db_err.constraint() == Some("group_grants_group_id_service_instance_id_key") =>
        {
            AppError::Conflict("service already granted to this group".into())
        }
        _ => AppError::Database(e),
    })?;

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "group_grant.created",
            resource_type: Some("group_grant"),
            resource_id: Some(grant_row.id),
            detail: serde_json::json!({
                "group_id": group_id,
                "service_instance_id": req.service_instance_id,
                "service_name": &svc.name,
                "access_level": &req.access_level,
                "auto_approve_reads": req.auto_approve_reads,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(Json(GroupGrantResponse {
        id: grant_row.id,
        group_id: grant_row.group_id,
        service_instance_id: grant_row.service_instance_id,
        service_name: svc.name,
        access_level: grant_row.access_level,
        auto_approve_reads: grant_row.auto_approve_reads,
        created_at: grant_row.created_at.to_string(),
    }))
}

async fn list_grants(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(group_id): Path<Uuid>,
) -> Result<Json<Vec<GroupGrantResponse>>> {
    // Verify group belongs to org
    require_org_owned(
        group::get_by_id(&state.db, group_id).await?,
        auth.org_id,
        "group",
    )?;

    let rows = group::list_grants(&state.db, group_id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| GroupGrantResponse {
                id: r.id,
                group_id: r.group_id,
                service_instance_id: r.service_instance_id,
                service_name: r.service_name,
                access_level: r.access_level,
                auto_approve_reads: r.auto_approve_reads,
                created_at: r.created_at.to_string(),
            })
            .collect(),
    ))
}

async fn remove_grant(
    State(state): State<AppState>,
    AdminAcl(acl): AdminAcl,
    ip: ClientIp,
    Path((group_id, grant_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<serde_json::Value>> {
    let auth = acl;
    // Verify group belongs to org
    let grp = require_org_owned(
        group::get_by_id(&state.db, group_id).await?,
        auth.org_id,
        "group",
    )?;

    // Prevent removing grants from system groups — would break ACL enforcement
    // (e.g., removing the Admins → overslash grant locks out all admins)
    if grp.is_system {
        return Err(AppError::BadRequest(
            "cannot remove grants from system groups".into(),
        ));
    }

    let deleted = group::remove_grant(&state.db, grant_id, group_id).await?;

    if deleted {
        let _ = audit::log(
            &state.db,
            &AuditEntry {
                org_id: auth.org_id,
                identity_id: auth.identity_id,
                action: "group_grant.deleted",
                resource_type: Some("group_grant"),
                resource_id: Some(grant_id),
                detail: serde_json::json!({ "group_id": group_id }),
                description: None,
                ip_address: ip.0.as_deref(),
            },
        )
        .await;
    }

    Ok(Json(serde_json::json!({ "deleted": deleted })))
}

// ── Member handlers ──────────────────────────────────────────────────

async fn assign_identity(
    State(state): State<AppState>,
    AdminAcl(acl): AdminAcl,
    ip: ClientIp,
    Path(group_id): Path<Uuid>,
    Json(req): Json<AssignIdentityRequest>,
) -> Result<Json<MemberResponse>> {
    let auth = acl;
    // Verify group belongs to org
    let grp = require_org_owned(
        group::get_by_id(&state.db, group_id).await?,
        auth.org_id,
        "group",
    )?;

    // Verify identity exists, belongs to org, and is a user
    let identity = require_org_owned(
        overslash_db::repos::identity::get_by_id(&state.db, req.identity_id).await?,
        auth.org_id,
        "identity",
    )?;
    if identity.kind != "user" {
        return Err(AppError::BadRequest(
            "only users can be assigned to groups (agents inherit via owner)".into(),
        ));
    }

    let row = group::assign_identity(&state.db, req.identity_id, group_id)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db_err)
                if db_err.constraint() == Some("identity_groups_pkey") =>
            {
                AppError::Conflict("identity already assigned to this group".into())
            }
            _ => AppError::Database(e),
        })?;

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "identity_group.assigned",
            resource_type: Some("identity_group"),
            resource_id: None,
            detail: serde_json::json!({
                "identity_id": req.identity_id,
                "group_id": group_id,
                "identity_name": &identity.name,
                "group_name": &grp.name,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(Json(MemberResponse {
        identity_id: row.identity_id,
        group_id: row.group_id,
        assigned_at: row.assigned_at.to_string(),
    }))
}

async fn list_members(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(group_id): Path<Uuid>,
) -> Result<Json<Vec<Uuid>>> {
    // Verify group belongs to org
    require_org_owned(
        group::get_by_id(&state.db, group_id).await?,
        auth.org_id,
        "group",
    )?;

    let ids = group::list_identity_ids_in_group(&state.db, group_id).await?;
    Ok(Json(ids))
}

async fn unassign_identity(
    State(state): State<AppState>,
    AdminAcl(acl): AdminAcl,
    ip: ClientIp,
    Path((group_id, identity_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<serde_json::Value>> {
    let auth = acl;
    // Verify group belongs to org
    let grp = require_org_owned(
        group::get_by_id(&state.db, group_id).await?,
        auth.org_id,
        "group",
    )?;

    // Prevent removing the last member from the Admins system group
    if grp.is_system && grp.name == "Admins" {
        let count = group::count_members_in_group(&state.db, group_id).await?;
        if count <= 1 {
            return Err(AppError::BadRequest(
                "cannot remove the last member from the Admins group".into(),
            ));
        }
    }

    let deleted = group::unassign_identity(&state.db, identity_id, group_id).await?;

    if deleted {
        let _ = audit::log(
            &state.db,
            &AuditEntry {
                org_id: auth.org_id,
                identity_id: auth.identity_id,
                action: "identity_group.unassigned",
                resource_type: Some("identity_group"),
                resource_id: None,
                detail: serde_json::json!({
                    "identity_id": identity_id,
                    "group_id": group_id,
                }),
                description: None,
                ip_address: ip.0.as_deref(),
            },
        )
        .await;
    }

    Ok(Json(serde_json::json!({ "deleted": deleted })))
}
