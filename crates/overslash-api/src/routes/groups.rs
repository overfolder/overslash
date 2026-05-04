use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::util::fmt_time;

use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::group::GroupRow;
use overslash_db::scopes::OrgScope;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, ClientIp, OrgAcl},
};
use overslash_core::permissions::AccessLevel;

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
    /// `'everyone'`, `'admins'`, or `'self'` for system groups; `null` otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    system_kind: Option<String>,
    /// Set iff `system_kind == 'self'` — the user-identity this Myself group is for.
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_identity_id: Option<Uuid>,
    created_at: String,
    updated_at: String,
}

impl From<GroupRow> for GroupResponse {
    fn from(r: GroupRow) -> Self {
        Self {
            id: r.id,
            org_id: r.org_id,
            name: r.name,
            description: r.description,
            allow_raw_http: r.allow_raw_http,
            is_system: r.is_system,
            system_kind: r.system_kind,
            owner_identity_id: r.owner_identity_id,
            created_at: fmt_time(r.created_at),
            updated_at: fmt_time(r.updated_at),
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
    scope: OrgScope,
    ip: ClientIp,
    Json(req): Json<CreateGroupRequest>,
) -> Result<Json<GroupResponse>> {
    let auth = acl;
    let row = scope
        .create_group(&req.name, &req.description, req.allow_raw_http)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db_err)
                if db_err.constraint() == Some("groups_org_id_name_key") =>
            {
                AppError::Conflict(format!("group '{}' already exists", req.name))
            }
            _ => AppError::Database(e),
        })?;

    let _ = OrgScope::new(auth.org_id, state.db.clone())
        .log_audit(AuditEntry {
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
        })
        .await;

    Ok(Json(GroupResponse::from(row)))
}

#[derive(Deserialize)]
struct ListGroupsQuery {
    /// Include other users' Myself groups (`system_kind = 'self'`) in the listing.
    /// Default `false` because they'd flood an admin's group list with one row
    /// per user; the caller's own Myself is always included so a regular user
    /// can manage it from the Groups page.
    #[serde(default)]
    include_self: bool,
}

async fn list_groups(
    OrgAcl {
        identity_id: caller_identity,
        ..
    }: OrgAcl,
    scope: OrgScope,
    Query(q): Query<ListGroupsQuery>,
) -> Result<Json<Vec<GroupResponse>>> {
    let rows = scope.list_groups().await?;
    let filtered: Vec<_> = rows
        .into_iter()
        .filter(|r| {
            // Always show non-self groups. For self groups, always show the
            // caller's own Myself; show others' only when the caller opts in
            // via `?include_self=true` (admin audit view).
            r.system_kind.as_deref() != Some("self")
                || q.include_self
                || (caller_identity.is_some() && r.owner_identity_id == caller_identity)
        })
        .map(GroupResponse::from)
        .collect();
    Ok(Json(filtered))
}

async fn get_group(scope: OrgScope, Path(id): Path<Uuid>) -> Result<Json<GroupResponse>> {
    let row = scope
        .get_group(id)
        .await?
        .ok_or_else(|| AppError::NotFound("group not found".into()))?;
    Ok(Json(GroupResponse::from(row)))
}

async fn update_group(
    State(state): State<AppState>,
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateGroupRequest>,
) -> Result<Json<GroupResponse>> {
    let auth = acl;
    // Prevent renaming or modifying system groups (Everyone, Admins).
    // Renaming would break the new-user auto-join and last-admin protection
    // which look up groups by name.
    let existing = scope
        .get_group(id)
        .await?
        .ok_or_else(|| AppError::NotFound("group not found".into()))?;
    if existing.is_system {
        return Err(AppError::BadRequest("cannot modify system group".into()));
    }

    let row = scope
        .update_group(id, &req.name, &req.description, req.allow_raw_http)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db_err)
                if db_err.constraint() == Some("groups_org_id_name_key") =>
            {
                AppError::Conflict(format!("group '{}' already exists", req.name))
            }
            _ => AppError::Database(e),
        })?
        .ok_or_else(|| AppError::NotFound("group not found".into()))?;

    let _ = OrgScope::new(auth.org_id, state.db.clone())
        .log_audit(AuditEntry {
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
        })
        .await;

    Ok(Json(GroupResponse::from(row)))
}

async fn delete_group(
    State(state): State<AppState>,
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let auth = acl;
    // Prevent deletion of system groups (Everyone, Admins)
    let grp = scope
        .get_group(id)
        .await?
        .ok_or_else(|| AppError::NotFound("group not found".into()))?;
    if grp.is_system {
        return Err(AppError::BadRequest("cannot delete system group".into()));
    }

    let deleted = scope.delete_group(id).await?;

    if deleted {
        let _ = OrgScope::new(auth.org_id, state.db.clone())
            .log_audit(AuditEntry {
                org_id: auth.org_id,
                identity_id: auth.identity_id,
                action: "group.deleted",
                resource_type: Some("group"),
                resource_id: Some(id),
                detail: serde_json::json!({}),
                description: None,
                ip_address: ip.0.as_deref(),
            })
            .await;
    }

    Ok(Json(serde_json::json!({ "deleted": deleted })))
}

// ── Grant handlers ───────────────────────────────────────────────────

async fn add_grant(
    State(state): State<AppState>,
    OrgAcl {
        org_id: caller_org,
        identity_id: caller_identity,
        access_level: caller_level,
    }: OrgAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(group_id): Path<Uuid>,
    Json(req): Json<AddGrantRequest>,
) -> Result<Json<GroupGrantResponse>> {
    // Validate access_level
    if !matches!(req.access_level.as_str(), "read" | "write" | "admin") {
        return Err(AppError::BadRequest(format!(
            "invalid access_level '{}': must be read, write, or admin",
            req.access_level
        )));
    }

    // Verify group exists and belongs to org
    let group = scope
        .get_group(group_id)
        .await?
        .ok_or_else(|| AppError::NotFound("group not found".into()))?;

    // Authority gate: org admins can grant on any group; the owner of a Myself
    // group can manage their own. Everything else (regular org-level groups for
    // a non-admin) requires admin.
    //
    // Permission split (see docs/design/agent-self-management.md §1): granting a
    // service to a non-Myself group is the *social* half of service management
    // and lives under `manage_services_share`. Adding a grant on the caller's
    // own Myself group is the local half — `manage_services_own` (e.g. via the
    // auto-grant in `kernel_create_service`) is sufficient. An agent holding
    // only `overslash:manage_services_own:*` lands here without admin and is
    // refused — exactly the boundary the split exists to draw.
    let owner_managing_self =
        group.system_kind.as_deref() == Some("self") && group.owner_identity_id == caller_identity;
    if !owner_managing_self && caller_level < AccessLevel::Admin {
        return Err(AppError::Forbidden("admin access required".into()));
    }

    // Verify service instance exists and belongs to org.
    // Services owned by individual users are now grantable too — owner access
    // flows through Myself grants, and admins can layer additional groups on
    // top to share a personal service org-wide.
    let svc = scope
        .get_service_instance(req.service_instance_id)
        .await?
        .ok_or_else(|| AppError::NotFound("service instance not found".into()))?;

    // Self-group guard: a `system_kind = 'self'` group can only carry grants
    // for services owned by its target user. Without this, an admin could
    // smuggle alice's service into bob's Myself group, giving bob silent
    // access via his own permission surface.
    if group.system_kind.as_deref() == Some("self")
        && svc.owner_identity_id != group.owner_identity_id
    {
        return Err(AppError::BadRequest(
            "Myself groups can only grant their owner's services".into(),
        ));
    }

    let grant_row = scope
        .add_group_grant(
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
        })?
        .ok_or_else(|| AppError::NotFound("group not found".into()))?;

    let _ = OrgScope::new(caller_org, state.db.clone())
        .log_audit(AuditEntry {
            org_id: caller_org,
            identity_id: caller_identity,
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
        })
        .await;

    Ok(Json(GroupGrantResponse {
        id: grant_row.id,
        group_id: grant_row.group_id,
        service_instance_id: grant_row.service_instance_id,
        service_name: svc.name,
        access_level: grant_row.access_level,
        auto_approve_reads: grant_row.auto_approve_reads,
        created_at: fmt_time(grant_row.created_at),
    }))
}

async fn list_grants(
    scope: OrgScope,
    Path(group_id): Path<Uuid>,
) -> Result<Json<Vec<GroupGrantResponse>>> {
    // Verify group belongs to org (returns None at the SQL boundary otherwise)
    scope
        .get_group(group_id)
        .await?
        .ok_or_else(|| AppError::NotFound("group not found".into()))?;

    let rows = scope.list_group_grants(group_id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| GroupGrantResponse {
                id: r.id,
                group_id: r.group_id,
                service_instance_id: r.service_instance_id,
                service_name: r.service_name,
                access_level: r.access_level,
                auto_approve_reads: r.auto_approve_reads,
                created_at: fmt_time(r.created_at),
            })
            .collect(),
    ))
}

async fn remove_grant(
    State(state): State<AppState>,
    OrgAcl {
        org_id: caller_org,
        identity_id: caller_identity,
        access_level: caller_level,
    }: OrgAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path((group_id, grant_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<serde_json::Value>> {
    // Verify group belongs to org
    let grp = scope
        .get_group(group_id)
        .await?
        .ok_or_else(|| AppError::NotFound("group not found".into()))?;

    // Authority gate: owner can manage their own Myself; org admins can
    // manage any non-self group. Everyone/Admins remain locked because removing
    // their grants would break org ACL enforcement.
    let owner_managing_self =
        grp.system_kind.as_deref() == Some("self") && grp.owner_identity_id == caller_identity;
    if owner_managing_self {
        // Owner-managed Myself group: allow.
    } else if grp.system_kind.as_deref() == Some("everyone")
        || grp.system_kind.as_deref() == Some("admins")
    {
        return Err(AppError::BadRequest(
            "cannot remove grants from system groups".into(),
        ));
    } else if caller_level < AccessLevel::Admin {
        return Err(AppError::Forbidden("admin access required".into()));
    }

    let deleted = scope.remove_group_grant(grant_id, group_id).await?;

    if deleted {
        let _ = OrgScope::new(caller_org, state.db.clone())
            .log_audit(AuditEntry {
                org_id: caller_org,
                identity_id: caller_identity,
                action: "group_grant.deleted",
                resource_type: Some("group_grant"),
                resource_id: Some(grant_id),
                detail: serde_json::json!({ "group_id": group_id }),
                description: None,
                ip_address: ip.0.as_deref(),
            })
            .await;
    }

    Ok(Json(serde_json::json!({ "deleted": deleted })))
}

// ── Member handlers ──────────────────────────────────────────────────

async fn assign_identity(
    State(state): State<AppState>,
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(group_id): Path<Uuid>,
    Json(req): Json<AssignIdentityRequest>,
) -> Result<Json<MemberResponse>> {
    let auth = acl;
    // Verify group belongs to org
    let grp = scope
        .get_group(group_id)
        .await?
        .ok_or_else(|| AppError::NotFound("group not found".into()))?;

    // Verify identity exists, belongs to org, and is a user
    let identity = scope
        .get_identity(req.identity_id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
    if identity.kind != "user" {
        return Err(AppError::BadRequest(
            "only users can be assigned to groups (agents inherit via owner)".into(),
        ));
    }

    // Self-group guard (mirror of the cross-owner check in `add_grant`):
    // a `system_kind = 'self'` group can only have its owner as a member.
    // Without this, an admin could add bob to alice's Myself group, and
    // since the ceiling query unions grants across all the user's groups,
    // bob would silently inherit every grant alice has via Myself —
    // including admin + auto_approve_reads on every service alice owns.
    if grp.system_kind.as_deref() == Some("self") && grp.owner_identity_id != Some(req.identity_id)
    {
        return Err(AppError::BadRequest(
            "Myself groups can only contain their owner".into(),
        ));
    }

    let row = scope
        .assign_identity_to_group(req.identity_id, group_id)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db_err)
                if db_err.constraint() == Some("identity_groups_pkey") =>
            {
                AppError::Conflict("identity already assigned to this group".into())
            }
            _ => AppError::Database(e),
        })?
        .ok_or_else(|| AppError::NotFound("group not found".into()))?;

    let _ = OrgScope::new(auth.org_id, state.db.clone())
        .log_audit(AuditEntry {
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
        })
        .await;

    Ok(Json(MemberResponse {
        identity_id: row.identity_id,
        group_id: row.group_id,
        assigned_at: fmt_time(row.assigned_at),
    }))
}

async fn list_members(scope: OrgScope, Path(group_id): Path<Uuid>) -> Result<Json<Vec<Uuid>>> {
    // Verify group belongs to org
    scope
        .get_group(group_id)
        .await?
        .ok_or_else(|| AppError::NotFound("group not found".into()))?;

    let ids = scope.list_identity_ids_in_group(group_id).await?;
    Ok(Json(ids))
}

async fn unassign_identity(
    State(state): State<AppState>,
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path((group_id, identity_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<serde_json::Value>> {
    let auth = acl;
    // Verify group belongs to org
    let grp = scope
        .get_group(group_id)
        .await?
        .ok_or_else(|| AppError::NotFound("group not found".into()))?;

    // Prevent removing the last member from the Admins system group.
    // Keyed on `system_kind` rather than the brittle `name == "Admins"`
    // literal that the rest of this PR migrated away from.
    if grp.system_kind.as_deref() == Some("admins") {
        let count = scope.count_members_in_group(group_id).await?;
        if count <= 1 {
            return Err(AppError::BadRequest(
                "cannot remove the last member from the Admins group".into(),
            ));
        }
    }

    // A Myself group always has exactly one member: its owner. Removing
    // that member would silently sever every grant the owner has on their
    // own services until someone re-adds them — pure availability vector,
    // no good reason to allow it. The owner can adjust their grants via
    // `/v1/groups/{self_id}/grants` if they need to revoke access.
    if grp.system_kind.as_deref() == Some("self") && grp.owner_identity_id == Some(identity_id) {
        return Err(AppError::BadRequest(
            "cannot remove a user from their own Myself group".into(),
        ));
    }

    let deleted = scope
        .unassign_identity_from_group(identity_id, group_id)
        .await?;

    if deleted {
        let _ = OrgScope::new(auth.org_id, state.db.clone())
            .log_audit(AuditEntry {
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
            })
            .await;
    }

    Ok(Json(serde_json::json!({ "deleted": deleted })))
}
