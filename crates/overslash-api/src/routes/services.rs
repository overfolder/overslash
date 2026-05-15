use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, patch, put},
};
use serde::Deserialize;
use uuid::Uuid;

use overslash_db::scopes::OrgScope;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, AuthContext, OrgAcl, WriteAcl},
    services::{
        group_ceiling,
        platform_caller::PlatformCallContext,
        platform_services::{
            self, CreateServiceInput, GetServiceInput, ServiceGroupRef, ServiceInstanceDetail,
            ServiceInstanceSummary, UpdateServiceInput,
        },
    },
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

// -- Request types --

#[derive(Deserialize)]
struct UpdateStatusRequest {
    status: String,
}

#[derive(Deserialize, Default)]
struct GetServiceQuery {
    /// When true, also resolve draft and archived instances. Used by the
    /// dashboard's detail view; execution callers leave this off so the
    /// active-only contract is preserved.
    #[serde(default)]
    include_inactive: bool,
}

#[derive(Deserialize, Default)]
struct ListServicesQuery {
    /// Admin-only: when true, return every service instance in the org
    /// (org-level + all users' user-level rows), bypassing the group ceiling.
    /// Silently ignored for non-admin callers so a stale dashboard tab does
    /// not start 403'ing when an admin flag is revoked.
    #[serde(default)]
    include_user_level: bool,
}

// -- Helpers --

/// Build a [`PlatformCallContext`] from the WriteAcl extractor for kernel calls.
fn ctx_from_acl(state: &AppState, acl: &OrgAcl) -> Result<PlatformCallContext> {
    let identity_id = acl.identity_id.ok_or_else(|| {
        AppError::Forbidden("identity-bound credential required for this operation".into())
    })?;
    Ok(PlatformCallContext {
        org_id: acl.org_id,
        // Always identity-bound at this entry point — the `?` above guarantees
        // it. Wrap with `Some` to match the kernel's `Option<Uuid>` shape.
        identity_id: Some(identity_id),
        access_level: acl.access_level,
        db: state.db.clone(),
        registry: state.registry.clone(),
        config: state.config.clone(),
        http_client: state.http_client.clone(),
    })
}

// -- Handlers --

async fn list_services(
    State(state): State<AppState>,
    auth: AuthContext,
    scope: OrgScope,
    Query(q): Query<ListServicesQuery>,
) -> Result<Json<Vec<ServiceInstanceSummary>>> {
    // Org-level API keys (no identity) bypass kernel and use a permissive
    // listing path — see the original implementation for why. Identity-bound
    // calls flow through `kernel_list_services` which enforces the group
    // ceiling so listings match call-time visibility.
    if auth.identity_id.is_none() {
        let rows = scope
            .list_available_service_instances_with_groups(None, None, None)
            .await?;
        let service_ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
        let grants = scope.list_groups_for_services(&service_ids).await?;
        let mut by_service: std::collections::HashMap<Uuid, Vec<ServiceGroupRef>> =
            std::collections::HashMap::new();
        for g in grants {
            by_service
                .entry(g.service_instance_id)
                .or_default()
                .push(g.into());
        }
        let mut summaries = Vec::with_capacity(rows.len());
        for row in rows {
            let groups = by_service.remove(&row.id).unwrap_or_default();
            let credentials_status = platform_services::compute_credentials_status(
                &state.db,
                &state.registry,
                &scope,
                &row,
                row.owner_identity_id,
            )
            .await;
            let mut summary = platform_services::row_to_summary(row, groups);
            summary.credentials_status = credentials_status;
            summaries.push(summary);
        }
        return Ok(Json(summaries));
    }

    let identity_id = auth.identity_id.unwrap();

    // Admin-only opt-in: when an org admin explicitly asks for the full org
    // view, skip the group-ceiling filter. We read `is_org_admin` directly
    // from the identity row instead of relying on `AdminAcl`, because
    // `AdminAcl` requires `AccessLevel::Admin` on the overslash service
    // grant — we want the flag-based admin check (same approach as the
    // dashboard secrets list, see `routes/secrets.rs`). Non-admins requesting
    // the flag get the standard ceiling-gated listing without an error so a
    // tab open across an admin-flag revocation does not start 403'ing.
    let admin_view_all = q.include_user_level
        && scope
            .get_identity(identity_id)
            .await?
            .map(|i| i.is_org_admin)
            .unwrap_or(false);

    let ctx = PlatformCallContext {
        org_id: auth.org_id,
        identity_id: auth.identity_id,
        access_level: overslash_core::permissions::AccessLevel::Read,
        db: state.db.clone(),
        registry: state.registry.clone(),
        config: state.config.clone(),
        http_client: state.http_client.clone(),
    };
    let summaries = platform_services::kernel_list_services(ctx, admin_view_all).await?;
    Ok(Json(summaries))
}

/// List the groups that grant access to a single service instance.
async fn list_service_groups(
    _: AuthContext,
    scope: OrgScope,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<ServiceGroupRef>>> {
    let instance = scope
        .get_service_instance(id)
        .await?
        .ok_or_else(|| AppError::NotFound("service instance not found".into()))?;
    let grants = scope.list_groups_for_service(instance.id).await?;
    Ok(Json(grants.into_iter().map(Into::into).collect()))
}

async fn get_service(
    State(state): State<AppState>,
    auth: AuthContext,
    scope: OrgScope,
    Path(name): Path<String>,
    Query(q): Query<GetServiceQuery>,
) -> Result<Json<ServiceInstanceDetail>> {
    // Org-level keys keep the legacy permissive lookup. Identity-bound calls
    // funnel through the kernel.
    let Some(identity_id) = auth.identity_id else {
        let row = if let Ok(uuid) = name.parse::<Uuid>() {
            scope.get_service_instance(uuid).await?
        } else if q.include_inactive {
            scope
                .resolve_service_instance_by_name_any_status(None, None, &name)
                .await?
        } else {
            scope
                .resolve_service_instance_by_name(None, None, &name)
                .await?
        }
        .ok_or_else(|| AppError::NotFound(format!("service '{name}' not found")))?;
        let credentials_status = platform_services::compute_credentials_status(
            &state.db,
            &state.registry,
            &scope,
            &row,
            row.owner_identity_id,
        )
        .await;
        let mut detail = platform_services::row_to_detail(row);
        detail.credentials_status = credentials_status;
        return Ok(Json(detail));
    };

    let ctx = PlatformCallContext {
        org_id: auth.org_id,
        // The early-return above already extracted `identity_id` from
        // `auth.identity_id`; the kernel signature wants the original
        // `Option<Uuid>` shape so wrap with `Some`.
        identity_id: Some(identity_id),
        access_level: overslash_core::permissions::AccessLevel::Read,
        db: state.db.clone(),
        registry: state.registry.clone(),
        config: state.config.clone(),
        http_client: state.http_client.clone(),
    };
    let detail = platform_services::kernel_get_service(
        ctx,
        GetServiceInput {
            name,
            include_inactive: q.include_inactive,
        },
    )
    .await?;
    Ok(Json(detail))
}

async fn create_service(
    State(state): State<AppState>,
    WriteAcl(acl): WriteAcl,
    Json(req): Json<CreateServiceInput>,
) -> Result<Json<ServiceInstanceDetail>> {
    let ctx = ctx_from_acl(&state, &acl)?;
    let detail = platform_services::kernel_create_service(ctx, req).await?;
    Ok(Json(detail))
}

async fn update_service(
    State(state): State<AppState>,
    AdminAcl(acl): AdminAcl,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateServiceInput>,
) -> Result<Json<ServiceInstanceDetail>> {
    let ctx = ctx_from_acl(&state, &acl)?;
    let detail = platform_services::kernel_update_service(ctx, id, req).await?;
    Ok(Json(detail))
}

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
    Ok(Json(platform_services::row_to_detail(row)))
}

/// Delete a service instance.
async fn delete_service(
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let auth = acl;
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
