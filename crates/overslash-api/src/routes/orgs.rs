use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, patch, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::repos::audit::AuditEntry;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, AuthContext, ClientIp},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/orgs", post(create_org))
        .route("/v1/orgs/{id}", get(get_org).patch(patch_org))
        .route(
            "/v1/orgs/{id}/subagent-cleanup-config",
            patch(patch_subagent_cleanup_config),
        )
}

// Bounds for sub-agent idle cleanup config (per replan).
// Floor: 4h. Ceiling: 60d.
const MIN_IDLE_TIMEOUT_SECS: i32 = 4 * 60 * 60; // 14_400
const MAX_IDLE_TIMEOUT_SECS: i32 = 60 * 24 * 60 * 60; // 5_184_000
const MIN_RETENTION_DAYS: i32 = 1;
const MAX_RETENTION_DAYS: i32 = 60;

#[derive(Deserialize)]
struct CreateOrgRequest {
    name: String,
    slug: String,
}

#[derive(Serialize)]
struct OrgResponse {
    id: Uuid,
    name: String,
    slug: String,
    subagent_idle_timeout_secs: i32,
    subagent_archive_retention_days: i32,
}

impl From<overslash_db::repos::org::OrgRow> for OrgResponse {
    fn from(o: overslash_db::repos::org::OrgRow) -> Self {
        Self {
            id: o.id,
            name: o.name,
            slug: o.slug,
            subagent_idle_timeout_secs: o.subagent_idle_timeout_secs,
            subagent_archive_retention_days: o.subagent_archive_retention_days,
        }
    }
}

async fn create_org(
    State(state): State<AppState>,
    ip: ClientIp,
    Json(req): Json<CreateOrgRequest>,
) -> Result<Json<OrgResponse>> {
    let org = overslash_db::repos::org::create(&state.db, &req.name, &req.slug).await?;

    // Bootstrap system assets: overslash service, Everyone + Admins groups, grants
    overslash_db::repos::org_bootstrap::bootstrap_org(&state.db, org.id, None).await?;

    // No auth context (org creation is the bootstrap entrypoint) — mint an
    // OrgScope for the freshly created org so the audit row is written under
    // it, rather than going through the repo directly.
    let bootstrap_scope = overslash_db::OrgScope::new(org.id, state.db.clone());
    let _ = bootstrap_scope
        .log_audit(AuditEntry {
            org_id: org.id,
            identity_id: None,
            action: "org.created",
            resource_type: Some("org"),
            resource_id: Some(org.id),
            detail: serde_json::json!({ "name": &org.name, "slug": &org.slug }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(org.into()))
}

async fn get_org(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<OrgResponse>> {
    if id != auth.org_id {
        return Err(AppError::Forbidden("cannot read another org".into()));
    }
    let org = overslash_db::repos::org::get_by_id(&state.db, id)
        .await?
        .ok_or_else(|| AppError::NotFound("org not found".into()))?;
    Ok(Json(org.into()))
}

#[derive(Deserialize)]
struct PatchOrgRequest {
    // Reserved for future use; currently no top-level org fields are mutable here.
    // Sub-agent cleanup config is mutated via its own endpoint for clarity.
}

async fn patch_org(
    State(_state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(_req): Json<PatchOrgRequest>,
) -> Result<Json<OrgResponse>> {
    if id != auth.org_id {
        return Err(AppError::Forbidden("cannot mutate another org".into()));
    }
    Err(AppError::BadRequest("no patchable fields supplied".into()))
}

#[derive(Deserialize)]
struct PatchCleanupConfigRequest {
    subagent_idle_timeout_secs: i32,
    subagent_archive_retention_days: i32,
}

async fn patch_subagent_cleanup_config(
    State(state): State<AppState>,
    AdminAcl(acl): AdminAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<PatchCleanupConfigRequest>,
) -> Result<Json<OrgResponse>> {
    // Org-level config is admin-only — read-only and write-only callers must
    // not be able to widen idle timeouts or retention windows.
    if id != acl.org_id {
        return Err(AppError::Forbidden(
            "cannot mutate another org's config".into(),
        ));
    }

    if !(MIN_IDLE_TIMEOUT_SECS..=MAX_IDLE_TIMEOUT_SECS).contains(&req.subagent_idle_timeout_secs) {
        return Err(AppError::BadRequest(format!(
            "subagent_idle_timeout_secs must be between {MIN_IDLE_TIMEOUT_SECS} and {MAX_IDLE_TIMEOUT_SECS} (4h–60d)"
        )));
    }
    if !(MIN_RETENTION_DAYS..=MAX_RETENTION_DAYS).contains(&req.subagent_archive_retention_days) {
        return Err(AppError::BadRequest(format!(
            "subagent_archive_retention_days must be between {MIN_RETENTION_DAYS} and {MAX_RETENTION_DAYS}"
        )));
    }

    let org = overslash_db::repos::org::update_subagent_cleanup_config(
        &state.db,
        id,
        req.subagent_idle_timeout_secs,
        req.subagent_archive_retention_days,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("org not found".into()))?;

    let _ = overslash_db::OrgScope::new(acl.org_id, state.db.clone())
        .log_audit(AuditEntry {
            org_id: org.id,
            identity_id: acl.identity_id,
            action: "org.subagent_cleanup_config.updated",
            resource_type: Some("org"),
            resource_id: Some(org.id),
            detail: serde_json::json!({
                "subagent_idle_timeout_secs": org.subagent_idle_timeout_secs,
                "subagent_archive_retention_days": org.subagent_archive_retention_days,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(org.into()))
}
