use axum::{Json, Router, extract::{Path, State}, http::StatusCode, routing::{get, post}};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::repos::audit::{self, AuditEntry};

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AuthContext, ClientIp},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/identities", post(create_identity).get(list_identities))
        .route(
            "/v1/identities/{id}",
            get(get_identity).put(update_identity).delete(delete_identity),
        )
}

#[derive(Deserialize)]
struct CreateIdentityRequest {
    name: String,
    kind: String,
    external_id: Option<String>,
    parent_id: Option<Uuid>,
}

#[derive(Deserialize)]
struct UpdateIdentityRequest {
    name: String,
}

#[derive(Serialize)]
struct IdentityResponse {
    id: Uuid,
    org_id: Uuid,
    name: String,
    kind: String,
    external_id: Option<String>,
    parent_id: Option<Uuid>,
    depth: i32,
    email: Option<String>,
    created_at: String,
}

fn identity_response(r: overslash_db::repos::identity::IdentityRow) -> IdentityResponse {
    IdentityResponse {
        id: r.id,
        org_id: r.org_id,
        name: r.name,
        kind: r.kind,
        external_id: r.external_id,
        parent_id: r.parent_id,
        depth: r.depth,
        email: r.email,
        created_at: r.created_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
    }
}

async fn create_identity(
    State(state): State<AppState>,
    auth: AuthContext,
    ip: ClientIp,
    Json(req): Json<CreateIdentityRequest>,
) -> Result<Json<IdentityResponse>> {
    // Validate kind
    if req.kind != "user" && req.kind != "agent" {
        return Err(AppError::BadRequest("kind must be 'user' or 'agent'".into()));
    }

    // Validate hierarchy rules
    if let Some(pid) = req.parent_id {
        let parent = overslash_db::repos::identity::get_by_id(&state.db, pid)
            .await?
            .ok_or_else(|| AppError::BadRequest("parent identity not found".into()))?;
        if parent.org_id != auth.org_id {
            return Err(AppError::BadRequest("parent identity not in same org".into()));
        }
        if req.kind == "user" {
            return Err(AppError::BadRequest("users cannot have a parent identity".into()));
        }
    } else if req.kind == "agent" {
        // Agents without a parent are allowed (org-level agents)
    }

    let row = overslash_db::repos::identity::create(
        &state.db,
        auth.org_id,
        &req.name,
        &req.kind,
        req.external_id.as_deref(),
        req.parent_id,
    )
    .await?;

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "identity.created",
            resource_type: Some("identity"),
            resource_id: Some(row.id),
            detail: serde_json::json!({ "name": &row.name, "kind": &row.kind, "parent_id": &row.parent_id }),
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(Json(identity_response(row)))
}

async fn list_identities(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<Vec<IdentityResponse>>> {
    let rows = overslash_db::repos::identity::list_by_org(&state.db, auth.org_id).await?;
    Ok(Json(rows.into_iter().map(identity_response).collect()))
}

async fn get_identity(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<IdentityResponse>> {
    let row = overslash_db::repos::identity::get_by_id(&state.db, id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
    if row.org_id != auth.org_id {
        return Err(AppError::NotFound("identity not found".into()));
    }
    Ok(Json(identity_response(row)))
}

async fn update_identity(
    State(state): State<AppState>,
    auth: AuthContext,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateIdentityRequest>,
) -> Result<Json<IdentityResponse>> {
    let row = overslash_db::repos::identity::update(&state.db, id, auth.org_id, &req.name)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "identity.updated",
            resource_type: Some("identity"),
            resource_id: Some(row.id),
            detail: serde_json::json!({ "name": &row.name }),
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(Json(identity_response(row)))
}

async fn delete_identity(
    State(state): State<AppState>,
    auth: AuthContext,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    // Verify identity belongs to this org
    let row = overslash_db::repos::identity::get_by_id(&state.db, id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
    if row.org_id != auth.org_id {
        return Err(AppError::NotFound("identity not found".into()));
    }

    overslash_db::repos::identity::delete(&state.db, id).await?;

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "identity.deleted",
            resource_type: Some("identity"),
            resource_id: Some(id),
            detail: serde_json::json!({ "name": &row.name, "kind": &row.kind }),
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}
