use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{delete, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::repos::audit::{self, AuditEntry};

use crate::{
    AppState,
    error::Result,
    extractors::{AuthContext, ClientIp},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/permissions",
            post(create_permission).get(list_permissions),
        )
        .route("/v1/permissions/{id}", delete(delete_permission))
}

#[derive(Deserialize)]
struct CreatePermissionRequest {
    identity_id: Uuid,
    action_pattern: String,
    #[serde(default = "default_allow")]
    effect: String,
}

fn default_allow() -> String {
    "allow".into()
}

#[derive(Serialize)]
struct PermissionResponse {
    id: Uuid,
    identity_id: Uuid,
    action_pattern: String,
    effect: String,
}

async fn create_permission(
    State(state): State<AppState>,
    auth: AuthContext,
    ip: ClientIp,
    Json(req): Json<CreatePermissionRequest>,
) -> Result<Json<PermissionResponse>> {
    let row = overslash_db::repos::permission_rule::create(
        &state.db,
        auth.org_id,
        req.identity_id,
        &req.action_pattern,
        &req.effect,
        None,
    )
    .await?;

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "permission_rule.created",
            resource_type: Some("permission_rule"),
            resource_id: Some(row.id),
            detail: serde_json::json!({
                "identity_id": req.identity_id,
                "action_pattern": &row.action_pattern,
                "effect": &row.effect,
            }),
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(Json(PermissionResponse {
        id: row.id,
        identity_id: row.identity_id,
        action_pattern: row.action_pattern,
        effect: row.effect,
    }))
}

async fn list_permissions(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<Vec<PermissionResponse>>> {
    // For MVP, list all permissions for the calling identity
    let identity_id = auth
        .identity_id
        .ok_or_else(|| crate::error::AppError::BadRequest("no identity on this key".into()))?;
    let rows =
        overslash_db::repos::permission_rule::list_by_identity(&state.db, identity_id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| PermissionResponse {
                id: r.id,
                identity_id: r.identity_id,
                action_pattern: r.action_pattern,
                effect: r.effect,
            })
            .collect(),
    ))
}

async fn delete_permission(
    State(state): State<AppState>,
    auth: AuthContext,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let deleted = overslash_db::repos::permission_rule::delete(&state.db, id, auth.org_id).await?;

    if deleted {
        let _ = overslash_db::repos::audit::log(
            &state.db,
            &overslash_db::repos::audit::AuditEntry {
                org_id: auth.org_id,
                identity_id: auth.identity_id,
                action: "permission_rule.deleted",
                resource_type: Some("permission_rule"),
                resource_id: Some(id),
                detail: serde_json::json!({}),
                ip_address: ip.0.as_deref(),
            },
        )
        .await;
    }

    Ok(Json(serde_json::json!({ "deleted": deleted })))
}
