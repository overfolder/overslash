use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{delete, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::OrgScope;
use overslash_db::repos::audit::AuditEntry;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, AuthContext, ClientIp},
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
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Json(req): Json<CreatePermissionRequest>,
) -> Result<Json<PermissionResponse>> {
    let auth = acl;
    let row = scope
        .create_permission_rule(req.identity_id, &req.action_pattern, &req.effect, None)
        .await?;

    let _ = OrgScope::new(auth.org_id, state.db.clone())
        .log_audit(AuditEntry {
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
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(PermissionResponse {
        id: row.id,
        identity_id: row.identity_id,
        action_pattern: row.action_pattern,
        effect: row.effect,
    }))
}

async fn list_permissions(
    auth: AuthContext,
    scope: OrgScope,
) -> Result<Json<Vec<PermissionResponse>>> {
    // For MVP, list all permissions for the calling identity
    let identity_id = auth
        .identity_id
        .ok_or_else(|| AppError::BadRequest("no identity on this key".into()))?;
    let rows = scope
        .list_permission_rules_for_identity(identity_id)
        .await?;
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
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let auth = acl;
    let deleted = scope.delete_permission_rule(id).await?;

    if deleted {
        let _ = OrgScope::new(auth.org_id, state.db.clone())
            .log_audit(AuditEntry {
                org_id: auth.org_id,
                identity_id: auth.identity_id,
                action: "permission_rule.deleted",
                resource_type: Some("permission_rule"),
                resource_id: Some(id),
                detail: serde_json::json!({}),
                description: None,
                ip_address: ip.0.as_deref(),
            })
            .await;
    }

    Ok(Json(serde_json::json!({ "deleted": deleted })))
}
