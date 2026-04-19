use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{delete, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::OrgScope;
use overslash_db::repos::audit::AuditEntry;

use super::util::fmt_time;
use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, AuthContext, ClientIp, OrgAcl},
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
    expires_at: Option<String>,
    created_at: String,
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
        expires_at: row.expires_at.map(fmt_time),
        created_at: fmt_time(row.created_at),
    }))
}

#[derive(Deserialize)]
struct ListPermissionsQuery {
    identity_id: Option<Uuid>,
}

async fn list_permissions(
    auth: AuthContext,
    scope: OrgScope,
    Query(q): Query<ListPermissionsQuery>,
) -> Result<Json<Vec<PermissionResponse>>> {
    // ?identity_id= is the identity-hierarchy detail panel filter: any
    // authenticated org member may list permission rules attached to a
    // specific identity in their own org. Cross-tenant ids are blocked at
    // the scope boundary (returns None).
    //
    // Without a query param the legacy MVP behaviour applies: list rules
    // for the calling identity.
    let identity_id = if let Some(target) = q.identity_id {
        scope
            .get_identity(target)
            .await?
            .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
        target
    } else {
        auth.identity_id
            .ok_or_else(|| AppError::BadRequest("no identity on this key".into()))?
    };
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
                expires_at: r.expires_at.map(fmt_time),
                created_at: fmt_time(r.created_at),
            })
            .collect(),
    ))
}

async fn delete_permission(
    acl: OrgAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    use overslash_core::permissions::AccessLevel;

    let rule = scope
        .get_permission_rule(id)
        .await?
        .ok_or_else(|| AppError::NotFound("permission rule not found".into()))?;

    // Allowed if (a) the caller owns this rule (self-service revoke from the
    // profile page) or (b) the caller has admin ACL on the org.
    let owns_it = acl
        .identity_id
        .map(|cid| cid == rule.identity_id)
        .unwrap_or(false);
    let is_admin = acl.access_level >= AccessLevel::Admin;
    if !owns_it && !is_admin {
        return Err(AppError::Forbidden(
            "cannot delete a permission rule you do not own".into(),
        ));
    }

    let deleted = scope.delete_permission_rule(id).await?;

    if deleted {
        let _ = scope
            .log_audit(AuditEntry {
                org_id: acl.org_id,
                identity_id: acl.identity_id,
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
