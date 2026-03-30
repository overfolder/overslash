use axum::{Json, Router, extract::State, routing::post};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::repos::audit::{self, AuditEntry};

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AuthContext, ClientIp},
};

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/identities", post(create_identity).get(list_identities))
}

#[derive(Deserialize)]
struct CreateIdentityRequest {
    name: String,
    kind: String,
    external_id: Option<String>,
    parent_id: Option<Uuid>,
    #[serde(default)]
    inherit_permissions: Option<bool>,
    #[serde(default)]
    can_create_sub: Option<bool>,
    max_sub_depth: Option<i32>,
}

#[derive(Serialize)]
struct IdentityResponse {
    id: Uuid,
    org_id: Uuid,
    name: String,
    kind: String,
    external_id: Option<String>,
    parent_id: Option<Uuid>,
    owner_id: Option<Uuid>,
    depth: i32,
    inherit_permissions: bool,
    can_create_sub: bool,
    max_sub_depth: Option<i32>,
}

impl From<overslash_db::repos::identity::IdentityRow> for IdentityResponse {
    fn from(r: overslash_db::repos::identity::IdentityRow) -> Self {
        Self {
            id: r.id,
            org_id: r.org_id,
            name: r.name,
            kind: r.kind,
            external_id: r.external_id,
            parent_id: r.parent_id,
            owner_id: r.owner_id,
            depth: r.depth,
            inherit_permissions: r.inherit_permissions,
            can_create_sub: r.can_create_sub,
            max_sub_depth: r.max_sub_depth,
        }
    }
}

async fn create_identity(
    State(state): State<AppState>,
    auth: AuthContext,
    ip: ClientIp,
    Json(req): Json<CreateIdentityRequest>,
) -> Result<Json<IdentityResponse>> {
    let row = if let Some(parent_id) = req.parent_id {
        // Hierarchical identity creation
        let parent = overslash_db::repos::identity::get_by_id(&state.db, parent_id)
            .await?
            .ok_or_else(|| AppError::NotFound("parent identity not found".into()))?;

        if parent.org_id != auth.org_id {
            return Err(AppError::Forbidden("parent belongs to another org".into()));
        }

        // Validate parent allows sub-identity creation
        if !parent.can_create_sub {
            return Err(AppError::Forbidden(
                "parent identity does not allow sub-identity creation (can_create_sub=false)"
                    .into(),
            ));
        }

        // Validate depth constraints — check all ancestors' max_sub_depth
        let new_depth = parent.depth + 1;
        let ancestors =
            overslash_db::repos::identity::get_ancestor_chain(&state.db, parent_id).await?;
        for ancestor in &ancestors {
            if let Some(max_depth) = ancestor.max_sub_depth {
                if new_depth > max_depth {
                    return Err(AppError::BadRequest(format!(
                        "depth {} exceeds max_sub_depth {} set by ancestor '{}'",
                        new_depth, max_depth, ancestor.name
                    )));
                }
            }
        }

        // Validate kind matches depth
        let expected_kind = match parent.depth + 1 {
            1 => "agent",
            _ => "subagent",
        };
        if req.kind != expected_kind {
            return Err(AppError::BadRequest(format!(
                "identity at depth {} must be kind '{}', got '{}'",
                parent.depth + 1,
                expected_kind,
                req.kind
            )));
        }

        overslash_db::repos::identity::create_sub_identity(
            &state.db,
            &overslash_db::repos::identity::CreateSubIdentity {
                org_id: auth.org_id,
                parent_id,
                name: &req.name,
                kind: &req.kind,
                inherit_permissions: req.inherit_permissions.unwrap_or(false),
                can_create_sub: req.can_create_sub.unwrap_or(false),
                max_sub_depth: req.max_sub_depth,
            },
        )
        .await?
    } else {
        // Flat identity creation (legacy path)
        overslash_db::repos::identity::create(
            &state.db,
            auth.org_id,
            &req.name,
            &req.kind,
            req.external_id.as_deref(),
        )
        .await?
    };

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "identity.created",
            resource_type: Some("identity"),
            resource_id: Some(row.id),
            detail: serde_json::json!({
                "name": &row.name,
                "kind": &row.kind,
                "parent_id": row.parent_id,
                "depth": row.depth,
            }),
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(Json(IdentityResponse::from(row)))
}

async fn list_identities(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<Vec<IdentityResponse>>> {
    let rows = overslash_db::repos::identity::list_by_org(&state.db, auth.org_id).await?;
    Ok(Json(rows.into_iter().map(IdentityResponse::from).collect()))
}
