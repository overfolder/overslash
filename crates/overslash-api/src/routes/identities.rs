use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use overslash_core::types::IdentityKind;
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
        .route("/v1/identities/{id}/children", get(list_children))
        .route("/v1/identities/{id}/chain", get(get_chain))
}

#[derive(Deserialize)]
struct CreateIdentityRequest {
    name: String,
    kind: IdentityKind,
    external_id: Option<String>,
    parent_id: Option<Uuid>,
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
    owner_id: Option<Uuid>,
    inherit_permissions: bool,
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
            depth: r.depth,
            owner_id: r.owner_id,
            inherit_permissions: r.inherit_permissions,
        }
    }
}

/// Fetch and validate a parent identity: must exist, belong to the same org, and be one of the allowed kinds.
async fn validate_parent(
    state: &AppState,
    parent_id: Uuid,
    org_id: Uuid,
    allowed_kinds: &[IdentityKind],
    child_kind: IdentityKind,
) -> Result<overslash_db::repos::identity::IdentityRow> {
    let parent = overslash_db::repos::identity::get_by_id(&state.db, parent_id).await?;
    let parent = crate::ownership::require_org_owned(parent, org_id, "parent identity")?;
    let parent_kind: IdentityKind = parent
        .kind
        .parse()
        .map_err(|_| AppError::Internal("invalid parent kind in database".into()))?;
    if !allowed_kinds.contains(&parent_kind) {
        let allowed: Vec<&str> = allowed_kinds.iter().map(IdentityKind::as_str).collect();
        return Err(AppError::BadRequest(format!(
            "{child_kind} parent must be a {} identity",
            allowed.join(" or ")
        )));
    }
    Ok(parent)
}

async fn create_identity(
    State(state): State<AppState>,
    auth: AuthContext,
    ip: ClientIp,
    Json(req): Json<CreateIdentityRequest>,
) -> Result<Json<IdentityResponse>> {
    let kind_str = req.kind.as_str();

    let row = match req.kind {
        IdentityKind::User => {
            if req.parent_id.is_some() {
                return Err(AppError::BadRequest(
                    "user identities cannot have a parent".into(),
                ));
            }
            overslash_db::repos::identity::create(
                &state.db,
                auth.org_id,
                &req.name,
                kind_str,
                req.external_id.as_deref(),
            )
            .await?
        }
        IdentityKind::Agent => {
            let parent_id = req.parent_id.ok_or_else(|| {
                AppError::BadRequest("agent identities require a parent_id".into())
            })?;
            let parent = validate_parent(
                &state,
                parent_id,
                auth.org_id,
                &[IdentityKind::User],
                req.kind,
            )
            .await?;
            overslash_db::repos::identity::create_with_parent(
                &state.db,
                auth.org_id,
                &req.name,
                kind_str,
                req.external_id.as_deref(),
                parent_id,
                parent.depth + 1,
                parent.id,
            )
            .await?
        }
        IdentityKind::SubAgent => {
            let parent_id = req.parent_id.ok_or_else(|| {
                AppError::BadRequest("sub_agent identities require a parent_id".into())
            })?;
            let parent = validate_parent(
                &state,
                parent_id,
                auth.org_id,
                &[IdentityKind::Agent, IdentityKind::SubAgent],
                req.kind,
            )
            .await?;
            let owner_id = parent.owner_id.ok_or_else(|| {
                AppError::BadRequest(
                    "cannot create sub_agent under an identity with no owner chain".into(),
                )
            })?;
            overslash_db::repos::identity::create_with_parent(
                &state.db,
                auth.org_id,
                &req.name,
                kind_str,
                req.external_id.as_deref(),
                parent_id,
                parent.depth + 1,
                owner_id,
            )
            .await?
        }
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

    Ok(Json(row.into()))
}

async fn list_identities(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<Vec<IdentityResponse>>> {
    let rows = overslash_db::repos::identity::list_by_org(&state.db, auth.org_id).await?;
    Ok(Json(rows.into_iter().map(IdentityResponse::from).collect()))
}

async fn list_children(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<IdentityResponse>>> {
    let ident = overslash_db::repos::identity::get_by_id(&state.db, id).await?;
    let _ident = crate::ownership::require_org_owned(ident, auth.org_id, "identity")?;
    let rows = overslash_db::repos::identity::list_children(&state.db, id).await?;
    Ok(Json(rows.into_iter().map(IdentityResponse::from).collect()))
}

async fn get_chain(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<IdentityResponse>>> {
    let ident = overslash_db::repos::identity::get_by_id(&state.db, id).await?;
    let _ident = crate::ownership::require_org_owned(ident, auth.org_id, "identity")?;
    let rows = overslash_db::repos::identity::get_ancestor_chain(&state.db, id).await?;
    Ok(Json(rows.into_iter().map(IdentityResponse::from).collect()))
}
