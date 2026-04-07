use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use overslash_core::types::IdentityKind;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::repos::audit::{self, AuditEntry};
use overslash_db::repos::identity::RestoreOutcome;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AuthContext, ClientIp, WriteAcl},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/identities", post(create_identity).get(list_identities))
        .route("/v1/identities/{id}/children", get(list_children))
        .route("/v1/identities/{id}/chain", get(get_chain))
        .route("/v1/identities/{id}/restore", post(restore_identity))
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
    last_active_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    archived_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    archived_reason: Option<String>,
}

fn fmt_rfc3339(t: time::OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
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
            last_active_at: fmt_rfc3339(r.last_active_at),
            archived_at: r.archived_at.map(fmt_rfc3339),
            archived_reason: r.archived_reason,
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
    // Block creation under an archived parent: the child would be born into a
    // disabled subtree AND would block the parent from ever being purged.
    if parent.archived_at.is_some() {
        return Err(AppError::BadRequest(format!(
            "cannot create {child_kind} under an archived parent identity; restore the parent first"
        )));
    }
    Ok(parent)
}

async fn create_identity(
    State(state): State<AppState>,
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    Json(req): Json<CreateIdentityRequest>,
) -> Result<Json<IdentityResponse>> {
    let auth = acl;
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

    // Auto-join new users to the Everyone group
    if row.kind == "user" {
        overslash_db::repos::org_bootstrap::add_to_everyone_group(&state.db, auth.org_id, row.id)
            .await?;
    }

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
            description: None,
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(Json(row.into()))
}

async fn list_identities(
    State(state): State<AppState>,
    crate::extractors::OrgAcl { org_id, .. }: crate::extractors::OrgAcl,
) -> Result<Json<Vec<IdentityResponse>>> {
    // Listing identities is a Read operation; OrgAcl resolves at least Read
    // for any authenticated caller in the org and supports both API keys and
    // dashboard sessions, so org membership is the right floor here.
    let rows = overslash_db::repos::identity::list_by_org(&state.db, org_id).await?;
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

#[derive(Serialize)]
struct RestoreResponse {
    identity: IdentityResponse,
    api_keys_resurrected: u64,
}

async fn restore_identity(
    State(state): State<AppState>,
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<RestoreResponse>> {
    // Restore mints fresh state (un-archives identity, resurrects API keys),
    // so it requires write-level ACL on the overslash service — read-only
    // users must not be able to revive archived identities.
    //
    // Org-scope and kind checks happen here for clear error messages, but the
    // parent-archived guard runs INSIDE the repo transaction (with FOR UPDATE
    // row locks) to close the TOCTOU race against archive_idle_subagents.
    let existing = overslash_db::repos::identity::get_by_id(&state.db, id).await?;
    let existing = crate::ownership::require_org_owned(existing, acl.org_id, "identity")?;
    if existing.kind != "sub_agent" {
        return Err(AppError::BadRequest(
            "only sub_agent identities can be restored".into(),
        ));
    }

    match overslash_db::repos::identity::restore(&state.db, id).await? {
        RestoreOutcome::Restored {
            identity,
            api_keys_resurrected,
        } => {
            let _ = audit::log(
                &state.db,
                &AuditEntry {
                    org_id: acl.org_id,
                    identity_id: acl.identity_id,
                    action: "identity.restored",
                    resource_type: Some("identity"),
                    resource_id: Some(identity.id),
                    detail: serde_json::json!({
                        "name": &identity.name,
                        "api_keys_resurrected": api_keys_resurrected,
                    }),
                    description: None,
                    ip_address: ip.0.as_deref(),
                },
            )
            .await;
            Ok(Json(RestoreResponse {
                identity: (*identity).into(),
                api_keys_resurrected,
            }))
        }
        RestoreOutcome::NotArchived => Err(AppError::BadRequest("identity is not archived".into())),
        RestoreOutcome::PastRetention => Err(AppError::Conflict(
            "identity is past its retention window and cannot be restored".into(),
        )),
        RestoreOutcome::ParentArchived => Err(AppError::Conflict(
            "cannot restore identity while parent is archived; restore the parent first".into(),
        )),
        RestoreOutcome::NotFound => Err(AppError::NotFound("identity not found".into())),
    }
}
