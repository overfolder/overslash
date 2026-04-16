use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, patch, post},
};
use overslash_core::types::IdentityKind;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::OrgScope;
use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::identity::RestoreOutcome;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, AuthContext, ClientIp, WriteAcl},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/identities", post(create_identity).get(list_identities))
        .route(
            "/v1/identities/{id}",
            patch(update_identity).delete(delete_identity),
        )
        .route("/v1/identities/{id}/children", get(list_children))
        .route("/v1/identities/{id}/chain", get(get_chain))
        .route("/v1/identities/{id}/restore", post(restore_identity))
        .route("/v1/whoami", get(whoami))
}

/// Bearer-friendly self-introspection for API-key callers (CLI, MCP).
/// Returns the calling identity's `identity_id`/`org_id`/`kind` so a
/// downstream call can supply `parent_id` (e.g. `mcp setup` creating an
/// agent under the calling user). The dashboard's `/auth/me*` endpoints
/// require a session cookie and aren't usable from a Bearer client.
async fn whoami(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<axum::Json<serde_json::Value>> {
    let identity_id = auth
        .identity_id
        .ok_or_else(|| AppError::Unauthorized("no identity bound to this key".into()))?;
    let scope = OrgScope::new(auth.org_id, state.db.clone());
    let ident = scope
        .get_identity(identity_id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
    Ok(axum::Json(serde_json::json!({
        "org_id": auth.org_id,
        "identity_id": identity_id,
        "kind": ident.kind,
        "name": ident.name,
        "parent_id": ident.parent_id,
        "owner_id": ident.owner_id,
    })))
}

#[derive(Deserialize)]
struct UpdateIdentityRequest {
    name: Option<String>,
    parent_id: Option<Uuid>,
    inherit_permissions: Option<bool>,
}

async fn update_identity(
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateIdentityRequest>,
) -> Result<Json<IdentityResponse>> {
    // AdminAcl already enforces admin-level access. Identity-mutation is
    // intentionally admin-only because it can rewire ownership chains and
    // delete agents/users.
    let target = scope
        .get_identity(id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;

    // Validate up front so we can run the actual mutations atomically.
    // Trim leading/trailing whitespace so the persisted value matches what
    // the user actually meant — `"  alice  "` becomes `"alice"`, and a
    // whitespace-only name is rejected.
    let trimmed_name = if let Some(ref name) = req.name {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(AppError::BadRequest("name cannot be empty".into()));
        }
        Some(trimmed)
    } else {
        None
    };

    // Resolve owner ids from the target's kind. Parent kind is validated
    // here for a clean error message; the parent's `depth` and the cycle
    // check are re-done **inside** the apply_patch transaction under
    // FOR UPDATE on both rows, so a concurrent move of the parent can't
    // race a stale depth or sneak a cycle past us.
    let move_to = if let Some(new_parent_id) = req.parent_id {
        let target_kind: IdentityKind = target
            .kind
            .parse()
            .map_err(|_| AppError::Internal("invalid identity kind".into()))?;
        let allowed: &[IdentityKind] = match target_kind {
            IdentityKind::User => {
                return Err(AppError::BadRequest(
                    "user identities cannot have a parent".into(),
                ));
            }
            IdentityKind::Agent => &[IdentityKind::User],
            IdentityKind::SubAgent => &[IdentityKind::Agent, IdentityKind::SubAgent],
        };
        let parent = validate_parent(&scope, new_parent_id, allowed, target_kind).await?;

        let new_owner_id = match target_kind {
            IdentityKind::Agent => parent.id,
            IdentityKind::SubAgent => parent
                .owner_id
                .ok_or_else(|| AppError::BadRequest("new parent has no owner chain".into()))?,
            IdentityKind::User => unreachable!(),
        };
        // For sub_agent descendants of the moved subtree, owner_id must be
        // the top-level user of the new chain.
        let descendant_owner_id = match target_kind {
            IdentityKind::Agent => parent.id,
            IdentityKind::SubAgent => parent.owner_id.unwrap(),
            IdentityKind::User => unreachable!(),
        };
        Some(overslash_db::repos::identity::MoveTo {
            parent_id: new_parent_id,
            new_owner_id,
            descendant_owner_id,
        })
    } else {
        None
    };

    use overslash_db::repos::identity::ApplyPatchOutcome;
    let updated = match scope
        .apply_identity_patch(
            id,
            overslash_db::repos::identity::PatchIdentity {
                name: trimmed_name,
                move_to,
                inherit_permissions: req.inherit_permissions,
            },
        )
        .await?
    {
        ApplyPatchOutcome::Updated(row) => *row,
        ApplyPatchOutcome::NotFound => {
            return Err(AppError::NotFound("identity not found".into()));
        }
        ApplyPatchOutcome::ParentNotFound => {
            return Err(AppError::NotFound(
                "new parent identity not found (it may have been deleted)".into(),
            ));
        }
        ApplyPatchOutcome::Cycle => {
            return Err(AppError::BadRequest(
                "cannot move identity under one of its descendants".into(),
            ));
        }
    };

    let _ = scope
        .log_audit(AuditEntry {
            org_id: acl.org_id,
            identity_id: acl.identity_id,
            action: "identity.updated",
            resource_type: Some("identity"),
            resource_id: Some(id),
            detail: serde_json::json!({
                "name": req.name,
                "parent_id": req.parent_id,
                "inherit_permissions": req.inherit_permissions,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(updated.into()))
}

async fn delete_identity(
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    use overslash_db::repos::identity::DeleteLeafOutcome;

    // Atomic delete: holds FOR UPDATE on the parent row so concurrent
    // FK-checking inserts can't sneak a child in between the leaf check
    // and the delete (which would otherwise be silently cascade-deleted).
    // Cross-tenant ids return NotFound at the SQL boundary.
    match scope.delete_identity_leaf(id).await? {
        DeleteLeafOutcome::Deleted => {}
        DeleteLeafOutcome::HasChildren => {
            return Err(AppError::Conflict(
                "identity has children; delete or move them first".into(),
            ));
        }
        DeleteLeafOutcome::NotFound => {
            return Err(AppError::NotFound("identity not found".into()));
        }
    }

    let _ = scope
        .log_audit(AuditEntry {
            org_id: acl.org_id,
            identity_id: acl.identity_id,
            action: "identity.deleted",
            resource_type: Some("identity"),
            resource_id: Some(id),
            detail: serde_json::json!({}),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct CreateIdentityRequest {
    name: String,
    kind: IdentityKind,
    external_id: Option<String>,
    parent_id: Option<Uuid>,
    /// Optional. Only meaningful for `agent` / `sub_agent`. When set, the
    /// new row is created and its `inherit_permissions` flag is toggled in
    /// the same request so the dashboard doesn't have to round-trip a
    /// follow-up PATCH (which could leave the row half-initialised if it
    /// fails). Ignored for `user` (no parent to inherit from).
    #[serde(default)]
    inherit_permissions: Option<bool>,
}

#[derive(Serialize)]
struct IdentityResponse {
    id: Uuid,
    org_id: Uuid,
    name: String,
    kind: String,
    external_id: Option<String>,
    email: Option<String>,
    provider: Option<String>,
    picture: Option<String>,
    parent_id: Option<Uuid>,
    depth: i32,
    owner_id: Option<Uuid>,
    inherit_permissions: bool,
    created_at: String,
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
        let provider = r
            .metadata
            .get("provider")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let picture = r
            .metadata
            .get("picture")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        Self {
            id: r.id,
            org_id: r.org_id,
            name: r.name,
            kind: r.kind,
            external_id: r.external_id,
            email: r.email,
            provider,
            picture,
            parent_id: r.parent_id,
            depth: r.depth,
            owner_id: r.owner_id,
            inherit_permissions: r.inherit_permissions,
            created_at: fmt_rfc3339(r.created_at),
            last_active_at: fmt_rfc3339(r.last_active_at),
            archived_at: r.archived_at.map(fmt_rfc3339),
            archived_reason: r.archived_reason,
        }
    }
}

/// Fetch and validate a parent identity: must exist, belong to the same org, and be one of the allowed kinds.
async fn validate_parent(
    scope: &OrgScope,
    parent_id: Uuid,
    allowed_kinds: &[IdentityKind],
    child_kind: IdentityKind,
) -> Result<overslash_db::repos::identity::IdentityRow> {
    let parent = scope
        .get_identity(parent_id)
        .await?
        .ok_or_else(|| AppError::NotFound("parent identity not found".into()))?;
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
    scope: OrgScope,
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
            scope
                .create_identity(&req.name, kind_str, req.external_id.as_deref())
                .await?
        }
        IdentityKind::Agent => {
            let parent_id = req.parent_id.ok_or_else(|| {
                AppError::BadRequest("agent identities require a parent_id".into())
            })?;
            let parent =
                validate_parent(&scope, parent_id, &[IdentityKind::User], req.kind).await?;
            scope
                .create_identity_with_parent(
                    &req.name,
                    kind_str,
                    req.external_id.as_deref(),
                    parent_id,
                    parent.depth + 1,
                    parent.id,
                    req.inherit_permissions.unwrap_or(false),
                )
                .await?
        }
        IdentityKind::SubAgent => {
            let parent_id = req.parent_id.ok_or_else(|| {
                AppError::BadRequest("sub_agent identities require a parent_id".into())
            })?;
            let parent = validate_parent(
                &scope,
                parent_id,
                &[IdentityKind::Agent, IdentityKind::SubAgent],
                req.kind,
            )
            .await?;
            let owner_id = parent.owner_id.ok_or_else(|| {
                AppError::BadRequest(
                    "cannot create sub_agent under an identity with no owner chain".into(),
                )
            })?;
            scope
                .create_identity_with_parent(
                    &req.name,
                    kind_str,
                    req.external_id.as_deref(),
                    parent_id,
                    parent.depth + 1,
                    owner_id,
                    req.inherit_permissions.unwrap_or(false),
                )
                .await?
        }
    };

    // Auto-join new users to the Everyone group
    if row.kind == "user" {
        overslash_db::repos::org_bootstrap::add_to_everyone_group(&state.db, auth.org_id, row.id)
            .await?;
    }

    let _ = OrgScope::new(auth.org_id, state.db.clone())
        .log_audit(AuditEntry {
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
        })
        .await;

    Ok(Json(row.into()))
}

async fn list_identities(
    _: crate::extractors::OrgAcl,
    scope: OrgScope,
) -> Result<Json<Vec<IdentityResponse>>> {
    let rows = scope.list_identities().await?;
    Ok(Json(rows.into_iter().map(IdentityResponse::from).collect()))
}

async fn list_children(
    scope: OrgScope,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<IdentityResponse>>> {
    // Verify the parent itself lives in this org. Cross-tenant ids return None.
    let _ident = scope
        .get_identity(id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
    let rows = scope.list_identity_children(id).await?;
    Ok(Json(rows.into_iter().map(IdentityResponse::from).collect()))
}

async fn get_chain(scope: OrgScope, Path(id): Path<Uuid>) -> Result<Json<Vec<IdentityResponse>>> {
    let _ident = scope
        .get_identity(id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
    let rows = scope.get_identity_ancestor_chain(id).await?;
    Ok(Json(rows.into_iter().map(IdentityResponse::from).collect()))
}

#[derive(Serialize)]
struct RestoreResponse {
    identity: IdentityResponse,
    api_keys_resurrected: u64,
}

async fn restore_identity(
    WriteAcl(acl): WriteAcl,
    scope: OrgScope,
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
    let existing = scope
        .get_identity(id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
    if existing.kind != "sub_agent" {
        return Err(AppError::BadRequest(
            "only sub_agent identities can be restored".into(),
        ));
    }

    match scope.restore_identity(id).await? {
        RestoreOutcome::Restored {
            identity,
            api_keys_resurrected,
        } => {
            let _ = scope
                .log_audit(AuditEntry {
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
                })
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
