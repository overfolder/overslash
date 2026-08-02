//! Identity CRUD: create, read (list / children / chain), update, delete —
//! plus admin member-removal and the `/v1/whoami` self-introspection probe.

use super::*;

/// Bearer-friendly self-introspection for API-key callers (CLI, MCP).
/// Returns the calling identity's `identity_id`/`org_id`/`kind` so a
/// downstream call can supply `parent_id` (e.g. `mcp setup` creating an
/// agent under the calling user). The dashboard's `/auth/me*` endpoints
/// require a session cookie and aren't usable from a Bearer client.
pub(super) async fn whoami(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: AuthContext,
) -> Result<axum::Json<serde_json::Value>> {
    let identity_id = auth
        .identity_id
        .ok_or_else(|| AppError::Unauthorized("no identity bound to this key".into()))?;
    let scope = OrgScope::new(auth.org_id, state.db_pool(&ext));
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
pub(super) struct UpdateIdentityRequest {
    name: Option<String>,
    parent_id: Option<Uuid>,
    inherit_permissions: Option<bool>,
}

pub(super) async fn update_identity(
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

pub(super) async fn delete_identity(
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    use overslash_db::repos::identity::DeleteLeafOutcome;

    // Look the target up first so we can branch on kind. A `user`-kind identity
    // that's linked to a human (`user_id`) represents that human's membership in
    // the org, not a deletable leaf node: hard-deleting just its row would orphan
    // the surviving `user_org_memberships` row (an invariant violation that 500s
    // the user's next login). So routing a delete at a linked user means "remove
    // this member from the org" — cascade-archive their subtree and drop their
    // membership. Bare user identities (no linked human — e.g. created directly
    // via the API) keep the original leaf hard-delete behaviour.
    let target = scope
        .get_identity(id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;

    if target.kind == "user" && target.user_id.is_some() {
        return remove_user_from_org(acl, scope, ip, id).await;
    }

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

/// Remove a human user from the org (admin-only). Cascade-archives the user's
/// identity subtree (revoking API keys + expiring approvals), drops their
/// `user_org_memberships` row, and detaches the archived identity from the user
/// — all atomically. Guards against removing yourself or the org's last admin.
async fn remove_user_from_org(
    acl: crate::extractors::OrgAcl,
    scope: OrgScope,
    ip: ClientIp,
    id: Uuid,
) -> Result<StatusCode> {
    use overslash_db::repos::identity::RemoveUserOutcome;

    // You can't evict yourself here — that would be a self-inflicted lockout
    // (and the last-admin guard wouldn't fire if you weren't an admin). Leaving
    // an org is a separate, self-service flow (`DELETE /v1/account/memberships`).
    if acl.identity_id == Some(id) {
        return Err(AppError::BadRequest(
            "cannot remove yourself from the org".into(),
        ));
    }

    let (user_id, archived_count, was_admin) = match scope.remove_user_from_org(id).await? {
        RemoveUserOutcome::Removed {
            user_id,
            archived_count,
            was_admin,
        } => (user_id, archived_count, was_admin),
        RemoveUserOutcome::LastAdmin => {
            return Err(AppError::BadRequest(
                "cannot remove the last admin of the org".into(),
            ));
        }
        RemoveUserOutcome::NotApplicable => {
            return Err(AppError::Conflict(
                "identity is not a removable org member".into(),
            ));
        }
        RemoveUserOutcome::NotFound => {
            return Err(AppError::NotFound("identity not found".into()));
        }
    };

    let _ = scope
        .log_audit(AuditEntry {
            org_id: acl.org_id,
            identity_id: acl.identity_id,
            action: "membership.removed",
            resource_type: Some("membership"),
            // The removed user identity — so audit filtering by resource_id
            // surfaces this removal (org_id would bury it under the org).
            resource_id: Some(id),
            detail: serde_json::json!({
                "user_id": user_id,
                "identity_id": id,
                "archived_count": archived_count,
                "was_admin": was_admin,
                "removed_by_admin": true,
            }),
            description: Some("Admin removed a member from the org"),
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub(super) struct CreateIdentityRequest {
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

pub(super) async fn create_identity(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
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

    // Auto-join new users to the Everyone group + create their Myself group.
    if row.kind == "user" {
        overslash_db::repos::org_bootstrap::bootstrap_user_in_org(
            state.db(&ext),
            auth.org_id,
            row.id,
        )
        .await?;
    }

    let _ = OrgScope::new(auth.org_id, state.db_pool(&ext))
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

/// Query params for the identity-listing endpoints. Archived rows are excluded
/// by default; callers that manage archived state (the dashboard, admin tools)
/// pass `?include_archived=true` to get the full set.
#[derive(Deserialize)]
pub(super) struct ListIdentitiesQuery {
    #[serde(default)]
    include_archived: bool,
}

pub(super) async fn list_identities(
    _: crate::extractors::OrgAcl,
    scope: OrgScope,
    Query(q): Query<ListIdentitiesQuery>,
) -> Result<Json<Vec<IdentityResponse>>> {
    let mut rows = scope.list_identities().await?;
    if !q.include_archived {
        rows.retain(|r| r.archived_at.is_none());
    }
    Ok(Json(rows.into_iter().map(IdentityResponse::from).collect()))
}

pub(super) async fn list_children(
    scope: OrgScope,
    Path(id): Path<Uuid>,
    Query(q): Query<ListIdentitiesQuery>,
) -> Result<Json<Vec<IdentityResponse>>> {
    // Verify the parent itself lives in this org. Cross-tenant ids return None.
    let _ident = scope
        .get_identity(id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
    let mut rows = scope.list_identity_children(id).await?;
    if !q.include_archived {
        rows.retain(|r| r.archived_at.is_none());
    }
    Ok(Json(rows.into_iter().map(IdentityResponse::from).collect()))
}

pub(super) async fn get_chain(
    scope: OrgScope,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<IdentityResponse>>> {
    let _ident = scope
        .get_identity(id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
    let rows = scope.get_identity_ancestor_chain(id).await?;
    Ok(Json(rows.into_iter().map(IdentityResponse::from).collect()))
}
