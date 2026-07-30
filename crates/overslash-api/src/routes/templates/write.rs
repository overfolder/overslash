//! Mutating endpoints: create / update / delete a standalone or derived
//! template layer.

use super::*;

/// Carry the system-managed MCP discovery fields (`discovered_tools`,
/// `discovered_at`) from `old` forward onto `new` when `new` does not
/// already declare them. The admin-facing update path accepts the same
/// template editor YAML that created the row, which doesn't round-trip
/// through the discovery blob — without this carry-over, each edit
/// would silently wipe the last resync.
fn preserve_mcp_discovered_fields(old: &serde_json::Value, new: &mut serde_json::Value) {
    let Some(old_mcp) = old.get("x-overslash-mcp").and_then(|v| v.as_object()) else {
        return;
    };
    let Some(new_mcp) = new
        .get_mut("x-overslash-mcp")
        .and_then(|v| v.as_object_mut())
    else {
        return;
    };
    for field in ["discovered_tools", "discovered_at"] {
        if !new_mcp.contains_key(field) {
            if let Some(v) = old_mcp.get(field) {
                new_mcp.insert(field.into(), v.clone());
            }
        }
    }
}

/// Resolve the owner identity + authority for a template-create request, shared
/// by the standalone and derived paths. Org-namespace (`user_level=false`) →
/// admin; user-namespace → `user_template_policy` gate.
async fn authorize_template_create(
    state: &AppState,
    ext: &axum::http::Extensions,
    acl: &crate::extractors::OrgAcl,
    user_level: bool,
) -> Result<Option<Uuid>> {
    if user_level {
        let identity_id = acl.identity_id.ok_or_else(|| {
            AppError::BadRequest("user-level templates require an identity-bound API key".into())
        })?;
        platform_templates::enforce_user_template_policy(state.db(ext), acl.org_id).await?;
        Ok(Some(identity_id))
    } else {
        if acl.access_level < AccessLevel::Admin {
            return Err(AppError::Forbidden(
                "admin access required to create org-level templates".into(),
            ));
        }
        Ok(None)
    }
}

/// Create a new org or user template — either a **standalone** layer (full
/// OpenAPI doc) or a **derived** layer (`extends` a base + a `delta`).
pub(super) async fn create_template(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    Json(req): Json<CreateTemplateRequest>,
) -> Result<Json<TemplateDetail>> {
    let owner_identity_id = authorize_template_create(&state, &ext, &acl, req.user_level).await?;

    if req.extends.is_some() {
        return create_derived_layer(&state, &ext, &acl, ip, owner_identity_id, req).await;
    }

    // ── Standalone layer ──────────────────────────────────────────────────
    let openapi_yaml = req.openapi.as_deref().ok_or_else(|| {
        AppError::BadRequest("a standalone template requires `openapi` (or set `extends`)".into())
    })?;
    let (doc, def) =
        parse_normalize_compile_and_check_disclose(openapi_yaml, state.registry.vars())
            .map_err(|report| AppError::TemplateValidationFailed { report })?;

    if def.key.is_empty() {
        return Err(AppError::BadRequest(
            "template key is required (set `info.key` or `info.x-overslash-key`)".into(),
        ));
    }

    // Check that key doesn't collide with a global template. (A derived layer
    // MAY reuse a global key — that's shadow-with-delta — but a standalone copy
    // reusing a global key is disallowed to avoid an unreviewed full override.)
    if state.registry.get(&def.key).is_some() {
        return Err(AppError::Conflict(format!(
            "template key '{}' conflicts with a global template",
            def.key
        )));
    }

    let input = CreateServiceTemplate {
        org_id: acl.org_id,
        owner_identity_id,
        key: &def.key,
        display_name: &def.display_name,
        description: def.description.as_deref().unwrap_or(""),
        category: def.category.as_deref().unwrap_or(""),
        hosts: &def.hosts,
        openapi: Some(doc),
        extends: None,
        delta: None,
        status: "active",
    };

    let row = service_template::create(state.db(&ext), &input)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.constraint().is_some() {
                    return AppError::Conflict(format!(
                        "template key '{}' already exists",
                        def.key
                    ));
                }
            }
            AppError::Database(e)
        })?;

    let tier = if row.owner_identity_id.is_some() {
        "user"
    } else {
        "org"
    };

    log_template_created(&state, &ext, &acl, &row, tier, ip.0.as_deref()).await;

    crate::services::embedding_backfill::refresh_template(
        state.db(&ext),
        state.embedder.as_ref(),
        tier,
        Some(acl.org_id),
        row.owner_identity_id,
        &def,
    )
    .await;

    Ok(Json(db_row_to_detail(&state, &ext, row, tier).await?))
}

/// Create a **derived** layer: validate the delta against its resolved base,
/// then persist `extends`/`delta`. The base is resolved in the layer's own
/// identity context (a user layer may extend a global, an org-namespace layer,
/// or its own user layers; an org layer may extend a global or org-namespace
/// layer — never another user's private layer, which the resolution context
/// makes structurally unreachable).
async fn create_derived_layer(
    state: &AppState,
    ext: &axum::http::Extensions,
    acl: &crate::extractors::OrgAcl,
    ip: ClientIp,
    owner_identity_id: Option<Uuid>,
    req: CreateTemplateRequest,
) -> Result<Json<TemplateDetail>> {
    if req.openapi.is_some() {
        return Err(AppError::BadRequest(
            "a derived layer sets `extends`+`delta`, not `openapi`".into(),
        ));
    }
    let extends = req.extends.expect("checked by caller");
    let delta_value = req
        .delta
        .ok_or_else(|| AppError::BadRequest("a derived layer requires `delta`".into()))?;
    let delta: Delta = serde_json::from_value(delta_value.clone())
        .map_err(|e| AppError::BadRequest(format!("malformed delta: {e}")))?;

    // The layer's own catalog key: distinct key → separate entry; default to the
    // base key → shadow-with-delta.
    let key = req.key.clone().unwrap_or_else(|| extends.clone());

    // Resolve the base (target-exists + chain-soundness guard) in the layer's
    // own identity context.
    let base = crate::services::template_resolve::resolve(
        state.db(ext),
        &state.registry,
        acl.org_id,
        owner_identity_id,
        &extends,
    )
    .await
    .map_err(|e| match e {
        AppError::NotFound(_) => AppError::BadRequest(format!(
            "base template '{extends}' not found or not visible to this layer"
        )),
        other => other,
    })?;

    // Write-time delta validation against the resolved base. `owner_identity_id`
    // set ⇒ a user-tier layer, which may not carry `instance_defaults`.
    let report =
        service_layer::validate_delta(&delta, &base.definition, owner_identity_id.is_some());
    if !report.valid {
        return Err(AppError::TemplateValidationFailed { report });
    }

    let display_name = req.display_name.clone().unwrap_or_else(|| {
        delta
            .display_name
            .clone()
            .unwrap_or_else(|| base.definition.display_name.clone())
    });
    let category = req.category.clone().unwrap_or_default();

    let input = CreateServiceTemplate {
        org_id: acl.org_id,
        owner_identity_id,
        key: &key,
        display_name: &display_name,
        description: "",
        category: &category,
        hosts: &[],
        openapi: None,
        extends: Some(&extends),
        delta: Some(delta_value),
        status: "active",
    };

    let row = service_template::create(state.db(ext), &input)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.constraint().is_some() {
                    return AppError::Conflict(format!("template key '{key}' already exists"));
                }
            }
            AppError::Database(e)
        })?;

    let tier = if row.owner_identity_id.is_some() {
        "user"
    } else {
        "org"
    };
    log_template_created(state, ext, acl, &row, tier, ip.0.as_deref()).await;
    refresh_layer_embeddings(state, ext, &row, tier).await;

    Ok(Json(db_row_to_detail(state, ext, row, tier).await?))
}

/// Index a **derived** layer's *effective* (folded) surface for semantic search,
/// mirroring the `refresh_template` call standalone create/update make. Uses the
/// resolved definition so masked actions stay out of the index and extensions
/// are included. Best-effort: a layer whose base fails to resolve is skipped
/// (keyword search still works through the fold at query time). Note: because
/// `extends` is a live pointer, a later base change is not cascaded into these
/// embeddings — re-saving the layer re-indexes it (cascade re-embedding is a
/// documented deferred item, same bucket as the materialized resolved cache).
async fn refresh_layer_embeddings(
    state: &AppState,
    ext: &axum::http::Extensions,
    row: &service_template::ServiceTemplateRow,
    tier: &'static str,
) {
    if let Ok(resolved) =
        crate::services::template_resolve::resolve_row(state.db(ext), &state.registry, row).await
    {
        crate::services::embedding_backfill::refresh_template(
            state.db(ext),
            state.embedder.as_ref(),
            tier,
            Some(row.org_id),
            row.owner_identity_id,
            &resolved.definition,
        )
        .await;
    }
}

async fn log_template_created(
    state: &AppState,
    ext: &axum::http::Extensions,
    acl: &crate::extractors::OrgAcl,
    row: &service_template::ServiceTemplateRow,
    tier: &str,
    ip: Option<&str>,
) {
    let _ = overslash_db::OrgScope::new(acl.org_id, state.db_pool(ext))
        .log_audit(AuditEntry {
            org_id: acl.org_id,
            identity_id: acl.identity_id,
            action: "template.created",
            resource_type: Some("template"),
            resource_id: Some(row.id),
            detail: serde_json::json!({
                "key": &row.key,
                "tier": tier,
                "owner_identity_id": row.owner_identity_id,
                "extends": &row.extends,
            }),
            description: None,
            ip_address: ip,
        })
        .await;
}

/// Update a DB-stored template by id.
pub(super) async fn update_template(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateTemplateRequest>,
) -> Result<Json<TemplateDetail>> {
    // Multi-tenancy guard + ownership check. Drafts are scoped to the
    // `/v1/templates/drafts/*` surface — routing them through this endpoint
    // would bypass the draft-specific audit trail and allow active-template
    // callers to mutate work-in-progress rows they cannot otherwise see.
    let existing = service_template::get_by_id(state.db(&ext), id)
        .await?
        .filter(|r| r.org_id == acl.org_id && r.status == "active")
        .ok_or_else(|| AppError::NotFound("template not found".into()))?;

    if existing.owner_identity_id.is_some() {
        // User-level: caller must own it, be an ancestor of the owner (the
        // parent→child ceiling allowance — a user managing its agents'
        // templates), or be admin.
        let scope = overslash_db::OrgScope::new(acl.org_id, state.db_pool(&ext));
        if !crate::services::permission_chain::caller_may_manage_owned(
            &scope,
            existing.owner_identity_id,
            acl.identity_id,
            acl.access_level,
        )
        .await?
        {
            return Err(AppError::Forbidden(
                "you can only modify your own templates".into(),
            ));
        }
    } else {
        // Org-level: admin required
        if acl.access_level < AccessLevel::Admin {
            return Err(AppError::Forbidden(
                "admin access required for org-level templates".into(),
            ));
        }
    }

    // A non-admin editing their own **user-namespace** layer must still satisfy
    // the org's `user_template_policy` — mirroring create. Forward-only downgrade
    // keeps existing layers *executing* (the fold never checks policy), but it
    // must not let a member edit one into a broader grant (e.g. add an extension
    // host under `none`), which would bypass the very restriction the policy
    // exists to enforce. Admins keep edit rights for compliance management
    // (pruning is delete; tightening is an admin edit).
    if existing.owner_identity_id.is_some() && acl.access_level < AccessLevel::Admin {
        platform_templates::enforce_user_template_policy(state.db(&ext), acl.org_id).await?;
    }

    // Derived layers are edited through their `delta` (their `extends` binding
    // is immutable, which also keeps the inheritance graph acyclic).
    if existing.extends.is_some() {
        return update_derived_layer(&state, &ext, &acl, ip, existing, req).await;
    }

    let openapi_yaml = req.openapi.as_deref().ok_or_else(|| {
        AppError::BadRequest("updating a standalone template requires `openapi`".into())
    })?;
    let (mut doc, def) =
        parse_normalize_compile_and_check_disclose(openapi_yaml, state.registry.vars())
            .map_err(|report| AppError::TemplateValidationFailed { report })?;

    // Template key cannot change via update — the unique index pins it.
    if def.key != existing.key {
        return Err(AppError::BadRequest(format!(
            "template key cannot change (existing: {:?}, new: {:?})",
            existing.key, def.key
        )));
    }

    // Preserve system-managed MCP discovery state across YAML edits.
    // Admins authoring the template in the editor don't hand-edit
    // x-overslash-mcp.discovered_tools / discovered_at — those are owned
    // by the resync flow. Wiping them on update would silently invalidate
    // every discovered-only tool until the admin hits resync again.
    if let Some(existing_doc) = &existing.openapi {
        preserve_mcp_discovered_fields(existing_doc, &mut doc);
    }

    let input = UpdateServiceTemplate {
        display_name: Some(&def.display_name),
        description: Some(def.description.as_deref().unwrap_or("")),
        category: Some(def.category.as_deref().unwrap_or("")),
        hosts: Some(&def.hosts),
        openapi: Some(doc),
        key: None,
        delta: None,
    };

    let row = service_template::update(state.db(&ext), id, &input)
        .await?
        .ok_or_else(|| AppError::NotFound("template not found".into()))?;

    let tier = if row.owner_identity_id.is_some() {
        "user"
    } else {
        "org"
    };

    let _ = overslash_db::OrgScope::new(acl.org_id, state.db_pool(&ext))
        .log_audit(AuditEntry {
            org_id: acl.org_id,
            identity_id: acl.identity_id,
            action: "template.updated",
            resource_type: Some("template"),
            resource_id: Some(row.id),
            detail: serde_json::json!({
                "key": &row.key,
                "tier": tier,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    crate::services::embedding_backfill::refresh_template(
        state.db(&ext),
        state.embedder.as_ref(),
        tier,
        Some(acl.org_id),
        row.owner_identity_id,
        &def,
    )
    .await;

    Ok(Json(db_row_to_detail(&state, &ext, row, tier).await?))
}

/// Update a **derived** layer's delta. Re-validates the new delta against the
/// (live) base and rejects an invalid one; `extends` is never changed.
async fn update_derived_layer(
    state: &AppState,
    ext: &axum::http::Extensions,
    acl: &crate::extractors::OrgAcl,
    ip: ClientIp,
    existing: service_template::ServiceTemplateRow,
    req: UpdateTemplateRequest,
) -> Result<Json<TemplateDetail>> {
    if req.openapi.is_some() {
        return Err(AppError::BadRequest(
            "a derived layer is edited via `delta`, not `openapi`".into(),
        ));
    }
    let delta_value = req
        .delta
        .ok_or_else(|| AppError::BadRequest("updating a derived layer requires `delta`".into()))?;
    let delta: Delta = serde_json::from_value(delta_value.clone())
        .map_err(|e| AppError::BadRequest(format!("malformed delta: {e}")))?;

    let extends = existing
        .extends
        .as_deref()
        .expect("derived layer has extends");
    let base = crate::services::template_resolve::resolve(
        state.db(ext),
        &state.registry,
        acl.org_id,
        existing.owner_identity_id,
        extends,
    )
    .await?;
    let report = service_layer::validate_delta(
        &delta,
        &base.definition,
        existing.owner_identity_id.is_some(),
    );
    if !report.valid {
        return Err(AppError::TemplateValidationFailed { report });
    }

    let input = UpdateServiceTemplate {
        display_name: None,
        description: None,
        category: None,
        hosts: None,
        openapi: None,
        key: None,
        delta: Some(delta_value),
    };
    let row = service_template::update(state.db(ext), existing.id, &input)
        .await?
        .ok_or_else(|| AppError::NotFound("template not found".into()))?;

    let tier = if row.owner_identity_id.is_some() {
        "user"
    } else {
        "org"
    };
    let _ = overslash_db::OrgScope::new(acl.org_id, state.db_pool(ext))
        .log_audit(AuditEntry {
            org_id: acl.org_id,
            identity_id: acl.identity_id,
            action: "template.updated",
            resource_type: Some("template"),
            resource_id: Some(row.id),
            detail: serde_json::json!({ "key": &row.key, "tier": tier, "extends": &row.extends }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;
    refresh_layer_embeddings(state, ext, &row, tier).await;

    Ok(Json(db_row_to_detail(state, ext, row, tier).await?))
}

/// Delete a DB-stored template by id (cannot delete global templates).
///
/// Only operates on `status='active'` rows. Drafts are deleted via the
/// dedicated `DELETE /v1/templates/drafts/{id}` endpoint so the audit trail
/// records `template.draft.discarded` (not `template.deleted`) and so the
/// active-template delete SQL can safely add `AND status='active'` without
/// blocking legitimate draft cleanup.
pub(super) async fn delete_template(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    // Multi-tenancy guard + status filter. Status filter pushes draft rows
    // to the dedicated endpoint so a caller who knows a draft's UUID can't
    // destroy it through here (and bypass the draft-audit action label).
    let existing = service_template::get_by_id(state.db(&ext), id)
        .await?
        .filter(|r| r.org_id == acl.org_id && r.status == "active")
        .ok_or_else(|| AppError::NotFound("template not found".into()))?;

    let owner_identity_id = existing.owner_identity_id;
    // Ownership check + delete live in `platform_templates` so the MCP
    // `delete_template` kernel and this HTTP handler stay in sync.
    let (key, tier, _) =
        delete_active_template_inner(state.db(&ext), existing, acl.identity_id, acl.access_level)
            .await?;

    let _ = overslash_db::OrgScope::new(acl.org_id, state.db_pool(&ext))
        .log_audit(AuditEntry {
            org_id: acl.org_id,
            identity_id: acl.identity_id,
            action: "template.deleted",
            resource_type: Some("template"),
            resource_id: Some(id),
            detail: serde_json::json!({
                "key": &key,
                "tier": tier,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    crate::services::embedding_backfill::delete_template_embeddings(
        state.db(&ext),
        tier,
        Some(acl.org_id),
        owner_identity_id,
        &key,
    )
    .await;

    Ok(Json(serde_json::json!({ "deleted": true })))
}
