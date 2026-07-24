//! OpenAPI import + draft lifecycle (import / list / get / update /
//! promote / discard).

use super::fetch::fetch_openapi_url;
use super::*;

// -- OpenAPI import / draft endpoints --

/// Source for `POST /v1/templates/import`.
///
/// Deserialized as a tagged enum so the client explicitly picks one of:
/// - `{"type": "url", "url": "https://..."}` — fetch with SSRF guards
/// - `{"type": "body", "content_type": "application/yaml", "body": "..."}` —
///   inline paste / file contents. `content_type` is an optional hint; if
///   omitted, JSON vs YAML is detected heuristically.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ImportSource {
    Url {
        url: String,
    },
    Body {
        #[serde(default)]
        content_type: Option<String>,
        body: String,
    },
}

#[derive(Deserialize)]
pub(super) struct ImportTemplateRequest {
    source: ImportSource,
    /// Keep only the listed operationIds (or synthesized ids) as actions.
    /// When omitted, every operation in the source becomes an action.
    #[serde(default)]
    include_operations: Option<Vec<String>>,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    user_level: bool,
    /// If set, replace the source of an existing draft instead of creating a
    /// new one. The caller must own the draft (same rules as PUT).
    #[serde(default)]
    draft_id: Option<Uuid>,
}

#[derive(Deserialize)]
pub(super) struct UpdateDraftRequest {
    openapi: String,
}

/// Compiled preview of a draft. Mirrors [`TemplateDetail`] but without an `id`
/// (draft id is at the top level of [`DraftTemplateDetail`]) and with the
/// compile view split out so it can be `None` when the draft doesn't yet
/// compile cleanly.
#[derive(Serialize)]
struct TemplatePreview {
    key: String,
    display_name: String,
    description: Option<String>,
    category: Option<String>,
    hosts: Vec<String>,
    auth: Vec<serde_json::Value>,
    actions: Vec<ActionSummary>,
}

#[derive(Serialize)]
pub(super) struct DraftTemplateDetail {
    id: Uuid,
    tier: String,
    /// Canonical OpenAPI 3.1 YAML, ready to drop straight into the dashboard
    /// editor. Round-trips through serde_yaml so aliases have been normalized
    /// to their `x-overslash-*` form.
    openapi: String,
    /// May be `None` if the draft doesn't yet compile into a ServiceDefinition
    /// (e.g., missing operationId on an action, unknown auth type). The
    /// editor surfaces `validation.errors` in that case.
    preview: Option<TemplatePreview>,
    validation: ValidationReport,
    /// Non-fatal feedback from the import pipeline (dropped features,
    /// derived keys, unresolved refs, HTTP warning, …).
    import_warnings: Vec<ImportWarning>,
    /// All operations discovered in the *original* source, with an `included`
    /// flag reflecting the current filter. Surfaces in the dashboard as a
    /// checkbox tree so users can refine selection without re-running import.
    operations: Vec<OperationInfo>,
}

/// POST /v1/templates/import
///
/// Fetch or accept an OpenAPI 3.x spec and persist it as a draft template.
/// Returns a [`platform_templates::DraftDetail`] with the canonicalized YAML,
/// a compile preview, validation report, import warnings, and the full list
/// of operations from the source (with `included` reflecting the filter).
///
/// The draft lives in `service_templates` with `status='draft'` and is
/// invisible to runtime lookups. Promote via
/// `POST /v1/templates/drafts/{id}/promote`.
///
/// The actual import pipeline lives in
/// [`platform_templates::kernel_import_template`] — this handler only
/// resolves the source (URL fetch or inline body) and writes the audit row.
pub(super) async fn import_template(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    Json(req): Json<ImportTemplateRequest>,
) -> Result<Json<platform_templates::DraftDetail>> {
    let (bytes, content_type_hint, fetch_warnings) = match req.source {
        ImportSource::Url { url } => fetch_openapi_url(&url).await?,
        ImportSource::Body { content_type, body } => {
            if body.len() > MAX_TEMPLATE_YAML_BYTES {
                return Err(AppError::BadRequest(format!(
                    "source too large: {} bytes (max {MAX_TEMPLATE_YAML_BYTES})",
                    body.len()
                )));
            }
            (body.into_bytes(), content_type, Vec::new())
        }
    };

    let include_operations = req
        .include_operations
        .clone()
        .map(|v| v.into_iter().collect::<HashSet<_>>());
    let operations_selected = include_operations.as_ref().map(|s| s.len());
    let opts = ImportOptions {
        include_operations,
        key: req.key,
        display_name: req.display_name,
    };

    let ctx = crate::services::platform_caller::PlatformCallContext {
        org_id: acl.org_id,
        // Pass the Option through so the kernel can enforce
        // "user-level requires identity-bound key" with a clean 400 instead
        // of a 500 from a nil-uuid FK violation.
        identity_id: acl.identity_id,
        access_level: acl.access_level,
        db: state.db_pool(&ext),
        registry: std::sync::Arc::clone(&state.registry),
        config: state.config.clone(),
        http_client: state.http_client.clone(),
    };
    let detail = kernel_import_template(
        ctx,
        bytes,
        content_type_hint,
        opts,
        req.user_level,
        req.draft_id,
        fetch_warnings,
    )
    .await?;

    let _ = overslash_db::OrgScope::new(acl.org_id, state.db_pool(&ext))
        .log_audit(AuditEntry {
            org_id: acl.org_id,
            identity_id: acl.identity_id,
            action: "template.draft.imported",
            resource_type: Some("template"),
            resource_id: Some(detail.id),
            detail: serde_json::json!({
                "key": &detail.key,
                "tier": &detail.tier,
                "owner_identity_id": detail.owner_identity_id,
                "operations_selected": operations_selected,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(detail))
}

/// GET /v1/templates/drafts
pub(super) async fn list_drafts(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(acl): WriteAcl,
) -> Result<Json<Vec<DraftTemplateDetail>>> {
    // Admins see every draft in the org (both org-level and all users').
    // Non-admins only see drafts they own — org-level drafts are
    // admin-read/write per `load_draft_for_write`, so listing them to a
    // non-admin would invite a 403 on click-through. Matches the SPEC's
    // "org drafts for admins, user drafts for their owner".
    let rows = if acl.access_level >= AccessLevel::Admin {
        service_template::list_all_drafts_in_org(state.db(&ext), acl.org_id).await?
    } else if let Some(identity_id) = acl.identity_id {
        service_template::list_user_drafts(state.db(&ext), acl.org_id, identity_id).await?
    } else {
        Vec::new()
    };
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(row_to_draft_detail(row));
    }
    Ok(Json(out))
}

/// GET /v1/templates/drafts/{id}
pub(super) async fn get_draft(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(acl): WriteAcl,
    Path(id): Path<Uuid>,
) -> Result<Json<DraftTemplateDetail>> {
    let row = service_template::get_by_id(state.db(&ext), id)
        .await?
        .filter(|r| r.org_id == acl.org_id && r.status == "draft")
        .ok_or_else(|| AppError::NotFound("draft not found".into()))?;

    // Reads follow the same authorization rules as writes (load_draft_for_write)
    // so admins can preview any draft they're allowed to modify. User-tier
    // drafts remain private to their owner unless the caller is admin.
    if row.owner_identity_id.is_some() {
        if row.owner_identity_id != acl.identity_id && acl.access_level < AccessLevel::Admin {
            return Err(AppError::Forbidden(
                "you can only read your own drafts".into(),
            ));
        }
    } else if acl.access_level < AccessLevel::Admin {
        return Err(AppError::Forbidden(
            "admin access required to read org-level drafts".into(),
        ));
    }
    Ok(Json(row_to_draft_detail(row)))
}

/// PUT /v1/templates/drafts/{id}
///
/// Replace the draft's YAML source. Re-runs the lenient validator so the
/// response mirrors the import-endpoint shape; the draft still persists even
/// if the new source has errors.
pub(super) async fn update_draft(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateDraftRequest>,
) -> Result<Json<DraftTemplateDetail>> {
    let existing = load_draft_for_write(&state, &ext, &acl, id).await?;

    if req.openapi.len() > MAX_TEMPLATE_YAML_BYTES {
        return Err(AppError::BadRequest(format!(
            "draft too large: {} bytes (max {MAX_TEMPLATE_YAML_BYTES})",
            req.openapi.len()
        )));
    }

    // Parse the raw YAML the caller sent (no import pre-processing — this is
    // a direct edit of a document that already went through normalization).
    let doc = openapi::parse_yaml(&req.openapi).map_err(|i| {
        let report = ValidationReport {
            valid: false,
            errors: vec![i],
            warnings: Vec::new(),
        };
        AppError::TemplateValidationFailed { report }
    })?;

    // Run a cheap import pass (no filter, no overrides) purely to surface
    // `info.x-overslash-key` derivation + `$ref` dereferencing for any
    // newly-added refs. This is idempotent on already-canonical documents.
    let prep = prepare_from_value(doc, &ImportOptions::default());
    let (canonical_doc, compiled, validation) = prepare_draft_from_value(prep.doc);
    let canonical_yaml = openapi::to_yaml_string(&canonical_doc).unwrap_or_default();

    let scalars = scalars_from_compiled(compiled.as_ref());

    let update = UpdateServiceTemplate {
        display_name: Some(&scalars.display_name),
        description: Some(&scalars.description),
        category: Some(&scalars.category),
        hosts: Some(&scalars.hosts),
        openapi: Some(canonical_doc),
        key: Some(&scalars.key),
        delta: None,
    };

    let row = service_template::update(state.db(&ext), existing.id, &update)
        .await?
        .ok_or_else(|| AppError::NotFound("draft not found".into()))?;

    let tier = tier_of(&row);

    let _ = overslash_db::OrgScope::new(acl.org_id, state.db_pool(&ext))
        .log_audit(AuditEntry {
            org_id: acl.org_id,
            identity_id: acl.identity_id,
            action: "template.draft.updated",
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

    Ok(Json(DraftTemplateDetail {
        id: row.id,
        tier: tier.into(),
        openapi: canonical_yaml,
        preview: compiled.as_ref().map(preview_from_compiled),
        validation,
        import_warnings: prep.warnings,
        operations: prep.operations,
    }))
}

/// POST /v1/templates/drafts/{id}/promote
///
/// Run the strict validator (`parse_normalize_compile_yaml`) against the
/// draft's stored YAML and, on success, flip `status='draft' → 'active'`.
/// On validation failure, the draft stays as-is and the caller gets
/// `TemplateValidationFailed` with the full report.
pub(super) async fn promote_draft(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<TemplateDetail>> {
    let existing = load_draft_for_write(&state, &ext, &acl, id).await?;

    // Re-serialize the stored doc to YAML and hand it to the strict validator,
    // so promotion uses the exact same code path as `POST /v1/templates`.
    // Drafts are always standalone imports, so `openapi` is present.
    let existing_doc = existing
        .openapi
        .as_ref()
        .ok_or_else(|| AppError::BadRequest("derived layers are not drafted/promoted".into()))?;
    let yaml_source = openapi::to_yaml_string(existing_doc).map_err(|i| {
        AppError::Internal(format!("stored draft serializer failed: {}", i.message))
    })?;
    let (_doc, def) = parse_normalize_compile_and_check_disclose(&yaml_source)
        .map_err(|report| AppError::TemplateValidationFailed { report })?;

    if def.key.is_empty() {
        return Err(AppError::BadRequest(
            "template key is required (set `info.key` or `info.x-overslash-key`) before promoting"
                .into(),
        ));
    }

    // Key collision: refuse if an active template already owns this key at
    // the same tier (global, org, or user). `get_by_key` filters for
    // `status='active'`, and this row is still `status='draft'`, so any
    // match is guaranteed to be a different row — no id comparison needed.
    if state.registry.get(&def.key).is_some() {
        return Err(AppError::Conflict(format!(
            "template key '{}' conflicts with a global template",
            def.key
        )));
    }
    if service_template::get_by_key(
        state.db(&ext),
        acl.org_id,
        existing.owner_identity_id,
        &def.key,
    )
    .await?
    .is_some()
    {
        return Err(AppError::Conflict(format!(
            "template key '{}' is already in use (delete the existing active template first)",
            def.key
        )));
    }

    let promoted = service_template::promote_draft(state.db(&ext), existing.id)
        .await?
        .ok_or_else(|| AppError::NotFound("draft not found".into()))?;

    let tier = tier_of(&promoted);

    let _ = overslash_db::OrgScope::new(acl.org_id, state.db_pool(&ext))
        .log_audit(AuditEntry {
            org_id: acl.org_id,
            identity_id: acl.identity_id,
            action: "template.draft.promoted",
            resource_type: Some("template"),
            resource_id: Some(promoted.id),
            detail: serde_json::json!({
                "key": &promoted.key,
                "tier": tier,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    crate::services::embedding_backfill::refresh_template(
        state.db(&ext),
        state.embedder.as_ref(),
        if tier == "user" { "user" } else { "org" },
        Some(acl.org_id),
        promoted.owner_identity_id,
        &def,
    )
    .await;

    Ok(Json(db_row_to_detail(&state, &ext, promoted, tier).await?))
}

/// DELETE /v1/templates/drafts/{id}
pub(super) async fn discard_draft(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let existing = load_draft_for_write(&state, &ext, &acl, id).await?;
    let key = existing.key.clone();

    // `delete_draft` has `AND status = 'draft'` baked into the SQL. If a
    // concurrent `promote_draft` flipped the row to `'active'` between our
    // load check and this call, the delete matches zero rows and we return
    // 409 rather than destroying an active template. Closes the TOCTOU
    // window on the draft-discard surface.
    let deleted = service_template::delete_draft(state.db(&ext), existing.id).await?;
    if !deleted {
        return Err(AppError::Conflict(
            "draft was promoted concurrently; nothing to discard".into(),
        ));
    }

    let _ = overslash_db::OrgScope::new(acl.org_id, state.db_pool(&ext))
        .log_audit(AuditEntry {
            org_id: acl.org_id,
            identity_id: acl.identity_id,
            action: "template.draft.discarded",
            resource_type: Some("template"),
            resource_id: Some(existing.id),
            detail: serde_json::json!({ "key": key }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(serde_json::json!({ "deleted": true })))
}

// -- Import helpers --

/// Load a draft for a mutating operation, enforcing tenancy + ownership.
/// Thin wrapper around [`load_draft_for_write_inner`].
async fn load_draft_for_write(
    state: &AppState,
    ext: &axum::http::Extensions,
    acl: &crate::extractors::OrgAcl,
    id: Uuid,
) -> Result<service_template::ServiceTemplateRow> {
    load_draft_for_write_inner(
        state.db(ext),
        acl.org_id,
        acl.identity_id,
        acl.access_level,
        id,
    )
    .await
}

fn row_to_draft_detail(row: service_template::ServiceTemplateRow) -> DraftTemplateDetail {
    // Run the import pre-pass first to enumerate operations and capture
    // warnings, then feed its output to the lenient validator. This avoids
    // walking+normalizing the document twice per draft (hot path for
    // `GET /v1/templates/drafts`).
    // Drafts are always standalone imports (they carry an openapi doc, never a
    // delta), so this is present in practice; default defensively.
    let doc = row.openapi.unwrap_or_default();
    let canonical_yaml = openapi::to_yaml_string(&doc).unwrap_or_default();
    let prep = prepare_from_value(doc, &ImportOptions::default());
    let (_canonical_doc, compiled, validation) = prepare_draft_from_value(prep.doc);
    DraftTemplateDetail {
        id: row.id,
        tier: tier_of_parts(row.owner_identity_id).into(),
        openapi: canonical_yaml,
        preview: compiled.as_ref().map(preview_from_compiled),
        validation,
        import_warnings: prep.warnings,
        operations: prep.operations,
    }
}

fn tier_of_parts(owner_identity_id: Option<Uuid>) -> &'static str {
    if owner_identity_id.is_some() {
        "user"
    } else {
        "org"
    }
}

fn tier_of(row: &service_template::ServiceTemplateRow) -> &'static str {
    tier_of_parts(row.owner_identity_id)
}

/// Lift a compiled [`ServiceDefinition`] into the JSON preview the dashboard
/// renders. Done in one place so adding fields doesn't require editing the
/// import, update-draft, and get-draft handlers in sync.
fn preview_from_compiled(def: &ServiceDefinition) -> TemplatePreview {
    TemplatePreview {
        key: def.key.clone(),
        display_name: def.display_name.clone(),
        description: def.description.clone(),
        category: def.category.clone(),
        hosts: def.hosts.clone(),
        auth: serde_json::to_value(&def.auth)
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default(),
        actions: actions_from_definition(def),
    }
}

/// Denormalized scalar columns written into `service_templates`. Strings rather
/// than `Option` because the DB columns are `NOT NULL DEFAULT ''`.
struct DraftScalars {
    key: String,
    display_name: String,
    description: String,
    category: String,
    hosts: Vec<String>,
}

fn scalars_from_compiled(compiled: Option<&ServiceDefinition>) -> DraftScalars {
    DraftScalars {
        key: compiled.map(|d| d.key.clone()).unwrap_or_default(),
        display_name: compiled.map(|d| d.display_name.clone()).unwrap_or_default(),
        description: compiled
            .and_then(|d| d.description.clone())
            .unwrap_or_default(),
        category: compiled
            .and_then(|d| d.category.clone())
            .unwrap_or_default(),
        hosts: compiled.map(|d| d.hosts.clone()).unwrap_or_default(),
    }
}
