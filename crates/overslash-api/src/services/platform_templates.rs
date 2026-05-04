use std::collections::HashSet;

use serde::Serialize;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use overslash_core::openapi;
use overslash_core::openapi::import::{
    ImportOptions, ImportWarning, OperationInfo, prepare_import,
};
use overslash_core::permissions::AccessLevel;
use overslash_core::template_validation::{ValidationReport, prepare_draft_from_value};
use overslash_core::types::ServiceDefinition;
use overslash_db::repos::{
    enabled_global_template, org as org_repo,
    service_template::{self, CreateServiceTemplate, ServiceTemplateRow, UpdateServiceTemplate},
};

use super::platform_caller::PlatformCallContext;
use crate::error::AppError;

/// Max body size accepted by import_template / create_template kernels. Mirrors
/// the HTTP-side cap so MCP-bridged calls cannot smuggle larger payloads past
/// the validator.
pub const MAX_TEMPLATE_YAML_BYTES: usize = 512 * 1024;

pub async fn kernel_list_templates(ctx: PlatformCallContext) -> Result<Value, AppError> {
    let global_filter = load_global_filter(&ctx.db, ctx.org_id).await?;

    let mut out = Vec::new();

    for svc in ctx.registry.all() {
        if !is_visible(&global_filter, &svc.key) {
            continue;
        }
        out.push(serde_json::json!({
            "key": svc.key,
            "display_name": svc.display_name,
            "description": svc.description,
            "category": svc.category,
            "hosts": svc.hosts,
            "action_count": svc.actions.len(),
            "tier": "global",
        }));
    }

    let user_templates_allowed = org_repo::get_allow_user_templates(&ctx.db, ctx.org_id)
        .await?
        .unwrap_or(false);
    let rows = service_template::list_available(&ctx.db, ctx.org_id, ctx.identity_id).await?;
    for t in rows {
        let is_user_tier = t.owner_identity_id.is_some();
        if is_user_tier && !user_templates_allowed {
            continue;
        }
        let action_count = openapi::compile_service(&t.openapi)
            .map(|(def, _)| def.actions.len())
            .unwrap_or(0);
        let tier = if is_user_tier { "user" } else { "org" };
        out.push(serde_json::json!({
            "key": t.key,
            "display_name": t.display_name,
            "description": if t.description.is_empty() { Value::Null } else { Value::String(t.description) },
            "category": if t.category.is_empty() { Value::Null } else { Value::String(t.category) },
            "hosts": t.hosts,
            "action_count": action_count,
            "tier": tier,
        }));
    }

    Ok(Value::Array(out))
}

pub async fn kernel_get_template(ctx: PlatformCallContext, key: String) -> Result<Value, AppError> {
    let user_templates_allowed = org_repo::get_allow_user_templates(&ctx.db, ctx.org_id)
        .await?
        .unwrap_or(false);
    // Org-level callers (no identity binding) can only see org/global tier;
    // skip the user-tier lookup when there is no caller identity to look up
    // *for*.
    if user_templates_allowed && let Some(identity_id) = ctx.identity_id {
        if let Some(t) =
            service_template::get_by_key(&ctx.db, ctx.org_id, Some(identity_id), &key).await?
        {
            return template_row_to_value(t, "user");
        }
    }

    if let Some(t) = service_template::get_by_key(&ctx.db, ctx.org_id, None, &key).await? {
        return template_row_to_value(t, "org");
    }

    let global_filter = load_global_filter(&ctx.db, ctx.org_id).await?;
    if !is_visible(&global_filter, &key) {
        return Err(AppError::NotFound(format!("template '{key}' not found")));
    }
    let svc = ctx
        .registry
        .get(&key)
        .ok_or_else(|| AppError::NotFound(format!("template '{key}' not found")))?;

    Ok(serde_json::json!({
        "key": svc.key,
        "display_name": svc.display_name,
        "description": svc.description,
        "category": svc.category,
        "hosts": svc.hosts,
        "action_count": svc.actions.len(),
        "tier": "global",
    }))
}

pub async fn kernel_create_template(
    ctx: PlatformCallContext,
    openapi_yaml: String,
    user_level: bool,
) -> Result<Value, AppError> {
    let owner_identity_id = if user_level {
        let identity_id = ctx.identity_id.ok_or_else(|| {
            AppError::BadRequest("user-level templates require an identity-bound API key".into())
        })?;
        let allowed = org_repo::get_allow_user_templates(&ctx.db, ctx.org_id)
            .await?
            .unwrap_or(false);
        if !allowed {
            return Err(AppError::Forbidden(
                "user templates are not enabled for this org".into(),
            ));
        }
        Some(identity_id)
    } else {
        if ctx.access_level < AccessLevel::Admin {
            return Err(AppError::Forbidden(
                "admin access required to create org-level templates".into(),
            ));
        }
        None
    };

    let (doc, def) =
        overslash_core::template_validation::parse_normalize_compile_yaml(&openapi_yaml)
            .map_err(|report| AppError::TemplateValidationFailed { report })?;

    if def.key.is_empty() {
        return Err(AppError::BadRequest(
            "template key is required (set `info.key` or `info.x-overslash-key`)".into(),
        ));
    }

    if ctx.registry.get(&def.key).is_some() {
        return Err(AppError::Conflict(format!(
            "template key '{}' conflicts with a global template",
            def.key
        )));
    }

    let input = service_template::CreateServiceTemplate {
        org_id: ctx.org_id,
        owner_identity_id,
        key: &def.key,
        display_name: &def.display_name,
        description: def.description.as_deref().unwrap_or(""),
        category: def.category.as_deref().unwrap_or(""),
        hosts: &def.hosts,
        openapi: doc,
        status: "active",
    };

    let row = service_template::create(&ctx.db, &input)
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

    Ok(serde_json::json!({
        "id": row.id,
        "key": row.key,
        "tier": tier,
    }))
}

/// Lenient draft creation. Mirrors the HTTP `import_template` body branch:
/// validates the import pipeline, persists a `status='draft'` row, and returns
/// the canonical YAML + compile preview + warnings for the caller (dashboard
/// editor or MCP agent).
///
/// `extra_warnings` carries warnings produced *before* the kernel runs (e.g.
/// `http_insecure` from the URL fetcher) so they appear on the same payload as
/// the parser's own warnings.
pub async fn kernel_import_template(
    ctx: PlatformCallContext,
    bytes: Vec<u8>,
    content_type_hint: Option<String>,
    opts: ImportOptions,
    user_level: bool,
    draft_id: Option<Uuid>,
    mut extra_warnings: Vec<ImportWarning>,
) -> Result<DraftDetail, AppError> {
    if bytes.len() > MAX_TEMPLATE_YAML_BYTES {
        return Err(AppError::BadRequest(format!(
            "source too large: {} bytes (max {MAX_TEMPLATE_YAML_BYTES})",
            bytes.len()
        )));
    }

    let prepared = prepare_import(&bytes, content_type_hint.as_deref(), &opts).map_err(|i| {
        let report = ValidationReport {
            valid: false,
            errors: vec![i],
            warnings: Vec::new(),
        };
        AppError::TemplateValidationFailed { report }
    })?;
    extra_warnings.extend(prepared.warnings);
    let operations = prepared.operations;

    let (canonical_doc, compiled, validation) = prepare_draft_from_value(prepared.doc);
    let canonical_yaml = openapi::to_yaml_string(&canonical_doc).unwrap_or_default();
    let scalars = scalars_from_compiled(compiled.as_ref());

    let row = if let Some(id) = draft_id {
        let existing =
            load_draft_for_write_inner(&ctx.db, ctx.org_id, ctx.identity_id, ctx.access_level, id)
                .await?;
        let update = UpdateServiceTemplate {
            display_name: Some(&scalars.display_name),
            description: Some(&scalars.description),
            category: Some(&scalars.category),
            hosts: Some(&scalars.hosts),
            openapi: Some(canonical_doc),
            key: Some(&scalars.key),
        };
        service_template::update(&ctx.db, existing.id, &update)
            .await?
            .ok_or_else(|| AppError::NotFound("draft not found".into()))?
    } else {
        let owner_identity_id = resolve_draft_owner_inner(
            &ctx.db,
            ctx.org_id,
            ctx.identity_id,
            ctx.access_level,
            user_level,
        )
        .await?;
        let input = CreateServiceTemplate {
            org_id: ctx.org_id,
            owner_identity_id,
            key: &scalars.key,
            display_name: &scalars.display_name,
            description: &scalars.description,
            category: &scalars.category,
            hosts: &scalars.hosts,
            openapi: canonical_doc,
            status: "draft",
        };
        service_template::create(&ctx.db, &input)
            .await
            .map_err(AppError::Database)?
    };

    let tier = if row.owner_identity_id.is_some() {
        "user"
    } else {
        "org"
    };

    let preview = compiled.as_ref().map(preview_value_from_compiled);

    Ok(DraftDetail {
        id: row.id,
        tier: tier.to_string(),
        openapi: canonical_yaml,
        preview,
        validation,
        import_warnings: extra_warnings,
        operations,
        key: row.key,
        owner_identity_id: row.owner_identity_id,
    })
}

pub async fn kernel_delete_template(
    ctx: PlatformCallContext,
    key: String,
) -> Result<Value, AppError> {
    // User-tier first (only when the caller has an identity binding —
    // org-level keys go straight to the org-tier lookup), then org-tier.
    // Global templates are not deletable through this kernel — they're
    // shipped on disk, not stored in the DB.
    let row = if let Some(identity_id) = ctx.identity_id
        && let Some(t) =
            service_template::get_by_key(&ctx.db, ctx.org_id, Some(identity_id), &key).await?
    {
        Some(t)
    } else {
        service_template::get_by_key(&ctx.db, ctx.org_id, None, &key).await?
    };
    let row = match row {
        Some(r) if r.status == "active" => r,
        _ => {
            if ctx.registry.get(&key).is_some() {
                return Err(AppError::BadRequest(format!(
                    "'{key}' is a global template and cannot be deleted via this action"
                )));
            }
            return Err(AppError::NotFound(format!("template '{key}' not found")));
        }
    };

    let (deleted_key, tier, _id) =
        delete_active_template_inner(&ctx.db, row, ctx.identity_id, ctx.access_level).await?;

    Ok(serde_json::json!({"deleted": true, "key": deleted_key, "tier": tier}))
}

// ─── Shared helpers reused by the HTTP routes/templates.rs handlers ──────────
//
// These are `pub(crate)` because the routes module calls them directly to
// avoid duplicating ownership-check + draft-resolution logic between the HTTP
// (id-based) and MCP (key-based) flows. Keeping them here means there is
// exactly one place where the rules live.

/// Apply ownership rules to an *active* template row and delete it. Returns
/// the deleted row's key and tier so the caller can write the audit log /
/// embedding cleanup with the same shape.
pub(crate) async fn delete_active_template_inner(
    db: &PgPool,
    row: ServiceTemplateRow,
    caller_identity_id: Option<Uuid>,
    access_level: AccessLevel,
) -> Result<(String, &'static str, Uuid), AppError> {
    if row.owner_identity_id.is_some() {
        if row.owner_identity_id != caller_identity_id && access_level < AccessLevel::Admin {
            return Err(AppError::Forbidden(
                "you can only delete your own templates".into(),
            ));
        }
    } else if access_level < AccessLevel::Admin {
        return Err(AppError::Forbidden(
            "admin access required for org-level templates".into(),
        ));
    }
    let tier = if row.owner_identity_id.is_some() {
        "user"
    } else {
        "org"
    };
    let key = row.key.clone();
    let id = row.id;
    let deleted = service_template::delete(db, id).await?;
    if !deleted {
        return Err(AppError::NotFound("template not found".into()));
    }
    Ok((key, tier, id))
}

/// Decide which tier a new draft / template should live in. Mirrors the
/// HTTP handler's `resolve_draft_owner` and `create_template` admin gate.
pub(crate) async fn resolve_draft_owner_inner(
    db: &PgPool,
    org_id: Uuid,
    caller_identity_id: Option<Uuid>,
    access_level: AccessLevel,
    user_level: bool,
) -> Result<Option<Uuid>, AppError> {
    if user_level {
        let identity_id = caller_identity_id.ok_or_else(|| {
            AppError::BadRequest("user-level drafts require an identity-bound API key".into())
        })?;
        let allowed = org_repo::get_allow_user_templates(db, org_id)
            .await?
            .unwrap_or(false);
        if !allowed {
            return Err(AppError::Forbidden(
                "user templates are not enabled for this org".into(),
            ));
        }
        Ok(Some(identity_id))
    } else {
        if access_level < AccessLevel::Admin {
            return Err(AppError::Forbidden(
                "admin access required to create org-level templates".into(),
            ));
        }
        Ok(None)
    }
}

/// Load a draft for a mutating operation, enforcing tenancy + ownership.
pub(crate) async fn load_draft_for_write_inner(
    db: &PgPool,
    org_id: Uuid,
    caller_identity_id: Option<Uuid>,
    access_level: AccessLevel,
    id: Uuid,
) -> Result<ServiceTemplateRow, AppError> {
    let existing = service_template::get_by_id(db, id)
        .await?
        .filter(|r| r.org_id == org_id && r.status == "draft")
        .ok_or_else(|| AppError::NotFound("draft not found".into()))?;

    if existing.owner_identity_id.is_some() {
        if existing.owner_identity_id != caller_identity_id && access_level < AccessLevel::Admin {
            return Err(AppError::Forbidden(
                "you can only modify your own drafts".into(),
            ));
        }
    } else if access_level < AccessLevel::Admin {
        return Err(AppError::Forbidden(
            "admin access required to modify org-level drafts".into(),
        ));
    }
    Ok(existing)
}

/// JSON-shaped draft detail returned from the import/draft kernels and from
/// the HTTP `/v1/templates/import` endpoint. `preview` is intentionally
/// `Option<Value>` (not a typed struct) so the HTTP layer's strongly-typed
/// `TemplatePreview` and the lean kernel build the same wire shape without
/// the kernel having to depend on `routes::templates` types.
///
/// `key` and `owner_identity_id` carry just enough provenance for the HTTP
/// handler's audit row without having to re-query the DB; both are
/// `#[serde(skip)]`'d so the wire format stays a clean superset of what the
/// dashboard's draft editor consumes.
#[derive(Debug, Serialize)]
pub struct DraftDetail {
    pub id: Uuid,
    pub tier: String,
    pub openapi: String,
    pub preview: Option<Value>,
    pub validation: ValidationReport,
    pub import_warnings: Vec<ImportWarning>,
    pub operations: Vec<OperationInfo>,
    #[serde(skip)]
    pub key: String,
    #[serde(skip)]
    pub owner_identity_id: Option<Uuid>,
}

pub(crate) struct DraftScalars {
    pub key: String,
    pub display_name: String,
    pub description: String,
    pub category: String,
    pub hosts: Vec<String>,
}

pub(crate) fn scalars_from_compiled(compiled: Option<&ServiceDefinition>) -> DraftScalars {
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

fn preview_value_from_compiled(def: &ServiceDefinition) -> Value {
    let mut actions: Vec<Value> = def
        .actions
        .iter()
        .map(|(k, a)| {
            let mut obj = serde_json::Map::new();
            obj.insert("key".into(), Value::String(k.clone()));
            obj.insert("method".into(), Value::String(a.method.clone()));
            obj.insert("path".into(), Value::String(a.path.clone()));
            obj.insert("description".into(), Value::String(a.description.clone()));
            obj.insert(
                "risk".into(),
                serde_json::to_value(a.risk).unwrap_or(Value::Null),
            );
            if let Some(t) = &a.mcp_tool {
                obj.insert("mcp_tool".into(), Value::String(t.clone()));
            }
            if let Some(s) = &a.output_schema {
                obj.insert("output_schema".into(), s.clone());
            }
            if a.disabled {
                obj.insert("disabled".into(), Value::Bool(true));
            }
            Value::Object(obj)
        })
        .collect();
    actions.sort_by(|a, b| {
        a.get("key")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .cmp(b.get("key").and_then(|v| v.as_str()).unwrap_or(""))
    });

    let auth = serde_json::to_value(&def.auth)
        .ok()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();

    serde_json::json!({
        "key": def.key,
        "display_name": def.display_name,
        "description": def.description,
        "category": def.category,
        "hosts": def.hosts,
        "auth": auth,
        "actions": actions,
    })
}

// ─── private helpers ──────────────────────────────────────────────────────────

async fn load_global_filter(
    db: &PgPool,
    org_id: Uuid,
) -> Result<Option<HashSet<String>>, AppError> {
    let enabled = org_repo::get_global_templates_enabled(db, org_id)
        .await?
        .unwrap_or(true);
    if enabled {
        return Ok(None);
    }
    let keys = enabled_global_template::list_enabled_keys(db, org_id).await?;
    Ok(Some(keys.into_iter().collect()))
}

fn is_visible(filter: &Option<HashSet<String>>, key: &str) -> bool {
    match filter {
        None => true,
        Some(set) => set.contains(key),
    }
}

fn template_row_to_value(t: ServiceTemplateRow, tier: &str) -> Result<Value, AppError> {
    let action_count = openapi::compile_service(&t.openapi)
        .map(|(def, _)| def.actions.len())
        .unwrap_or(0);
    Ok(serde_json::json!({
        "id": t.id,
        "key": t.key,
        "display_name": t.display_name,
        "description": if t.description.is_empty() { Value::Null } else { Value::String(t.description) },
        "category": if t.category.is_empty() { Value::Null } else { Value::String(t.category) },
        "hosts": t.hosts,
        "action_count": action_count,
        "tier": tier,
    }))
}
