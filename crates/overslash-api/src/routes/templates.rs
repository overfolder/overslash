use std::collections::HashSet;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{delete, get, post, put},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_core::openapi;
use overslash_core::permissions::AccessLevel;
use overslash_core::template_validation::{
    ValidationReport, parse_normalize_compile_yaml, validate_template_yaml,
};
use overslash_core::types::{Risk, ServiceDefinition};
use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::service_template::{self, CreateServiceTemplate, UpdateServiceTemplate};
use overslash_db::repos::{enabled_global_template, org as org_repo};

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, AuthContext, ClientIp, WriteAcl},
};

/// Max body size accepted by `POST /v1/templates/validate`. 512 KiB is roughly
/// 4x the largest shipped template and several orders of magnitude above any
/// plausible hand-authored one — enough headroom for auto-generated specs
/// without leaving a DoS-friendly validation endpoint wide open.
const MAX_TEMPLATE_YAML_BYTES: usize = 512 * 1024;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/templates", get(list_templates).post(create_template))
        .route("/v1/templates/search", get(search_templates))
        // Fixed-path routes MUST come before the `{key}` wildcard.
        .route("/v1/templates/validate", post(validate_template))
        .route("/v1/templates/admin", get(list_templates_admin))
        .route(
            "/v1/templates/enabled-globals",
            get(list_enabled_globals).post(enable_global_template),
        )
        .route(
            "/v1/templates/enabled-globals/{key}",
            delete(disable_global_template),
        )
        .route("/v1/templates/{key}", get(get_template))
        .route("/v1/templates/{key}/actions", get(list_template_actions))
        .route(
            "/v1/templates/{id}/manage",
            put(update_template).delete(delete_template),
        )
}

// -- Response types --

#[derive(Serialize)]
struct TemplateSummary {
    key: String,
    display_name: String,
    description: Option<String>,
    category: Option<String>,
    hosts: Vec<String>,
    action_count: usize,
    tier: String,
}

#[derive(Serialize)]
struct TemplateDetail {
    key: String,
    display_name: String,
    description: Option<String>,
    category: Option<String>,
    hosts: Vec<String>,
    /// Compiled auth view for the dashboard's connect flows.
    auth: Vec<serde_json::Value>,
    /// Canonical OpenAPI 3.1 YAML source — the editable document. For DB
    /// templates this is the stored, alias-normalized text. For global
    /// templates it's the shipped YAML verbatim.
    openapi: String,
    /// Compiled actions view for rendering the service detail page without
    /// re-parsing on the client.
    actions: Vec<ActionSummary>,
    tier: String,
    /// DB id for org/user templates; None for global.
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<Uuid>,
}

#[derive(Serialize)]
struct AdminTemplateSummary {
    key: String,
    display_name: String,
    description: Option<String>,
    category: Option<String>,
    hosts: Vec<String>,
    action_count: usize,
    tier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_identity_id: Option<Uuid>,
    /// For global templates: whether the template is explicitly enabled
    /// when `global_templates_enabled` is off. Always `true` for org/user tiers.
    enabled: bool,
}

#[derive(Serialize, Clone)]
pub(crate) struct ActionSummary {
    key: String,
    method: String,
    path: String,
    description: String,
    risk: Risk,
}

// -- Request types --

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
}

#[derive(Deserialize)]
struct CreateTemplateRequest {
    /// Raw OpenAPI 3.1 YAML source. Must include `info.key` (or
    /// `info.x-overslash-key`) as the template key and enough structure to
    /// compile a service definition.
    openapi: String,
    /// If true, create as a user-level template (requires identity-bound key).
    #[serde(default)]
    user_level: bool,
}

#[derive(Deserialize)]
struct UpdateTemplateRequest {
    /// Replacement OpenAPI 3.1 YAML source. The template `key` must match the
    /// existing template's key — it cannot be changed via update.
    openapi: String,
}

#[derive(Deserialize)]
struct EnableGlobalRequest {
    template_key: String,
}

// -- Helpers --

/// Returns the set of visible global template keys for this org.
/// When `global_templates_enabled` is true, returns `None` (all visible).
/// When false, returns `Some(HashSet)` of explicitly enabled keys.
async fn visible_global_filter(state: &AppState, org_id: Uuid) -> Result<Option<HashSet<String>>> {
    let enabled = org_repo::get_global_templates_enabled(&state.db, org_id)
        .await?
        .unwrap_or(true);
    if enabled {
        return Ok(None);
    }
    let keys = enabled_global_template::list_enabled_keys(&state.db, org_id).await?;
    Ok(Some(keys.into_iter().collect()))
}

/// Check whether a single global key is visible.
fn is_global_visible(filter: &Option<HashSet<String>>, key: &str) -> bool {
    match filter {
        None => true,
        Some(set) => set.contains(key),
    }
}

fn actions_from_definition(def: &ServiceDefinition) -> Vec<ActionSummary> {
    let mut out: Vec<ActionSummary> = def
        .actions
        .iter()
        .map(|(k, a)| ActionSummary {
            key: k.clone(),
            method: a.method.clone(),
            path: a.path.clone(),
            description: a.description.clone(),
            risk: a.risk,
        })
        .collect();
    out.sort_by(|a, b| a.key.cmp(&b.key));
    out
}

fn db_row_to_detail(t: service_template::ServiceTemplateRow, tier: &str) -> Result<TemplateDetail> {
    // Re-compile the stored openapi doc to produce the actions summary for
    // the dashboard. The stored doc is already normalized on write, so
    // compile should not surface new issues.
    let def = compile_row(&t)?;
    let openapi_yaml = openapi::to_yaml_string(&t.openapi).unwrap_or_default();
    let auth = serde_json::to_value(&def.auth)
        .ok()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    Ok(TemplateDetail {
        key: t.key,
        display_name: t.display_name,
        description: Some(t.description).filter(|s| !s.is_empty()),
        category: Some(t.category).filter(|s| !s.is_empty()),
        hosts: t.hosts,
        auth,
        openapi: openapi_yaml,
        actions: actions_from_definition(&def),
        tier: tier.into(),
        id: Some(t.id),
    })
}

fn compile_row(t: &service_template::ServiceTemplateRow) -> Result<ServiceDefinition> {
    let (def, _warnings) = openapi::compile_service(&t.openapi).map_err(|errors| {
        AppError::Internal(format!(
            "stored openapi for '{}' failed to compile: {:?}",
            t.key, errors
        ))
    })?;
    Ok(def)
}

// -- Handlers --

/// List all templates visible to the caller: global (filtered) + org + user tiers merged.
async fn list_templates(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<Vec<TemplateSummary>>> {
    let mut templates = Vec::new();

    let global_filter = visible_global_filter(&state, auth.org_id).await?;

    // Global tier (in-memory registry, filtered by org setting)
    for svc in state.registry.all() {
        if !is_global_visible(&global_filter, &svc.key) {
            continue;
        }
        templates.push(TemplateSummary {
            key: svc.key.clone(),
            display_name: svc.display_name.clone(),
            description: svc.description.clone(),
            category: svc.category.clone(),
            hosts: svc.hosts.clone(),
            action_count: svc.actions.len(),
            tier: "global".into(),
        });
    }

    // Org + user tiers (DB)
    let user_templates_allowed = org_repo::get_allow_user_templates(&state.db, auth.org_id)
        .await?
        .unwrap_or(false);
    let db_templates =
        service_template::list_available(&state.db, auth.org_id, auth.identity_id).await?;
    for t in db_templates {
        let is_user_tier = t.owner_identity_id.is_some();
        if is_user_tier && !user_templates_allowed {
            continue;
        }
        let action_count = openapi::compile_service(&t.openapi)
            .map(|(def, _)| def.actions.len())
            .unwrap_or(0);
        let tier = if is_user_tier { "user" } else { "org" };
        templates.push(TemplateSummary {
            key: t.key,
            display_name: t.display_name,
            description: Some(t.description).filter(|s| !s.is_empty()),
            category: Some(t.category).filter(|s| !s.is_empty()),
            hosts: t.hosts,
            action_count,
            tier: tier.into(),
        });
    }

    Ok(Json(templates))
}

/// Search templates across all tiers by query string.
async fn search_templates(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(params): Query<SearchQuery>,
) -> Result<Json<Vec<TemplateSummary>>> {
    let q = params.q.to_lowercase();
    let mut results = Vec::new();

    let global_filter = visible_global_filter(&state, auth.org_id).await?;

    // Search global tier
    for svc in state.registry.search(&params.q) {
        if !is_global_visible(&global_filter, &svc.key) {
            continue;
        }
        results.push(TemplateSummary {
            key: svc.key.clone(),
            display_name: svc.display_name.clone(),
            description: svc.description.clone(),
            category: svc.category.clone(),
            hosts: svc.hosts.clone(),
            action_count: svc.actions.len(),
            tier: "global".into(),
        });
    }

    // Search DB templates (simple substring match on key/display_name)
    let user_templates_allowed = org_repo::get_allow_user_templates(&state.db, auth.org_id)
        .await?
        .unwrap_or(false);
    let db_templates =
        service_template::list_available(&state.db, auth.org_id, auth.identity_id).await?;
    for t in db_templates {
        let is_user_tier = t.owner_identity_id.is_some();
        if is_user_tier && !user_templates_allowed {
            continue;
        }
        if t.key.to_lowercase().contains(&q)
            || t.display_name.to_lowercase().contains(&q)
            || t.description.to_lowercase().contains(&q)
        {
            let action_count = openapi::compile_service(&t.openapi)
                .map(|(def, _)| def.actions.len())
                .unwrap_or(0);
            let tier = if is_user_tier { "user" } else { "org" };
            results.push(TemplateSummary {
                key: t.key,
                display_name: t.display_name,
                description: Some(t.description).filter(|s| !s.is_empty()),
                category: Some(t.category).filter(|s| !s.is_empty()),
                hosts: t.hosts,
                action_count,
                tier: tier.into(),
            });
        }
    }

    Ok(Json(results))
}

/// Get a specific template by key, resolving through tier hierarchy:
/// user (if identity) → org → global (filtered).
async fn get_template(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(key): Path<String>,
) -> Result<Json<TemplateDetail>> {
    // Try user tier first (only if user templates are enabled)
    if let Some(identity_id) = auth.identity_id {
        let user_templates_allowed = org_repo::get_allow_user_templates(&state.db, auth.org_id)
            .await?
            .unwrap_or(false);
        if user_templates_allowed {
            if let Some(t) =
                service_template::get_by_key(&state.db, auth.org_id, Some(identity_id), &key)
                    .await?
            {
                return Ok(Json(db_row_to_detail(t, "user")?));
            }
        }
    }

    // Try org tier
    if let Some(t) = service_template::get_by_key(&state.db, auth.org_id, None, &key).await? {
        return Ok(Json(db_row_to_detail(t, "org")?));
    }

    // Try global tier (respect visibility filter)
    let global_filter = visible_global_filter(&state, auth.org_id).await?;
    if !is_global_visible(&global_filter, &key) {
        return Err(AppError::NotFound(format!("template '{key}' not found")));
    }

    let svc = state
        .registry
        .get(&key)
        .ok_or_else(|| AppError::NotFound(format!("template '{key}' not found")))?;

    // For global templates, load the shipped YAML verbatim for the editor.
    // Falls back to an empty string if the file is not present (read-only
    // view still works via the compiled actions list).
    let openapi_yaml = load_global_yaml(&svc.key).unwrap_or_default();

    let auth = serde_json::to_value(&svc.auth)
        .ok()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    Ok(Json(TemplateDetail {
        key: svc.key.clone(),
        display_name: svc.display_name.clone(),
        description: svc.description.clone(),
        category: svc.category.clone(),
        hosts: svc.hosts.clone(),
        auth,
        openapi: openapi_yaml,
        actions: actions_from_definition(svc),
        tier: "global".into(),
        id: None,
    }))
}

/// Read the shipped OpenAPI YAML for a global template off disk, if present.
fn load_global_yaml(key: &str) -> Option<String> {
    // Walk upward from the executable dir to find `services/{key}.yaml`.
    // Works in both `cargo run` and installed-binary contexts.
    let services_dir = std::env::var_os("OVERSLASH_SERVICES_DIR")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::current_dir().ok().map(|p| p.join("services")))?;
    let path = services_dir.join(format!("{key}.yaml"));
    std::fs::read_to_string(&path).ok()
}

/// List actions for a template.
async fn list_template_actions(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(key): Path<String>,
) -> Result<Json<Vec<ActionSummary>>> {
    // Check if the template would be visible (same rules as get_template).
    let user_templates_allowed = org_repo::get_allow_user_templates(&state.db, auth.org_id)
        .await?
        .unwrap_or(false);
    let in_user_tier = user_templates_allowed
        && auth.identity_id.is_some()
        && service_template::get_by_key(&state.db, auth.org_id, auth.identity_id, &key)
            .await?
            .is_some();
    let in_org_tier = !in_user_tier
        && service_template::get_by_key(&state.db, auth.org_id, None, &key)
            .await?
            .is_some();

    if !in_user_tier && !in_org_tier {
        // Would resolve to global — check visibility
        let global_filter = visible_global_filter(&state, auth.org_id).await?;
        if !is_global_visible(&global_filter, &key) {
            return Err(AppError::NotFound(format!("template '{key}' not found")));
        }
    }

    // When user templates are disabled, mask identity so resolve skips user tier.
    let effective_auth = if user_templates_allowed {
        auth.clone()
    } else {
        AuthContext {
            org_id: auth.org_id,
            identity_id: None,
            key_id: auth.key_id,
        }
    };
    let actions = resolve_template_actions(&state, &effective_auth, &key).await?;
    Ok(Json(actions))
}

/// POST /v1/templates/validate
///
/// Lint an OpenAPI 3.1 template definition without persisting it. Accepts the
/// raw YAML as the request body (any Content-Type; typically
/// `application/yaml` or `text/plain`) so dashboards and CLIs can pipe files
/// directly:
///
/// ```sh
/// curl --data-binary @service.yaml $API/v1/templates/validate
/// ```
///
/// Always returns 200 with a `ValidationReport`. A YAML parse failure, alias
/// ambiguity, or duplicate operationId is itself a reported validation error,
/// not a transport-level error — the dashboard editor calls this on every
/// keystroke and wants structured diagnostics, not HTTP 400s.
async fn validate_template(auth: AuthContext, body: String) -> Result<Json<ValidationReport>> {
    // Auth extraction enforces authentication. Template linting is stateless
    // and org-independent — the org_id is used only for tracing / rate-limit
    // bucketing at the middleware layer. Binding it here satisfies the
    // ignored-auth pre-commit gate (see PR #60).
    let _ = auth.org_id;

    if body.len() > MAX_TEMPLATE_YAML_BYTES {
        return Err(AppError::BadRequest(format!(
            "template too large: {} bytes (max {MAX_TEMPLATE_YAML_BYTES})",
            body.len()
        )));
    }
    Ok(Json(validate_template_yaml(&body)))
}

/// Create a new org or user template.
async fn create_template(
    State(state): State<AppState>,
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    Json(req): Json<CreateTemplateRequest>,
) -> Result<Json<TemplateDetail>> {
    let owner_identity_id = if req.user_level {
        // User-level: need identity + org setting check
        let identity_id = acl.identity_id.ok_or_else(|| {
            AppError::BadRequest("user-level templates require an identity-bound API key".into())
        })?;
        let allowed = org_repo::get_allow_user_templates(&state.db, acl.org_id)
            .await?
            .unwrap_or(false);
        if !allowed {
            return Err(AppError::Forbidden(
                "user templates are not enabled for this org".into(),
            ));
        }
        Some(identity_id)
    } else {
        // Org-level: require admin
        if acl.access_level < AccessLevel::Admin {
            return Err(AppError::Forbidden(
                "admin access required to create org-level templates".into(),
            ));
        }
        None
    };

    let (doc, def) = parse_normalize_compile_yaml(&req.openapi)
        .map_err(|report| AppError::TemplateValidationFailed { report })?;

    if def.key.is_empty() {
        return Err(AppError::BadRequest(
            "template key is required (set `info.key` or `info.x-overslash-key`)".into(),
        ));
    }

    // Check that key doesn't collide with a global template
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
        openapi: doc,
    };

    let row = service_template::create(&state.db, &input)
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

    let _ = overslash_db::OrgScope::new(acl.org_id, state.db.clone())
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
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(db_row_to_detail(row, tier)?))
}

/// Update a DB-stored template by id.
async fn update_template(
    State(state): State<AppState>,
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateTemplateRequest>,
) -> Result<Json<TemplateDetail>> {
    // Multi-tenancy guard + ownership check.
    let existing = service_template::get_by_id(&state.db, id)
        .await?
        .filter(|r| r.org_id == acl.org_id)
        .ok_or_else(|| AppError::NotFound("template not found".into()))?;

    if existing.owner_identity_id.is_some() {
        // User-level: caller must own it or be admin
        if existing.owner_identity_id != acl.identity_id && acl.access_level < AccessLevel::Admin {
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

    let (doc, def) = parse_normalize_compile_yaml(&req.openapi)
        .map_err(|report| AppError::TemplateValidationFailed { report })?;

    // Template key cannot change via update — the unique index pins it.
    if def.key != existing.key {
        return Err(AppError::BadRequest(format!(
            "template key cannot change (existing: {:?}, new: {:?})",
            existing.key, def.key
        )));
    }

    let input = UpdateServiceTemplate {
        display_name: Some(&def.display_name),
        description: Some(def.description.as_deref().unwrap_or("")),
        category: Some(def.category.as_deref().unwrap_or("")),
        hosts: Some(&def.hosts),
        openapi: Some(doc),
    };

    let row = service_template::update(&state.db, id, &input)
        .await?
        .ok_or_else(|| AppError::NotFound("template not found".into()))?;

    let tier = if row.owner_identity_id.is_some() {
        "user"
    } else {
        "org"
    };

    let _ = overslash_db::OrgScope::new(acl.org_id, state.db.clone())
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

    Ok(Json(db_row_to_detail(row, tier)?))
}

/// Delete a DB-stored template by id (cannot delete global templates).
async fn delete_template(
    State(state): State<AppState>,
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    // Multi-tenancy guard + ownership check.
    let existing = service_template::get_by_id(&state.db, id)
        .await?
        .filter(|r| r.org_id == acl.org_id)
        .ok_or_else(|| AppError::NotFound("template not found".into()))?;

    if existing.owner_identity_id.is_some() {
        // User-level: caller must own it or be admin
        if existing.owner_identity_id != acl.identity_id && acl.access_level < AccessLevel::Admin {
            return Err(AppError::Forbidden(
                "you can only delete your own templates".into(),
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

    let tier = if existing.owner_identity_id.is_some() {
        "user"
    } else {
        "org"
    };
    let key = existing.key.clone();

    let deleted = service_template::delete(&state.db, id).await?;
    if !deleted {
        return Err(AppError::NotFound("template not found".into()));
    }

    let _ = overslash_db::OrgScope::new(acl.org_id, state.db.clone())
        .log_audit(AuditEntry {
            org_id: acl.org_id,
            identity_id: acl.identity_id,
            action: "template.deleted",
            resource_type: Some("template"),
            resource_id: Some(id),
            detail: serde_json::json!({
                "key": key,
                "tier": tier,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(serde_json::json!({ "deleted": true })))
}

// -- Admin endpoints --

/// Admin compliance view: list ALL templates across all tiers.
/// Global templates include an `enabled` flag reflecting the org's setting.
async fn list_templates_admin(
    State(state): State<AppState>,
    AdminAcl(acl): AdminAcl,
) -> Result<Json<Vec<AdminTemplateSummary>>> {
    let mut templates = Vec::new();

    let globals_on = org_repo::get_global_templates_enabled(&state.db, acl.org_id)
        .await?
        .unwrap_or(true);

    let enabled_keys: HashSet<String> = if globals_on {
        HashSet::new() // not needed when all are on
    } else {
        enabled_global_template::list_enabled_keys(&state.db, acl.org_id)
            .await?
            .into_iter()
            .collect()
    };

    // Global tier — show all, with enabled flag
    for svc in state.registry.all() {
        let enabled = globals_on || enabled_keys.contains(&svc.key);
        templates.push(AdminTemplateSummary {
            key: svc.key.clone(),
            display_name: svc.display_name.clone(),
            description: svc.description.clone(),
            category: svc.category.clone(),
            hosts: svc.hosts.clone(),
            action_count: svc.actions.len(),
            tier: "global".into(),
            id: None,
            owner_identity_id: None,
            enabled,
        });
    }

    // ALL DB templates (org + all users')
    let db_templates = service_template::list_all_by_org(&state.db, acl.org_id).await?;
    for t in db_templates {
        let action_count = openapi::compile_service(&t.openapi)
            .map(|(def, _)| def.actions.len())
            .unwrap_or(0);
        let tier = if t.owner_identity_id.is_some() {
            "user"
        } else {
            "org"
        };
        templates.push(AdminTemplateSummary {
            key: t.key,
            display_name: t.display_name,
            description: Some(t.description).filter(|s| !s.is_empty()),
            category: Some(t.category).filter(|s| !s.is_empty()),
            hosts: t.hosts,
            action_count,
            tier: tier.into(),
            id: Some(t.id),
            owner_identity_id: t.owner_identity_id,
            enabled: true, // org/user templates are always "enabled"
        });
    }

    Ok(Json(templates))
}

/// List which global templates are explicitly enabled for this org.
async fn list_enabled_globals(
    State(state): State<AppState>,
    AdminAcl(acl): AdminAcl,
) -> Result<Json<Vec<String>>> {
    let keys = enabled_global_template::list_enabled_keys(&state.db, acl.org_id).await?;
    Ok(Json(keys))
}

/// Enable a specific global template for this org (relevant when
/// `global_templates_enabled` is off).
async fn enable_global_template(
    State(state): State<AppState>,
    AdminAcl(acl): AdminAcl,
    ip: ClientIp,
    Json(req): Json<EnableGlobalRequest>,
) -> Result<Json<serde_json::Value>> {
    // Verify the key actually exists in global registry
    if state.registry.get(&req.template_key).is_none() {
        return Err(AppError::NotFound(format!(
            "global template '{}' not found",
            req.template_key
        )));
    }

    enabled_global_template::enable(&state.db, acl.org_id, &req.template_key, acl.identity_id)
        .await?;

    let _ = overslash_db::OrgScope::new(acl.org_id, state.db.clone())
        .log_audit(AuditEntry {
            org_id: acl.org_id,
            identity_id: acl.identity_id,
            action: "template.global.enabled",
            resource_type: Some("template"),
            resource_id: None,
            detail: serde_json::json!({ "template_key": &req.template_key }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(
        serde_json::json!({ "enabled": true, "template_key": req.template_key }),
    ))
}

/// Disable a previously-enabled global template for this org.
async fn disable_global_template(
    State(state): State<AppState>,
    AdminAcl(acl): AdminAcl,
    ip: ClientIp,
    Path(key): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let removed = enabled_global_template::disable(&state.db, acl.org_id, &key).await?;
    if !removed {
        return Err(AppError::NotFound(
            "template was not in the enabled list".into(),
        ));
    }

    let _ = overslash_db::OrgScope::new(acl.org_id, state.db.clone())
        .log_audit(AuditEntry {
            org_id: acl.org_id,
            identity_id: acl.identity_id,
            action: "template.global.disabled",
            resource_type: Some("template"),
            resource_id: None,
            detail: serde_json::json!({ "template_key": &key }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(
        serde_json::json!({ "disabled": true, "template_key": key }),
    ))
}

// -- Shared helpers (used by services routes too) --

/// Resolve template actions across tiers (helper reused by both templates and services routes).
pub(crate) async fn resolve_template_actions(
    state: &AppState,
    auth: &AuthContext,
    key: &str,
) -> Result<Vec<ActionSummary>> {
    // Try user tier
    if let Some(identity_id) = auth.identity_id {
        if let Some(t) =
            service_template::get_by_key(&state.db, auth.org_id, Some(identity_id), key).await?
        {
            let def = compile_row(&t)?;
            return Ok(actions_from_definition(&def));
        }
    }

    // Try org tier
    if let Some(t) = service_template::get_by_key(&state.db, auth.org_id, None, key).await? {
        let def = compile_row(&t)?;
        return Ok(actions_from_definition(&def));
    }

    // Try global
    let svc = state
        .registry
        .get(key)
        .ok_or_else(|| AppError::NotFound(format!("template '{key}' not found")))?;

    Ok(actions_from_definition(svc))
}

/// Resolve a ServiceDefinition from a template key across all tiers.
/// Used by action execution when resolving through a service instance.
/// NOTE: Does NOT apply global_templates_enabled filtering — hidden globals
/// remain resolvable so existing service instances keep working.
pub(crate) async fn resolve_template_definition(
    state: &AppState,
    org_id: Uuid,
    identity_id: Option<Uuid>,
    key: &str,
) -> Result<ServiceDefinition> {
    // Try user tier
    if let Some(identity_id) = identity_id {
        if let Some(t) =
            service_template::get_by_key(&state.db, org_id, Some(identity_id), key).await?
        {
            return compile_row(&t);
        }
    }

    // Try org tier
    if let Some(t) = service_template::get_by_key(&state.db, org_id, None, key).await? {
        return compile_row(&t);
    }

    // Try global
    state
        .registry
        .get(key)
        .cloned()
        .ok_or_else(|| AppError::NotFound(format!("template '{key}' not found")))
}
