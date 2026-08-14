//! Service-template registry endpoints (`/v1/templates`): the catalog
//! read surface, org/user template CRUD, the admin compliance view, and
//! the OpenAPI import / draft lifecycle.

use std::collections::HashSet;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{delete, get, post, put},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_core::openapi::{
    self,
    import::{ImportOptions, ImportWarning, OperationInfo, prepare_from_value},
};
use overslash_core::permissions::AccessLevel;
use overslash_core::service_layer::{self, Delta};
use overslash_core::template_validation::{
    ValidationIssue, ValidationReport, parse_normalize_compile_yaml, prepare_draft_from_value,
    validate_template_yaml,
};
use overslash_core::types::{ActionParam, DeclaredRisk, ScopeParamRef, ServiceDefinition};

use crate::services::icon_url::resolve_icon_url;
use crate::services::platform_services::{ScopeCoverage, ScopeKnowledge, action_scope_coverage};
use crate::services::platform_templates::{
    self, MAX_TEMPLATE_YAML_BYTES, delete_active_template_inner, kernel_import_template,
    load_draft_for_write_inner,
};
use crate::services::response_filter;
use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::service_template::{self, CreateServiceTemplate, UpdateServiceTemplate};
use overslash_db::repos::{enabled_global_template, org as org_repo};

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, AuthContext, ClientIp, ReqExt, WriteAcl},
};

mod admin;
mod drafts;
mod dto;
mod fetch;
mod read;
mod validate;
mod write;

use admin::{
    disable_global_template, enable_global_template, list_enabled_globals, list_templates_admin,
};
use drafts::{discard_draft, get_draft, import_template, list_drafts, promote_draft, update_draft};
use dto::*;
use read::{
    get_template, get_template_action, list_template_actions, list_template_vars, list_templates,
    search_templates,
};
use validate::{validate_delta_route, validate_template};
use write::{create_template, delete_template, update_template};

// The service-instance action listing (`routes::services`) renders the same
// rows as `/v1/templates/{key}/actions`.
pub(crate) use dto::ActionSummary;

/// Run `parse_normalize_compile_yaml` and then validate that every
/// `x-overslash-disclose` filter and `x-overslash-sql-database` expression is
/// a syntactically valid jq expression. jq syntax validation lives in
/// `overslash-api` (jq isn't compiled into `overslash-core` to keep it
/// WASM-friendly), so this is the single gate any register / update /
/// import / promote path must go through.
fn parse_normalize_compile_and_check_disclose(
    yaml: &str,
    vars: &overslash_core::template_vars::Vars,
) -> std::result::Result<(serde_json::Value, ServiceDefinition), ValidationReport> {
    let (doc, def) = parse_normalize_compile_yaml(yaml, vars)?;
    let mut extra = Vec::new();
    for (action_key, action) in &def.actions {
        for (i, f) in action.disclose.iter().enumerate() {
            if let Err(msg) =
                response_filter::validate_syntax(&response_filter::ResponseFilter::Jq {
                    expr: f.filter.clone(),
                })
            {
                extra.push(ValidationIssue::new(
                    "disclose_invalid_jq",
                    format!("filter is not a valid jq expression: {msg}"),
                    format!("actions.{action_key}.disclose[{i}].filter"),
                ));
            }
        }
        for (param_name, param) in &action.params {
            if let Some(expr) = &param.sql_database
                && let Err(msg) =
                    response_filter::validate_syntax(&response_filter::ResponseFilter::Jq {
                        expr: expr.clone(),
                    })
            {
                extra.push(ValidationIssue::new(
                    "sql_database_invalid_jq",
                    format!("x-overslash-sql-database is not a valid jq expression: {msg}"),
                    format!("actions.{action_key}.params.{param_name}.x-overslash-sql-database"),
                ));
            }
        }
    }
    if extra.is_empty() {
        Ok((doc, def))
    } else {
        Err(ValidationReport {
            valid: false,
            errors: extra,
            warnings: Vec::new(),
        })
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/templates", get(list_templates).post(create_template))
        .route("/v1/templates/search", get(search_templates))
        // Fixed-path routes MUST come before the `{key}` wildcard.
        .route("/v1/templates/vars", get(list_template_vars))
        .route("/v1/templates/validate", post(validate_template))
        .route("/v1/templates/validate-delta", post(validate_delta_route))
        .route("/v1/templates/import", post(import_template))
        .route("/v1/templates/drafts", get(list_drafts))
        .route(
            "/v1/templates/drafts/{id}",
            get(get_draft).put(update_draft).delete(discard_draft),
        )
        .route("/v1/templates/drafts/{id}/promote", post(promote_draft))
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
            "/v1/templates/{key}/actions/{action_key}",
            get(get_template_action),
        )
        .route(
            "/v1/templates/{id}/manage",
            put(update_template).delete(delete_template),
        )
}

// -- Helpers --

/// Returns the set of visible global template keys for this org.
/// When `global_templates_enabled` is true, returns `None` (all visible).
/// When false, returns `Some(HashSet)` of explicitly enabled keys.
async fn visible_global_filter(
    state: &AppState,
    ext: &axum::http::Extensions,
    org_id: Uuid,
) -> Result<Option<HashSet<String>>> {
    let enabled = org_repo::get_global_templates_enabled(state.db(ext), org_id)
        .await?
        .unwrap_or(true);
    if enabled {
        return Ok(None);
    }
    let keys = enabled_global_template::list_enabled_keys(state.db(ext), org_id).await?;
    Ok(Some(keys.into_iter().collect()))
}

/// Check whether a single global key is visible.
fn is_global_visible(filter: &Option<HashSet<String>>, key: &str) -> bool {
    match filter {
        None => true,
        Some(set) => set.contains(key),
    }
}

/// Union the OAuth scopes that fully cover this template into a sorted, deduped
/// list — every action's `required_scopes` plus, for MCP-runtime `auth.kind:
/// oauth` templates, the service-level `McpAuth::OAuth { scopes }` (MCP tools
/// carry no per-action scopes). Mirrors `platform_services::template_action_scopes`;
/// surfaced on `TemplateDetail` so white-label partners (token-vault import)
/// request exactly these.
fn template_required_scopes(def: &ServiceDefinition) -> Vec<String> {
    use overslash_core::types::McpAuth;
    let mut scopes: std::collections::BTreeSet<String> = def
        .actions
        .values()
        .flat_map(|a| a.required_scopes.iter().cloned())
        .collect();
    if let Some(McpAuth::OAuth {
        scopes: mcp_scopes, ..
    }) = def.mcp.as_ref().map(|m| &m.auth)
    {
        scopes.extend(mcp_scopes.iter().cloned());
    }
    scopes.into_iter().collect()
}

fn actions_from_definition(def: &ServiceDefinition) -> Vec<ActionSummary> {
    actions_from_definition_inner(def, None)
}

/// Like [`actions_from_definition`] but annotates each scope-bearing action with
/// its coverage against a configured instance's bound connection. Used by
/// `list_service_actions` so an agent sees `needs_reconnect` at discovery time.
pub(crate) fn actions_from_definition_with_coverage(
    def: &ServiceDefinition,
    scopes: ScopeKnowledge<'_>,
) -> Vec<ActionSummary> {
    actions_from_definition_inner(def, Some(scopes))
}

fn actions_from_definition_inner(
    def: &ServiceDefinition,
    scopes: Option<ScopeKnowledge<'_>>,
) -> Vec<ActionSummary> {
    let mut out: Vec<ActionSummary> = def
        .actions
        .iter()
        .map(|(k, a)| {
            // Only scope-bearing (OAuth) actions get a coverage annotation, and
            // only when resolving for a concrete instance.
            let (scope_coverage, missing_scopes) = match scopes {
                Some(knowledge) if !a.required_scopes.is_empty() => {
                    let (c, m) = action_scope_coverage(a, knowledge);
                    (Some(c), m)
                }
                _ => (None, Vec::new()),
            };
            ActionSummary {
                key: k.clone(),
                method: a.method.clone(),
                path: a.path.clone(),
                description: a.description.clone(),
                summary: a.summary.clone(),
                risk: a.risk,
                mcp_tool: a.mcp_tool.clone(),
                output_schema: a.output_schema.clone(),
                disabled: a.disabled,
                scope_coverage,
                missing_scopes,
                wait_mode: a.wait_mode,
            }
        })
        .collect();
    out.sort_by(|a, b| a.key.cmp(&b.key));
    out
}

/// Render a stored template row to its dashboard detail. Resolves through the
/// layered-template fold: a **standalone** layer compiles its own openapi doc; a
/// **derived** layer folds its delta over the live base, so `actions`/`hosts`/
/// `hidden` reflect the effective surface and `resolution_report` carries any
/// drift warnings.
async fn db_row_to_detail(
    state: &AppState,
    ext: &axum::http::Extensions,
    t: service_template::ServiceTemplateRow,
    tier: &str,
) -> Result<TemplateDetail> {
    let resolved =
        crate::services::template_resolve::resolve_row(state.db(ext), &state.registry, &t).await?;
    let def = &resolved.definition;
    // Standalone layers expose their editable OpenAPI YAML; derived layers are
    // edited through their `delta`, so `openapi` is empty for them.
    let openapi_yaml = t
        .openapi
        .as_ref()
        .map(|doc| openapi::to_yaml_string(doc).unwrap_or_default())
        .unwrap_or_default();
    let auth = serde_json::to_value(&def.auth)
        .ok()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    let runtime = runtime_string(def);
    // Build the MCP detail from the *resolved* def so a derived MCP layer (which
    // has no openapi of its own) still returns a `mcp` object consistent with
    // `runtime: "mcp"`. The openapi doc only supplies `discovered_at`; a derived
    // layer has none, so pass `Null` and let it resolve to `None`.
    let mcp_doc = t.openapi.clone().unwrap_or(serde_json::Value::Null);
    let mcp = mcp_detail_from(def, &mcp_doc);
    Ok(TemplateDetail {
        key: t.key,
        display_name: def.display_name.clone(),
        description: def.description.clone().filter(|s| !s.is_empty()),
        category: def.category.clone().filter(|s| !s.is_empty()),
        hosts: def.hosts.clone(),
        icon_url: resolve_icon_url(def.icon.as_ref(), &state.config.public_url),
        auth,
        secrets: def.all_slots(),
        openapi: openapi_yaml,
        actions: actions_from_definition(def),
        scopes: template_required_scopes(def),
        tier: tier.into(),
        id: Some(t.id),
        runtime,
        mcp,
        hidden: def.hidden,
        configurable_url: configurable_url(def),
        instance_config_params: instance_config_params(def),
        instance_defaults: def.instance_defaults.clone(),
        extends: t.extends,
        delta: t.delta,
        resolution_report: ResolutionReport {
            warnings: resolved.warnings,
        },
    })
}

/// Values an org may set per instance, deduped by name.
///
/// A param can appear on several actions (`X-Mailbox-Imap` rides all three
/// email operations); the form shows one field, so the first occurrence wins
/// for type/description and `required` is the AND across occurrences — a pin
/// that is optional anywhere must not be forced on the form. Credential config
/// vars join the same list; a name collision between the two is a template
/// error, so neither can shadow the other here.
fn instance_config_params(def: &ServiceDefinition) -> Vec<InstanceConfigParam> {
    use std::collections::BTreeMap;

    let mut acc: BTreeMap<&str, InstanceConfigParam> = BTreeMap::new();
    for action in def.actions.values() {
        for (name, p) in &action.params {
            if !p.instance_config {
                continue;
            }
            acc.entry(name.as_str())
                .and_modify(|existing| existing.required &= p.required)
                .or_insert_with(|| InstanceConfigParam {
                    name: name.clone(),
                    param_type: p.param_type.clone(),
                    description: p.description.clone(),
                    required: p.required,
                    label: String::new(),
                });
        }
    }
    for var in &def.config {
        acc.entry(var.key.as_str())
            .or_insert_with(|| InstanceConfigParam {
                name: var.key.clone(),
                param_type: "string".to_string(),
                description: var.description.clone(),
                required: var.required,
                label: var.label.clone(),
            });
    }
    acc.into_values().collect()
}

/// True when a service's endpoint URL is set per instance rather than baked
/// into the template: MCP-runtime services (their `mcp.url`) and HTTP gateways
/// that pair a shared org gateway key (`secret_source: org`) with a per-instance
/// credential — e.g. the `email` Mailbox Gateway (overfwd). Drives whether the
/// dashboard shows a URL field on the instance form.
fn configurable_url(def: &ServiceDefinition) -> bool {
    use overslash_core::types::{Runtime, SecretSource, ServiceAuth};
    // A template that names no host has nowhere to send a request until the
    // instance supplies one, so the field is not merely available — it is the
    // only way the instance can work. Covers `servers: []` (telegram, whatsapp)
    // and, since D44, a `${VAR?}` endpoint the deployment left unset
    // (metabase). The `http` pseudo-service is the one host-less template this
    // must not claim: its callers pass a full URL per call.
    (def.hosts.is_empty() && def.key != "http")
        || def.runtime == Runtime::Mcp
        || def.auth.iter().any(|a| {
            matches!(
                a,
                ServiceAuth::Secret {
                    secret_source: SecretSource::Org,
                    ..
                }
            )
        })
}

fn runtime_string(def: &ServiceDefinition) -> String {
    use overslash_core::types::Runtime;
    match def.runtime {
        Runtime::Http => "http".into(),
        Runtime::Mcp => "mcp".into(),
        Runtime::Platform => "platform".into(),
    }
}

fn mcp_detail_from(def: &ServiceDefinition, openapi: &serde_json::Value) -> Option<McpDetail> {
    use overslash_core::types::McpAuth;
    let spec = def.mcp.as_ref()?;
    let (auth_kind, has_default_secret_name, provider, scopes) = match &spec.auth {
        McpAuth::None => ("none".to_string(), false, None, Vec::new()),
        McpAuth::Bearer { secret_name } => (
            "bearer".to_string(),
            secret_name.is_some(),
            None,
            Vec::new(),
        ),
        // OAuth MCP servers don't carry a default secret — auth comes from the
        // caller's connection for the named provider, with these scopes.
        McpAuth::OAuth { provider, scopes } => (
            "oauth".to_string(),
            false,
            Some(provider.clone()),
            scopes.clone(),
        ),
    };
    let discovered_at = openapi
        .get("x-overslash-mcp")
        .and_then(|v| v.get("discovered_at"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    Some(McpDetail {
        url: spec.url.clone(),
        auth_kind,
        has_default_secret_name,
        provider,
        scopes,
        autodiscover: spec.autodiscover,
        discovered_at,
    })
}

/// A stored row summarized through its **effective** (folded) template — the
/// single source of truth for list/search rows. For a derived layer this
/// reflects the live base + delta (so a relabel in the delta, or an upstream
/// base change, is never stale against the denormalized columns); for a
/// standalone layer it equals the compiled openapi. Falls back to the row's
/// denormalized columns if resolution fails.
struct RowSummary {
    display_name: String,
    description: Option<String>,
    category: Option<String>,
    hosts: Vec<String>,
    action_count: usize,
    hidden: bool,
    icon: Option<overslash_core::service_icon::ServiceIcon>,
    warnings: usize,
}

async fn resolved_summary(
    state: &AppState,
    ext: &axum::http::Extensions,
    t: &service_template::ServiceTemplateRow,
) -> RowSummary {
    match crate::services::template_resolve::resolve_row(state.db(ext), &state.registry, t).await {
        Ok(r) => {
            let d = r.definition;
            RowSummary {
                display_name: d.display_name,
                description: d.description.filter(|s| !s.is_empty()),
                category: d.category.filter(|s| !s.is_empty()),
                hosts: d.hosts,
                action_count: d.actions.len(),
                hidden: d.hidden,
                icon: d.icon,
                warnings: r.warnings.len(),
            }
        }
        // Fall back to the denormalized columns so a broken base still lists.
        Err(_) => RowSummary {
            display_name: t.display_name.clone(),
            description: Some(t.description.clone()).filter(|s| !s.is_empty()),
            category: Some(t.category.clone()).filter(|s| !s.is_empty()),
            hosts: t.hosts.clone(),
            action_count: 0,
            hidden: false,
            // The denormalized columns carry no icon, and the letter tile is a
            // more honest rendering of "this template does not resolve" than a
            // mark implying it does.
            icon: None,
            warnings: 0,
        },
    }
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

// -- Shared helpers (used by services routes too) --

/// Resolve template actions across tiers (helper reused by both templates and services routes).
pub(crate) async fn resolve_template_actions(
    state: &AppState,
    ext: &axum::http::Extensions,
    auth: &AuthContext,
    key: &str,
) -> Result<Vec<ActionSummary>> {
    // Resolve through the layered-template fold so a derived layer reports its
    // effective (masked/extended) action set — compiling the row's raw OpenAPI
    // directly would fail on a derived layer, which carries no OpenAPI doc.
    let def = resolve_template_definition(state, ext, auth.org_id, auth.identity_id, key).await?;
    Ok(actions_from_definition(&def))
}

/// Resolve a ServiceDefinition from a template key across all tiers.
/// Used by action execution when resolving through a service instance.
/// NOTE: Does NOT apply global_templates_enabled filtering — hidden globals
/// remain resolvable so existing service instances keep working.
/// Resolve a template key to its effective [`ServiceDefinition`] through the
/// layered-template fold (user → org → global precedence, derived layers folded
/// over their base). Thin wrapper over the shared resolver so every call site
/// reads the same effective surface.
pub(crate) async fn resolve_template_definition(
    state: &AppState,
    ext: &axum::http::Extensions,
    org_id: Uuid,
    identity_id: Option<Uuid>,
    key: &str,
) -> Result<ServiceDefinition> {
    crate::services::template_resolve::resolve_definition(
        state.db(ext),
        &state.registry,
        org_id,
        identity_id,
        key,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    // Shipped global templates never pass through the register/import
    // routes above, so without this test a typo'd disclose filter in
    // services/*.yaml would only surface at approval time in production.
    #[test]
    fn shipped_service_disclose_filters_compile() {
        let services_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("services");
        for entry in std::fs::read_dir(&services_dir).unwrap() {
            let path = entry.unwrap().path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext != "yaml" && ext != "yml" {
                continue;
            }
            let yaml = std::fs::read_to_string(&path).unwrap();
            if let Err(report) = parse_normalize_compile_and_check_disclose(
                &yaml,
                &overslash_core::template_vars::Vars::for_tests(),
            ) {
                panic!(
                    "shipped template {} failed disclose jq validation: {:?}",
                    path.display(),
                    report.errors
                );
            }
        }
    }
}
