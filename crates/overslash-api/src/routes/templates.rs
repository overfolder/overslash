use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, put},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_core::types::Risk;
use overslash_db::repos::service_template::{self, CreateServiceTemplate, UpdateServiceTemplate};

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::AuthContext,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/templates", get(list_templates).post(create_template))
        .route("/v1/templates/search", get(search_templates))
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
    auth: Vec<serde_json::Value>,
    actions: serde_json::Value,
    tier: String,
    /// DB id for org/user templates; None for global.
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<Uuid>,
}

#[derive(Serialize)]
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
    key: String,
    display_name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    hosts: Vec<String>,
    #[serde(default)]
    auth: serde_json::Value,
    #[serde(default)]
    actions: serde_json::Value,
    /// If true, create as a user-level template (requires identity-bound key).
    #[serde(default)]
    user_level: bool,
}

#[derive(Deserialize)]
struct UpdateTemplateRequest {
    display_name: Option<String>,
    description: Option<String>,
    category: Option<String>,
    hosts: Option<Vec<String>>,
    auth: Option<serde_json::Value>,
    actions: Option<serde_json::Value>,
}

// -- Handlers --

/// List all templates visible to the caller: global + org + user tiers merged.
async fn list_templates(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<Vec<TemplateSummary>>> {
    let mut templates = Vec::new();

    // Global tier (in-memory registry)
    for svc in state.registry.all() {
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
    let db_templates =
        service_template::list_available(&state.db, auth.org_id, auth.identity_id).await?;
    for t in db_templates {
        let actions: serde_json::Map<String, serde_json::Value> =
            serde_json::from_value(t.actions).unwrap_or_default();
        let tier = if t.owner_identity_id.is_some() {
            "user"
        } else {
            "org"
        };
        templates.push(TemplateSummary {
            key: t.key,
            display_name: t.display_name,
            description: Some(t.description).filter(|s| !s.is_empty()),
            category: Some(t.category).filter(|s| !s.is_empty()),
            hosts: t.hosts,
            action_count: actions.len(),
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

    // Search global tier
    for svc in state.registry.search(&params.q) {
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
    let db_templates =
        service_template::list_available(&state.db, auth.org_id, auth.identity_id).await?;
    for t in db_templates {
        if t.key.to_lowercase().contains(&q)
            || t.display_name.to_lowercase().contains(&q)
            || t.description.to_lowercase().contains(&q)
        {
            let actions: serde_json::Map<String, serde_json::Value> =
                serde_json::from_value(t.actions).unwrap_or_default();
            let tier = if t.owner_identity_id.is_some() {
                "user"
            } else {
                "org"
            };
            results.push(TemplateSummary {
                key: t.key,
                display_name: t.display_name,
                description: Some(t.description).filter(|s| !s.is_empty()),
                category: Some(t.category).filter(|s| !s.is_empty()),
                hosts: t.hosts,
                action_count: actions.len(),
                tier: tier.into(),
            });
        }
    }

    Ok(Json(results))
}

/// Get a specific template by key, resolving through tier hierarchy:
/// user (if identity) → org → global.
async fn get_template(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(key): Path<String>,
) -> Result<Json<TemplateDetail>> {
    // Try user tier first
    if let Some(identity_id) = auth.identity_id {
        if let Some(t) =
            service_template::get_by_key(&state.db, auth.org_id, Some(identity_id), &key).await?
        {
            return Ok(Json(db_template_to_detail(t, "user")));
        }
    }

    // Try org tier
    if let Some(t) = service_template::get_by_key(&state.db, auth.org_id, None, &key).await? {
        return Ok(Json(db_template_to_detail(t, "org")));
    }

    // Try global tier
    let svc = state
        .registry
        .get(&key)
        .ok_or_else(|| AppError::NotFound(format!("template '{key}' not found")))?;

    Ok(Json(TemplateDetail {
        key: svc.key.clone(),
        display_name: svc.display_name.clone(),
        description: svc.description.clone(),
        category: svc.category.clone(),
        hosts: svc.hosts.clone(),
        auth: serde_json::to_value(&svc.auth)
            .unwrap_or_default()
            .as_array()
            .cloned()
            .unwrap_or_default(),
        actions: serde_json::to_value(&svc.actions).unwrap_or_default(),
        tier: "global".into(),
        id: None,
    }))
}

/// List actions for a template.
async fn list_template_actions(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(key): Path<String>,
) -> Result<Json<Vec<ActionSummary>>> {
    // Resolve the template (same hierarchy as get_template)
    let actions = resolve_template_actions(&state, &auth, &key).await?;
    Ok(Json(actions))
}

/// Create a new org or user template.
async fn create_template(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(req): Json<CreateTemplateRequest>,
) -> Result<Json<TemplateDetail>> {
    let owner_identity_id = if req.user_level {
        Some(auth.identity_id.ok_or_else(|| {
            AppError::BadRequest("user-level templates require an identity-bound API key".into())
        })?)
    } else {
        None
    };

    // Check that key doesn't collide with a global template
    if state.registry.get(&req.key).is_some() {
        return Err(AppError::Conflict(format!(
            "template key '{}' conflicts with a global template",
            req.key
        )));
    }

    let input = CreateServiceTemplate {
        org_id: auth.org_id,
        owner_identity_id,
        key: &req.key,
        display_name: &req.display_name,
        description: &req.description,
        category: &req.category,
        hosts: &req.hosts,
        auth: if req.auth.is_null() {
            serde_json::Value::Array(vec![])
        } else {
            req.auth
        },
        actions: if req.actions.is_null() {
            serde_json::Value::Object(Default::default())
        } else {
            req.actions
        },
    };

    let row = service_template::create(&state.db, &input)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.constraint().is_some() {
                    return AppError::Conflict(format!(
                        "template key '{}' already exists",
                        req.key
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
    Ok(Json(db_template_to_detail(row, tier)))
}

/// Update a DB-stored template by id.
async fn update_template(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateTemplateRequest>,
) -> Result<Json<TemplateDetail>> {
    // Multi-tenancy guard.
    service_template::get_by_id(&state.db, id)
        .await?
        .filter(|r| r.org_id == auth.org_id)
        .ok_or_else(|| AppError::NotFound("template not found".into()))?;

    let input = UpdateServiceTemplate {
        display_name: req.display_name.as_deref(),
        description: req.description.as_deref(),
        category: req.category.as_deref(),
        hosts: req.hosts.as_deref(),
        auth: req.auth,
        actions: req.actions,
    };

    let row = service_template::update(&state.db, id, &input)
        .await?
        .ok_or_else(|| AppError::NotFound("template not found".into()))?;

    let tier = if row.owner_identity_id.is_some() {
        "user"
    } else {
        "org"
    };
    Ok(Json(db_template_to_detail(row, tier)))
}

/// Delete a DB-stored template by id (cannot delete global templates).
async fn delete_template(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    // Multi-tenancy guard.
    service_template::get_by_id(&state.db, id)
        .await?
        .filter(|r| r.org_id == auth.org_id)
        .ok_or_else(|| AppError::NotFound("template not found".into()))?;

    let deleted = service_template::delete(&state.db, id).await?;
    if !deleted {
        return Err(AppError::NotFound("template not found".into()));
    }
    Ok(Json(serde_json::json!({ "deleted": true })))
}

// -- Helpers --

fn db_template_to_detail(t: service_template::ServiceTemplateRow, tier: &str) -> TemplateDetail {
    TemplateDetail {
        key: t.key,
        display_name: t.display_name,
        description: Some(t.description).filter(|s| !s.is_empty()),
        category: Some(t.category).filter(|s| !s.is_empty()),
        hosts: t.hosts,
        auth: t.auth.as_array().cloned().unwrap_or_default(),
        actions: t.actions,
        tier: tier.into(),
        id: Some(t.id),
    }
}

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
            return Ok(actions_from_json(&t.actions));
        }
    }

    // Try org tier
    if let Some(t) = service_template::get_by_key(&state.db, auth.org_id, None, key).await? {
        return Ok(actions_from_json(&t.actions));
    }

    // Try global
    let svc = state
        .registry
        .get(key)
        .ok_or_else(|| AppError::NotFound(format!("template '{key}' not found")))?;

    Ok(svc
        .actions
        .iter()
        .map(|(k, a)| ActionSummary {
            key: k.clone(),
            method: a.method.clone(),
            path: a.path.clone(),
            description: a.description.clone(),
            risk: a.risk,
        })
        .collect())
}

fn actions_from_json(actions: &serde_json::Value) -> Vec<ActionSummary> {
    let map: serde_json::Map<String, serde_json::Value> =
        serde_json::from_value(actions.clone()).unwrap_or_default();
    map.into_iter()
        .map(|(k, v)| ActionSummary {
            key: k,
            method: v["method"].as_str().unwrap_or("GET").to_string(),
            path: v["path"].as_str().unwrap_or("").to_string(),
            description: v["description"].as_str().unwrap_or("").to_string(),
            risk: serde_json::from_value(v["risk"].clone()).unwrap_or_default(),
        })
        .collect()
}

/// Resolve a ServiceDefinition from a template key across all tiers.
/// Used by action execution when resolving through a service instance.
pub(crate) async fn resolve_template_definition(
    state: &AppState,
    org_id: Uuid,
    identity_id: Option<Uuid>,
    key: &str,
) -> Result<overslash_core::types::ServiceDefinition> {
    // Try user tier
    if let Some(identity_id) = identity_id {
        if let Some(t) =
            service_template::get_by_key(&state.db, org_id, Some(identity_id), key).await?
        {
            return db_row_to_definition(t);
        }
    }

    // Try org tier
    if let Some(t) = service_template::get_by_key(&state.db, org_id, None, key).await? {
        return db_row_to_definition(t);
    }

    // Try global
    state
        .registry
        .get(key)
        .cloned()
        .ok_or_else(|| AppError::NotFound(format!("template '{key}' not found")))
}

fn db_row_to_definition(
    t: service_template::ServiceTemplateRow,
) -> Result<overslash_core::types::ServiceDefinition> {
    use overslash_core::types::{ServiceAction, ServiceAuth, ServiceDefinition};
    use std::collections::HashMap;

    let auth: Vec<ServiceAuth> = serde_json::from_value(t.auth).unwrap_or_default();
    let actions: HashMap<String, ServiceAction> =
        serde_json::from_value(t.actions).unwrap_or_default();

    Ok(ServiceDefinition {
        key: t.key,
        display_name: t.display_name,
        description: Some(t.description).filter(|s| !s.is_empty()),
        category: Some(t.category).filter(|s| !s.is_empty()),
        hosts: t.hosts,
        auth,
        actions,
    })
}
