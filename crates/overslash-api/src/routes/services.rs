use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use serde::{Deserialize, Serialize};

use overslash_core::types::Risk;

use crate::{AppState, error::Result, extractors::AuthContext};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/services", get(list_services))
        .route("/v1/services/search", get(search_services))
        .route("/v1/services/{key}", get(get_service))
        .route("/v1/services/{key}/actions", get(list_actions))
}

#[derive(Serialize)]
struct ServiceSummary {
    key: String,
    display_name: String,
    hosts: Vec<String>,
    action_count: usize,
}

#[derive(Serialize)]
struct ServiceDetail {
    key: String,
    display_name: String,
    hosts: Vec<String>,
    auth: Vec<serde_json::Value>,
    actions: serde_json::Value,
}

#[derive(Serialize)]
struct ActionSummary {
    key: String,
    method: String,
    path: String,
    description: String,
    risk: Risk,
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
}

async fn list_services(
    State(state): State<AppState>,
    _auth: AuthContext,
) -> Result<Json<Vec<ServiceSummary>>> {
    let services: Vec<ServiceSummary> = state
        .registry
        .all()
        .into_iter()
        .map(|s| ServiceSummary {
            key: s.key.clone(),
            display_name: s.display_name.clone(),
            hosts: s.hosts.clone(),
            action_count: s.actions.len(),
        })
        .collect();
    Ok(Json(services))
}

async fn search_services(
    State(state): State<AppState>,
    _auth: AuthContext,
    Query(params): Query<SearchQuery>,
) -> Result<Json<Vec<ServiceSummary>>> {
    let results: Vec<ServiceSummary> = state
        .registry
        .search(&params.q)
        .into_iter()
        .map(|s| ServiceSummary {
            key: s.key.clone(),
            display_name: s.display_name.clone(),
            hosts: s.hosts.clone(),
            action_count: s.actions.len(),
        })
        .collect();
    Ok(Json(results))
}

async fn get_service(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(key): Path<String>,
) -> Result<Json<ServiceDetail>> {
    let svc = state
        .registry
        .get(&key)
        .ok_or_else(|| crate::error::AppError::NotFound(format!("service '{key}' not found")))?;

    Ok(Json(ServiceDetail {
        key: svc.key.clone(),
        display_name: svc.display_name.clone(),
        hosts: svc.hosts.clone(),
        auth: serde_json::to_value(&svc.auth)
            .unwrap_or_default()
            .as_array()
            .cloned()
            .unwrap_or_default(),
        actions: serde_json::to_value(&svc.actions).unwrap_or_default(),
    }))
}

async fn list_actions(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(key): Path<String>,
) -> Result<Json<Vec<ActionSummary>>> {
    let svc = state
        .registry
        .get(&key)
        .ok_or_else(|| crate::error::AppError::NotFound(format!("service '{key}' not found")))?;

    let actions: Vec<ActionSummary> = svc
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
    Ok(Json(actions))
}
