use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, header},
    routing::get,
};
use serde::{Deserialize, Serialize};

use overslash_db::repos::identity;

use crate::{
    AppState,
    error::{AppError, Result},
    services::jwt,
};

pub fn router() -> Router<AppState> {
    Router::new().route(
        "/auth/me/preferences",
        get(get_preferences).put(put_preferences),
    )
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct UserPreferences {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_display: Option<String>, // "relative" | "absolute"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub theme: Option<String>, // "light" | "dark" | "system"
}

fn parse(value: &serde_json::Value) -> UserPreferences {
    serde_json::from_value(value.clone()).unwrap_or_default()
}

fn require_session(state: &AppState, headers: &HeaderMap) -> Result<jwt::Claims> {
    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("not authenticated".into()))?;
    let token = cookie_header
        .split(';')
        .find_map(|p| p.trim().strip_prefix("oss_session="))
        .ok_or_else(|| AppError::Unauthorized("not authenticated".into()))?;
    let key = hex::decode(&state.config.signing_key)
        .unwrap_or_else(|_| state.config.signing_key.as_bytes().to_vec());
    jwt::verify(&key, token).map_err(|_| AppError::Unauthorized("invalid session".into()))
}

async fn get_preferences(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<UserPreferences>> {
    let claims = require_session(&state, &headers)?;
    let ident = identity::get_by_id(&state.db, claims.sub)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
    Ok(Json(parse(&ident.preferences)))
}

async fn put_preferences(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(patch): Json<UserPreferences>,
) -> Result<Json<UserPreferences>> {
    let claims = require_session(&state, &headers)?;
    // Atomic server-side merge: avoids the read-modify-write race where two
    // concurrent PUTs could each load the same row and clobber each other.
    let patch_value =
        serde_json::to_value(&patch).map_err(|e| AppError::Internal(format!("serialize: {e}")))?;
    let updated = identity::merge_preferences(&state.db, claims.sub, patch_value)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
    Ok(Json(parse(&updated.preferences)))
}
