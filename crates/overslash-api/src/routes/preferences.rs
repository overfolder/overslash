use axum::{Json, Router, routing::get};
use serde::{Deserialize, Serialize};

use overslash_db::UserScope;

use crate::{
    AppState,
    error::{AppError, Result},
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

fn merge(existing: UserPreferences, patch: UserPreferences) -> UserPreferences {
    UserPreferences {
        time_display: patch.time_display.or(existing.time_display),
        theme: patch.theme.or(existing.theme),
    }
}

async fn get_preferences(scope: UserScope) -> Result<Json<UserPreferences>> {
    let ident = scope
        .get_self_identity()
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
    Ok(Json(parse(&ident.preferences)))
}

async fn put_preferences(
    scope: UserScope,
    Json(patch): Json<UserPreferences>,
) -> Result<Json<UserPreferences>> {
    let updated = scope
        .update_self_preferences(|existing| {
            let merged = merge(parse(existing), patch.clone());
            serde_json::to_value(&merged).unwrap_or(serde_json::Value::Null)
        })
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
    Ok(Json(parse(&updated.preferences)))
}
