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
#[cfg(test)]
mod unit {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_empty_object_yields_defaults() {
        let p = parse(&json!({}));
        assert!(p.theme.is_none());
        assert!(p.time_display.is_none());
    }

    #[test]
    fn parse_unknown_keys_are_ignored() {
        let p = parse(&json!({ "theme": "dark", "unknown": 42 }));
        assert_eq!(p.theme.as_deref(), Some("dark"));
    }

    #[test]
    fn parse_garbage_value_falls_back_to_defaults() {
        // A non-object (e.g. legacy null) must not panic — it falls back to default.
        let p = parse(&serde_json::Value::Null);
        assert!(p.theme.is_none());
        assert!(p.time_display.is_none());
    }

    #[test]
    fn merge_patch_overrides_existing_keys() {
        let existing = UserPreferences {
            theme: Some("light".into()),
            time_display: Some("relative".into()),
        };
        let patch = UserPreferences {
            theme: Some("dark".into()),
            time_display: None,
        };
        let merged = merge(existing, patch);
        assert_eq!(merged.theme.as_deref(), Some("dark"));
        // Unset patch key keeps the existing value.
        assert_eq!(merged.time_display.as_deref(), Some("relative"));
    }

    #[test]
    fn merge_into_empty_existing_takes_patch() {
        let merged = merge(
            UserPreferences::default(),
            UserPreferences {
                theme: Some("system".into()),
                time_display: Some("absolute".into()),
            },
        );
        assert_eq!(merged.theme.as_deref(), Some("system"));
        assert_eq!(merged.time_display.as_deref(), Some("absolute"));
    }

    #[test]
    fn merge_empty_patch_is_identity() {
        let existing = UserPreferences {
            theme: Some("dark".into()),
            time_display: Some("relative".into()),
        };
        let merged = merge(existing.clone(), UserPreferences::default());
        assert_eq!(merged.theme, existing.theme);
        assert_eq!(merged.time_display, existing.time_display);
    }

    #[test]
    fn serialized_default_omits_none_fields() {
        // skip_serializing_if=Option::is_none means a defaulted prefs blob
        // round-trips as an empty object — important so storing defaults
        // doesn't pollute the JSONB column with explicit nulls.
        let s = serde_json::to_string(&UserPreferences::default()).unwrap();
        assert_eq!(s, "{}");
    }
}
