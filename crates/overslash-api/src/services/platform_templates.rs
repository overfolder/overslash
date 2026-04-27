use std::collections::HashSet;

use serde_json::Value;
use uuid::Uuid;

use overslash_core::openapi;
use overslash_db::repos::{enabled_global_template, org as org_repo, service_template};

use super::platform_caller::PlatformCallContext;
use crate::error::AppError;

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
    let rows = service_template::list_available(&ctx.db, ctx.org_id, Some(ctx.identity_id)).await?;
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
    if user_templates_allowed {
        if let Some(t) =
            service_template::get_by_key(&ctx.db, ctx.org_id, Some(ctx.identity_id), &key).await?
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
        let allowed = org_repo::get_allow_user_templates(&ctx.db, ctx.org_id)
            .await?
            .unwrap_or(false);
        if !allowed {
            return Err(AppError::Forbidden(
                "user templates are not enabled for this org".into(),
            ));
        }
        Some(ctx.identity_id)
    } else {
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

// ─── helpers ──────────────────────────────────────────────────────────────────

async fn load_global_filter(
    db: &sqlx::PgPool,
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

fn template_row_to_value(
    t: service_template::ServiceTemplateRow,
    tier: &str,
) -> Result<Value, AppError> {
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
