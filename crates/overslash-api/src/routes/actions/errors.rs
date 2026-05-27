//! Structured error builders with caller-visible instance hints.

use axum::http::StatusCode;
use uuid::Uuid;

use overslash_db::scopes::OrgScope;

use crate::error::AppError;

use super::*;

/// Compute the set of org-level service ids the caller's ceiling user can
/// see — mirrors the visibility filter applied by `routes/search.rs` and
/// `routes/services.rs::list_services`. Returning `None` (when the call
/// has no identity) preserves the existing org-key-bypasses-groups
/// behavior. The error helpers must apply this filter so we never leak
/// instance names the caller couldn't otherwise see.
pub(super) async fn caller_visible_instance_ids(
    scope: &OrgScope,
    ceiling_user_id: Option<Uuid>,
) -> Result<Option<Vec<Uuid>>, AppError> {
    Ok(match ceiling_user_id {
        Some(c) => Some(scope.get_visible_service_ids(c).await?),
        None => None,
    })
}

/// List up to `ERROR_INSTANCE_HINT_CAP` active instance names that share the
/// given template key and are visible to the caller (group ceiling
/// applied). Used to populate the `available_instances` field on
/// `ServiceResolution` errors so the agent can pick a callable name
/// without re-running search.
pub(super) async fn instance_names_for_template(
    scope: &OrgScope,
    identity_id: Option<Uuid>,
    ceiling_user_id: Option<Uuid>,
    template_key: &str,
) -> Result<Vec<String>, AppError> {
    let visible_ids = caller_visible_instance_ids(scope, ceiling_user_id).await?;
    let rows = scope
        .list_available_service_instances_with_groups(
            identity_id,
            ceiling_user_id,
            visible_ids.as_deref(),
        )
        .await?;
    Ok(rows
        .into_iter()
        .filter(|r| r.status == "active" && r.template_key == template_key)
        .map(|r| r.name)
        .take(ERROR_INSTANCE_HINT_CAP)
        .collect())
}

/// List up to `ERROR_INSTANCE_HINT_CAP` active instance names visible to the
/// caller (group ceiling applied), regardless of template. Used when the
/// supplied service name matches no template at all — gives the agent a
/// starting point.
pub(super) async fn caller_visible_instance_names(
    scope: &OrgScope,
    identity_id: Option<Uuid>,
    ceiling_user_id: Option<Uuid>,
) -> Result<Vec<String>, AppError> {
    let visible_ids = caller_visible_instance_ids(scope, ceiling_user_id).await?;
    let rows = scope
        .list_available_service_instances_with_groups(
            identity_id,
            ceiling_user_id,
            visible_ids.as_deref(),
        )
        .await?;
    Ok(rows
        .into_iter()
        .filter(|r| r.status == "active")
        .map(|r| r.name)
        .take(ERROR_INSTANCE_HINT_CAP)
        .collect())
}

/// Resolve the right `ServiceResolution` error for an MCP runtime that
/// couldn't find a `url` or `secret_name`. Two distinct cases:
///
/// 1. **Instance found but misconfigured.** The caller passed a real
///    instance name; that instance just lacks the field. Tell the caller
///    to fix the instance — don't pretend they confused a template for an
///    instance.
/// 2. **No instance, template requires per-instance config.** This is the
///    common case the user complained about: agent passed `whatsapp`
///    instead of `whatsapp_angel`. Surface the template's instances so
///    the agent can pick one.
pub(super) async fn mcp_missing_config_error(
    scope: &OrgScope,
    identity_id: Option<Uuid>,
    ceiling_user_id: Option<Uuid>,
    service_key: &str,
    instance: Option<&overslash_db::repos::service_instance::ServiceInstanceRow>,
    missing_field: &'static str,
) -> AppError {
    if let Some(inst) = instance {
        // Look up siblings under the same template so the hint can suggest
        // a different instance if this one is broken.
        let siblings = match instance_names_for_template(
            scope,
            identity_id,
            ceiling_user_id,
            &inst.template_key,
        )
        .await
        {
            Ok(names) => names.into_iter().filter(|n| n != &inst.name).collect(),
            Err(_) => Vec::new(),
        };
        let extra = if siblings.is_empty() {
            String::new()
        } else {
            format!(
                " Other instances of template '{}': {}.",
                inst.template_key,
                siblings.join(", ")
            )
        };
        return AppError::ServiceResolution {
            status: StatusCode::BAD_REQUEST,
            message: format!(
                "instance '{}' is missing `{missing_field}` configuration. \
                 Set `{missing_field}` on the instance, or pick a different instance.{extra}",
                inst.name
            ),
            matched_template: Some(inst.template_key.clone()),
            available_instances: siblings,
            hint: Some(format!(
                "Each MCP instance must carry its own `{missing_field}`; the template doesn't supply one."
            )),
        };
    }

    let available = instance_names_for_template(scope, identity_id, ceiling_user_id, service_key)
        .await
        .unwrap_or_default();
    template_without_instance_error(service_key, available)
}

pub(super) fn template_without_instance_error(
    template_key: &str,
    available: Vec<String>,
) -> AppError {
    let message = if available.is_empty() {
        format!(
            "'{template_key}' is a service template, not a configured instance, \
             and no instances are configured for this caller. Use \
             overslash_auth.create_service_from_template to set one up."
        )
    } else {
        format!(
            "'{template_key}' is a service template, not a configured instance. \
             Pass an instance name as `service` (e.g. one of: {}). Run \
             overslash_search to discover instances.",
            available.join(", ")
        )
    };
    AppError::ServiceResolution {
        status: StatusCode::BAD_REQUEST,
        message,
        matched_template: Some(template_key.to_string()),
        available_instances: available,
        hint: Some(
            "The `service` argument must be an instance name (e.g. 'gmail_work'), not a template key.".to_string(),
        ),
    }
}

pub(super) fn unknown_service_error(service_key: &str, available: Vec<String>) -> AppError {
    let message = if available.is_empty() {
        format!(
            "no service or instance named '{service_key}', and no instances are \
             configured for this caller. Use overslash_search to discover \
             services or overslash_auth.create_service_from_template to set one up."
        )
    } else {
        format!(
            "no service or instance named '{service_key}'. Available instances \
             include: {}. Run overslash_search to discover more.",
            available.join(", ")
        )
    };
    AppError::ServiceResolution {
        status: StatusCode::NOT_FOUND,
        message,
        matched_template: None,
        available_instances: available,
        hint: Some(
            "The `service` argument must match an instance name visible to the caller.".to_string(),
        ),
    }
}
