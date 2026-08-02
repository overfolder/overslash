//! Read endpoints: list / search / get a template and its actions.

use super::*;

// -- Handlers --

/// List all templates visible to the caller: global (filtered) + org + user tiers merged.
pub(super) async fn list_templates(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: AuthContext,
) -> Result<Json<Vec<TemplateSummary>>> {
    let mut templates = Vec::new();

    let global_filter = visible_global_filter(&state, &ext, auth.org_id).await?;

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
            hidden: svc.hidden,
            extends: None,
            warnings: 0,
        });
    }

    // Org + user tiers (DB)
    let user_templates_allowed = org_repo::get_allow_user_templates(state.db(&ext), auth.org_id)
        .await?
        .unwrap_or(false);
    let db_templates =
        service_template::list_available(state.db(&ext), auth.org_id, auth.identity_id).await?;
    for t in db_templates {
        let is_user_tier = t.owner_identity_id.is_some();
        if is_user_tier && !user_templates_allowed {
            continue;
        }
        let s = resolved_summary(&state, &ext, &t).await;
        let tier = if is_user_tier { "user" } else { "org" };
        templates.push(TemplateSummary {
            key: t.key,
            display_name: s.display_name,
            description: s.description,
            category: s.category,
            hosts: s.hosts,
            action_count: s.action_count,
            tier: tier.into(),
            hidden: s.hidden,
            extends: t.extends,
            warnings: s.warnings,
        });
    }

    Ok(Json(templates))
}

/// GET /v1/templates/vars
///
/// The `${VAR}` references a template authored on this deployment can resolve
/// (D44). Backs the template editor's reference panel: without it an author
/// has to guess names and finds out only when `validate` reports
/// `template_var_unset`.
///
/// Values are returned in the clear to any authenticated caller — see
/// [`TemplateVar`] for why hiding them would buy nothing, and why nothing
/// secret may be configured under this prefix.
pub(super) async fn list_template_vars(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<Vec<TemplateVar>>> {
    // Deployment-scoped, not org-scoped; bound to satisfy the ignored-auth
    // pre-commit gate (see PR #60), as `validate` does.
    let _ = auth.org_id;
    Ok(Json(
        state
            .registry
            .vars()
            .iter()
            .map(|(name, value)| TemplateVar {
                name: name.to_string(),
                value: value.to_string(),
            })
            .collect(),
    ))
}

/// Search templates across all tiers by query string.
pub(super) async fn search_templates(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: AuthContext,
    Query(params): Query<SearchQuery>,
) -> Result<Json<Vec<TemplateSummary>>> {
    let q = params.q.to_lowercase();
    let mut results = Vec::new();

    let global_filter = visible_global_filter(&state, &ext, auth.org_id).await?;

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
            hidden: svc.hidden,
            extends: None,
            warnings: 0,
        });
    }

    // Search DB templates (simple substring match on key/display_name)
    let user_templates_allowed = org_repo::get_allow_user_templates(state.db(&ext), auth.org_id)
        .await?
        .unwrap_or(false);
    let db_templates =
        service_template::list_available(state.db(&ext), auth.org_id, auth.identity_id).await?;
    for t in db_templates {
        let is_user_tier = t.owner_identity_id.is_some();
        if is_user_tier && !user_templates_allowed {
            continue;
        }
        // Match on the effective (resolved) fields, not the possibly-stale
        // denormalized columns, so a derived layer relabeled in its delta is
        // findable by its effective name.
        let s = resolved_summary(&state, &ext, &t).await;
        if t.key.to_lowercase().contains(&q)
            || s.display_name.to_lowercase().contains(&q)
            || s.description
                .as_deref()
                .unwrap_or("")
                .to_lowercase()
                .contains(&q)
        {
            let tier = if is_user_tier { "user" } else { "org" };
            results.push(TemplateSummary {
                key: t.key,
                display_name: s.display_name,
                description: s.description,
                category: s.category,
                hosts: s.hosts,
                action_count: s.action_count,
                tier: tier.into(),
                hidden: s.hidden,
                extends: t.extends,
                warnings: s.warnings,
            });
        }
    }

    Ok(Json(results))
}

/// Get a specific template by key, resolving through tier hierarchy:
/// user (if identity) → org → global (filtered).
pub(super) async fn get_template(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: AuthContext,
    Path(key): Path<String>,
) -> Result<Json<TemplateDetail>> {
    // Try user tier first (only if user templates are enabled)
    if let Some(identity_id) = auth.identity_id {
        let user_templates_allowed =
            org_repo::get_allow_user_templates(state.db(&ext), auth.org_id)
                .await?
                .unwrap_or(false);
        if user_templates_allowed {
            if let Some(t) =
                service_template::get_by_key(state.db(&ext), auth.org_id, Some(identity_id), &key)
                    .await?
            {
                return Ok(Json(db_row_to_detail(&state, &ext, t, "user").await?));
            }
        }
    }

    // Try org tier
    if let Some(t) = service_template::get_by_key(state.db(&ext), auth.org_id, None, &key).await? {
        return Ok(Json(db_row_to_detail(&state, &ext, t, "org").await?));
    }

    // Try global tier (respect visibility filter)
    let global_filter = visible_global_filter(&state, &ext, auth.org_id).await?;
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
    let runtime = runtime_string(svc);
    // Globals ship their tool list in the YAML on disk; discovered_at is
    // never populated on a global (resync is not available).
    let mcp = mcp_detail_from(svc, &serde_json::Value::Null);
    Ok(Json(TemplateDetail {
        key: svc.key.clone(),
        display_name: svc.display_name.clone(),
        description: svc.description.clone(),
        category: svc.category.clone(),
        hosts: svc.hosts.clone(),
        auth,
        secrets: svc.all_slots(),
        openapi: openapi_yaml,
        actions: actions_from_definition(svc),
        scopes: template_required_scopes(svc),
        tier: "global".into(),
        id: None,
        runtime,
        mcp,
        hidden: svc.hidden,
        configurable_url: configurable_url(svc),
        instance_config_params: instance_config_params(svc),
        // A global template is never a layer, so it never carries defaults.
        instance_defaults: None,
        extends: None,
        delta: None,
        resolution_report: ResolutionReport::default(),
    }))
}

/// Resolve visibility for `{key}`-style template lookups: returns 404 if the
/// template resolves to a hidden global, and reports the effective identity
/// to use for further resolution (drops user tier when user templates are
/// disabled org-wide).
async fn ensure_template_visible(
    state: &AppState,
    ext: &axum::http::Extensions,
    auth: &AuthContext,
    key: &str,
) -> Result<Option<Uuid>> {
    let user_templates_allowed = org_repo::get_allow_user_templates(state.db(ext), auth.org_id)
        .await?
        .unwrap_or(false);
    let in_user_tier = user_templates_allowed
        && auth.identity_id.is_some()
        && service_template::get_by_key(state.db(ext), auth.org_id, auth.identity_id, key)
            .await?
            .is_some();
    let in_org_tier = !in_user_tier
        && service_template::get_by_key(state.db(ext), auth.org_id, None, key)
            .await?
            .is_some();

    if !in_user_tier && !in_org_tier {
        let global_filter = visible_global_filter(state, ext, auth.org_id).await?;
        if !is_global_visible(&global_filter, key) {
            return Err(AppError::NotFound(format!("template '{key}' not found")));
        }
    }

    Ok(if user_templates_allowed {
        auth.identity_id
    } else {
        None
    })
}

/// List actions for a template.
pub(super) async fn list_template_actions(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: AuthContext,
    Path(key): Path<String>,
) -> Result<Json<Vec<ActionSummary>>> {
    let effective_identity = ensure_template_visible(&state, &ext, &auth, &key).await?;
    let effective_auth = AuthContext {
        org_id: auth.org_id,
        identity_id: effective_identity,
        key_id: auth.key_id,
        user_id: auth.user_id,
        impersonated_by: auth.impersonated_by,
        mcp_client_id: auth.mcp_client_id.clone(),
    };
    let actions = resolve_template_actions(&state, &ext, &effective_auth, &key).await?;
    Ok(Json(actions))
}

/// Get a single action's full details (including parameter schema) for a
/// template. Used by the API Explorer to auto-generate parameter forms.
pub(super) async fn get_template_action(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: AuthContext,
    Path((key, action_key)): Path<(String, String)>,
) -> Result<Json<ActionDetail>> {
    let effective_identity = ensure_template_visible(&state, &ext, &auth, &key).await?;
    let def =
        resolve_template_definition(&state, &ext, auth.org_id, effective_identity, &key).await?;
    let action = def.actions.get(&action_key).ok_or_else(|| {
        AppError::NotFound(format!(
            "action '{action_key}' not found in template '{key}'"
        ))
    })?;

    Ok(Json(ActionDetail {
        key: action_key,
        method: action.method.clone(),
        path: action.path.clone(),
        description: action.description.clone(),
        summary: action.summary.clone(),
        risk: action.risk,
        params: action.params.clone(),
        scope_param: action.scope_param.refs().to_vec(),
    }))
}
