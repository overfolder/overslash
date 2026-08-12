//! Admin compliance view and the per-org global-template enable list.

use super::*;

// -- Admin endpoints --

/// Admin compliance view: list ALL templates across all tiers.
/// Global templates include an `enabled` flag reflecting the org's setting.
pub(super) async fn list_templates_admin(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    AdminAcl(acl): AdminAcl,
) -> Result<Json<Vec<AdminTemplateSummary>>> {
    let mut templates = Vec::new();

    let globals_on = org_repo::get_global_templates_enabled(state.db(&ext), acl.org_id)
        .await?
        .unwrap_or(true);

    let enabled_keys: HashSet<String> = if globals_on {
        HashSet::new() // not needed when all are on
    } else {
        enabled_global_template::list_enabled_keys(state.db(&ext), acl.org_id)
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
            icon_url: resolve_icon_url(svc.icon.as_ref(), &state.config.public_url),
            id: None,
            owner_identity_id: None,
            enabled,
            hidden: svc.hidden,
            extends: None,
            delta: None,
            warnings: 0,
        });
    }

    // ALL DB templates (org + all users')
    let db_templates = service_template::list_all_by_org(state.db(&ext), acl.org_id).await?;
    for t in db_templates {
        let s = resolved_summary(&state, &ext, &t).await;
        let tier = if t.owner_identity_id.is_some() {
            "user"
        } else {
            "org"
        };
        templates.push(AdminTemplateSummary {
            key: t.key,
            display_name: s.display_name,
            description: s.description,
            category: s.category,
            hosts: s.hosts,
            action_count: s.action_count,
            tier: tier.into(),
            icon_url: resolve_icon_url(s.icon.as_ref(), &state.config.public_url),
            id: Some(t.id),
            owner_identity_id: t.owner_identity_id,
            enabled: true, // org/user templates are always "enabled"
            hidden: s.hidden,
            extends: t.extends,
            delta: t.delta,
            warnings: s.warnings,
        });
    }

    Ok(Json(templates))
}

/// List which global templates are explicitly enabled for this org.
pub(super) async fn list_enabled_globals(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    AdminAcl(acl): AdminAcl,
) -> Result<Json<Vec<String>>> {
    let keys = enabled_global_template::list_enabled_keys(state.db(&ext), acl.org_id).await?;
    Ok(Json(keys))
}

/// Enable a specific global template for this org (relevant when
/// `global_templates_enabled` is off).
pub(super) async fn enable_global_template(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
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

    enabled_global_template::enable(
        state.db(&ext),
        acl.org_id,
        &req.template_key,
        acl.identity_id,
    )
    .await?;

    let _ = overslash_db::OrgScope::new(acl.org_id, state.db_pool(&ext))
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
pub(super) async fn disable_global_template(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    AdminAcl(acl): AdminAcl,
    ip: ClientIp,
    Path(key): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let removed = enabled_global_template::disable(state.db(&ext), acl.org_id, &key).await?;
    if !removed {
        return Err(AppError::NotFound(
            "template was not in the enabled list".into(),
        ));
    }

    let _ = overslash_db::OrgScope::new(acl.org_id, state.db_pool(&ext))
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
