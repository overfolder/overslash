//! Template resolution helpers: source tier, definition fold, and the
//! OAuth-provider / action-scope readers the kernels drive auto-connect from.

use super::*;

/// Pull the OAuth provider declared on a template's auth schemes, if any.
/// Returns `None` for templates that don't declare an OAuth auth (secret-based
/// only, MCP bearer only, no auth, etc.) — in which case the auto-connect
/// orchestration in `kernel_create_service` is a no-op.
pub(crate) fn template_oauth_provider(def: &ServiceDefinition) -> Option<&str> {
    // HTTP-runtime OAuth scheme first…
    if let Some(provider) = def.auth.iter().find_map(|a| match a {
        ServiceAuth::OAuth { provider, .. } => Some(provider.as_str()),
        _ => None,
    }) {
        return Some(provider);
    }
    // …then an MCP-runtime `auth.kind: oauth` provider — both resolve through
    // the same connection machinery, so auto-connect orchestration, pinned-
    // connection validation, and credentials-status surfacing treat them
    // identically. Covers HubSpot + Slack (remote OAuth MCP servers).
    match def.mcp.as_ref().map(|m| &m.auth) {
        Some(McpAuth::OAuth { provider, .. }) => Some(provider.as_str()),
        _ => None,
    }
}

/// Union the scopes the auto-connect flow should request into a sorted, deduped
/// list. For HTTP-runtime templates this is every action's `required_scopes`.
/// For MCP-runtime `auth.kind: oauth` templates the scopes live at the service
/// level in `McpAuth::OAuth { scopes }` (MCP tools carry no per-action scopes),
/// so include those too — otherwise the connect flow requests an empty scope
/// set and the minted token lacks the permissions every tool needs.
pub(super) fn template_action_scopes(def: &ServiceDefinition) -> Vec<String> {
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

/// Resolve the [`ServiceDefinition`] for a template key through the
/// layered-template fold (user/org/global tiers, derived layers folded over
/// their base). Thin wrapper over the shared resolver.
pub async fn resolve_template_definition(
    db: &sqlx::PgPool,
    registry: &overslash_core::registry::ServiceRegistry,
    org_id: Uuid,
    identity_id: Option<Uuid>,
    key: &str,
) -> Result<ServiceDefinition, AppError> {
    crate::services::template_resolve::resolve_definition(db, registry, org_id, identity_id, key)
        .await
}

/// Determine the template source tier and optional DB template id for a given key.
pub async fn resolve_template_source(
    db: &sqlx::PgPool,
    registry: &overslash_core::registry::ServiceRegistry,
    org_id: Uuid,
    identity_id: Option<Uuid>,
    key: &str,
) -> Result<(String, Option<Uuid>), AppError> {
    if let Some(identity_id) = identity_id {
        if let Some(t) = service_template::get_by_key(db, org_id, Some(identity_id), key).await? {
            return Ok(("user".into(), Some(t.id)));
        }
    }
    if let Some(t) = service_template::get_by_key(db, org_id, None, key).await? {
        return Ok(("org".into(), Some(t.id)));
    }
    if registry.get(key).is_some() {
        return Ok(("global".into(), None));
    }
    Err(AppError::NotFound(format!(
        "template '{key}' not found in any tier"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::platform_services::test_fixtures::*;

    #[test]
    fn mcp_oauth_provider_and_scopes_surface_for_auto_connect() {
        let def = mcp_oauth_template("slack", &["chat:write", "channels:read"]);
        // Provider must resolve so auto-connect / pinned-connection validation fire.
        assert_eq!(template_oauth_provider(&def), Some("slack"));
        // Scopes come from the mcp.auth block, not (empty) per-action scopes —
        // otherwise the connect flow requests nothing and the token is useless.
        assert_eq!(
            template_action_scopes(&def),
            vec!["channels:read".to_string(), "chat:write".to_string()]
        );
    }
}
