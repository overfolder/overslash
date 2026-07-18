//! Effective MCP config resolution — shared by the action exec path and the
//! instance-scoped resync route so the two can't drift.
//!
//! An MCP template (e.g. `telegram`) deliberately omits `url`/`secret_name`
//! and defers them to each service instance (one fast-mcp container per
//! end-user). "Effective" here means: instance value wins, template is the
//! fallback — the same precedence for the URL, the bearer secret, and (for
//! OAuth) which connection mints the token.

use uuid::Uuid;

use overslash_core::types::{AuthHeader, McpAuth, McpSpec, ServiceDefinition};
use overslash_db::repos::connection::ConnectionRow;
use overslash_db::repos::service_instance::ServiceInstanceRow;
use overslash_db::scopes::{OrgScope, UserScope};

use crate::{AppState, error::AppError, services::platform_connections};

use super::auth::resolve_mcp_oauth_bearer;
use super::errors::mcp_missing_config_error;

/// Overlay a service instance's MCP `discovered_tools` onto a compiled
/// [`ServiceDefinition`], in place. No-op when the instance has never been
/// resynced. Applied at every read path that has an instance in scope (actions
/// listing, the call/validate resolver, visibility-scoped search) so the tools
/// discovered on an instance become callable and searchable.
pub(crate) fn overlay_instance_discovered_tools(
    instance: Option<&ServiceInstanceRow>,
    def: &mut ServiceDefinition,
) {
    if let Some(tools) = instance.and_then(|i| i.discovered_tools.as_ref()) {
        overslash_core::openapi::overlay_discovered_tools(def, &tools.0);
    }
}

/// Fully-resolved MCP target: where to connect and how to authenticate.
pub(crate) struct ResolvedMcp {
    /// Effective server URL (instance wins, template fallback).
    pub url: String,
    /// Resolved auth descriptor. For `Bearer`, `secret_name` is the effective
    /// vault key (instance wins); for `OAuth`, the live token rides in
    /// `oauth_header` instead and this just names the provider/scopes.
    pub auth: McpAuth,
    /// Out-of-band bearer for OAuth MCP servers (never persisted). `None` for
    /// `Bearer`/`None` auth, where the header is derived from the vault at
    /// send time.
    pub oauth_header: Option<AuthHeader>,
}

/// Resolve the connection an instance's OAuth actions actually execute against.
///
/// Precedence mirrors the exec-path scope gate (`check_required_scopes`):
/// 1. `instance.connection_id` — an explicit binding wins (org-scoped lookup).
/// 2. `instance.use_default_connection` — fall back to the owner's default
///    connection for the provider.
/// 3. otherwise `None` — the instance opted out of the default fallback and
///    has no explicit binding, so the caller surfaces `needs_authentication`.
///
/// With no instance (`None`), always the owner's default connection — the
/// behavior the replay path relies on.
pub(crate) async fn resolve_instance_connection(
    scope: &OrgScope,
    owner_identity_id: Uuid,
    instance: Option<&ServiceInstanceRow>,
    provider: &str,
) -> Result<Option<ConnectionRow>, AppError> {
    let user_scope = UserScope::new(scope.org_id(), owner_identity_id, scope.db().clone());
    let connection = if let Some(inst) = instance {
        if let Some(conn_id) = inst.connection_id {
            scope.get_connection(conn_id).await?
        } else if inst.use_default_connection {
            user_scope.find_my_connection_by_provider(provider).await?
        } else {
            None
        }
    } else {
        user_scope.find_my_connection_by_provider(provider).await?
    };
    Ok(connection)
}

/// Resolve the effective URL + auth for an MCP call against `instance`.
///
/// - **URL:** `instance.url ?? mcp.url` → else a structured missing-config 400.
/// - **Bearer:** `instance.secret_name ?? template secret_name` → else 400.
/// - **OAuth:** mint a live bearer from the instance's connection (see
///   [`resolve_instance_connection`]); when none exists yet, gate to a fresh
///   auth URL via `needs_authentication` — the same envelope a Try-an-action
///   call produces, so the dashboard's connect flow handles it uniformly.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn resolve_effective_mcp(
    state: &AppState,
    ext: &axum::http::Extensions,
    scope: &OrgScope,
    identity_id: Option<Uuid>,
    ceiling_user_id: Uuid,
    service_key: &str,
    instance: Option<&ServiceInstanceRow>,
    mcp: &McpSpec,
    return_url_hint: Option<&str>,
) -> Result<ResolvedMcp, AppError> {
    // URL: instance wins, template is fallback.
    let url = match instance
        .and_then(|i| i.url.as_deref().map(str::to_string))
        .or_else(|| mcp.url.clone())
    {
        Some(u) => u,
        None => {
            return Err(mcp_missing_config_error(
                scope,
                identity_id,
                Some(ceiling_user_id),
                service_key,
                instance,
                "url",
            )
            .await);
        }
    };

    // Auth: Bearer picks the effective secret_name (instance wins); OAuth
    // resolves a live bearer now, gating when no connection exists yet.
    let mut oauth_header: Option<AuthHeader> = None;
    let auth = match &mcp.auth {
        McpAuth::None => McpAuth::None,
        McpAuth::Bearer {
            secret_name: tpl_sn,
        } => {
            let sn = match instance
                .and_then(|i| i.secret_name.as_deref())
                .or(tpl_sn.as_deref())
            {
                Some(s) => s.to_string(),
                None => {
                    return Err(mcp_missing_config_error(
                        scope,
                        identity_id,
                        Some(ceiling_user_id),
                        service_key,
                        instance,
                        "secret_name",
                    )
                    .await);
                }
            };
            McpAuth::Bearer {
                secret_name: Some(sn),
            }
        }
        McpAuth::OAuth { provider, scopes } => {
            match resolve_mcp_oauth_bearer(
                state,
                ext,
                scope,
                ceiling_user_id,
                instance,
                provider,
                return_url_hint,
            )
            .await?
            {
                Some(header) => oauth_header = Some(header),
                None => {
                    // No connection yet — mint a gated auth URL and hand the
                    // caller a `needs_authentication` envelope, mirroring the
                    // HTTP OAuth path.
                    let urls = platform_connections::mint_initial_auth_url(
                        state,
                        scope.org_id(),
                        ceiling_user_id,
                        provider,
                        scopes,
                        None,
                        return_url_hint,
                    )
                    .await?;
                    return Err(AppError::NeedsAuthentication {
                        service: Some(service_key.to_string()),
                        service_instance_id: instance.map(|i| i.id),
                        connection_id: None,
                        auth_url: Some(urls.auth_url),
                        short: urls.short,
                        provider: Some(provider.clone()),
                        required_scopes: scopes.clone(),
                        account_email: None,
                        headless: false,
                    });
                }
            }
            McpAuth::OAuth {
                provider: provider.clone(),
                scopes: scopes.clone(),
            }
        }
    };

    Ok(ResolvedMcp {
        url,
        auth,
        oauth_header,
    })
}
