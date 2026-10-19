//! Connection listing: the summary shape `GET /v1/connections` returns, and
//! the `list_connections` platform kernel that hands the same shape to agents
//! so they can see which connection a reconnect landed on.

use super::*;
use crate::routes::util::fmt_time;
use overslash_db::scopes::UserScope;

#[derive(Debug, Serialize)]
pub struct ConnectionSummary {
    pub id: Uuid,
    /// Owner identity of the connection. Connections are bound to the user
    /// identity (D22), so this is the user who owns the linked account. The
    /// dashboard resolves it to a name in the admin "all users" view.
    pub owner_identity_id: Uuid,
    pub provider_key: String,
    pub account_email: Option<String>,
    /// Provider-hosted avatar for the linked account, when the provider named
    /// one at connect time. The dashboard hotlinks it beside the label and
    /// falls back to initials when it is absent or the URL has rotted.
    pub account_picture: Option<String>,
    /// Scopes the provider actually granted at the last OAuth flow. The
    /// dashboard renders these as chips and compares them to a template's
    /// required scopes when deciding whether to offer the "upgrade" prompt.
    pub scopes: Vec<String>,
    /// Template keys of active service instances currently bound to this
    /// connection. The dashboard's new-service wizard uses this to prefer a
    /// connection that *isn't* already in use for the template being created.
    pub used_by_service_templates: Vec<String>,
    pub is_default: bool,
    /// When true, this connection is preserved from the service-deletion
    /// auto-cleanup — the dashboard renders it as a "kept" toggle.
    pub keep: bool,
    /// When true, the connection must be re-authorized before use (e.g. its
    /// pinned BYOC client was replaced) — the dashboard renders a warning badge.
    pub reauth_required: bool,
    pub created_at: String,
    /// Bumped by every reconnect, which updates the row in place — the only
    /// way to tell a reconnect landed, since the id does not change.
    pub updated_at: String,
}

/// Summarize `rows`, attaching the templates each connection is bound to.
pub async fn summarize_connections(
    scope: &OrgScope,
    rows: Vec<ConnectionRow>,
) -> Result<Vec<ConnectionSummary>, AppError> {
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let mut usage: HashMap<Uuid, Vec<String>> = HashMap::new();
    for (conn_id, tpl) in scope.connection_usage_by_template(&ids).await? {
        usage.entry(conn_id).or_default().push(tpl);
    }
    Ok(rows
        .into_iter()
        .map(|r| ConnectionSummary {
            used_by_service_templates: usage.remove(&r.id).unwrap_or_default(),
            id: r.id,
            owner_identity_id: r.identity_id,
            provider_key: r.provider_key,
            account_email: r.account_email,
            account_picture: r.account_picture,
            scopes: r.scopes.unwrap_or_default(),
            is_default: r.is_default,
            keep: r.keep,
            reauth_required: r.reauth_required,
            created_at: fmt_time(r.created_at),
            updated_at: fmt_time(r.updated_at),
        })
        .collect())
}

#[derive(Debug, Default, Deserialize)]
pub struct ListConnectionsInput {
    /// Only this provider's connections.
    #[serde(default)]
    pub provider: Option<String>,
}

/// The caller's connections — its ceiling user's, since connections live on
/// the owner (D22) and every agent under that user shares them.
pub async fn kernel_list_connections(
    ctx: PlatformCallContext,
    input: ListConnectionsInput,
) -> Result<Vec<ConnectionSummary>, AppError> {
    let caller = ctx.identity_id.ok_or_else(|| {
        AppError::BadRequest("listing connections requires an identity-bound API key".into())
    })?;
    let scope = OrgScope::new(ctx.org_id, ctx.db.clone());
    let owner = group_ceiling::resolve_ceiling_user_id(&scope, caller).await?;
    let mut rows = UserScope::new(ctx.org_id, owner, ctx.db.clone())
        .list_my_connections()
        .await?;
    if let Some(provider) = input.provider.as_deref().filter(|p| !p.is_empty()) {
        rows.retain(|r| r.provider_key == provider);
    }
    summarize_connections(&scope, rows).await
}

/// Adapter for the platform registry.
pub async fn dispatch_list_connections(
    ctx: PlatformCallContext,
    params: HashMap<String, serde_json::Value>,
) -> Result<serde_json::Value, AppError> {
    let value = serde_json::Value::Object(params.into_iter().collect());
    let input: ListConnectionsInput = serde_json::from_value(value)
        .map_err(|e| AppError::BadRequest(format!("invalid params: {e}")))?;
    let list = kernel_list_connections(ctx, input).await?;
    Ok(serde_json::to_value(list).unwrap_or(serde_json::Value::Null))
}
