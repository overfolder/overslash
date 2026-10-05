//! Who may pin which OAuth connection onto a service instance.
//!
//! A connection belongs to one user (D23), and a pinned `connection_id` is
//! the credential every call through the instance authenticates with. So the
//! rule mirrors the secret write rule (D119): an instance may only pin a
//! connection owned by the instance's own owner (or by one of that owner's
//! own agents — a legacy shape D23 re-homed, still the same user), for the
//! provider its
//! template authenticates with. An org-level instance has no owner and
//! cannot pin one at all. The same check runs at call time
//! ([`pinned_connection_usable`]), so a row written before this rule — or by
//! any path that forgets it — is never resolved into someone else's token.

use super::*;

/// Validate pinning `connection_id` onto an instance owned by
/// `instance_owner` from template `template_def`. Shared by create and
/// update.
pub(super) async fn validate_connection_binding(
    scope: &OrgScope,
    instance_owner: Option<Uuid>,
    template_def: &ServiceDefinition,
    connection_id: Uuid,
) -> Result<(), AppError> {
    let expected_owner = instance_owner.ok_or_else(|| {
        AppError::BadRequest(
            "org-level services cannot pin a connection_id (connections are identity-owned)".into(),
        )
    })?;
    let connection = scope
        .get_connection_any_owner(connection_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("connection '{connection_id}' not found")))?;
    if !belongs_to_user(scope, expected_owner, connection.identity_id).await? {
        return Err(AppError::Forbidden(
            "connection belongs to another identity; a service can only use its owner's \
             connections"
                .into(),
        ));
    }
    // Covers both an HTTP `oauth` scheme and an MCP `auth.kind: oauth`
    // provider — a pinned connection on an mcp-oauth template (HubSpot,
    // Slack) must validate the same as an HTTP OAuth template.
    match template_oauth_provider(template_def) {
        Some(tpl_provider) if tpl_provider != connection.provider_key => {
            Err(AppError::BadRequest(format!(
                "connection_provider_mismatch: template '{}' uses '{}' but connection is for '{}'",
                template_def.key, tpl_provider, connection.provider_key
            )))
        }
        None => Err(AppError::BadRequest(format!(
            "connection_provider_mismatch: template '{}' does not use OAuth",
            template_def.key
        ))),
        _ => Ok(()),
    }
}

/// Is `conn_identity` the user `owner`, or one of `owner`'s own agents?
async fn belongs_to_user(
    scope: &OrgScope,
    owner: Uuid,
    conn_identity: Uuid,
) -> Result<bool, AppError> {
    group_ceiling::identity_belongs_to_user(scope, owner, conn_identity).await
}

/// The call-time half: may an instance owned by `instance_owner` authenticate
/// with pinned connection `conn`, for a template whose OAuth provider is
/// `provider` (`None` = the caller checks the provider itself)? `false` means
/// "treat the pin as absent" — never use it.
pub async fn pinned_connection_usable(
    scope: &OrgScope,
    instance_owner: Option<Uuid>,
    conn_identity: Uuid,
    conn_provider: &str,
    provider: Option<&str>,
) -> Result<bool, AppError> {
    let Some(owner) = instance_owner else {
        return Ok(false);
    };
    Ok(provider.is_none_or(|p| p == conn_provider)
        && belongs_to_user(scope, owner, conn_identity).await?)
}

/// The write half for paths that pin an already-known connection onto
/// instances they were handed (the OAuth callback's `pin_service_ids`, token
/// import). Same rule as [`validate_connection_binding`], answered as the
/// coarse code those paths report per instance: `Ok(Err(code))` refuses the
/// pin, `Err` is a server-side failure.
pub(crate) async fn check_pin(
    scope: &OrgScope,
    db: &sqlx::PgPool,
    registry: &overslash_core::registry::ServiceRegistry,
    instance: &ServiceInstanceRow,
    conn_identity: Uuid,
    conn_provider: &str,
) -> Result<Result<(), &'static str>, AppError> {
    let Some(owner) = instance.owner_identity_id else {
        return Ok(Err("service_instance_owner_mismatch"));
    };
    if !belongs_to_user(scope, owner, conn_identity).await? {
        return Ok(Err("service_instance_owner_mismatch"));
    }
    let def = instance_template(db, registry, instance).await?;
    if template_oauth_provider(&def) != Some(conn_provider) {
        return Ok(Err("connection_provider_mismatch"));
    }
    Ok(Ok(()))
}

/// Pinned connections a view may show, by instance — see [`usable_pins`].
pub(crate) struct UsablePins {
    connections: std::collections::HashMap<Uuid, overslash_db::repos::connection::ConnectionRow>,
    by_instance: std::collections::HashMap<Uuid, Uuid>,
}

impl UsablePins {
    /// The connection pinned on `instance_id`, if the call path would use it.
    pub(crate) fn get(
        &self,
        instance_id: &Uuid,
    ) -> Option<&overslash_db::repos::connection::ConnectionRow> {
        self.connections.get(self.by_instance.get(instance_id)?)
    }
}

/// The read half for views (services list and detail, credentials status,
/// search, tool principals): each instance's pinned connection, only where
/// the call path would use it — the instance owner's own connection (or an
/// own agent's). A foreign pin is left out, so a view shows "not connected"
/// exactly where a call refuses the pin, and never a colleague's
/// `account_email` or scopes. Takes `(instance_id, instance_owner,
/// connection_id)` so it serves every row shape. Provider is not checked
/// here; the call path still checks it.
pub(crate) async fn usable_pins(
    scope: &OrgScope,
    pins: impl IntoIterator<Item = (Uuid, Option<Uuid>, Uuid)>,
) -> Result<UsablePins, AppError> {
    let pins: Vec<_> = pins.into_iter().collect();
    let mut ids: Vec<Uuid> = pins.iter().map(|(_, _, c)| *c).collect();
    ids.sort_unstable();
    ids.dedup();
    let connections = scope.get_connections_by_ids_any_owner(&ids).await?;
    let mut by_instance = std::collections::HashMap::new();
    for (instance_id, owner, conn_id) in pins {
        if let Some(conn) = connections.get(&conn_id)
            && pinned_connection_usable(scope, owner, conn.identity_id, &conn.provider_key, None)
                .await?
        {
            by_instance.insert(instance_id, conn_id);
        }
    }
    Ok(UsablePins {
        connections,
        by_instance,
    })
}

/// [`usable_pins`] for one instance.
pub(crate) async fn usable_pin(
    scope: &OrgScope,
    instance: &ServiceInstanceRow,
) -> Result<Option<overslash_db::repos::connection::ConnectionRow>, AppError> {
    let Some(conn_id) = instance.connection_id else {
        return Ok(None);
    };
    let mut pins = usable_pins(scope, [(instance.id, instance.owner_identity_id, conn_id)]).await?;
    Ok(match pins.by_instance.remove(&instance.id) {
        Some(id) => pins.connections.remove(&id),
        None => None,
    })
}

/// The call-time read: the connection pinned on `instance`, if the instance
/// may authenticate with it — the owner's own (or an own agent's), for a
/// provider `provider_ok` accepts. Anything else (a deleted connection, a
/// colleague's, another provider's) is `None`: treated as absent, never
/// resolved into someone else's token.
pub async fn pinned_connection(
    scope: &OrgScope,
    instance: &ServiceInstanceRow,
    provider_ok: impl Fn(&str) -> bool,
) -> Result<Option<overslash_db::repos::connection::ConnectionRow>, AppError> {
    let Some(conn_id) = instance.connection_id else {
        return Ok(None);
    };
    let Some(conn) = scope.get_connection_any_owner(conn_id).await? else {
        return Ok(None);
    };
    if provider_ok(&conn.provider_key)
        && pinned_connection_usable(
            scope,
            instance.owner_identity_id,
            conn.identity_id,
            &conn.provider_key,
            None,
        )
        .await?
    {
        return Ok(Some(conn));
    }
    tracing::warn!(
        instance_id = %instance.id,
        connection_id = %conn.id,
        "pinned connection is not the instance owner's (or wrong provider); ignoring"
    );
    Ok(None)
}
