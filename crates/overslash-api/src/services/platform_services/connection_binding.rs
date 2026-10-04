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
        .get_connection(connection_id)
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
    if conn_identity == owner {
        return Ok(true);
    }
    Ok(scope
        .get_identity(conn_identity)
        .await?
        .is_some_and(|i| i.kind != "user" && i.owner_id == Some(owner)))
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
