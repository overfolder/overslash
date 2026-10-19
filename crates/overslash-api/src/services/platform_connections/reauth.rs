//! Re-authorization targeting for `create_connection`: turn a `service` or an
//! `upgrade_connection_id` on the input into an in-place upgrade of the right
//! connection row, so a reconnect never strands a duplicate next to the row
//! every binding still points at.

use super::*;
use crate::services::platform_services::{
    instance_template, pinned_connection, resolve_readable_instance, template_oauth_provider,
};
use overslash_db::scopes::UserScope;

/// Rewrite `input` so the flow it mints reconnects the existing connection
/// when there is one. Returns the identity the flow must bind to: `owner`
/// (the caller's ceiling user) for a fresh connection, or the target
/// connection's own identity for an upgrade — the callback refuses an upgrade
/// whose flow identity differs from the row's.
///
/// - `service` names an instance the caller can read. Its template fixes the
///   provider. If the instance already authenticates with a connection (its
///   usable pin, else the owner's default for the provider), that connection
///   becomes the upgrade target; otherwise the instance is queued for the
///   callback to pin the new connection onto.
/// - `upgrade_connection_id` (explicit, or set by `service`) must belong to
///   `owner` — checked here, so a bad target fails before the user is sent
///   through the provider rather than at the callback. Its granted scopes
///   are unioned into the request and its BYOC client reused: a refresh token
///   only works with the client that minted it.
pub(super) async fn resolve_reauth_target(
    ctx: &PlatformCallContext,
    scope: &OrgScope,
    owner: Uuid,
    input: &mut CreateConnectionInput,
) -> Result<Uuid, AppError> {
    if let Some(name) = input.service.take() {
        let caller = ctx.identity_id.unwrap_or(owner);
        // Active instances first, as calls resolve them: an archived row of
        // the same name must not shadow the one the agent actually uses. Fall
        // back to any status only for one still being set up (`pending_setup`,
        // `draft`) — reconnecting an archived service is refused.
        let instance = match resolve_readable_instance(scope, caller, &name, false).await {
            Err(AppError::NotFound(_)) => {
                resolve_readable_instance(scope, caller, &name, true).await?
            }
            other => other?,
        };
        if instance.status == "archived" {
            return Err(AppError::BadRequest(format!(
                "service '{name}' is archived; restore it before reconnecting"
            )));
        }
        // Connections belong to the instance's owner (D22). Another user's
        // instance — readable through a group grant or as an admin — can only
        // be reconnected by that owner: its connection is not ours to
        // re-authorize, and a new one of ours could not be bound to it.
        // An org-level instance (no owner) authenticates with the caller's own
        // default connection, so that one is ours to fix.
        if instance.owner_identity_id.is_some_and(|o| o != owner) {
            return Err(AppError::Forbidden(format!(
                "service '{name}' belongs to another user; only its owner can reconnect it"
            )));
        }
        let def = instance_template(&ctx.db, &ctx.registry, &instance).await?;
        let provider = template_oauth_provider(&def)
            .ok_or_else(|| {
                AppError::BadRequest(format!(
                    "service '{name}' does not authenticate with OAuth; nothing to connect"
                ))
            })?
            .to_string();
        if !input.provider.is_empty() && input.provider != provider {
            return Err(AppError::BadRequest(format!(
                "service '{name}' authenticates with '{provider}', not '{}'",
                input.provider
            )));
        }
        input.provider = provider;

        if input.upgrade_connection_id.is_none() {
            let current = match pinned_connection(scope, &instance, |p| p == input.provider).await?
            {
                Some(conn) => Some(conn),
                // No usable pin: the instance follows the default connection
                // unless it opted out. An org-level instance resolves to the
                // caller's own default at call time, so the owner fallback
                // covers it too.
                None if instance.use_default_connection => {
                    UserScope::new(ctx.org_id, owner, ctx.db.clone())
                        .find_my_connection_by_provider(&input.provider)
                        .await?
                }
                None => None,
            };
            match current {
                Some(conn) => input.upgrade_connection_id = Some(conn.id),
                // Nothing to upgrade — bind the new connection on callback.
                // Only the owner's own instance: the callback's `check_pin`
                // would refuse anyone else's anyway.
                None if instance.owner_identity_id == Some(owner)
                    && !input.pin_service_ids.contains(&instance.id) =>
                {
                    input.pin_service_ids.push(instance.id);
                }
                None => {}
            }
        }
    }

    let Some(conn_id) = input.upgrade_connection_id else {
        return Ok(owner);
    };
    // `NotFound` for every refusal: the caller must not learn which ids exist.
    let not_found = || AppError::NotFound("connection not found".into());
    let conn = scope
        .get_connection_any_owner(conn_id)
        .await?
        .ok_or_else(not_found)?;
    if !group_ceiling::identity_belongs_to_user(scope, owner, conn.identity_id).await? {
        return Err(not_found());
    }
    if input.provider.is_empty() {
        input.provider = conn.provider_key.clone();
    } else if input.provider != conn.provider_key {
        return Err(AppError::BadRequest(format!(
            "connection is for '{}', not '{}'",
            conn.provider_key, input.provider
        )));
    }
    input.scopes = merge_scopes(conn.scopes.as_deref().unwrap_or(&[]), &input.scopes);
    // The upgrade keeps the row's `byoc_credential_id`, so tokens minted by a
    // different client would land on a row whose refresh uses this one.
    match (input.byoc_credential_id, conn.byoc_credential_id) {
        (None, pinned) => input.byoc_credential_id = pinned,
        (Some(asked), pinned) if Some(asked) != pinned => {
            return Err(AppError::BadRequest(
                "byoc_credential_id differs from the connection's own OAuth client".into(),
            ));
        }
        _ => {}
    }
    Ok(conn.identity_id)
}
