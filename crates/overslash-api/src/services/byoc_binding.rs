//! Which BYOC OAuth client a connection may run on.
//!
//! A BYOC credential is one user's own OAuth app (D23: identity-bound), and a
//! connection that pins it presents that app's `client_id` at authorize time
//! and its `client_secret` at every exchange and refresh. So the rule mirrors
//! the connection-pin rule (D120): a pin must name a BYOC owned by the
//! connection's own user (or one of that user's own agents), registered for
//! the provider the connection authenticates with. Admins are not exempt —
//! the secret is somebody's, and the provider's `token_endpoint` is where it
//! lands.
//!
//! Both halves live here. The write half runs wherever a pin enters the
//! system (`POST /v1/connections`, `/v1/connections/import`, MCP
//! `create_connection`, upgrades): all of them reach it through the tier-1
//! pin of [`client_credentials::resolve`](super::client_credentials::resolve).
//! The read half runs at every exchange and refresh (tier 1a), so a pin
//! written before this rule is never resolved into a colleague's app.

use overslash_db::OrgScope;
use overslash_db::repos::byoc_credential::ByocCredentialRow;
use uuid::Uuid;

use super::group_ceiling;
use crate::error::AppError;

/// The BYOC row `byoc_id`, if a connection belonging to `connection_identity`
/// may run on it for `provider_key`. `None` covers a missing row, another
/// org's row, another user's row and a provider mismatch alike — the caller
/// decides whether that is an error (an explicit pin) or "absent" (a stored
/// one).
pub async fn usable_byoc_pin(
    scope: &OrgScope,
    connection_identity: Uuid,
    provider_key: &str,
    byoc_id: Uuid,
) -> Result<Option<ByocCredentialRow>, AppError> {
    let Some(row) = scope.get_byoc_credential_any_owner(byoc_id).await? else {
        return Ok(None);
    };
    if row.provider_key != provider_key {
        return Ok(None);
    }
    let user = group_ceiling::resolve_ceiling_user_id(scope, connection_identity).await?;
    if !group_ceiling::identity_belongs_to_user(scope, user, row.identity_id).await? {
        return Ok(None);
    }
    Ok(Some(row))
}
