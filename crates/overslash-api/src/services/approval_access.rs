//! Who may see an approval at all — its summary, `action_detail`, and
//! disclosure.
//!
//! Deliberately **not** "same org". Before this module, `GET /v1/approvals`
//! with no scope and `GET /v1/approvals/{id}` answered every identity in the
//! org, so any agent could read every other user's pending call payloads.
//!
//! The rule is the SSE audience for approval events
//! ([`crate::services::events::audience`]): org admin, or self-or-ancestor of
//! the requester, or self-or-ancestor of the current resolver. The endpoint
//! and the stream now answer the same question the same way.
//!
//! Wider than [`crate::services::execution_access::may_read_execution`] on
//! purpose: that ladder guards the upstream *response body* and asks for
//! `Write` before honouring ancestry; this one guards the request a subtree
//! made, which its owner must always be able to see to decide on it. Every
//! caller that may read the execution may read the approval, never the other
//! way round.

use uuid::Uuid;

use overslash_core::permissions::AccessLevel;
use overslash_db::scopes::OrgScope;

use crate::error::Result;
use crate::extractors::OrgAcl;
use crate::services::permission_chain::is_self_or_ancestor;

/// May this caller see the approval with this requester and current resolver?
pub async fn may_read_approval(
    scope: &OrgScope,
    acl: &OrgAcl,
    requester_id: Uuid,
    resolver_id: Uuid,
) -> Result<bool> {
    if acl.access_level >= AccessLevel::Admin {
        return Ok(true);
    }
    let Some(caller) = acl.identity_id else {
        return Ok(false);
    };
    if caller == requester_id || caller == resolver_id {
        return Ok(true);
    }
    Ok(is_self_or_ancestor(scope, caller, requester_id).await?
        || is_self_or_ancestor(scope, caller, resolver_id).await?)
}
