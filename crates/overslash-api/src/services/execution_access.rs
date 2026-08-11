//! Who may read an execution's result body.
//!
//! One function, three call sites, so the rule cannot be stated twice and drift.
//!
//! Deliberately **not** "same org". That was the shape of
//! `GET /v1/approvals/{id}/execution` before this module existed, and it made
//! every identity-bound credential in an org a reader of every upstream
//! response body in it — including the ones that come back from a
//! token-minting endpoint or a config read.
//!
//! Modelled on the ladder `POST /v1/approvals/{id}/call` already uses, with one
//! deliberate difference in axis: replay asks about ancestry over the
//! *resolver* (who may act), while a read asks about ancestry over the
//! *requester* (who may see what their own subtree did). Both are honoured —
//! bubbling usually collapses them, but a resolver who approved a call has a
//! legitimate claim on how it turned out.

use uuid::Uuid;

use overslash_core::permissions::AccessLevel;
use overslash_db::scopes::OrgScope;

use crate::error::{AppError, Result};
use crate::extractors::OrgAcl;

/// May this caller see the execution's `result` / `error`?
///
/// `requester_id` is the identity whose call it was; `resolver_id` is the
/// approval's current resolver, or `None` for an execution that was never
/// gated.
pub async fn may_read_execution(
    scope: &OrgScope,
    acl: &OrgAcl,
    requester_id: Uuid,
    resolver_id: Option<Uuid>,
) -> Result<bool> {
    // Org admins see everything in the org — they can already read the audit
    // log, which carries the same bodies when capture is on.
    if acl.access_level >= AccessLevel::Admin {
        return Ok(true);
    }
    // The requester always reads its own result, with no ACL level required.
    // Same carve-out the replay path makes: an agent must be able to collect
    // the output of a call it made.
    if acl.identity_id == Some(requester_id) {
        return Ok(true);
    }
    if acl.access_level < AccessLevel::Write {
        return Ok(false);
    }
    let Some(caller) = acl.identity_id else {
        return Ok(false);
    };
    if crate::services::permission_chain::is_self_or_ancestor(scope, caller, requester_id).await? {
        return Ok(true);
    }
    if let Some(resolver_id) = resolver_id
        && crate::services::permission_chain::is_self_or_ancestor(scope, caller, resolver_id)
            .await?
    {
        return Ok(true);
    }
    Ok(false)
}

/// May this caller cancel the execution? Same ladder as reading it.
///
/// Cancelling is strictly less dangerous than reading — it reveals nothing —
/// but the set of people with a legitimate interest is identical, and two
/// ladders that differ by nothing are two ladders to keep in sync.
pub async fn may_cancel_execution(
    scope: &OrgScope,
    acl: &OrgAcl,
    requester_id: Uuid,
    resolver_id: Option<Uuid>,
) -> Result<bool> {
    may_read_execution(scope, acl, requester_id, resolver_id).await
}

/// Standard refusal. 403 rather than 404 on purpose: for the approval-backed
/// endpoints the caller can already see the approval, so a 404 would be a lie
/// that helps nobody debug.
pub fn forbidden() -> AppError {
    AppError::Forbidden("caller is not authorized to read this execution".into())
}
