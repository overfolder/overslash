//! `SystemScope` SQL methods for the `approvals` resource.
//!
//! These methods are intentionally cross-org and are exposed only on
//! `SystemScope`. They back the background jobs in
//! `overslash-api::lib::run`, `overslash-api::services::permission_chain` and
//! `overslash-api::services::approval_expiry`.

use crate::repos::approval::{ApprovalRow, ExpiredApproval};
use crate::scopes::SystemScope;

impl SystemScope {
    /// List every pending approval in every org whose current resolver has
    /// held it longer than that org's `approval_auto_bubble_secs` setting.
    /// Used by the auto-bubble background loop.
    pub async fn list_pending_approvals_for_auto_bubble(
        &self,
    ) -> Result<Vec<ApprovalRow>, sqlx::Error> {
        crate::repos::approval::list_pending_for_auto_bubble(self.db()).await
    }

    /// Mark up to `limit` pending approvals whose `expires_at` has passed as
    /// expired, returning the rows that were flipped. Used by the expiry
    /// background loop, which emits `approval.resolved` for each of them.
    ///
    /// Returns rows rather than a count because the emitter needs the audience
    /// pair off each one, and takes a `limit` because it is the only thing
    /// standing between a cross-org sweep and an unbounded result set. A caller
    /// draining a backlog calls this repeatedly; see
    /// `overslash-api::services::approval_expiry`.
    pub async fn expire_stale_approvals(
        &self,
        limit: i64,
    ) -> Result<Vec<ExpiredApproval>, sqlx::Error> {
        crate::repos::approval::expire_stale(self.db(), limit).await
    }
}
