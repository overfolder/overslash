//! `SystemScope` SQL methods for the `approvals` resource.
//!
//! These methods are intentionally cross-org and are exposed only on
//! `SystemScope`. They back the background jobs in
//! `overslash-api::lib::run` and `overslash-api::services::permission_chain`.

use crate::repos::approval::ApprovalRow;
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

    /// Mark every pending approval whose `expires_at` has passed as expired.
    /// Returns the number of rows affected. Used by the expiry background loop.
    pub async fn expire_stale_approvals(&self) -> Result<u64, sqlx::Error> {
        crate::repos::approval::expire_stale(self.db()).await
    }
}
