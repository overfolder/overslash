//! `SystemScope` SQL methods for the `identities` resource.
//!
//! These methods are intentionally cross-org and are exposed only on
//! `SystemScope`. They back:
//! - the login bootstrap path, where the org is not yet known
//!   (`find_user_identity_by_email`),
//! - the idle-cleanup background loops in `overslash-api::lib::run`
//!   (`archive_idle_subagents`, `purge_archived_subagents`).

use crate::repos::identity::{self, IdentityRow};
use crate::scopes::SystemScope;

impl SystemScope {
    /// Look up a user identity by email across every org. Reserved for the
    /// login bootstrap path: HTTP handlers should obtain a verified org from
    /// the session/key first and then go through `OrgScope::get_identity`.
    pub async fn find_user_identity_by_email(
        &self,
        email: &str,
    ) -> Result<Option<IdentityRow>, sqlx::Error> {
        identity::find_user_by_email_global(self.db(), email).await
    }

    /// Cross-org sweep: archive sub-agents whose `last_active_at` is past
    /// their org's idle window. Returns the number of identities archived in
    /// this pass.
    pub async fn archive_idle_subagents(&self) -> Result<u64, sqlx::Error> {
        identity::archive_idle_subagents(self.db()).await
    }

    /// Cross-org sweep: hard-delete sub-agents whose archive retention has
    /// elapsed. Returns the number of rows purged.
    pub async fn purge_archived_subagents(&self) -> Result<u64, sqlx::Error> {
        identity::purge_archived_subagents(self.db()).await
    }
}
