//! `OrgScope` SQL methods for the `org_invites` resource. Mirrors the
//! pattern in `scopes::org_idp_config` — every mutation funnels through
//! `self.org_id()` so an admin in one org can't reach into another.
//!
//! The login callback path consumes invites via the public
//! `repos::org_invite::find_pending` / `mark_accepted` helpers, not these
//! methods — there's no `OrgScope` available before the user is admitted.

use uuid::Uuid;

use crate::repos::org_invite::OrgInviteRow;
use crate::scopes::OrgScope;

impl OrgScope {
    /// Mint a pending invite for `email` with `role`. The `(org_id, email)`
    /// partial unique index guarantees at most one pending invite per email
    /// — duplicates surface as `sqlx::Error::Database(is_unique_violation())`.
    pub async fn create_org_invite(
        &self,
        email: &str,
        role: &str,
        invited_by: Option<Uuid>,
    ) -> Result<OrgInviteRow, sqlx::Error> {
        crate::repos::org_invite::create(self.db(), self.org_id(), email, role, invited_by).await
    }

    /// Look up an invite by id, scoped to this org.
    pub async fn get_org_invite(&self, id: Uuid) -> Result<Option<OrgInviteRow>, sqlx::Error> {
        crate::repos::org_invite::get_by_id(self.db(), id, self.org_id()).await
    }

    /// List every invite (pending + accepted) for this org.
    pub async fn list_org_invites(&self) -> Result<Vec<OrgInviteRow>, sqlx::Error> {
        crate::repos::org_invite::list_by_org(self.db(), self.org_id()).await
    }

    /// Revoke a pending invite. No-op on accepted invites (their row is
    /// kept for audit history).
    pub async fn delete_org_invite(&self, id: Uuid) -> Result<bool, sqlx::Error> {
        crate::repos::org_invite::delete_pending(self.db(), id, self.org_id()).await
    }
}
