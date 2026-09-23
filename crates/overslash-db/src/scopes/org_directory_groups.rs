//! `OrgScope` SQL methods for directory groups — discovery, the sync-owned
//! membership table, and the admin-owned mapping into Layer 1 groups.
//!
//! As in `org_groups`, every method funnels `self.org_id()`, so an id
//! belonging to another tenant returns `None` / `false` / no rows rather than
//! reaching across the boundary.

use uuid::Uuid;

use crate::repos::directory_group::{
    self, DirectoryGroupRow, DirectoryGroupSummaryRow, GroupMemberOriginRow,
};
use crate::scopes::OrgScope;

impl OrgScope {
    // ── Discovery ────────────────────────────────────────────────────

    /// Record that a directory group exists, refreshing its label.
    pub async fn upsert_directory_group(
        &self,
        idp_config_id: Option<Uuid>,
        source: &str,
        external_id: &str,
        display_name: &str,
    ) -> Result<DirectoryGroupRow, sqlx::Error> {
        directory_group::upsert(
            self.db(),
            self.org_id(),
            idp_config_id,
            source,
            external_id,
            display_name,
        )
        .await
    }

    /// Every directory group discovered in this org, with member and mapping counts.
    pub async fn list_directory_groups(
        &self,
    ) -> Result<Vec<DirectoryGroupSummaryRow>, sqlx::Error> {
        directory_group::list_by_org(self.db(), self.org_id()).await
    }

    /// Look up a directory group by id, scoped to this org.
    pub async fn get_directory_group(
        &self,
        id: Uuid,
    ) -> Result<Option<DirectoryGroupRow>, sqlx::Error> {
        directory_group::get_by_id(self.db(), self.org_id(), id).await
    }

    // ── Sync-owned membership ────────────────────────────────────────

    /// Reconcile one identity's directory membership to exactly
    /// `directory_group_ids`, confined to one `(idp_config_id, source)` pair.
    /// Returns `(added, removed)`.
    pub async fn replace_directory_memberships(
        &self,
        identity_id: Uuid,
        idp_config_id: Option<Uuid>,
        source: &str,
        directory_group_ids: &[Uuid],
    ) -> Result<(Vec<Uuid>, Vec<Uuid>), sqlx::Error> {
        directory_group::replace_memberships_for_identity(
            self.db(),
            self.org_id(),
            identity_id,
            idp_config_id,
            source,
            directory_group_ids,
        )
        .await
    }

    // ── Admin-owned mapping ──────────────────────────────────────────

    /// Map a directory group into an Overslash group. The system-group refusal
    /// lives in the handler; this is the tenancy-safe write.
    pub async fn add_group_directory_source(
        &self,
        group_id: Uuid,
        directory_group_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        directory_group::add_source(self.db(), self.org_id(), group_id, directory_group_id).await
    }

    /// Unmap a directory group from an Overslash group.
    pub async fn remove_group_directory_source(
        &self,
        group_id: Uuid,
        directory_group_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        directory_group::remove_source(self.db(), self.org_id(), group_id, directory_group_id).await
    }

    /// The directory groups feeding one Overslash group.
    pub async fn list_group_directory_sources(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<DirectoryGroupRow>, sqlx::Error> {
        directory_group::list_sources_for_group(self.db(), self.org_id(), group_id).await
    }

    /// Members of a group, tagged direct / via-directory / both.
    pub async fn list_group_members_with_origin(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<GroupMemberOriginRow>, sqlx::Error> {
        directory_group::list_members_with_origin(self.db(), self.org_id(), group_id).await
    }

    /// `true` when this membership exists only because a directory asserts it,
    /// so there is no manual row for an admin to remove.
    pub async fn membership_is_directory_only(
        &self,
        group_id: Uuid,
        identity_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        directory_group::membership_is_directory_only(
            self.db(),
            self.org_id(),
            group_id,
            identity_id,
        )
        .await
    }
}
