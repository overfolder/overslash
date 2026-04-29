//! `OrgScope` SQL methods for the `groups` resource (groups, grants,
//! identity↔group membership, and the user ceiling).
//!
//! Every method here funnels through `self.org_id()`. The previously unscoped
//! repo functions (`get_by_id`, `add_grant`, `remove_grant`,
//! `list_groups_for_identity`, `get_ceiling_for_user`, `get_visible_service_ids`)
//! used to trust the caller for org context — they now bound the SQL to
//! `self.org_id()` so a row id from another tenant returns `None` / `0` rows.

use uuid::Uuid;

use crate::repos::group::{
    self, GroupGrantDetailRow, GroupGrantRow, GroupRow, IdentityGroupRow, ServiceGroupRow,
    UserCeiling,
};
use crate::scopes::OrgScope;

impl OrgScope {
    // ── Group CRUD ───────────────────────────────────────────────────

    /// Create a new group in this org.
    pub async fn create_group(
        &self,
        name: &str,
        description: &str,
        allow_raw_http: bool,
    ) -> Result<GroupRow, sqlx::Error> {
        group::create(self.db(), self.org_id(), name, description, allow_raw_http).await
    }

    /// Look up a group by id, scoped to this org. Returns `None` if the id
    /// belongs to another tenant.
    pub async fn get_group(&self, id: Uuid) -> Result<Option<GroupRow>, sqlx::Error> {
        group::get_by_id(self.db(), self.org_id(), id).await
    }

    /// List all groups in this org.
    pub async fn list_groups(&self) -> Result<Vec<GroupRow>, sqlx::Error> {
        group::list_by_org(self.db(), self.org_id()).await
    }

    /// Update a group's mutable fields, scoped to this org.
    pub async fn update_group(
        &self,
        id: Uuid,
        name: &str,
        description: &str,
        allow_raw_http: bool,
    ) -> Result<Option<GroupRow>, sqlx::Error> {
        group::update(
            self.db(),
            id,
            self.org_id(),
            name,
            description,
            allow_raw_http,
        )
        .await
    }

    /// Delete a group, scoped to this org.
    pub async fn delete_group(&self, id: Uuid) -> Result<bool, sqlx::Error> {
        group::delete(self.db(), id, self.org_id()).await
    }

    /// Find the system "Everyone" group for this org.
    pub async fn find_everyone_group(&self) -> Result<Option<GroupRow>, sqlx::Error> {
        group::find_everyone_group(self.db(), self.org_id()).await
    }

    /// Whether an identity is a member of the system "Admins" group of this org.
    pub async fn is_identity_in_admins(&self, identity_id: Uuid) -> Result<bool, sqlx::Error> {
        group::is_identity_in_admins(self.db(), self.org_id(), identity_id).await
    }

    /// Find the Myself group for a user-identity in this org, if one exists.
    pub async fn find_self_group(
        &self,
        identity_id: Uuid,
    ) -> Result<Option<GroupRow>, sqlx::Error> {
        group::find_self_group(self.db(), self.org_id(), identity_id).await
    }

    /// Ensure a Myself group exists for a user-identity in this org. Creates it
    /// (and adds the identity as the sole member) if missing. Returns the group id.
    pub async fn ensure_self_group(
        &self,
        identity_id: Uuid,
        label: &str,
    ) -> Result<Uuid, sqlx::Error> {
        group::ensure_self_group(self.db(), self.org_id(), identity_id, label).await
    }

    /// Auto-grant a service instance to its owner's Myself group with admin
    /// access and `auto_approve_reads = true`. Idempotent.
    pub async fn grant_service_to_self_group(
        &self,
        owner_identity_id: Uuid,
        service_instance_id: Uuid,
        owner_label: &str,
    ) -> Result<(), sqlx::Error> {
        group::grant_to_self_group(
            self.db(),
            self.org_id(),
            owner_identity_id,
            service_instance_id,
            owner_label,
        )
        .await
    }

    // ── Grants ───────────────────────────────────────────────────────

    /// Add a grant to a group. The group and the service instance must both
    /// belong to this org; otherwise `Ok(None)` is returned.
    pub async fn add_group_grant(
        &self,
        group_id: Uuid,
        service_instance_id: Uuid,
        access_level: &str,
        auto_approve_reads: bool,
    ) -> Result<Option<GroupGrantRow>, sqlx::Error> {
        group::add_grant(
            self.db(),
            self.org_id(),
            group_id,
            service_instance_id,
            access_level,
            auto_approve_reads,
        )
        .await
    }

    /// List grants attached to a group, scoped to this org.
    pub async fn list_group_grants(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<GroupGrantDetailRow>, sqlx::Error> {
        group::list_grants(self.db(), self.org_id(), group_id).await
    }

    /// Remove a grant from a group, scoped to this org.
    pub async fn remove_group_grant(
        &self,
        grant_id: Uuid,
        group_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        group::remove_grant(self.db(), self.org_id(), grant_id, group_id).await
    }

    /// List the groups that grant access to a single service instance. The
    /// service instance and groups are bounded to this org.
    pub async fn list_groups_for_service(
        &self,
        service_instance_id: Uuid,
    ) -> Result<Vec<ServiceGroupRow>, sqlx::Error> {
        group::list_groups_for_service(self.db(), self.org_id(), service_instance_id).await
    }

    /// Batch list of group grants keyed by service instance id. Used by the
    /// services list to annotate each row without N+1 queries.
    pub async fn list_groups_for_services(
        &self,
        service_instance_ids: &[Uuid],
    ) -> Result<Vec<ServiceGroupRow>, sqlx::Error> {
        group::list_groups_for_services(self.db(), self.org_id(), service_instance_ids).await
    }

    // ── Identity ↔ Group membership ──────────────────────────────────

    /// Assign an identity to a group. Both the identity and the group must
    /// belong to this org; otherwise `Ok(None)` is returned.
    pub async fn assign_identity_to_group(
        &self,
        identity_id: Uuid,
        group_id: Uuid,
    ) -> Result<Option<IdentityGroupRow>, sqlx::Error> {
        group::assign_identity(self.db(), self.org_id(), identity_id, group_id).await
    }

    /// Remove an identity from a group, scoped to this org.
    pub async fn unassign_identity_from_group(
        &self,
        identity_id: Uuid,
        group_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        group::unassign_identity(self.db(), self.org_id(), identity_id, group_id).await
    }

    /// List groups an identity belongs to within this org.
    pub async fn list_groups_for_identity(
        &self,
        identity_id: Uuid,
    ) -> Result<Vec<GroupRow>, sqlx::Error> {
        group::list_groups_for_identity(self.db(), self.org_id(), identity_id).await
    }

    /// List identity ids belonging to a group within this org.
    pub async fn list_identity_ids_in_group(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        group::list_identity_ids_in_group(self.db(), self.org_id(), group_id).await
    }

    /// Count members of a group within this org.
    pub async fn count_members_in_group(&self, group_id: Uuid) -> Result<i64, sqlx::Error> {
        group::count_members_in_group(self.db(), self.org_id(), group_id).await
    }

    // ── Ceiling queries (hot auth path) ──────────────────────────────

    /// Aggregate the user's group ceiling (grants + `allow_raw_http`) within
    /// this org. The user identity, the groups, and the granted service
    /// instances must all live in `self.org_id()` — cross-tenant rows are
    /// excluded at the SQL boundary, which is what makes this safe to call
    /// from the auth-time `OrgAcl` extractor.
    pub async fn get_ceiling_for_user(
        &self,
        user_identity_id: Uuid,
    ) -> Result<UserCeiling, sqlx::Error> {
        group::get_ceiling_for_user(self.db(), self.org_id(), user_identity_id).await
    }

    /// Service instance ids visible to a user through group membership,
    /// bounded to this org.
    pub async fn get_visible_service_ids(
        &self,
        user_identity_id: Uuid,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        group::get_visible_service_ids(self.db(), self.org_id(), user_identity_id).await
    }
}
