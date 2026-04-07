//! `OrgScope` SQL methods for the `identities` resource.
//!
//! Every method here funnels through `self.org_id()` so a row id from another
//! tenant returns `None` / no rows. The previously unscoped repo helpers
//! (`get_by_id`, `list_children`, `get_ancestor_chain`, `update_profile`,
//! `set_inherit_permissions`, `delete`, `touch_last_active`, `restore`) now
//! all bind their SQL to `self.org_id()` at the boundary.
//!
//! Cross-org identity lookup by email exists only on `SystemScope`
//! (`find_user_identity_by_email`) and is reserved for the login bootstrap
//! path, where the org is not yet known.

use uuid::Uuid;

use crate::repos::identity::{self, IdentityRow, RestoreOutcome};
use crate::scopes::OrgScope;

impl OrgScope {
    /// Create a bare identity (no parent) in this org.
    pub async fn create_identity(
        &self,
        name: &str,
        kind: &str,
        external_id: Option<&str>,
    ) -> Result<IdentityRow, sqlx::Error> {
        identity::create(self.db(), self.org_id(), name, kind, external_id).await
    }

    /// Create a user identity carrying email + metadata in this org.
    pub async fn create_identity_with_email(
        &self,
        name: &str,
        kind: &str,
        external_id: Option<&str>,
        email: Option<&str>,
        metadata: serde_json::Value,
    ) -> Result<IdentityRow, sqlx::Error> {
        identity::create_with_email(
            self.db(),
            self.org_id(),
            name,
            kind,
            external_id,
            email,
            metadata,
        )
        .await
    }

    /// Create an agent / sub-agent identity grafted onto an existing parent
    /// in this org. The caller must already have validated `parent_id` lives
    /// in the same org via `get_identity`.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_identity_with_parent(
        &self,
        name: &str,
        kind: &str,
        external_id: Option<&str>,
        parent_id: Uuid,
        depth: i32,
        owner_id: Uuid,
    ) -> Result<IdentityRow, sqlx::Error> {
        identity::create_with_parent(
            self.db(),
            self.org_id(),
            name,
            kind,
            external_id,
            parent_id,
            depth,
            owner_id,
        )
        .await
    }

    /// Look up an identity by id, scoped to this org. Returns `None` for an
    /// id that belongs to another tenant.
    pub async fn get_identity(&self, id: Uuid) -> Result<Option<IdentityRow>, sqlx::Error> {
        identity::get_by_id(self.db(), self.org_id(), id).await
    }

    /// Total identity count for this org.
    pub async fn count_identities(&self) -> Result<i64, sqlx::Error> {
        identity::count_by_org(self.db(), self.org_id()).await
    }

    /// List every identity in this org.
    pub async fn list_identities(&self) -> Result<Vec<IdentityRow>, sqlx::Error> {
        identity::list_by_org(self.db(), self.org_id()).await
    }

    /// List the direct children of `parent_id`, bounded to this org. A parent
    /// id from another tenant returns an empty vec.
    pub async fn list_identity_children(
        &self,
        parent_id: Uuid,
    ) -> Result<Vec<IdentityRow>, sqlx::Error> {
        identity::list_children(self.db(), self.org_id(), parent_id).await
    }

    /// Walk the ancestor chain (root user → requester) for an identity in
    /// this org. The recursive seed is bounded by `self.org_id()`, so a
    /// cross-tenant id returns an empty vec.
    pub async fn get_identity_ancestor_chain(
        &self,
        identity_id: Uuid,
    ) -> Result<Vec<IdentityRow>, sqlx::Error> {
        identity::get_ancestor_chain(self.db(), self.org_id(), identity_id).await
    }

    /// Resolve display names for a batch of identity ids, bounded to this org.
    /// Ids belonging to other tenants are silently dropped from the result.
    pub async fn get_identity_names_by_ids(
        &self,
        ids: &[Uuid],
    ) -> Result<Vec<(Uuid, String)>, sqlx::Error> {
        let rows = sqlx::query!(
            "SELECT id, name FROM identities WHERE org_id = $1 AND id = ANY($2)",
            self.org_id(),
            ids,
        )
        .fetch_all(self.db())
        .await?;
        Ok(rows.into_iter().map(|r| (r.id, r.name)).collect())
    }

    /// Update an identity's display name + metadata, scoped to this org.
    pub async fn update_identity_profile(
        &self,
        id: Uuid,
        name: &str,
        metadata: serde_json::Value,
    ) -> Result<Option<IdentityRow>, sqlx::Error> {
        identity::update_profile(self.db(), self.org_id(), id, name, metadata).await
    }

    /// Toggle `inherit_permissions` on an identity in this org.
    pub async fn set_identity_inherit_permissions(
        &self,
        id: Uuid,
        inherit: bool,
    ) -> Result<bool, sqlx::Error> {
        identity::set_inherit_permissions(self.db(), self.org_id(), id, inherit).await
    }

    /// Delete an identity by id, scoped to this org.
    pub async fn delete_identity(&self, id: Uuid) -> Result<bool, sqlx::Error> {
        identity::delete(self.db(), self.org_id(), id).await
    }

    /// Stamp `last_active_at = now()` for a sub-agent in this org. Used by the
    /// auth middleware to keep idle-cleanup tracking current.
    pub async fn touch_identity_last_active(&self, id: Uuid) -> Result<(), sqlx::Error> {
        identity::touch_last_active(self.db(), self.org_id(), id).await
    }

    /// Restore an archived sub-agent in this org and resurrect its
    /// auto-revoked API keys.
    pub async fn restore_identity(&self, id: Uuid) -> Result<RestoreOutcome, sqlx::Error> {
        identity::restore(self.db(), self.org_id(), id).await
    }
}
