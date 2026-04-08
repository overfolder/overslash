//! `OrgScope` SQL methods for the `permission_rules` resource.
//!
//! Every method funnels through `self.org_id()` so the permission-chain
//! walk physically cannot see rules belonging to another tenant, even if
//! a row id or identity id from another org is somehow passed in.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::repos::permission_rule::{self, PermissionRuleRow};
use crate::scopes::OrgScope;

impl OrgScope {
    /// Insert a new permission rule for an identity in this org.
    pub async fn create_permission_rule(
        &self,
        identity_id: Uuid,
        action_pattern: &str,
        effect: &str,
        expires_at: Option<OffsetDateTime>,
    ) -> Result<PermissionRuleRow, sqlx::Error> {
        permission_rule::create(
            self.db(),
            self.org_id(),
            identity_id,
            action_pattern,
            effect,
            expires_at,
        )
        .await
    }

    /// List the non-expired rules directly owned by an identity, bounded to
    /// this org. An identity id from another tenant returns an empty vec.
    pub async fn list_permission_rules_for_identity(
        &self,
        identity_id: Uuid,
    ) -> Result<Vec<PermissionRuleRow>, sqlx::Error> {
        permission_rule::list_by_identity(self.db(), self.org_id(), identity_id).await
    }

    /// List the non-expired rules for a batch of identities, bounded to this
    /// org. Ids belonging to other tenants are silently dropped.
    pub async fn list_permission_rules_for_identities(
        &self,
        identity_ids: &[Uuid],
    ) -> Result<Vec<PermissionRuleRow>, sqlx::Error> {
        permission_rule::list_by_identities(self.db(), self.org_id(), identity_ids).await
    }

    /// Delete a rule by id, scoped to this org. A row id belonging to another
    /// tenant returns `false` without touching any rows.
    pub async fn delete_permission_rule(&self, id: Uuid) -> Result<bool, sqlx::Error> {
        permission_rule::delete(self.db(), self.org_id(), id).await
    }

    /// Look up a single rule by id, scoped to this org. Used when a handler
    /// needs to make an authorization decision based on the rule's owner
    /// (e.g. self-service revoke). A row id belonging to another tenant
    /// returns `None`.
    pub async fn get_permission_rule(
        &self,
        id: Uuid,
    ) -> Result<Option<PermissionRuleRow>, sqlx::Error> {
        permission_rule::get_by_id(self.db(), self.org_id(), id).await
    }
}
