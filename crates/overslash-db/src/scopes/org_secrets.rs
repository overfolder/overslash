//! `OrgScope` SQL methods for the `secrets` resource.
//!
//! Every method here filters by `self.org_id` — callers cannot reach secrets
//! belonging to another org, even if they hold a matching `name`.

use uuid::Uuid;

use crate::repos::secret::{SecretRow, SecretVersionMeta, SecretVersionRow, ServiceUsingSecret};
use crate::scopes::OrgScope;

impl OrgScope {
    /// Store or update a secret. Creates a new version each time.
    ///
    /// `created_by` names the identity the secret slot *belongs to* (API
    /// writes: the caller; request fulfillment: the target identity).
    /// `provisioned_by_user_id` names the human who physically pasted the
    /// value on the standalone provide page — only set by the secret-request
    /// flow, and only when a same-org session cookie was present.
    pub async fn put_secret(
        &self,
        name: &str,
        encrypted_value: &[u8],
        created_by: Option<Uuid>,
        provisioned_by_user_id: Option<Uuid>,
    ) -> Result<(SecretRow, SecretVersionRow), sqlx::Error> {
        crate::repos::secret::put(
            self.db(),
            self.org_id(),
            name,
            encrypted_value,
            created_by,
            provisioned_by_user_id,
        )
        .await
    }

    /// Look up a secret's metadata by name within this org.
    pub async fn get_secret_by_name(&self, name: &str) -> Result<Option<SecretRow>, sqlx::Error> {
        crate::repos::secret::get_by_name(self.db(), self.org_id(), name).await
    }

    /// Fetch the current encrypted version of a secret by name within this org.
    pub async fn get_current_secret_value(
        &self,
        name: &str,
    ) -> Result<Option<SecretVersionRow>, sqlx::Error> {
        crate::repos::secret::get_current_value(self.db(), self.org_id(), name).await
    }

    /// List all live secrets in this org. Admin-only callers should use
    /// this; non-admins must use `list_secrets_visible_to_user`.
    pub async fn list_secrets(&self) -> Result<Vec<SecretRow>, sqlx::Error> {
        crate::repos::secret::list_by_org(self.db(), self.org_id()).await
    }

    /// List secrets owned by a user's subtree. SPEC §6: a non-admin user
    /// sees their own secrets and any secret created by an agent/sub-agent
    /// whose ceiling user is them.
    pub async fn list_secrets_visible_to_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<SecretRow>, sqlx::Error> {
        crate::repos::secret::list_visible_to_user(self.db(), self.org_id(), user_id).await
    }

    /// True if the named secret's slot owner (version 1 creator's ceiling
    /// user) is `user_id`. Detail / reveal / restore / delete must check
    /// this before letting a non-admin see the secret.
    pub async fn secret_visible_to_user(
        &self,
        name: &str,
        user_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        crate::repos::secret::is_visible_to_user(self.db(), self.org_id(), name, user_id).await
    }

    /// Soft-delete a secret by name in this org. Returns true if a row was affected.
    pub async fn soft_delete_secret(&self, name: &str) -> Result<bool, sqlx::Error> {
        crate::repos::secret::soft_delete(self.db(), self.org_id(), name).await
    }

    /// Soft-delete multiple secrets atomically. All deletes succeed or
    /// none do — useful when a logical resource (e.g. an OAuth App
    /// Credential pair) spans two secret names.
    pub async fn soft_delete_secrets(&self, names: &[&str]) -> Result<u64, sqlx::Error> {
        crate::repos::secret::soft_delete_many(self.db(), self.org_id(), names).await
    }

    /// Put multiple secrets atomically. All writes commit together or none
    /// do — useful when a logical resource (e.g. an OAuth App Credential
    /// pair) spans two secret names.
    pub async fn put_secrets(
        &self,
        entries: &[(&str, &[u8])],
        created_by: Option<Uuid>,
    ) -> Result<(), sqlx::Error> {
        crate::repos::secret::put_many(self.db(), self.org_id(), entries, created_by).await
    }

    /// List every version of a secret (newest first) without exposing
    /// ciphertext. Used by the dashboard detail view.
    pub async fn list_secret_versions(
        &self,
        name: &str,
    ) -> Result<Vec<SecretVersionMeta>, sqlx::Error> {
        crate::repos::secret::list_versions(self.db(), self.org_id(), name).await
    }

    /// Fetch a specific version (with encrypted value) for the reveal /
    /// restore flows.
    pub async fn get_secret_value_at_version(
        &self,
        name: &str,
        version: i32,
    ) -> Result<Option<SecretVersionRow>, sqlx::Error> {
        crate::repos::secret::get_value_at_version(self.db(), self.org_id(), name, version).await
    }

    /// Identity that wrote version 1 of this secret — the slot owner per
    /// SPEC §6. Returns None if the version 1 row's `created_by` was set to
    /// NULL (e.g. the creator identity was later deleted).
    pub async fn secret_owner_identity(&self, name: &str) -> Result<Option<Uuid>, sqlx::Error> {
        crate::repos::secret::first_version_creator(self.db(), self.org_id(), name).await
    }

    /// Service instances that reference this secret by name (any status).
    pub async fn list_services_using_secret(
        &self,
        name: &str,
    ) -> Result<Vec<ServiceUsingSecret>, sqlx::Error> {
        crate::repos::secret::list_services_using_secret(self.db(), self.org_id(), name).await
    }
}
