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
    /// `created_by` names the identity that wrote *this version* (audit
    /// attribution). `owner_identity_id` names the identity that owns the
    /// *slot* — written only on first insert; preserved across subsequent
    /// versions of the same slot. Visibility (subtree of owner) is keyed
    /// off the slot owner, not the per-version creator.
    /// `provisioned_by_user_id` names the human who physically pasted the
    /// value on the standalone provide page — only set by the secret-request
    /// flow, and only when a same-org session cookie was present.
    pub async fn put_secret(
        &self,
        name: &str,
        encrypted_value: &[u8],
        created_by: Option<Uuid>,
        owner_identity_id: Option<Uuid>,
        provisioned_by_user_id: Option<Uuid>,
    ) -> Result<(SecretRow, SecretVersionRow), sqlx::Error> {
        crate::repos::secret::put(
            self.db(),
            self.org_id(),
            name,
            encrypted_value,
            created_by,
            owner_identity_id,
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
    /// this; non-admins must use `list_secrets_visible_to_identity`.
    pub async fn list_secrets(&self) -> Result<Vec<SecretRow>, sqlx::Error> {
        crate::repos::secret::list_by_org(self.db(), self.org_id()).await
    }

    /// List secrets whose `owner_identity_id` is in `caller_id`'s downward
    /// `parent_id` subtree (the caller plus all descendants). Used for
    /// non-admin list views — admins use `list_secrets`.
    pub async fn list_secrets_visible_to_identity(
        &self,
        caller_id: Uuid,
    ) -> Result<Vec<SecretRow>, sqlx::Error> {
        crate::repos::secret::list_visible_to_identity(self.db(), self.org_id(), caller_id).await
    }

    /// True if the named secret is owned by `caller_id` or any descendant.
    /// Detail / reveal / restore must check this before letting a non-admin
    /// see the secret.
    pub async fn secret_visible_to_identity(
        &self,
        name: &str,
        caller_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        crate::repos::secret::is_visible_to_identity(self.db(), self.org_id(), name, caller_id)
            .await
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
    ///
    /// `owner_identity_id` is written only on first insert; subsequent
    /// versions of an existing slot preserve the original owner.
    pub async fn put_secrets(
        &self,
        entries: &[(&str, &[u8])],
        created_by: Option<Uuid>,
        owner_identity_id: Option<Uuid>,
    ) -> Result<(), sqlx::Error> {
        crate::repos::secret::put_many(
            self.db(),
            self.org_id(),
            entries,
            created_by,
            owner_identity_id,
        )
        .await
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

    /// Service instances that reference this secret by name (any status).
    pub async fn list_services_using_secret(
        &self,
        name: &str,
    ) -> Result<Vec<ServiceUsingSecret>, sqlx::Error> {
        crate::repos::secret::list_services_using_secret(self.db(), self.org_id(), name).await
    }
}
