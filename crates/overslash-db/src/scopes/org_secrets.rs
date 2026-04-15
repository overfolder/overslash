//! `OrgScope` SQL methods for the `secrets` resource.
//!
//! Every method here filters by `self.org_id` — callers cannot reach secrets
//! belonging to another org, even if they hold a matching `name`.

use uuid::Uuid;

use crate::repos::secret::{SecretRow, SecretVersionRow};
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

    /// List all live secrets in this org.
    pub async fn list_secrets(&self) -> Result<Vec<SecretRow>, sqlx::Error> {
        crate::repos::secret::list_by_org(self.db(), self.org_id()).await
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
}
