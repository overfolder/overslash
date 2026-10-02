//! `OrgScope` SQL methods for the `secrets` resource.
//!
//! Every method here filters by `self.org_id` — callers cannot reach secrets
//! belonging to another org, even if they hold a matching `name`. Within an
//! org, every name-keyed method is scoped to one [`SecretNamespace`] (a
//! user's vault or the org vault): there is no lookup by bare name, so a
//! caller can only reach a secret by naming the namespace it lives in.

use overslash_core::types::{SecretNamespace, SecretPath};
use uuid::Uuid;

use crate::repos::secret::{SecretRow, SecretVersionMeta, SecretVersionRow, ServiceUsingSecret};
use crate::scopes::OrgScope;

impl OrgScope {
    /// Store or update a secret at `path`. Creates a new version each time.
    ///
    /// `created_by` names the identity that wrote *this version* (audit
    /// attribution); the namespace in `path` names the vault that owns the
    /// slot. `provisioned_by_user_id` names the human who physically pasted
    /// the value on the standalone provide page — only set by the
    /// secret-request flow, and only when a same-org session cookie was
    /// present.
    pub async fn put_secret(
        &self,
        path: &SecretPath,
        encrypted_value: &[u8],
        created_by: Option<Uuid>,
        provisioned_by_user_id: Option<Uuid>,
    ) -> Result<(SecretRow, SecretVersionRow), sqlx::Error> {
        crate::repos::secret::put(
            self.db(),
            self.org_id(),
            path.ns.owner(),
            &path.name,
            encrypted_value,
            created_by,
            provisioned_by_user_id,
        )
        .await
    }

    /// Look up a live secret's metadata at `path`.
    pub async fn get_secret(&self, path: &SecretPath) -> Result<Option<SecretRow>, sqlx::Error> {
        crate::repos::secret::get_by_name(self.db(), self.org_id(), path.ns.owner(), &path.name)
            .await
    }

    /// Fetch the current encrypted version of the secret at `path`.
    pub async fn get_current_secret_value(
        &self,
        path: &SecretPath,
    ) -> Result<Option<SecretVersionRow>, sqlx::Error> {
        crate::repos::secret::get_current_value(
            self.db(),
            self.org_id(),
            path.ns.owner(),
            &path.name,
        )
        .await
    }

    /// List all live secrets in this org, every namespace. Admin-only.
    pub async fn list_secrets(&self) -> Result<Vec<SecretRow>, sqlx::Error> {
        crate::repos::secret::list_by_org(self.db(), self.org_id()).await
    }

    /// List live secrets in one namespace.
    pub async fn list_secrets_in(
        &self,
        ns: SecretNamespace,
    ) -> Result<Vec<SecretRow>, sqlx::Error> {
        crate::repos::secret::list_in_namespace(self.db(), self.org_id(), ns.owner()).await
    }

    /// Soft-delete the secret at `path`. Returns true if a row was affected.
    pub async fn soft_delete_secret(&self, path: &SecretPath) -> Result<bool, sqlx::Error> {
        crate::repos::secret::soft_delete(self.db(), self.org_id(), path.ns.owner(), &path.name)
            .await
    }

    /// Soft-delete multiple secrets of one namespace atomically. All deletes
    /// succeed or none do — useful when a logical resource (e.g. an OAuth App
    /// Credential pair) spans two secret names.
    pub async fn soft_delete_secrets(
        &self,
        ns: SecretNamespace,
        names: &[&str],
    ) -> Result<u64, sqlx::Error> {
        crate::repos::secret::soft_delete_many(self.db(), self.org_id(), ns.owner(), names).await
    }

    /// Put multiple secrets into one namespace atomically. All writes commit
    /// together or none do — useful when a logical resource (e.g. an OAuth
    /// App Credential pair) spans two secret names.
    pub async fn put_secrets(
        &self,
        ns: SecretNamespace,
        entries: &[(&str, &[u8])],
        created_by: Option<Uuid>,
    ) -> Result<(), sqlx::Error> {
        crate::repos::secret::put_many(self.db(), self.org_id(), ns.owner(), entries, created_by)
            .await
    }

    /// List every version of the secret at `path` (newest first) without
    /// exposing ciphertext. Used by the dashboard detail view.
    pub async fn list_secret_versions(
        &self,
        path: &SecretPath,
    ) -> Result<Vec<SecretVersionMeta>, sqlx::Error> {
        crate::repos::secret::list_versions(self.db(), self.org_id(), path.ns.owner(), &path.name)
            .await
    }

    /// Fetch a specific version (with encrypted value) for the reveal /
    /// restore flows.
    pub async fn get_secret_value_at_version(
        &self,
        path: &SecretPath,
        version: i32,
    ) -> Result<Option<SecretVersionRow>, sqlx::Error> {
        crate::repos::secret::get_value_at_version(
            self.db(),
            self.org_id(),
            path.ns.owner(),
            &path.name,
            version,
        )
        .await
    }

    /// Service instances bound to the secret at `path` (any status).
    pub async fn list_services_using_secret(
        &self,
        path: &SecretPath,
    ) -> Result<Vec<ServiceUsingSecret>, sqlx::Error> {
        crate::repos::secret::list_services_using_secret(
            self.db(),
            self.org_id(),
            &path.to_canonical(),
        )
        .await
    }
}
