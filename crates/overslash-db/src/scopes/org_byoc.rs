//! `OrgScope` SQL methods for the `byoc_credentials` resource.
//!
//! BYOC credentials are org-owned. Every method here checks `row.org_id`
//! against `self.org_id()` and returns `None` on mismatch, so cross-org
//! reads are impossible at this layer.

use uuid::Uuid;

use crate::repos::byoc_credential::{ByocCredentialRow, CreateByocCredential};
use crate::scopes::OrgScope;

impl OrgScope {
    /// Create a BYOC credential in this org. The supplied input's `org_id`
    /// is overwritten with `self.org_id()` so callers cannot stash a
    /// credential under another tenant.
    pub async fn create_byoc_credential(
        &self,
        identity_id: Option<Uuid>,
        provider_key: &str,
        encrypted_client_id: &[u8],
        encrypted_client_secret: &[u8],
    ) -> Result<ByocCredentialRow, sqlx::Error> {
        let input = CreateByocCredential {
            org_id: self.org_id(),
            identity_id,
            provider_key,
            encrypted_client_id,
            encrypted_client_secret,
        };
        crate::repos::byoc_credential::create(self.db(), &input).await
    }

    /// Look up a BYOC credential by id, scoped to this org. Returns `None`
    /// if the row belongs to another tenant.
    pub async fn get_byoc_credential(
        &self,
        id: Uuid,
    ) -> Result<Option<ByocCredentialRow>, sqlx::Error> {
        let row = crate::repos::byoc_credential::get_by_id(self.db(), id).await?;
        Ok(row.filter(|r| r.org_id == self.org_id()))
    }

    /// List BYOC credentials in this org.
    pub async fn list_byoc_credentials(&self) -> Result<Vec<ByocCredentialRow>, sqlx::Error> {
        crate::repos::byoc_credential::list_by_org(self.db(), self.org_id()).await
    }

    /// Delete a BYOC credential, scoped to this org.
    pub async fn delete_byoc_credential(&self, id: Uuid) -> Result<bool, sqlx::Error> {
        crate::repos::byoc_credential::delete_by_org(self.db(), id, self.org_id()).await
    }

    /// Resolve the most-specific BYOC credential for the given identity +
    /// provider in this org. Returns identity-level match first, then the
    /// org-level fallback.
    pub async fn resolve_byoc_credential(
        &self,
        identity_id: Option<Uuid>,
        provider_key: &str,
    ) -> Result<Option<ByocCredentialRow>, sqlx::Error> {
        crate::repos::byoc_credential::resolve(self.db(), self.org_id(), identity_id, provider_key)
            .await
    }
}
