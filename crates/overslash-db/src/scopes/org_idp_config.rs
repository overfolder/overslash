//! `OrgScope` SQL methods for the `org_idp_configs` resource.
//!
//! Org IdP configs are org-owned. Mutations and lookups by id all funnel
//! through `self.org_id()`. The login bootstrap path looks configs up by
//! the unauthenticated user's email domain — that lookup has no org
//! context yet and lives on `SystemScope::find_idp_configs_by_email_domain`.

use uuid::Uuid;

pub use crate::repos::org_idp_config::CredentialsUpdate;
use crate::repos::org_idp_config::OrgIdpConfigRow;
use crate::scopes::OrgScope;

impl OrgScope {
    /// Create an IdP config in this org.
    ///
    /// `encrypted_client_id` / `encrypted_client_secret` are both `None` when
    /// the config defers to org-level OAuth App Credentials, both `Some`
    /// when the config has its own dedicated credentials. The DB CHECK
    /// enforces the both-or-neither invariant.
    pub async fn create_org_idp_config(
        &self,
        provider_key: &str,
        encrypted_client_id: Option<&[u8]>,
        encrypted_client_secret: Option<&[u8]>,
        enabled: bool,
        allowed_email_domains: &[String],
    ) -> Result<OrgIdpConfigRow, sqlx::Error> {
        crate::repos::org_idp_config::create(
            self.db(),
            self.org_id(),
            provider_key,
            encrypted_client_id,
            encrypted_client_secret,
            enabled,
            allowed_email_domains,
        )
        .await
    }

    /// Look up an IdP config by id, scoped to this org. Returns `None` if
    /// the id belongs to another tenant.
    pub async fn get_org_idp_config(
        &self,
        id: Uuid,
    ) -> Result<Option<OrgIdpConfigRow>, sqlx::Error> {
        crate::repos::org_idp_config::get_by_id(self.db(), id, self.org_id()).await
    }

    /// Look up an IdP config by provider key in this org.
    pub async fn get_org_idp_config_by_provider(
        &self,
        provider_key: &str,
    ) -> Result<Option<OrgIdpConfigRow>, sqlx::Error> {
        crate::repos::org_idp_config::get_by_org_and_provider(
            self.db(),
            self.org_id(),
            provider_key,
        )
        .await
    }

    /// List all IdP configs in this org.
    pub async fn list_org_idp_configs(&self) -> Result<Vec<OrgIdpConfigRow>, sqlx::Error> {
        crate::repos::org_idp_config::list_by_org(self.db(), self.org_id()).await
    }

    /// List enabled IdP configs in this org. Used by the login picker.
    pub async fn list_enabled_org_idp_configs(&self) -> Result<Vec<OrgIdpConfigRow>, sqlx::Error> {
        crate::repos::org_idp_config::list_enabled_by_org(self.db(), self.org_id()).await
    }

    /// Fetch the org's designated default IdP, if any is set and enabled.
    /// `/oauth/authorize` on a corp subdomain reads this to bounce
    /// unauthenticated callers straight through the configured IdP.
    pub async fn get_default_org_idp_config(&self) -> Result<Option<OrgIdpConfigRow>, sqlx::Error> {
        crate::repos::org_idp_config::get_default_by_org(self.db(), self.org_id()).await
    }

    /// Mark `id` as the org's default IdP, atomically clearing the prior
    /// default in the same transaction.
    pub async fn set_default_org_idp_config(
        &self,
        id: Uuid,
    ) -> Result<Option<OrgIdpConfigRow>, sqlx::Error> {
        crate::repos::org_idp_config::set_default(self.db(), id, self.org_id()).await
    }

    /// Clear the default flag on `id`. No-op if it wasn't the default.
    pub async fn clear_default_org_idp_config(
        &self,
        id: Uuid,
    ) -> Result<Option<OrgIdpConfigRow>, sqlx::Error> {
        crate::repos::org_idp_config::clear_default(self.db(), id, self.org_id()).await
    }

    /// Update an IdP config, scoped to this org. Returns `None` if the id
    /// belongs to another tenant.
    pub async fn update_org_idp_config(
        &self,
        id: Uuid,
        creds: CredentialsUpdate<'_>,
        enabled: Option<bool>,
        allowed_email_domains: Option<&[String]>,
    ) -> Result<Option<OrgIdpConfigRow>, sqlx::Error> {
        crate::repos::org_idp_config::update(
            self.db(),
            id,
            self.org_id(),
            creds,
            enabled,
            allowed_email_domains,
        )
        .await
    }

    /// Delete an IdP config, scoped to this org.
    pub async fn delete_org_idp_config(&self, id: Uuid) -> Result<bool, sqlx::Error> {
        crate::repos::org_idp_config::delete(self.db(), id, self.org_id()).await
    }
}
