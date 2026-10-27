//! `OrgScope` SQL methods for `org_oauth_signin_overrides` — whether the
//! org's OAuth App Credentials also serve managed sign-in per provider.

use crate::scopes::OrgScope;

impl OrgScope {
    /// Provider keys whose org OAuth App Credentials also serve sign-in.
    pub async fn list_oauth_signin_overrides(&self) -> Result<Vec<String>, sqlx::Error> {
        crate::repos::org_oauth_signin_override::list_by_org(self.db(), self.org_id()).await
    }

    pub async fn oauth_signin_override_enabled(
        &self,
        provider_key: &str,
    ) -> Result<bool, sqlx::Error> {
        crate::repos::org_oauth_signin_override::is_enabled(self.db(), self.org_id(), provider_key)
            .await
    }

    /// Turn the opt-in on or off. Idempotent either way.
    pub async fn set_oauth_signin_override(
        &self,
        provider_key: &str,
        enabled: bool,
    ) -> Result<(), sqlx::Error> {
        crate::repos::org_oauth_signin_override::set(
            self.db(),
            self.org_id(),
            provider_key,
            enabled,
        )
        .await
    }
}
