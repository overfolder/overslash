//! `SystemScope` SQL methods for cross-org IdP config lookups.
//!
//! The login flow needs to find which org(s) accept a given email
//! domain *before* it has any org context (the user has not yet picked
//! an org). This lookup therefore lives on `SystemScope`, which is the
//! only scope authorised to read across tenants.

use crate::repos::org_idp_config::OrgIdpConfigRow;
use crate::scopes::SystemScope;

impl SystemScope {
    /// Find enabled IdP configs whose `allowed_email_domains` contain the
    /// supplied domain. Used by the login bootstrap to route a user to
    /// the org(s) that accept their email.
    pub async fn find_idp_configs_by_email_domain(
        &self,
        domain: &str,
    ) -> Result<Vec<OrgIdpConfigRow>, sqlx::Error> {
        crate::repos::org_idp_config::find_by_email_domain(self.db(), domain).await
    }
}
