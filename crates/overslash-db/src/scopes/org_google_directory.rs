//! `OrgScope` SQL methods for the org's Google Workspace Directory config.
//!
//! Every method funnels `self.org_id()`: the config table is keyed on it, so
//! there is no id another tenant could pass in.

use crate::repos::google_directory_config::{
    self, DirectoryCandidate, GoogleDirectoryConfigRow, GoogleDirectoryCredential,
    GoogleDirectorySettings,
};
use crate::scopes::OrgScope;

impl OrgScope {
    pub async fn get_google_directory_config(
        &self,
    ) -> Result<Option<GoogleDirectoryConfigRow>, sqlx::Error> {
        google_directory_config::get_by_org(self.db(), self.org_id()).await
    }

    pub async fn create_google_directory_config(
        &self,
        credential: GoogleDirectoryCredential<'_>,
        admin_subject: &str,
        customer_id: &str,
        domains: &[String],
        enabled: bool,
        sync_interval_hours: i32,
    ) -> Result<GoogleDirectoryConfigRow, sqlx::Error> {
        google_directory_config::create(
            self.db(),
            self.org_id(),
            credential,
            admin_subject,
            customer_id,
            domains,
            enabled,
            sync_interval_hours,
        )
        .await
    }

    pub async fn update_google_directory_config(
        &self,
        credential: Option<GoogleDirectoryCredential<'_>>,
        settings: GoogleDirectorySettings<'_>,
    ) -> Result<Option<GoogleDirectoryConfigRow>, sqlx::Error> {
        google_directory_config::update(self.db(), self.org_id(), credential, settings).await
    }

    /// Delete the config and revoke everything it reported.
    pub async fn delete_google_directory_config(&self) -> Result<bool, sqlx::Error> {
        google_directory_config::delete(self.db(), self.org_id()).await
    }

    /// Queue one manual run. `false` when a run is already queued.
    pub async fn request_google_directory_sync(&self) -> Result<bool, sqlx::Error> {
        google_directory_config::request_sync(self.db(), self.org_id()).await
    }

    /// The org's live user identities whose email is under `domains`.
    pub async fn list_google_directory_candidates(
        &self,
        domains: &[String],
    ) -> Result<Vec<DirectoryCandidate>, sqlx::Error> {
        google_directory_config::list_candidates(self.db(), self.org_id(), domains).await
    }
}
