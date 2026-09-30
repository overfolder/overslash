//! `OrgScope` SQL methods for the org's Google Workspace Directory connection.
//!
//! Every method funnels `self.org_id()`: the config table is keyed on it, so
//! there is no id another tenant could pass in.

use uuid::Uuid;

use crate::repos::google_directory_config::{
    self, DirectoryCandidate, GoogleDirectoryConfigRow, GoogleDirectorySettings,
};
use crate::scopes::OrgScope;

impl OrgScope {
    pub async fn get_google_directory_config(
        &self,
    ) -> Result<Option<GoogleDirectoryConfigRow>, sqlx::Error> {
        google_directory_config::get_by_org(self.db(), self.org_id()).await
    }

    /// Record a proven Workspace connection. See
    /// [`google_directory_config::connect`] for the uniqueness refusal.
    pub async fn connect_google_directory(
        &self,
        admin_subject: &str,
        domain: &str,
        identity_id: Uuid,
    ) -> Result<GoogleDirectoryConfigRow, sqlx::Error> {
        google_directory_config::connect(
            self.db(),
            self.org_id(),
            admin_subject,
            domain,
            identity_id,
        )
        .await
    }

    pub async fn update_google_directory_config(
        &self,
        settings: GoogleDirectorySettings,
    ) -> Result<Option<GoogleDirectoryConfigRow>, sqlx::Error> {
        google_directory_config::update(self.db(), self.org_id(), settings).await
    }

    /// Delete the config and revoke everything it reported.
    pub async fn delete_google_directory_config(&self) -> Result<bool, sqlx::Error> {
        google_directory_config::delete(self.db(), self.org_id()).await
    }

    /// Queue one manual run. `false` when a run is already queued.
    pub async fn request_google_directory_sync(&self) -> Result<bool, sqlx::Error> {
        google_directory_config::request_sync(self.db(), self.org_id()).await
    }

    /// The org's live user identities whose email is under `domain`.
    pub async fn list_google_directory_candidates(
        &self,
        domain: &str,
    ) -> Result<Vec<DirectoryCandidate>, sqlx::Error> {
        google_directory_config::list_candidates(self.db(), self.org_id(), domain).await
    }

    /// Start a "Sign in with Google" connect bound to `identity_id`.
    pub async fn create_google_directory_connect_flow(
        &self,
        identity_id: Uuid,
        pkce_verifier: &str,
        ttl_secs: i64,
    ) -> Result<Uuid, sqlx::Error> {
        google_directory_config::create_connect_flow(
            self.db(),
            self.org_id(),
            identity_id,
            pkce_verifier,
            ttl_secs,
        )
        .await
    }
}
