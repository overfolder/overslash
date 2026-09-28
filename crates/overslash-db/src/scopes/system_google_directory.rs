//! `SystemScope` SQL methods for the Google Directory sync worker.
//!
//! Claiming due configs is inherently cross-tenant — the worker does not know
//! which org is next until the claim returns it — so it lives here. Once a row
//! is claimed, the sync itself runs under that org's `OrgScope`.

use uuid::Uuid;

use crate::repos::google_directory_config;
use crate::scopes::SystemScope;

impl SystemScope {
    /// Lease up to `limit` due Google Directory configs to `worker_id`.
    pub async fn claim_due_google_directory_syncs(
        &self,
        worker_id: &str,
        lease_ttl_secs: i64,
        limit: i64,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        google_directory_config::claim_due(self.db(), worker_id, lease_ttl_secs, limit).await
    }

    /// Record a run's outcome and release the lease if `worker_id` still holds it.
    pub async fn finish_google_directory_sync(
        &self,
        org_id: Uuid,
        worker_id: &str,
        status: &str,
        error: Option<&str>,
        stats: Option<&serde_json::Value>,
    ) -> Result<bool, sqlx::Error> {
        google_directory_config::finish(self.db(), org_id, worker_id, status, error, stats).await
    }
}
