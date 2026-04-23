//! `OrgScope` SQL methods for the `rate_limits` resource.
//!
//! Rate limit configs are org-owned. Every method funnels through
//! `self.org_id()`, so a row id from another tenant returns `false` /
//! `None` at the SQL boundary.

use uuid::Uuid;

use crate::repos::rate_limit::RateLimitRow;
use crate::scopes::OrgScope;

impl OrgScope {
    /// Upsert a rate limit config in this org. See `repos::rate_limit::upsert`
    /// for the per-scope conflict targets.
    pub async fn upsert_rate_limit(
        &self,
        scope: &str,
        identity_id: Option<Uuid>,
        group_id: Option<Uuid>,
        max_requests: i32,
        window_seconds: i32,
    ) -> Result<RateLimitRow, sqlx::Error> {
        crate::repos::rate_limit::upsert(
            self.db(),
            self.org_id(),
            scope,
            identity_id,
            group_id,
            max_requests,
            window_seconds,
        )
        .await
    }

    /// Get the rate limit row for a specific identity in this org.
    pub async fn get_rate_limit_for_identity(
        &self,
        identity_id: Uuid,
        scope: &str,
    ) -> Result<Option<RateLimitRow>, sqlx::Error> {
        crate::repos::rate_limit::get_for_identity(self.db(), self.org_id(), identity_id, scope)
            .await
    }

    /// Pick the most permissive group rate limit across the supplied groups
    /// in this org.
    pub async fn most_permissive_group_rate_limit(
        &self,
        group_ids: &[Uuid],
    ) -> Result<Option<RateLimitRow>, sqlx::Error> {
        crate::repos::rate_limit::get_most_permissive_for_groups(
            self.db(),
            self.org_id(),
            group_ids,
        )
        .await
    }

    /// Get the org-wide default rate limit.
    pub async fn get_org_default_rate_limit(&self) -> Result<Option<RateLimitRow>, sqlx::Error> {
        crate::repos::rate_limit::get_org_default(self.db(), self.org_id()).await
    }

    /// List all rate limit configs in this org.
    pub async fn list_rate_limits(&self) -> Result<Vec<RateLimitRow>, sqlx::Error> {
        crate::repos::rate_limit::list_by_org(self.db(), self.org_id()).await
    }

    /// Delete a rate limit config, scoped to this org.
    pub async fn delete_rate_limit(&self, id: Uuid) -> Result<bool, sqlx::Error> {
        crate::repos::rate_limit::delete(self.db(), id, self.org_id()).await
    }
}
