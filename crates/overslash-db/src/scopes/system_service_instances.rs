//! `SystemScope` SQL methods for the `service_instances` resource.
//!
//! Cross-org by design and therefore exposed only on `SystemScope`. One method
//! today, backing the `service_setup_draft_purge` sweep in
//! `overslash-api::lib::run`.

use crate::repos::service_instance;
use crate::scopes::SystemScope;

impl SystemScope {
    /// Delete unverified setup drafts older than `max_age_secs`, across every
    /// org. See [`service_instance::purge_expired_setup_drafts`] for what is
    /// and is not swept, and why the age is measured from `created_at`.
    pub async fn purge_expired_setup_drafts(&self, max_age_secs: i64) -> Result<u64, sqlx::Error> {
        service_instance::purge_expired_setup_drafts(self.db(), max_age_secs).await
    }
}
