//! `SystemScope` SQL methods for the `executions` resource.

use crate::scopes::SystemScope;

impl SystemScope {
    /// Mark pending executions whose 15-minute window has passed as expired.
    pub async fn expire_stale_executions(&self) -> Result<u64, sqlx::Error> {
        crate::repos::execution::expire_stale(self.db()).await
    }

    /// Reap `executing` rows that have been in flight longer than any legit
    /// replay — the API likely crashed mid-call.
    pub async fn expire_orphaned_executions(&self, grace_secs: i64) -> Result<u64, sqlx::Error> {
        crate::repos::execution::expire_orphaned_executing(self.db(), grace_secs).await
    }
}
