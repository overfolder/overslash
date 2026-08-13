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

// ── Async (worker-run) executions ────────────────────────────────────────────
//
// These are `SystemScope` rather than `OrgScope` because the worker sweeps
// across every org: it claims whatever is next in the global queue, and only
// then learns which org the row belongs to. `finalize_async_execution` takes an
// explicit `org_id` for that reason — the scope has none, so the worker passes
// back the one it got from the claim.

impl SystemScope {
    /// Lease up to `limit` queued async rows to `worker_id`.
    pub async fn claim_async_executions(
        &self,
        worker_id: &str,
        lease_ttl_secs: i64,
        limit: i64,
    ) -> Result<Vec<crate::repos::execution::AsyncClaim>, sqlx::Error> {
        crate::repos::execution::claim_async_batch(self.db(), worker_id, lease_ttl_secs, limit)
            .await
    }

    /// Renew a lease and report whether a cancel was requested. `None` means
    /// the lease was lost and the worker must abandon its result.
    pub async fn heartbeat_async_execution(
        &self,
        id: uuid::Uuid,
        worker_id: &str,
        lease_ttl_secs: i64,
    ) -> Result<Option<bool>, sqlx::Error> {
        crate::repos::execution::heartbeat_async(self.db(), id, worker_id, lease_ttl_secs).await
    }

    /// Hand a claimed row back to the queue without charging an attempt.
    pub async fn release_async_execution(
        &self,
        id: uuid::Uuid,
        worker_id: &str,
        queue_ttl_secs: i64,
    ) -> Result<bool, sqlx::Error> {
        crate::repos::execution::release_async(self.db(), id, worker_id, queue_ttl_secs).await
    }

    /// Terminal transition, guarded on lease ownership.
    pub async fn finalize_async_execution(
        &self,
        org_id: uuid::Uuid,
        id: uuid::Uuid,
        worker_id: &str,
        outcome: crate::repos::execution::AsyncOutcome<'_>,
    ) -> Result<Option<crate::repos::execution::ExecutionRow>, sqlx::Error> {
        crate::repos::execution::finalize_async(self.db(), org_id, id, worker_id, outcome).await
    }

    /// Requeue async rows whose lease expired, charging one attempt.
    pub async fn requeue_expired_async_leases(
        &self,
        max_attempts: i32,
        queue_ttl_secs: i64,
    ) -> Result<u64, sqlx::Error> {
        crate::repos::execution::requeue_expired_leases(self.db(), max_attempts, queue_ttl_secs)
            .await
    }

    /// Fail hybrid rows whose replica died mid-call. Never requeues: the
    /// upstream already received the request.
    pub async fn fail_expired_hybrid_leases(&self) -> Result<u64, sqlx::Error> {
        crate::repos::execution::fail_expired_hybrid_leases(self.db()).await
    }

    /// Fail async rows that have exhausted their attempts.
    pub async fn fail_exhausted_async_executions(
        &self,
        max_attempts: i32,
    ) -> Result<u64, sqlx::Error> {
        crate::repos::execution::fail_exhausted_async(self.db(), max_attempts).await
    }

    /// Fail async rows that outran the wall clock despite heartbeating.
    pub async fn fail_async_executions_over_wall(
        &self,
        wall_secs: i64,
    ) -> Result<u64, sqlx::Error> {
        crate::repos::execution::fail_async_over_wall(self.db(), wall_secs).await
    }
}
