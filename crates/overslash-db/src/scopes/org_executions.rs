//! `OrgScope` SQL methods for the `executions` resource.
//!
//! Every method filters by `self.org_id`, so a probe with a foreign
//! approval_id returns `None` rather than leaking the row's existence.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::repos::execution::ExecutionRow;
use crate::scopes::OrgScope;

impl OrgScope {
    pub async fn create_pending_execution(
        &self,
        approval_id: Uuid,
        remember: bool,
        remember_keys: Option<&[String]>,
        remember_rule_ttl: Option<OffsetDateTime>,
        expires_at: OffsetDateTime,
    ) -> Result<ExecutionRow, sqlx::Error> {
        crate::repos::execution::create_pending(
            self.db(),
            self.org_id(),
            approval_id,
            remember,
            remember_keys,
            remember_rule_ttl,
            expires_at,
        )
        .await
    }

    /// Atomic `pending → executing` transition with expiry guard. Returns
    /// `None` if the row is not pending OR has already expired OR belongs
    /// to a different org.
    pub async fn claim_execution(
        &self,
        approval_id: Uuid,
        triggered_by: &str,
    ) -> Result<Option<ExecutionRow>, sqlx::Error> {
        crate::repos::execution::claim_for_execution(
            self.db(),
            self.org_id(),
            approval_id,
            triggered_by,
        )
        .await
    }

    pub async fn finalize_execution_executed(
        &self,
        id: Uuid,
        result: &serde_json::Value,
    ) -> Result<Option<ExecutionRow>, sqlx::Error> {
        crate::repos::execution::finalize_executed(self.db(), self.org_id(), id, result).await
    }

    pub async fn finalize_execution_failed(
        &self,
        id: Uuid,
        error: &str,
    ) -> Result<Option<ExecutionRow>, sqlx::Error> {
        crate::repos::execution::finalize_failed(self.db(), self.org_id(), id, error).await
    }

    /// Atomic `pending → cancelled`. Returns the updated row, or `None` if
    /// the row was not in `pending` (already executing / terminal).
    pub async fn cancel_pending_execution(
        &self,
        approval_id: Uuid,
    ) -> Result<Option<ExecutionRow>, sqlx::Error> {
        crate::repos::execution::cancel_if_pending(self.db(), self.org_id(), approval_id).await
    }

    pub async fn get_execution_by_approval(
        &self,
        approval_id: Uuid,
    ) -> Result<Option<ExecutionRow>, sqlx::Error> {
        crate::repos::execution::find_by_approval(self.db(), self.org_id(), approval_id).await
    }

    pub async fn list_executions_by_approvals(
        &self,
        approval_ids: &[Uuid],
    ) -> Result<Vec<ExecutionRow>, sqlx::Error> {
        crate::repos::execution::find_by_approval_ids(self.db(), self.org_id(), approval_ids).await
    }

    /// Stamp `result_viewed_at` on a terminal execution. Idempotent — the
    /// dashboard never needs this; only the requesting agent's GET is meant
    /// to mark a result read. Returns `true` on the first read, `false`
    /// thereafter (already stamped or row not in a terminal state).
    pub async fn mark_execution_viewed(&self, id: Uuid) -> Result<bool, sqlx::Error> {
        crate::repos::execution::mark_viewed(self.db(), self.org_id(), id).await
    }
}
