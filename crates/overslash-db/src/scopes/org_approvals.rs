//! `OrgScope` SQL methods for the `approvals` resource.
//!
//! Approvals are the most security-sensitive resource in the system: a
//! cross-tenant id or token leak would let an attacker resolve another
//! org's pending action. Every method here filters by `self.org_id` so a
//! probe with a foreign id returns `None` instead of the row.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::repos::approval::{ApprovalRow, CreateApproval};
use crate::scopes::OrgScope;

impl OrgScope {
    /// Create an approval. The caller's `OrgScope` is the source of truth for
    /// `org_id` — any `org_id` field on the input is ignored and overwritten
    /// to prevent cross-tenant smuggling at the construction site.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_approval<'a>(
        &self,
        identity_id: Uuid,
        current_resolver_identity_id: Uuid,
        action_summary: &'a str,
        action_detail: Option<serde_json::Value>,
        disclosed_fields: Option<serde_json::Value>,
        replay_payload: Option<serde_json::Value>,
        permission_keys: &'a [String],
        token: &'a str,
        expires_at: OffsetDateTime,
    ) -> Result<ApprovalRow, sqlx::Error> {
        let input = CreateApproval {
            org_id: self.org_id(),
            identity_id,
            current_resolver_identity_id,
            action_summary,
            action_detail,
            disclosed_fields,
            replay_payload,
            permission_keys,
            token,
            expires_at,
        };
        crate::repos::approval::create(self.db(), &input).await
    }

    /// Look up an approval by id, scoped to this org. Returns `None` if the
    /// id belongs to another tenant — was previously an unscoped lookup.
    pub async fn get_approval(&self, id: Uuid) -> Result<Option<ApprovalRow>, sqlx::Error> {
        crate::repos::approval::get_by_id(self.db(), self.org_id(), id).await
    }

    /// Look up an approval by token, scoped to this org. Returns `None` if
    /// the token is from another tenant — was previously an unscoped lookup.
    pub async fn get_approval_by_token(
        &self,
        token: &str,
    ) -> Result<Option<ApprovalRow>, sqlx::Error> {
        crate::repos::approval::get_by_token(self.db(), self.org_id(), token).await
    }

    /// Atomically resolve a pending approval in this org. Returns `None` if
    /// the approval is not pending, the resolver has been advanced, OR the
    /// approval belongs to a different org — the SQL was previously unscoped.
    pub async fn resolve_approval(
        &self,
        id: Uuid,
        status: &str,
        resolved_by: &str,
        remember: bool,
        expected_resolver: Uuid,
    ) -> Result<Option<ApprovalRow>, sqlx::Error> {
        crate::repos::approval::resolve(
            self.db(),
            self.org_id(),
            id,
            status,
            resolved_by,
            remember,
            expected_resolver,
        )
        .await
    }

    /// Atomically advance the current resolver of a pending approval in this
    /// org. Returns `None` on stale resolver, status drift, or cross-tenant
    /// id — the SQL was previously unscoped.
    pub async fn update_approval_resolver(
        &self,
        id: Uuid,
        new_resolver: Uuid,
        expected_resolver: Uuid,
    ) -> Result<Option<ApprovalRow>, sqlx::Error> {
        crate::repos::approval::update_resolver(
            self.db(),
            self.org_id(),
            id,
            new_resolver,
            expected_resolver,
        )
        .await
    }

    /// List pending approvals for this org.
    pub async fn list_pending_approvals(&self) -> Result<Vec<ApprovalRow>, sqlx::Error> {
        crate::repos::approval::list_pending_by_org(self.db(), self.org_id()).await
    }

    /// List approvals requested by `identity_id` (the "mine" inbox view).
    pub async fn list_mine_approvals(
        &self,
        identity_id: Uuid,
    ) -> Result<Vec<ApprovalRow>, sqlx::Error> {
        crate::repos::approval::list_mine(self.db(), self.org_id(), identity_id).await
    }

    /// List approvals for `identity_id` with the given `status`.
    pub async fn list_mine_approvals_by_status(
        &self,
        identity_id: Uuid,
        status: &str,
    ) -> Result<Vec<ApprovalRow>, sqlx::Error> {
        crate::repos::approval::list_mine_by_status(self.db(), self.org_id(), identity_id, status)
            .await
    }

    /// List approvals where `identity_id` is the current resolver right now.
    pub async fn list_assigned_approvals(
        &self,
        identity_id: Uuid,
    ) -> Result<Vec<ApprovalRow>, sqlx::Error> {
        crate::repos::approval::list_assigned_to_identity(self.db(), self.org_id(), identity_id)
            .await
    }

    /// List approvals `identity_id` could act on (current resolver, or any
    /// descendant of theirs is). Excludes approvals the caller requested.
    pub async fn list_actionable_approvals(
        &self,
        identity_id: Uuid,
    ) -> Result<Vec<ApprovalRow>, sqlx::Error> {
        crate::repos::approval::list_actionable_for_identity(self.db(), self.org_id(), identity_id)
            .await
    }
}
