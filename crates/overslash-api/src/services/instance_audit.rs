//! Instance-level audit trail (`instance_audit_log`, migration 140): every
//! action taken with instance-admin rights, across all orgs.
//!
//! Org-scoped instance-admin actions (plan, trial, create) are ALSO written to
//! the affected org's own `audit_log` by their handlers, so that org's members
//! keep seeing them. This trail is the instance-wide view and outlives the org.

use axum::http::Extensions;
use overslash_db::repos::instance_admin::{self, InstanceAuditEntry};
use uuid::Uuid;

use crate::{AppState, extractors::ClientIp};

/// Best-effort, like `OrgScope::log_audit`: a failed audit write is logged,
/// never surfaced, because the action it records has already happened.
pub async fn log(
    state: &AppState,
    ext: &Extensions,
    actor_user_id: Uuid,
    action: &str,
    org_id: Option<Uuid>,
    detail: serde_json::Value,
    ip: &ClientIp,
) {
    let entry = InstanceAuditEntry {
        actor_user_id,
        action,
        org_id,
        detail,
        ip_address: ip.0.as_deref(),
    };
    if let Err(e) = instance_admin::log(state.db(ext), &entry).await {
        tracing::error!(%action, error = %e, "instance audit write failed");
    }
}
