//! The approval expiry sweep: flip approvals nobody decided in time, and tell
//! everyone who was watching.
//!
//! Cross-org and bulk, like [`permission_chain::process_auto_bubble`] — the
//! other background sweep that emits. Both share the same shape: rows come off
//! a `SystemScope`, an `OrgScope` is minted per org so the follow-up work stays
//! tenant-bounded, and the events are built from the approval row alone, since
//! there is no caller to derive an audience from.
//!
//! [`permission_chain::process_auto_bubble`]: crate::services::permission_chain::process_auto_bubble

use std::collections::BTreeMap;

use overslash_db::repos::approval::ExpiredApproval;
use overslash_db::repos::audit::AuditEntry;
use overslash_db::scopes::SystemScope;
use uuid::Uuid;

use crate::error::AppError;
use crate::services::events;

/// Rows flipped per `UPDATE`. Matches `events::bus::CATCH_UP_LIMIT` — the same
/// question ("how much of a backlog does one pass take?") with the same answer.
const EXPIRY_BATCH: i64 = 500;

/// How many batches one 60s tick will drain before yielding. Each expired
/// approval costs an audit insert and a pair of identity-chain walks, and eight
/// other maintenance steps run behind this one in the same tick, so a backlog
/// must not be allowed to monopolise it. The remainder is picked up a minute
/// later, which costs a caller nothing observable: the approvals were already
/// past `expires_at` and unusable.
const MAX_BATCHES_PER_TICK: usize = 4;

/// Expire every approval that has run out of time, emitting `approval.resolved`
/// with `status: "expired"` for each one.
///
/// Returns the count the background loop logs and turns into `expired` metric
/// samples.
pub async fn process_expiry(
    system: &SystemScope,
    http_client: &reqwest::Client,
) -> Result<u64, AppError> {
    process_expiry_batched(system, http_client, EXPIRY_BATCH).await
}

/// [`process_expiry`] with the batch size supplied, so a test can drive the
/// drain loop and its ceiling without seeding [`EXPIRY_BATCH`] approvals.
pub async fn process_expiry_batched(
    system: &SystemScope,
    http_client: &reqwest::Client,
    batch_size: i64,
) -> Result<u64, AppError> {
    let mut total = 0u64;
    for batch_no in 0..MAX_BATCHES_PER_TICK {
        // A later batch failing must not discard the earlier ones: those rows
        // are committed and their events are already on the wire, so returning
        // `Err` here would lose their log line and their metric samples while
        // subscribers had long since been told. Report what actually happened.
        let batch = match system.expire_stale_approvals(batch_size).await {
            Ok(batch) => batch,
            Err(e) if total > 0 => {
                tracing::error!("approval_expiry failed after {total} rows: {e}");
                break;
            }
            Err(e) => return Err(e.into()),
        };
        if batch.is_empty() {
            break;
        }
        let drained_everything = (batch.len() as i64) < batch_size;
        total += batch.len() as u64;
        announce(system, http_client, batch).await;
        if drained_everything {
            break;
        }
        if batch_no + 1 == MAX_BATCHES_PER_TICK {
            // Never truncate silently: "expired 2000" reads like the whole
            // backlog unless the log says otherwise.
            tracing::warn!(
                "approval_expiry hit its per-tick ceiling at {total} rows; \
                 the rest drains on the next tick"
            );
        }
    }
    Ok(total)
}

/// Write the audit row and publish the event for each expired approval,
/// one org at a time.
///
/// Grouped by org because the audience walk needs an `OrgScope`, and batched
/// into one [`events::emit_all`] per org because that call appends every draft
/// to the event log *before* dispatching any webhook: the stream — the transport
/// this sweep exists to feed — never waits on some tenant's endpoint, and a
/// tenant's endpoint is never hit by hundreds of parallel deliveries either.
async fn announce(
    system: &SystemScope,
    http_client: &reqwest::Client,
    batch: Vec<ExpiredApproval>,
) {
    let mut by_org: BTreeMap<Uuid, Vec<ExpiredApproval>> = BTreeMap::new();
    for approval in batch {
        by_org.entry(approval.org_id).or_default().push(approval);
    }

    for (org_id, approvals) in by_org {
        let scope = system.scope_for_org(org_id);
        let mut drafts = Vec::with_capacity(approvals.len());
        for approval in approvals {
            // Attributed to the approval's subject, consistent with
            // `approval.resolved` and `approval.cascade_resolved`: there is no
            // resolver to credit — running out of time is the whole point.
            let _ = scope
                .log_audit_tagged(
                    AuditEntry {
                        org_id,
                        identity_id: Some(approval.identity_id),
                        action: "approval.expired",
                        resource_type: Some("approval"),
                        resource_id: Some(approval.id),
                        detail: serde_json::json!({
                            "resolved_by": "system",
                            "current_resolver_identity_id":
                                approval.current_resolver_identity_id,
                        }),
                        description: None,
                        ip_address: None,
                    },
                    &approval.tags,
                )
                .await;

            drafts.push(
                events::approvals::expired(
                    &scope,
                    approval.id,
                    approval.identity_id,
                    approval.current_resolver_identity_id,
                    &approval.action_summary,
                )
                .await,
            );
        }
        events::emit_all(system.db().clone(), http_client.clone(), drafts);
    }
}
