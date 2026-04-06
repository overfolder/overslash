//! Hierarchical permission resolution (SPEC §5).
//!
//! Walks the ancestor chain of a requesting identity. Each non-user level must
//! authorize: either it carries `inherit_permissions=true` (defers to its
//! parent) or its own permission rules cover the requested keys. The first
//! level without either is the **gap**.
//!
//! When a gap is found we also compute:
//!  - **rule_placement_id**: where an "Allow & Remember" rule should be added
//!    -- the closest non-`inherit_permissions` ancestor of the requester
//!    (inclusive). Identities that just borrow permissions are skipped.
//!  - **initial_resolver_id**: who should act on the approval first --
//!    the closest ancestor *above the gap* whose own rules already cover the
//!    request (a parent cannot grant more than it has). If no agent qualifies,
//!    or if `force_user_resolver=true`, the user is the resolver.

use sqlx::PgPool;
use uuid::Uuid;

use overslash_core::permissions::{PermissionKey, PermissionResult, check_permissions};
use overslash_core::types::{PermissionEffect, PermissionRule};
use overslash_db::repos::identity::IdentityRow;

use crate::error::AppError;

pub enum ChainWalkResult {
    /// Every level authorized -- proceed to execute.
    Allowed,
    /// A gap was found in the chain.
    Gap {
        uncovered_keys: Vec<PermissionKey>,
        gap_identity_id: Uuid,
        initial_resolver_id: Uuid,
        rule_placement_id: Uuid,
    },
    /// An explicit deny rule fired somewhere in the chain.
    Denied(String),
}

/// Walk the requester's ancestor chain and decide whether to allow, deny,
/// or open an approval.
///
/// `force_user_resolver` short-circuits the resolver search and assigns the
/// user directly -- used when the org has set `approval_auto_bubble_secs = 0`.
pub async fn walk(
    pool: &PgPool,
    requester_id: Uuid,
    perm_keys: &[PermissionKey],
    force_user_resolver: bool,
) -> Result<ChainWalkResult, AppError> {
    // chain is depth ASC: chain[0] is the user (root), chain.last() is requester.
    let chain = overslash_db::repos::identity::get_ancestor_chain(pool, requester_id).await?;
    if chain.is_empty() {
        return Err(AppError::Internal("identity chain is empty".into()));
    }

    // Walk from requester upward, stopping before the user (handled by Layer 1).
    let mut gap_idx: Option<usize> = None;
    let mut uncovered_keys: Vec<PermissionKey> = Vec::new();
    let last = chain.len() - 1;
    let mut i = last;
    while i >= 1 {
        let ident = &chain[i];
        if ident.inherit_permissions {
            // Defers to parent -- continue upward.
            i -= 1;
            continue;
        }
        let rules = load_rules(pool, ident.id).await?;
        match check_permissions(&rules, perm_keys) {
            PermissionResult::Allowed => {
                i -= 1;
                continue;
            }
            PermissionResult::Denied(reason) => {
                return Ok(ChainWalkResult::Denied(reason));
            }
            PermissionResult::NeedsApproval(uncovered) => {
                gap_idx = Some(i);
                uncovered_keys = uncovered;
                break;
            }
        }
    }

    let Some(gap_idx) = gap_idx else {
        return Ok(ChainWalkResult::Allowed);
    };

    let gap_identity_id = chain[gap_idx].id;
    let rule_placement_id = compute_rule_placement(&chain);
    let initial_resolver_id = if force_user_resolver {
        chain[0].id
    } else {
        compute_resolver_above(pool, &chain, gap_idx, &uncovered_keys).await?
    };

    Ok(ChainWalkResult::Gap {
        uncovered_keys,
        gap_identity_id,
        initial_resolver_id,
        rule_placement_id,
    })
}

/// Find the next eligible resolver after `current_resolver_id` for an approval
/// that targets `requester_id`. Used by explicit BubbleUp and the auto-bubble
/// background loop.
pub async fn find_next_resolver(
    pool: &PgPool,
    requester_id: Uuid,
    current_resolver_id: Uuid,
    keys: &[PermissionKey],
) -> Result<Uuid, AppError> {
    let chain = overslash_db::repos::identity::get_ancestor_chain(pool, requester_id).await?;
    if chain.is_empty() {
        return Err(AppError::Internal("identity chain is empty".into()));
    }
    // Find current resolver's index in the chain. If they're not in it
    // (shouldn't happen but be defensive), bubble straight to user.
    let current_idx = chain.iter().position(|c| c.id == current_resolver_id);
    let Some(current_idx) = current_idx else {
        return Ok(chain[0].id);
    };
    // If the user is already the resolver, no further bubbling.
    if current_idx == 0 {
        return Ok(chain[0].id);
    }
    // Walk strictly above the current resolver.
    let next_idx = current_idx - 1;
    if next_idx == 0 {
        return Ok(chain[0].id);
    }
    // Search from next_idx down to 1 for an agent that qualifies; else user.
    let mut j = next_idx;
    while j >= 1 {
        let ident = &chain[j];
        if !ident.inherit_permissions {
            let rules = load_rules(pool, ident.id).await?;
            if matches!(check_permissions(&rules, keys), PermissionResult::Allowed) {
                return Ok(ident.id);
            }
        }
        j -= 1;
    }
    Ok(chain[0].id)
}

/// Compute the rule placement target for an approval whose requester is
/// `chain.last()`. Returns the closest non-`inherit_permissions` ancestor
/// of the requester (inclusive). If every level inherits (unusual), falls
/// back to the user at the root.
fn compute_rule_placement(chain: &[IdentityRow]) -> Uuid {
    let last = chain.len() - 1;
    let mut i = last;
    loop {
        if !chain[i].inherit_permissions {
            return chain[i].id;
        }
        if i == 0 {
            return chain[0].id;
        }
        i -= 1;
    }
}

/// Search above the gap level for the first ancestor whose own rules already
/// cover the uncovered keys. Skips `inherit_permissions=true` ancestors. Falls
/// back to the user at chain[0] if no agent qualifies.
async fn compute_resolver_above(
    pool: &PgPool,
    chain: &[IdentityRow],
    gap_idx: usize,
    uncovered: &[PermissionKey],
) -> Result<Uuid, AppError> {
    if gap_idx == 0 {
        return Ok(chain[0].id);
    }
    let mut j = gap_idx - 1;
    while j >= 1 {
        let ident = &chain[j];
        if !ident.inherit_permissions {
            let rules = load_rules(pool, ident.id).await?;
            if matches!(
                check_permissions(&rules, uncovered),
                PermissionResult::Allowed
            ) {
                return Ok(ident.id);
            }
        }
        j -= 1;
    }
    Ok(chain[0].id)
}

/// Load and convert this identity's OWN permission rules (no inheritance walk).
async fn load_rules(pool: &PgPool, identity_id: Uuid) -> Result<Vec<PermissionRule>, AppError> {
    let rows = overslash_db::repos::permission_rule::list_by_identity(pool, identity_id).await?;
    Ok(rows
        .into_iter()
        .map(|r| PermissionRule {
            id: r.id,
            org_id: r.org_id,
            identity_id: r.identity_id,
            action_pattern: r.action_pattern,
            effect: if r.effect == "deny" {
                PermissionEffect::Deny
            } else {
                PermissionEffect::Allow
            },
            created_at: r.created_at,
        })
        .collect())
}

/// Compute the rule-placement target for a given requester independent of any
/// chain walk. Used by approval resolution when storing "Allow & Remember"
/// rules: the rule must land on the closest non-`inherit_permissions` ancestor
/// of the requester (inclusive), not on the requester itself if the requester
/// just borrows permissions.
pub async fn rule_placement_for(pool: &PgPool, requester_id: Uuid) -> Result<Uuid, AppError> {
    let chain = overslash_db::repos::identity::get_ancestor_chain(pool, requester_id).await?;
    if chain.is_empty() {
        return Err(AppError::Internal("identity chain is empty".into()));
    }
    Ok(compute_rule_placement(&chain))
}

/// One pass of the auto-bubble sweep: advance every pending approval whose
/// current resolver has held it longer than its org's
/// `approval_auto_bubble_secs`. Returns the number of approvals advanced.
///
/// Exposed as a standalone function so the background loop and tests can both
/// call it.
pub async fn process_auto_bubble(pool: &PgPool) -> Result<u64, AppError> {
    let stale = overslash_db::repos::approval::list_pending_for_auto_bubble(pool).await?;
    let mut bubbled = 0u64;
    for approval in stale {
        let perm_keys: Vec<PermissionKey> = approval
            .permission_keys
            .iter()
            .map(|k| PermissionKey(k.clone()))
            .collect();
        let next = find_next_resolver(
            pool,
            approval.identity_id,
            approval.current_resolver_identity_id,
            &perm_keys,
        )
        .await?;
        // Skip if there's nowhere to bubble to (already at user / no change).
        if next == approval.current_resolver_identity_id {
            continue;
        }
        if overslash_db::repos::approval::update_resolver(pool, approval.id, next)
            .await?
            .is_some()
        {
            let _ = overslash_db::repos::audit::log(
                pool,
                &overslash_db::repos::audit::AuditEntry {
                    org_id: approval.org_id,
                    identity_id: None,
                    action: "approval.auto_bubbled",
                    resource_type: Some("approval"),
                    resource_id: Some(approval.id),
                    detail: serde_json::json!({
                        "from": approval.current_resolver_identity_id,
                        "to": next,
                    }),
                    description: None,
                    ip_address: None,
                },
            )
            .await;
            bubbled += 1;
        }
    }
    Ok(bubbled)
}

/// Returns true if `candidate` is `target` or any ancestor of `target`.
/// Used for resolver authorization: a higher-up agent (or the user) can
/// always step in for a lower one.
pub async fn is_self_or_ancestor(
    pool: &PgPool,
    candidate: Uuid,
    target: Uuid,
) -> Result<bool, AppError> {
    if candidate == target {
        return Ok(true);
    }
    let chain = overslash_db::repos::identity::get_ancestor_chain(pool, target).await?;
    Ok(chain.iter().any(|c| c.id == candidate))
}
