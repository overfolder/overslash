//! Event drafts for the three moments an approval needs a decision from
//! someone new: it was raised, it was handed upward, and — derived from both —
//! it is now waiting on a particular resolver.
//!
//! `approval.pending` is the signal a caller subscribes to when all it wants is
//! an inbox. It restates what `approval.created` and `approval.bubbled` already
//! said, so it is deliberately absent from the audit log (which records facts,
//! not notifications) but present on the stream and on webhooks, where the
//! whole point is not having to reconstruct "is this mine now?" from two
//! different event shapes.
//!
//! Every draft here is built from the approval row rather than from a caller,
//! so the background auto-bubble sweep — which has no `AuthContext` — produces
//! exactly the same events as a human pressing the button.

use serde_json::json;
use uuid::Uuid;

use overslash_db::OrgScope;

use super::audience;
use super::{EventDraft, EventType};

/// How an approval came to be waiting on its current resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingReason {
    /// The approval was just raised at this resolver.
    Created,
    /// It was handed up to this resolver from a previous one.
    Bubbled,
}

impl PendingReason {
    fn as_str(self) -> &'static str {
        match self {
            PendingReason::Created => "created",
            PendingReason::Bubbled => "bubbled",
        }
    }
}

/// Who moved the approval up the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BubbleVia {
    /// A resolver chose to hand it up.
    User,
    /// The auto-bubble sweep did it after the org's grace period.
    Auto,
}

impl BubbleVia {
    fn as_str(self) -> &'static str {
        match self {
            BubbleVia::User => "user",
            BubbleVia::Auto => "auto",
        }
    }
}

/// Everyone who can act on the approval right now: the current resolver and
/// its strict ancestors, minus the requester, who can never resolve its own
/// request. Computed once here so subscribers don't each walk the tree.
async fn can_be_handled_by(
    scope: &OrgScope,
    resolver_id: Uuid,
    requester_id: Uuid,
) -> Vec<serde_json::Value> {
    scope
        .get_identity_ancestor_chain(resolver_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|i| i.id != requester_id)
        .map(|i| json!({ "identity_id": i.id, "kind": i.kind, "name": i.name }))
        .collect()
}

/// `approval.pending` — this approval is now awaiting a decision from
/// `resolver_id`.
pub async fn pending(
    scope: &OrgScope,
    approval_id: Uuid,
    requester_id: Uuid,
    resolver_id: Uuid,
    action_summary: &str,
    reason: PendingReason,
) -> EventDraft {
    EventDraft {
        org_id: scope.org_id(),
        event_type: EventType::ApprovalPending,
        payload: json!({
            "approval_id": approval_id,
            "identity_id": requester_id,
            "current_resolver_identity_id": resolver_id,
            "can_be_handled_by": can_be_handled_by(scope, resolver_id, requester_id).await,
            "action_summary": action_summary,
            "reason": reason.as_str(),
        }),
        audience: audience::for_approval(scope, requester_id, Some(resolver_id)).await,
    }
}

/// `approval.bubbled` — the approval moved from one resolver to the next one
/// up the chain. Carries both ends so a subscriber can tell whether it just
/// gained or lost the item without refetching.
pub async fn bubbled(
    scope: &OrgScope,
    approval_id: Uuid,
    requester_id: Uuid,
    from: Uuid,
    to: Uuid,
    via: BubbleVia,
) -> EventDraft {
    // Audience spans both resolvers: the one losing the item needs to know as
    // much as the one gaining it, and after a hand-up the previous resolver may
    // no longer be on the new resolver's chain.
    let mut audience = audience::for_approval(scope, requester_id, Some(to)).await;
    for id in audience::for_approval(scope, requester_id, Some(from)).await {
        if !audience.contains(&id) {
            audience.push(id);
        }
    }

    EventDraft {
        org_id: scope.org_id(),
        event_type: EventType::ApprovalBubbled,
        payload: json!({
            "approval_id": approval_id,
            "identity_id": requester_id,
            "from": from,
            "to": to,
            "via": via.as_str(),
        }),
        audience,
    }
}
