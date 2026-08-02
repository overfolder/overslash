//! Who is allowed to see an event.
//!
//! Audience is resolved once, by the code path that emits the event, and
//! frozen into the row. That is deliberate on two counts. It is where the
//! identity chains are already loaded, so it costs at most one extra query
//! instead of one per subscriber; and an event is a historical fact, so
//! re-deriving visibility at read time would let tomorrow's re-parenting
//! change who could see what happened today.
//!
//! The rules mirror the corresponding read endpoints. An event must never
//! reach an identity that could not have fetched the same object over REST —
//! and, because `GET /v1/approvals` currently has no ACL gate of its own, the
//! stream is deliberately *narrower* than that endpoint rather than matching
//! its org-wide behaviour.

use uuid::Uuid;

use overslash_db::OrgScope;

/// `id` plus every ancestor, or just `id` if the walk fails. Degrading to the
/// narrowest audience on error keeps a transient database problem from
/// widening visibility.
async fn chain(scope: &OrgScope, id: Uuid) -> Vec<Uuid> {
    match scope.get_identity_ancestor_chain(id).await {
        Ok(rows) if !rows.is_empty() => rows.into_iter().map(|r| r.id).collect(),
        Ok(_) => vec![id],
        Err(e) => {
            tracing::warn!("audience: ancestor chain for {id} failed: {e}");
            vec![id]
        }
    }
}

fn merge(into: &mut Vec<Uuid>, ids: impl IntoIterator<Item = Uuid>) {
    for id in ids {
        if !into.contains(&id) {
            into.push(id);
        }
    }
}

/// Approvals: the requester's chain plus the resolver's chain.
///
/// The requester covers `?scope=mine`; the resolver covers `?scope=assigned`;
/// and the resolver's *ancestors* are exactly the `?scope=actionable` set,
/// since an identity can act on an approval iff the current resolver is itself
/// or one of its descendants. The requester's ancestors come along so a parent
/// keeps seeing what its sub-agents are doing. Bubbling usually places the
/// resolver on the requester's own chain, so in practice the two collapse into
/// one list.
pub async fn for_approval(
    scope: &OrgScope,
    requester_id: Uuid,
    resolver_id: Option<Uuid>,
) -> Vec<Uuid> {
    let mut audience = chain(scope, requester_id).await;
    if let Some(resolver_id) = resolver_id
        && resolver_id != requester_id
    {
        merge(&mut audience, chain(scope, resolver_id).await);
    }
    audience
}

/// [`for_approval`] for callers that already hold the resolver's ancestor
/// chain — the approval-creation path computes it anyway to populate
/// `can_be_handled_by`, and re-walking it would be a wasted query on the
/// hottest of these sites.
pub async fn for_approval_with_resolver_chain(
    scope: &OrgScope,
    requester_id: Uuid,
    resolver_chain: impl IntoIterator<Item = Uuid>,
) -> Vec<Uuid> {
    let mut audience = chain(scope, requester_id).await;
    merge(&mut audience, resolver_chain);
    audience
}

/// Connections: the owner's chain plus whoever performed the action.
///
/// Not the owner's descendants. Sub-agents *use* an owner-level connection via
/// `on_behalf_of`, but they cannot list or manage it — `listConnections` is
/// owner-scoped — and an event stream must never be wider than the read model
/// it reflects. Org-level connections have no owner, so only the actor (and
/// org admins) see them.
pub async fn for_connection(
    scope: &OrgScope,
    owner_id: Option<Uuid>,
    actor_id: Option<Uuid>,
) -> Vec<Uuid> {
    let mut audience = Vec::new();
    if let Some(owner_id) = owner_id {
        merge(&mut audience, chain(scope, owner_id).await);
    }
    if let Some(actor_id) = actor_id {
        merge(&mut audience, [actor_id]);
    }
    audience
}

/// Secret requests: the requesting agent's chain plus the target identity's.
///
/// The requester is the agent blocked waiting on the secret — it is the whole
/// point of the `fulfilled` event. The target's chain covers the owner-user
/// whose vault slot gets written. Whoever actually submits the value is
/// anonymous (a capability URL, no session required) and is not an audience
/// member by virtue of submitting.
pub async fn for_secret_request(
    scope: &OrgScope,
    requested_by: Uuid,
    target_identity_id: Uuid,
) -> Vec<Uuid> {
    let mut audience = chain(scope, requested_by).await;
    if target_identity_id != requested_by {
        merge(&mut audience, chain(scope, target_identity_id).await);
    }
    audience
}
