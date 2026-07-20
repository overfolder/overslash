//! Direct unit coverage for the ancestry authorization helpers in
//! `services::permission_chain`. The route tests (services_admin_view.rs,
//! templates.rs) exercise these through the HTTP surface; here we call them
//! straight so the parent→child ceiling semantics are pinned independently of
//! any handler wiring.
//!
//! `caller_may_manage_owned` short-circuits (owner==caller / Admin / org-level)
//! without touching the DB; the ancestry branch and `is_self_or_ancestor` walk
//! a real identity tree built via the API, so the tests seed one and assert the
//! boolean verdicts directly.

// Seeds the identity tree via the HTTP API; asserts on helper return values.
#![allow(clippy::disallowed_methods)]

use crate::common;

use serde_json::Value;
use uuid::Uuid;

use overslash_api::services::permission_chain::{caller_may_manage_owned, is_self_or_ancestor};
use overslash_core::permissions::AccessLevel;
use overslash_db::scopes::OrgScope;

/// Create an `agent`/`sub_agent` under `parent_id` and return its identity id.
async fn create_child(
    base: &str,
    client: &reqwest::Client,
    org_key: &str,
    kind: &str,
    parent_id: Uuid,
    name: &str,
) -> Uuid {
    let ident: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&serde_json::json!({ "name": name, "kind": kind, "parent_id": parent_id }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    ident["id"]
        .as_str()
        .unwrap_or_else(|| panic!("identity create failed: {ident}"))
        .parse()
        .unwrap()
}

/// A small identity tree rooted at the write-user:
///
/// ```text
/// user (user_ids[1])
///  └─ agent
///      └─ sub_agent
///  └─ sibling (agent)
/// user2 (user_ids[2])   — unrelated
/// ```
struct Tree {
    scope: OrgScope,
    user: Uuid,
    agent: Uuid,
    sub_agent: Uuid,
    sibling: Uuid,
    user2: Uuid,
}

async fn build_tree() -> Tree {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let user = fx.user_ids[1];
    let user2 = fx.user_ids[2];
    let agent = create_child(&base, &client, &fx.org_key, "agent", user, "agent").await;
    let sub_agent = create_child(&base, &client, &fx.org_key, "sub_agent", agent, "sub").await;
    let sibling = create_child(&base, &client, &fx.org_key, "agent", user, "sibling").await;

    Tree {
        scope: OrgScope::new(fx.org_id, pool),
        user,
        agent,
        sub_agent,
        sibling,
        user2,
    }
}

// ---------------------------------------------------------------------------
// caller_may_manage_owned — the verdict used by every owned-resource mutation.
// ---------------------------------------------------------------------------

/// The owner branch is independent of access level: a Read-level caller who
/// owns the resource is permitted (no ancestry/DB lookup needed).
#[tokio::test]
async fn owner_is_allowed_regardless_of_level() {
    let t = build_tree().await;
    let ok = caller_may_manage_owned(&t.scope, Some(t.agent), Some(t.agent), AccessLevel::Read)
        .await
        .unwrap();
    assert!(ok, "a caller may always manage a resource it owns");
}

/// Admin is permitted even against a resource it does not own and is unrelated
/// to (org-level included).
#[tokio::test]
async fn admin_is_allowed_for_any_owner() {
    let t = build_tree().await;
    assert!(
        caller_may_manage_owned(&t.scope, Some(t.user2), Some(t.user), AccessLevel::Admin)
            .await
            .unwrap(),
        "admin may manage another identity's resource"
    );
    assert!(
        caller_may_manage_owned(&t.scope, None, Some(t.user), AccessLevel::Admin)
            .await
            .unwrap(),
        "admin may manage an org-level resource"
    );
}

/// Org-level resources (owner `None`) never match the ancestry branch: a
/// non-admin caller is denied, and an org-level caller (`None`) is too.
#[tokio::test]
async fn org_level_requires_admin() {
    let t = build_tree().await;
    assert!(
        !caller_may_manage_owned(&t.scope, None, Some(t.user), AccessLevel::Write)
            .await
            .unwrap(),
        "a non-admin may not manage an org-level resource"
    );
    assert!(
        !caller_may_manage_owned(&t.scope, Some(t.agent), None, AccessLevel::Write)
            .await
            .unwrap(),
        "an org-level key (no identity) may not manage an owned resource"
    );
}

/// The parent→child ceiling allowance: a user may manage a resource owned by an
/// agent or sub_agent beneath it, and a mid-level agent may manage its own
/// sub_agent's resource.
#[tokio::test]
async fn ancestor_may_manage_descendant_owned() {
    let t = build_tree().await;
    assert!(
        caller_may_manage_owned(&t.scope, Some(t.agent), Some(t.user), AccessLevel::Write)
            .await
            .unwrap(),
        "user may manage its agent's resource"
    );
    assert!(
        caller_may_manage_owned(
            &t.scope,
            Some(t.sub_agent),
            Some(t.user),
            AccessLevel::Write
        )
        .await
        .unwrap(),
        "user may manage its sub_agent's resource (transitive)"
    );
    assert!(
        caller_may_manage_owned(
            &t.scope,
            Some(t.sub_agent),
            Some(t.agent),
            AccessLevel::Write
        )
        .await
        .unwrap(),
        "agent may manage its own sub_agent's resource"
    );
}

/// One-directional: a descendant may not reach up to an ancestor's resource,
/// a sibling may not reach laterally, and unrelated identities are denied.
#[tokio::test]
async fn non_ancestor_is_denied() {
    let t = build_tree().await;
    assert!(
        !caller_may_manage_owned(&t.scope, Some(t.user), Some(t.agent), AccessLevel::Write)
            .await
            .unwrap(),
        "an agent may not manage its owner-user's resource (child→parent)"
    );
    assert!(
        !caller_may_manage_owned(&t.scope, Some(t.sibling), Some(t.agent), AccessLevel::Write)
            .await
            .unwrap(),
        "a sibling agent may not manage another agent's resource"
    );
    assert!(
        !caller_may_manage_owned(&t.scope, Some(t.agent), Some(t.user2), AccessLevel::Write)
            .await
            .unwrap(),
        "an unrelated user may not manage another user's agent's resource"
    );
}

// ---------------------------------------------------------------------------
// is_self_or_ancestor — the primitive the allowance is built on.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn is_self_or_ancestor_matches_self_and_ancestors() {
    let t = build_tree().await;
    // self
    assert!(
        is_self_or_ancestor(&t.scope, t.agent, t.agent)
            .await
            .unwrap()
    );
    // direct parent + grandparent of the sub_agent
    assert!(
        is_self_or_ancestor(&t.scope, t.agent, t.sub_agent)
            .await
            .unwrap()
    );
    assert!(
        is_self_or_ancestor(&t.scope, t.user, t.sub_agent)
            .await
            .unwrap()
    );
    // user is ancestor of its direct agent
    assert!(
        is_self_or_ancestor(&t.scope, t.user, t.agent)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn is_self_or_ancestor_rejects_descendants_siblings_and_unrelated() {
    let t = build_tree().await;
    // child is not an ancestor of its parent
    assert!(
        !is_self_or_ancestor(&t.scope, t.agent, t.user)
            .await
            .unwrap()
    );
    // siblings
    assert!(
        !is_self_or_ancestor(&t.scope, t.sibling, t.agent)
            .await
            .unwrap()
    );
    // unrelated user
    assert!(
        !is_self_or_ancestor(&t.scope, t.user2, t.sub_agent)
            .await
            .unwrap()
    );
}
