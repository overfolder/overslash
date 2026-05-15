//! Direct scope-method tests for identity rename / move / apply_patch /
//! delete_leaf. These complement the route-level integration tests by
//! exercising the SQL paths in isolation, including edge cases that are
//! awkward to drive through the HTTP layer (cross-org guard at the SQL
//! boundary, depth-delta math on deeper trees, the leaf-delete TOCTOU
//! resolver).

mod common;

use overslash_db::OrgScope;
use overslash_db::repos::identity::{
    ApplyPatchOutcome, DeleteLeafOutcome, IdentityRow, MoveTo, PatchIdentity,
};
use sqlx::PgPool;
use uuid::Uuid;

async fn make_scope(pool: &PgPool) -> OrgScope {
    let org = overslash_db::repos::org::create(
        pool,
        "T",
        &format!("o-{}", Uuid::new_v4().simple()),
        "standard",
    )
    .await
    .unwrap();
    OrgScope::new(org.id, pool.clone())
}

async fn make_user(scope: &OrgScope, name: &str) -> IdentityRow {
    scope.create_identity(name, "user", None).await.unwrap()
}

async fn make_agent(scope: &OrgScope, name: &str, parent: &IdentityRow) -> IdentityRow {
    scope
        .create_identity_with_parent(
            name,
            "agent",
            None,
            parent.id,
            parent.depth + 1,
            parent.id,
            false,
        )
        .await
        .unwrap()
}

async fn make_sub(scope: &OrgScope, name: &str, parent: &IdentityRow, owner: Uuid) -> IdentityRow {
    scope
        .create_identity_with_parent(
            name,
            "sub_agent",
            None,
            parent.id,
            parent.depth + 1,
            owner,
            false,
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn rename_updates_name() {
    let pool = common::test_pool().await;
    let scope = make_scope(&pool).await;
    let alice = make_user(&scope, "alice").await;

    let updated = scope
        .rename_identity(alice.id, "alice2")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.name, "alice2");
    assert_eq!(updated.id, alice.id);

    let reread = scope.get_identity(alice.id).await.unwrap().unwrap();
    assert_eq!(reread.name, "alice2");
}

#[tokio::test]
async fn rename_returns_none_for_wrong_org() {
    let pool = common::test_pool().await;
    let scope_a = make_scope(&pool).await;
    let scope_b = make_scope(&pool).await;
    let alice = make_user(&scope_a, "alice").await;

    // Same id, but rename through the *other* org's scope — must not update.
    let res = scope_b.rename_identity(alice.id, "x").await.unwrap();
    assert!(res.is_none(), "rename across orgs must not return a row");

    // Original row untouched (re-read through the owning scope).
    let reread = scope_a.get_identity(alice.id).await.unwrap().unwrap();
    assert_eq!(reread.name, "alice");
}

#[tokio::test]
async fn rename_unknown_id_returns_none() {
    let pool = common::test_pool().await;
    let scope = make_scope(&pool).await;
    let res = scope.rename_identity(Uuid::new_v4(), "x").await.unwrap();
    assert!(res.is_none());
}

#[tokio::test]
async fn move_under_cascades_depth_and_owner() {
    let pool = common::test_pool().await;
    let scope = make_scope(&pool).await;
    let alice = make_user(&scope, "alice").await;
    let bob = make_user(&scope, "bob").await;
    let henry = make_agent(&scope, "henry", &alice).await;
    let s1 = make_sub(&scope, "s1", &henry, alice.id).await;
    let s2 = make_sub(&scope, "s2", &s1, alice.id).await;

    // Sanity: depths and owners as built.
    assert_eq!(henry.depth, 1);
    assert_eq!(s1.depth, 2);
    assert_eq!(s2.depth, 3);
    assert_eq!(s1.owner_id, Some(alice.id));
    assert_eq!(s2.owner_id, Some(alice.id));

    // Move henry under bob (same depth-0 parents → no delta) — owners must
    // rewrite for sub_agent descendants.
    let moved = scope
        .move_identity_under(henry.id, bob.id, 1, bob.id, bob.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(moved.parent_id, Some(bob.id));
    assert_eq!(moved.depth, 1);
    assert_eq!(moved.owner_id, Some(bob.id));

    let s1_re = scope.get_identity(s1.id).await.unwrap().unwrap();
    let s2_re = scope.get_identity(s2.id).await.unwrap().unwrap();
    assert_eq!(
        s1_re.owner_id,
        Some(bob.id),
        "sub_agent owner must be rewritten"
    );
    assert_eq!(s2_re.owner_id, Some(bob.id));
    assert_eq!(s1_re.depth, 2);
    assert_eq!(s2_re.depth, 3);
}

#[tokio::test]
async fn move_under_shifts_descendant_depth_by_delta() {
    // Build alice → henry(agent, d=1) → s1 → s2
    // and bob → carol(agent, d=1) → carol_sub(d=2)
    // Move s1 (depth=2) under carol_sub (depth=2): s1 becomes depth=3,
    // s2 becomes depth=4. Owner becomes bob.
    let pool = common::test_pool().await;
    let scope = make_scope(&pool).await;
    let alice = make_user(&scope, "alice").await;
    let bob = make_user(&scope, "bob").await;
    let henry = make_agent(&scope, "henry", &alice).await;
    let s1 = make_sub(&scope, "s1", &henry, alice.id).await;
    let s2 = make_sub(&scope, "s2", &s1, alice.id).await;
    let carol = make_agent(&scope, "carol", &bob).await;
    let carol_sub = make_sub(&scope, "carol_sub", &carol, bob.id).await;

    let moved = scope
        .move_identity_under(s1.id, carol_sub.id, carol_sub.depth + 1, bob.id, bob.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(moved.depth, 3);
    assert_eq!(moved.parent_id, Some(carol_sub.id));
    assert_eq!(moved.owner_id, Some(bob.id));

    let s2_re = scope.get_identity(s2.id).await.unwrap().unwrap();
    assert_eq!(s2_re.depth, 4, "descendant must shift by the same delta");
    assert_eq!(s2_re.owner_id, Some(bob.id));
}

#[tokio::test]
async fn move_under_unknown_id_returns_none() {
    let pool = common::test_pool().await;
    let scope = make_scope(&pool).await;
    let alice = make_user(&scope, "alice").await;
    let res = scope
        .move_identity_under(Uuid::new_v4(), alice.id, 1, alice.id, alice.id)
        .await
        .unwrap();
    assert!(res.is_none());
}

#[tokio::test]
async fn move_under_cross_org_returns_none() {
    let pool = common::test_pool().await;
    let scope_a = make_scope(&pool).await;
    let scope_b = make_scope(&pool).await;
    let alice = make_user(&scope_a, "alice").await;
    let bob = make_user(&scope_b, "bob").await;
    let henry = make_agent(&scope_a, "henry", &alice).await;

    // Wrong scope for henry — repo must refuse via the org_id filter.
    let res = scope_b
        .move_identity_under(henry.id, bob.id, 1, bob.id, bob.id)
        .await
        .unwrap();
    assert!(res.is_none());

    let reread = scope_a.get_identity(henry.id).await.unwrap().unwrap();
    assert_eq!(reread.parent_id, Some(alice.id), "row must be untouched");
    assert_eq!(reread.owner_id, Some(alice.id));
}

#[tokio::test]
async fn apply_patch_atomic_combination() {
    // Single PATCH that renames, moves, and toggles inherit_permissions
    // in one transaction.
    let pool = common::test_pool().await;
    let scope = make_scope(&pool).await;
    let alice = make_user(&scope, "alice").await;
    let bob = make_user(&scope, "bob").await;
    let henry = make_agent(&scope, "henry", &alice).await;
    let s1 = make_sub(&scope, "s1", &henry, alice.id).await;

    let outcome = scope
        .apply_identity_patch(
            henry.id,
            PatchIdentity {
                name: Some("henry2"),
                move_to: Some(MoveTo {
                    parent_id: bob.id,
                    new_owner_id: bob.id,
                    descendant_owner_id: bob.id,
                }),
                inherit_permissions: Some(true),
            },
        )
        .await
        .unwrap();
    let ApplyPatchOutcome::Updated(updated) = outcome else {
        panic!("expected Updated, got something else");
    };
    let updated = *updated;
    assert_eq!(updated.name, "henry2");
    assert_eq!(updated.parent_id, Some(bob.id));
    assert_eq!(updated.owner_id, Some(bob.id));
    assert!(updated.inherit_permissions);

    // Sub-agent owner cascaded.
    let s1_re = scope.get_identity(s1.id).await.unwrap().unwrap();
    assert_eq!(s1_re.owner_id, Some(bob.id));
}

#[tokio::test]
async fn apply_patch_unknown_id_returns_none() {
    let pool = common::test_pool().await;
    let scope = make_scope(&pool).await;
    let outcome = scope
        .apply_identity_patch(
            Uuid::new_v4(),
            PatchIdentity {
                name: Some("x"),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(matches!(outcome, ApplyPatchOutcome::NotFound));
}

#[tokio::test]
async fn apply_patch_cycle_rejected_inside_tx() {
    // Build alice → henry(agent) → s1(sub_agent). Try to move henry under
    // s1 — that's a cycle. apply_patch must catch it under FOR UPDATE and
    // return Cycle, not crash or commit.
    let pool = common::test_pool().await;
    let scope = make_scope(&pool).await;
    let alice = make_user(&scope, "alice").await;
    let henry = make_agent(&scope, "henry", &alice).await;
    let s1 = make_sub(&scope, "s1", &henry, alice.id).await;

    let outcome = scope
        .apply_identity_patch(
            henry.id,
            PatchIdentity {
                move_to: Some(MoveTo {
                    parent_id: s1.id,
                    new_owner_id: alice.id,
                    descendant_owner_id: alice.id,
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(matches!(outcome, ApplyPatchOutcome::Cycle));

    // henry's parent is unchanged.
    let henry_re = scope.get_identity(henry.id).await.unwrap().unwrap();
    assert_eq!(henry_re.parent_id, Some(alice.id));
}

#[tokio::test]
async fn apply_patch_parent_not_found_is_domain_outcome() {
    // The route's pre-tx parent lookup is best-effort: a concurrent
    // delete can land between then and apply_patch starting. Surface
    // that as ParentNotFound rather than letting RowNotFound bubble up
    // as a 500.
    let pool = common::test_pool().await;
    let scope = make_scope(&pool).await;
    let alice = make_user(&scope, "alice").await;
    let henry = make_agent(&scope, "henry", &alice).await;

    let phantom = Uuid::new_v4();
    let outcome = scope
        .apply_identity_patch(
            henry.id,
            PatchIdentity {
                move_to: Some(MoveTo {
                    parent_id: phantom,
                    new_owner_id: phantom,
                    descendant_owner_id: phantom,
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(matches!(outcome, ApplyPatchOutcome::ParentNotFound));

    // henry's parent is unchanged.
    let henry_re = scope.get_identity(henry.id).await.unwrap().unwrap();
    assert_eq!(henry_re.parent_id, Some(alice.id));
}

#[tokio::test]
async fn delete_leaf_succeeds_for_leaf() {
    let pool = common::test_pool().await;
    let scope = make_scope(&pool).await;
    let alice = make_user(&scope, "alice").await;

    let outcome = scope.delete_identity_leaf(alice.id).await.unwrap();
    assert!(matches!(outcome, DeleteLeafOutcome::Deleted));
    assert!(scope.get_identity(alice.id).await.unwrap().is_none());
}

#[tokio::test]
async fn delete_leaf_blocks_when_children_exist() {
    let pool = common::test_pool().await;
    let scope = make_scope(&pool).await;
    let alice = make_user(&scope, "alice").await;
    let henry = make_agent(&scope, "henry", &alice).await;

    let outcome = scope.delete_identity_leaf(alice.id).await.unwrap();
    assert!(matches!(outcome, DeleteLeafOutcome::HasChildren));

    // alice still exists; so does henry (no silent cascade).
    assert!(scope.get_identity(alice.id).await.unwrap().is_some());
    assert!(scope.get_identity(henry.id).await.unwrap().is_some());
}

#[tokio::test]
async fn delete_leaf_ignores_archived_children() {
    // Archived sub-agents are soft-deleted from the user's perspective and
    // would cascade-delete with the parent anyway. They must not block an
    // admin from deleting the parent.
    let pool = common::test_pool().await;
    let scope = make_scope(&pool).await;
    let alice = make_user(&scope, "alice").await;
    let henry = make_agent(&scope, "henry", &alice).await;
    let s1 = make_sub(&scope, "s1", &henry, alice.id).await;

    // Manually flip the sub-agent to archived (the production path is
    // archive_idle_subagents but we just need the column set).
    sqlx::query!(
        "UPDATE identities SET archived_at = now(), archived_reason = 'idle_timeout'
         WHERE id = $1",
        s1.id,
    )
    .execute(&pool)
    .await
    .unwrap();

    // henry now only has an archived child — leaf delete must succeed.
    let outcome = scope.delete_identity_leaf(henry.id).await.unwrap();
    assert!(matches!(outcome, DeleteLeafOutcome::Deleted));

    // The archived sub-agent cascade-deleted with its parent.
    assert!(scope.get_identity(s1.id).await.unwrap().is_none());
}

#[tokio::test]
async fn delete_leaf_unknown_id_returns_not_found() {
    let pool = common::test_pool().await;
    let scope = make_scope(&pool).await;
    let outcome = scope.delete_identity_leaf(Uuid::new_v4()).await.unwrap();
    assert!(matches!(outcome, DeleteLeafOutcome::NotFound));
}

#[tokio::test]
async fn delete_leaf_cross_org_returns_not_found() {
    let pool = common::test_pool().await;
    let scope_a = make_scope(&pool).await;
    let scope_b = make_scope(&pool).await;
    let alice = make_user(&scope_a, "alice").await;

    let outcome = scope_b.delete_identity_leaf(alice.id).await.unwrap();
    assert!(matches!(outcome, DeleteLeafOutcome::NotFound));
    assert!(scope_a.get_identity(alice.id).await.unwrap().is_some());
}
