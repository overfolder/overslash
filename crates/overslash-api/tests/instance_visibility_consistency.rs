//! Consistency property tests for the service-instance visibility/resolve
//! surface. Pins the invariant that the list view and the call resolver
//! agree on which instances a given caller can reach.
//!
//! Two bugs in this area shipped recently:
//!   - PR #306: search listed group-granted instances that `resolve_by_name`
//!     refused to find, surfacing as 404 at `/v1/actions/call`.
//!   - Follow-up: the OAuth re-auth helper crossed user boundaries via
//!     `on_behalf_of`, returning 403 even though the caller had legitimate
//!     group access.
//!
//! Both root in the same drift between list / resolve / authorise. This
//! test seeds an explicit matrix of ownership + group-grant configurations
//! and asserts the cross-function invariants so the drift becomes a CI
//! failure next time.
//!
//! Setup mirrors production: every user-owned instance is granted to the
//! owner's Myself group and every org-level instance is granted to
//! Everyone, matching what `kernel_create_service` and `bootstrap_org` do
//! in the live API surface.
//!
//! Invariants asserted for every (caller, instance) cell:
//!   1. `LISTED == RESOLVED` — list_available_service_instances_with_groups
//!      and resolve_by_name agree on visibility.
//!   2. `RESOLVED implies RESOLVED_ANY` — active-only resolve is a subset
//!      of the dashboard's any-status resolve (vet flagged this missing
//!      step-5 parity in PR #306).

#![allow(clippy::disallowed_methods)]

mod common;

use overslash_db::OrgScope;
use overslash_db::repos::identity::IdentityRow;
use overslash_db::repos::service_instance::{CreateServiceInstance, ServiceInstanceRow};
use overslash_db::repos::{org as org_repo, org_bootstrap};
use uuid::Uuid;

async fn make_bootstrapped_scope() -> OrgScope {
    let pool = common::test_pool().await;
    let org = org_repo::create(
        &pool,
        "test-org",
        &format!("o-{}", Uuid::new_v4().simple()),
        "standard",
    )
    .await
    .unwrap();
    // Seed Everyone + Admins groups, the system `overslash` + `http`
    // instances, and the default grants. Without this the system-managed
    // Everyone group doesn't exist and our `inst_org` grant has nowhere
    // to land.
    org_bootstrap::bootstrap_org(&pool, org.id, None)
        .await
        .unwrap();
    OrgScope::new(org.id, pool)
}

async fn make_user(scope: &OrgScope, name: &str) -> IdentityRow {
    let row = scope.create_identity(name, "user", None).await.unwrap();
    // Mirror what the create-identity route does: join Everyone, create
    // a Myself group. Without this the user has no group memberships and
    // `get_visible_service_ids` returns an empty set.
    org_bootstrap::bootstrap_user_in_org(scope.db(), scope.org_id(), row.id)
        .await
        .unwrap();
    row
}

async fn make_agent_under(scope: &OrgScope, name: &str, parent: &IdentityRow) -> IdentityRow {
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

/// Create a service instance and add the production-shape group grants:
/// owned instances go on the owner's Myself group; org-level instances
/// go on Everyone. Mirrors `kernel_create_service`.
async fn make_instance(scope: &OrgScope, name: &str, owner: Option<Uuid>) -> ServiceInstanceRow {
    let row = scope
        .create_service_instance(CreateServiceInstance {
            org_id: scope.org_id(),
            owner_identity_id: owner,
            name,
            template_source: "global",
            template_key: "x",
            template_id: None,
            connection_id: None,
            secret_name: None,
            credentials: &Default::default(),
            url: None,
            use_default_connection: true,
            status: "active",
        })
        .await
        .unwrap();

    match owner {
        Some(owner_id) => {
            scope
                .grant_service_to_self_group(owner_id, row.id, name)
                .await
                .unwrap();
        }
        None => {
            // Org-level instance — visible to all org members via Everyone.
            let everyone = scope
                .find_everyone_group()
                .await
                .unwrap()
                .expect("bootstrap_org should have created Everyone");
            scope
                .add_group_grant(everyone.id, row.id, "write", false)
                .await
                .unwrap();
        }
    }
    row
}

/// Mirror of `ceiling_user_id_from_identity` from the API crate — duplicated
/// here so this test stays DB-only. Users are their own ceiling; agents
/// use their `owner_id`.
fn ceiling_for(identity: &IdentityRow) -> Uuid {
    match identity.kind.as_str() {
        "user" => identity.id,
        _ => identity.owner_id.expect("agent must carry owner_id"),
    }
}

#[tokio::test]
async fn list_and_resolve_agree_on_visibility_across_ownership_matrix() {
    let scope = make_bootstrapped_scope().await;

    // ── Identities ────────────────────────────────────────────────────────
    let user_a = make_user(&scope, "user_a").await;
    let user_b = make_user(&scope, "user_b").await;
    // Spare third user with no extra group memberships beyond the system
    // defaults — exercises the "no cross-user grant" cell.
    let user_c = make_user(&scope, "user_c").await;
    let agent_a = make_agent_under(&scope, "agent_a", &user_a).await;
    let agent_b = make_agent_under(&scope, "agent_b", &user_b).await;

    // ── Instances ─────────────────────────────────────────────────────────
    let inst_org = make_instance(&scope, "inst_org", None).await;
    let inst_a_owned = make_instance(&scope, "inst_a_owned", Some(user_a.id)).await;
    let inst_b_owned = make_instance(&scope, "inst_b_owned", Some(user_b.id)).await;
    let inst_b_grouped = make_instance(&scope, "inst_b_grouped", Some(user_b.id)).await;
    // Dedicated group with a + b, used to share inst_b_grouped with A.
    let group_ab = scope.create_group("g_ab", "shared services").await.unwrap();
    scope
        .assign_identity_to_group(user_a.id, group_ab.id)
        .await
        .unwrap();
    scope
        .assign_identity_to_group(user_b.id, group_ab.id)
        .await
        .unwrap();
    scope
        .add_group_grant(group_ab.id, inst_b_grouped.id, "write", false)
        .await
        .unwrap();

    // ── Matrix ────────────────────────────────────────────────────────────
    let callers: [(&str, &IdentityRow); 5] = [
        ("user_a", &user_a),
        ("user_b", &user_b),
        ("user_c", &user_c),
        ("agent_a", &agent_a),
        ("agent_b", &agent_b),
    ];
    let instances: [(&str, &ServiceInstanceRow); 4] = [
        ("inst_org", &inst_org),
        ("inst_a_owned", &inst_a_owned),
        ("inst_b_owned", &inst_b_owned),
        ("inst_b_grouped", &inst_b_grouped),
    ];

    let mut mismatches: Vec<String> = Vec::new();

    for (caller_name, caller) in &callers {
        let ceiling = ceiling_for(caller);
        let visible_ids = scope.get_visible_service_ids(ceiling).await.unwrap();
        let listed = scope
            .list_available_service_instances_with_groups(
                Some(caller.id),
                Some(ceiling),
                Some(&visible_ids),
            )
            .await
            .unwrap();
        let listed_ids: std::collections::HashSet<Uuid> = listed.iter().map(|r| r.id).collect();

        for (inst_name, inst) in &instances {
            let is_listed = listed_ids.contains(&inst.id);

            let resolved = scope
                .resolve_service_instance_by_name(Some(caller.id), Some(ceiling), &inst.name)
                .await
                .unwrap();
            let is_resolved = resolved.is_some();

            let resolved_any = scope
                .resolve_service_instance_by_name_any_status(
                    Some(caller.id),
                    Some(ceiling),
                    &inst.name,
                )
                .await
                .unwrap();
            let is_resolved_any = resolved_any.is_some();

            // Invariant 1: LISTED == RESOLVED.
            if is_listed != is_resolved {
                mismatches.push(format!(
                    "(caller={caller_name}, inst={inst_name}): LISTED={is_listed} \
                     RESOLVED={is_resolved} (expected equal)"
                ));
            }
            // Invariant 2: RESOLVED ⇒ RESOLVED_ANY.
            if is_resolved && !is_resolved_any {
                mismatches.push(format!(
                    "(caller={caller_name}, inst={inst_name}): RESOLVED=true but \
                     RESOLVED_ANY=false — any_status must be a superset"
                ));
            }
        }
    }

    assert!(
        mismatches.is_empty(),
        "list/resolve consistency violated:\n  - {}",
        mismatches.join("\n  - ")
    );
}
