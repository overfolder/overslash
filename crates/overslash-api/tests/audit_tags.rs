//! Metadata tags: minting, persistence across approval → execution → audit,
//! and the audit log's `tag` / `tag_contains` search.
//!
//! The vocabulary itself is unit-tested in `overslash_core::tags` and
//! `routes/actions/tags.rs`. What can only be checked end-to-end is that a tag
//! set survives every hop: the approval row it is minted onto, the execution
//! that copies it, and the audit rows for both — and that the search predicates
//! actually select on it.
// Test setup seeds rows directly.
#![allow(clippy::disallowed_methods)]

use crate::common;

use overslash_db::repos::audit::{AuditEntry, AuditFilter};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn insert_org(pool: &PgPool) -> Uuid {
    let org_id = Uuid::new_v4();
    sqlx::query("INSERT INTO orgs (id, name, slug) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind("TagOrg")
        .bind(format!("tag-{}", Uuid::new_v4()))
        .execute(pool)
        .await
        .unwrap();
    org_id
}

async fn insert_identity(pool: &PgPool, org_id: Uuid, kind: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO identities (id, org_id, kind, name) VALUES ($1, $2, $3, $4)")
        .bind(id)
        .bind(org_id)
        .bind(kind)
        .bind(format!("tagged-{}", &id.to_string()[..8]))
        .execute(pool)
        .await
        .unwrap();
    id
}

fn tagged_entry<'a>(org_id: Uuid, action: &'a str) -> AuditEntry<'a> {
    AuditEntry {
        org_id,
        identity_id: None,
        action,
        resource_type: None,
        resource_id: None,
        detail: json!({}),
        description: None,
        ip_address: None,
    }
}

fn filter(org_id: Uuid) -> AuditFilter {
    AuditFilter {
        org_id,
        limit: 50,
        ..Default::default()
    }
}

fn tags(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

// ===========================================================================
// Persistence: approval → execution
// ===========================================================================

#[tokio::test]
async fn execution_inherits_its_approvals_tags() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;
    let identity_id = insert_identity(&pool, org_id, "agent").await;
    let scope = overslash_db::OrgScope::new(org_id, pool.clone());

    let minted = tags(&[
        "service:metabase",
        "sql:write",
        "table_mut:warehouse/public.orders",
    ]);
    let approval = scope
        .create_approval(
            identity_id,
            identity_id,
            "run a write query",
            None,
            None,
            None,
            &[],
            &format!("tok-{}", Uuid::new_v4()),
            time::OffsetDateTime::now_utc() + time::Duration::hours(1),
            &minted,
        )
        .await
        .unwrap();
    assert_eq!(approval.tags, minted, "tags must round-trip through INSERT");

    // `create_pending` copies from the approval rather than taking a parameter,
    // so an execution can never disagree with what its approver was shown.
    let execution = scope
        .create_pending_execution(
            approval.id,
            false,
            None,
            None,
            time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        )
        .await
        .unwrap();
    assert_eq!(
        execution.tags, minted,
        "execution must inherit the approval's tags verbatim"
    );
}

#[tokio::test]
async fn an_untagged_approval_yields_an_untagged_execution() {
    // Pre-feature approvals (and non-action approvals) carry no tags; the
    // copy must degrade to an empty array, not NULL or a failed insert.
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;
    let identity_id = insert_identity(&pool, org_id, "agent").await;
    let scope = overslash_db::OrgScope::new(org_id, pool.clone());

    let approval = scope
        .create_approval(
            identity_id,
            identity_id,
            "untagged",
            None,
            None,
            None,
            &[],
            &format!("tok-{}", Uuid::new_v4()),
            time::OffsetDateTime::now_utc() + time::Duration::hours(1),
            &[],
        )
        .await
        .unwrap();
    let execution = scope
        .create_pending_execution(
            approval.id,
            false,
            None,
            None,
            time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        )
        .await
        .unwrap();
    assert!(approval.tags.is_empty());
    assert!(execution.tags.is_empty());
}

// ===========================================================================
// Audit search
// ===========================================================================

#[tokio::test]
async fn tag_filter_requires_every_requested_tag() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;
    let scope = overslash_db::OrgScope::new(org_id, pool.clone());

    scope
        .log_audit_tagged(
            tagged_entry(org_id, "action.executed"),
            &tags(&["service:metabase", "sql:write", "risk:write"]),
        )
        .await
        .unwrap();
    scope
        .log_audit_tagged(
            tagged_entry(org_id, "action.executed"),
            &tags(&["service:metabase", "sql:read", "risk:read"]),
        )
        .await
        .unwrap();
    scope
        .log_audit_tagged(
            tagged_entry(org_id, "action.executed"),
            &tags(&["service:github", "sql:write"]),
        )
        .await
        .unwrap();

    // One tag: everything carrying it.
    let rows = scope
        .query_audit_log(AuditFilter {
            tags: Some(tags(&["service:metabase"])),
            ..filter(org_id)
        })
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);

    // Two tags AND — "writes against Metabase" is one row, not three.
    let rows = scope
        .query_audit_log(AuditFilter {
            tags: Some(tags(&["service:metabase", "sql:write"])),
            ..filter(org_id)
        })
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].tags.contains(&"risk:write".to_string()));

    // A tag no row carries selects nothing (rather than falling open).
    let rows = scope
        .query_audit_log(AuditFilter {
            tags: Some(tags(&["service:stripe"])),
            ..filter(org_id)
        })
        .await
        .unwrap();
    assert!(rows.is_empty());
}

#[tokio::test]
async fn tag_contains_matches_any_single_tag() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;
    let scope = overslash_db::OrgScope::new(org_id, pool.clone());

    scope
        .log_audit_tagged(
            tagged_entry(org_id, "action.executed"),
            &tags(&["table:warehouse/public.orders", "sql:read"]),
        )
        .await
        .unwrap();
    scope
        .log_audit_tagged(
            tagged_entry(org_id, "action.executed"),
            &tags(&["table:warehouse/public.customers", "sql:read"]),
        )
        .await
        .unwrap();

    // The point of `tag ~`: find a relation without knowing the db label.
    let rows = scope
        .query_audit_log(AuditFilter {
            tag_contains: Some("public.orders".into()),
            ..filter(org_id)
        })
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);

    // Substring is case-insensitive and spans the whole tag.
    let rows = scope
        .query_audit_log(AuditFilter {
            tag_contains: Some("WAREHOUSE".into()),
            ..filter(org_id)
        })
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
}

#[tokio::test]
async fn tag_filters_compose_with_the_existing_ones() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;
    let scope = overslash_db::OrgScope::new(org_id, pool.clone());

    scope
        .log_audit_tagged(
            tagged_entry(org_id, "action.executed"),
            &tags(&["sql:write"]),
        )
        .await
        .unwrap();
    scope
        .log_audit_tagged(
            tagged_entry(org_id, "approval.created"),
            &tags(&["sql:write"]),
        )
        .await
        .unwrap();

    let rows = scope
        .query_audit_log(AuditFilter {
            action: Some("action.executed".into()),
            tags: Some(tags(&["sql:write"])),
            ..filter(org_id)
        })
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, "action.executed");
}

#[tokio::test]
async fn tags_are_org_scoped() {
    let pool = common::test_pool().await;
    let mine = insert_org(&pool).await;
    let theirs = insert_org(&pool).await;

    overslash_db::OrgScope::new(theirs, pool.clone())
        .log_audit_tagged(
            tagged_entry(theirs, "action.executed"),
            &tags(&["service:metabase", "sql:write"]),
        )
        .await
        .unwrap();

    // A tag search must not reach across tenants even when the tag matches.
    let rows = overslash_db::OrgScope::new(mine, pool.clone())
        .query_audit_log(AuditFilter {
            tags: Some(tags(&["service:metabase"])),
            ..filter(mine)
        })
        .await
        .unwrap();
    assert!(rows.is_empty());
}

#[tokio::test]
async fn untagged_rows_are_unaffected_by_tag_filters() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;
    let scope = overslash_db::OrgScope::new(org_id, pool.clone());

    // The ~100 non-action audit sites still call plain `log_audit`.
    scope
        .log_audit(tagged_entry(org_id, "identity.created"))
        .await
        .unwrap();

    // Absent filter → the row is returned as always.
    assert_eq!(
        scope.query_audit_log(filter(org_id)).await.unwrap().len(),
        1
    );
    // Present filter → an empty tag array matches nothing.
    let rows = scope
        .query_audit_log(AuditFilter {
            tags: Some(tags(&["sql:read"])),
            ..filter(org_id)
        })
        .await
        .unwrap();
    assert!(rows.is_empty());
}
