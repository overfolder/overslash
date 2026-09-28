//! The curated `bi` schema (docs/runbooks/bi.md): the views answer "which orgs
//! exist and who owns them", and the `bi_reader` role that BigQuery federation
//! logs in through can read them — and nothing in `public`.
// Test setup seeds rows directly.
#![allow(clippy::disallowed_methods)]

use crate::common;
use sqlx::Row;
use uuid::Uuid;

#[tokio::test]
async fn org_summary_lists_orgs_with_their_admins() {
    let pool = common::test_pool().await;

    let creator: Uuid =
        sqlx::query_scalar("INSERT INTO users (email) VALUES ('founder@acme.test') RETURNING id")
            .fetch_one(&pool)
            .await
            .unwrap();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO orgs (name, slug, creator_user_id) VALUES ('Acme', 'acme-bi', $1) RETURNING id",
    )
    .bind(creator)
    .fetch_one(&pool)
    .await
    .unwrap();
    let admin: Uuid = sqlx::query_scalar(
        "INSERT INTO identities (org_id, name, kind, email, is_org_admin)
         VALUES ($1, 'founder', 'user', 'founder@acme.test', true) RETURNING id",
    )
    .bind(org)
    .fetch_one(&pool)
    .await
    .unwrap();
    for (name, kind, email, parent) in [
        ("member", "user", Some("member@acme.test"), None),
        ("bot", "agent", None, Some(admin)),
    ] {
        sqlx::query(
            "INSERT INTO identities (org_id, name, kind, email, parent_id, owner_id, depth)
             VALUES ($1, $2, $3, $4, $5, $5, CASE WHEN $5::uuid IS NULL THEN 0 ELSE 1 END)",
        )
        .bind(org)
        .bind(name)
        .bind(kind)
        .bind(email)
        .bind(parent)
        .execute(&pool)
        .await
        .unwrap();
    }

    let row = sqlx::query(
        "SELECT name, creator_email, admin_emails, user_count, agent_count
         FROM bi.org_summary WHERE id = $1",
    )
    .bind(org)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("name"), "Acme");
    assert_eq!(row.get::<String, _>("creator_email"), "founder@acme.test");
    assert_eq!(row.get::<String, _>("admin_emails"), "founder@acme.test");
    assert_eq!(row.get::<i64, _>("user_count"), 2);
    assert_eq!(row.get::<i64, _>("agent_count"), 1);

    let members: i64 = sqlx::query_scalar("SELECT count(*) FROM bi.org_members WHERE org_id = $1")
        .bind(org)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(members, 2, "org_members lists users only, never agents");
}

#[tokio::test]
async fn bi_reader_sees_bi_views_but_not_public() {
    let pool = common::test_pool().await;
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL ROLE bi_reader")
        .execute(&mut *tx)
        .await
        .unwrap();

    sqlx::query("SELECT * FROM bi.org_summary")
        .fetch_all(&mut *tx)
        .await
        .expect("bi_reader reads the bi views");

    let err = sqlx::query("SELECT 1 FROM public.secrets LIMIT 1")
        .fetch_all(&mut *tx)
        .await
        .expect_err("bi_reader must not read public tables");
    assert!(err.to_string().contains("permission denied"), "{err}");
}

/// The API owns the `bi` login role: each boot creates or re-passwords it and
/// makes it a member of `bi_reader` and of nothing else, so it never picks up
/// the `cloudsqlsuperuser` membership Cloud SQL gives API-created users.
#[tokio::test]
async fn boot_reconcile_owns_the_bi_login_role() {
    let pool = common::test_pool().await;

    // No password configured = BI off = hands off.
    overslash_db::bi::reconcile_bi_user(&pool, None).await;

    let password = overslash_db::bi::BiPassword::parse(&"a1".repeat(16)).unwrap();
    // Twice: the first boot may create the role (it's cluster-wide, so an
    // earlier run may already have), the second must be a clean no-op.
    for _ in 0..2 {
        overslash_db::bi::reconcile_bi_user(&pool, Some(&password)).await;
        let (login, reader, other): (bool, bool, i64) = sqlx::query_as(
            "SELECT r.rolcanlogin,
                    pg_has_role('bi', 'bi_reader', 'MEMBER'),
                    (SELECT count(*) FROM pg_auth_members m
                       JOIN pg_roles g ON g.oid = m.roleid
                      WHERE m.member = r.oid AND g.rolname <> 'bi_reader')
             FROM pg_roles r WHERE r.rolname = 'bi'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(login, "bi must be able to log in");
        assert!(reader, "bi must hold bi_reader");
        assert_eq!(other, 0, "bi must hold no role besides bi_reader");
    }
}
