//! The BI read path (docs/runbooks/bi.md): the boot reconcile turns `bi` into
//! a LOGIN role with SELECT on an allow-list of columns only, and every
//! terraform-owned BI query (`infra/modules/bi/sql/*.sql`) runs as that role.
//! This is what catches a column rename, or a query reaching past the
//! allow-list, before BigQuery does.
//!
//! One test, not several: `bi` is cluster-wide, and parallel tests
//! re-passwording it would race each other on the catalog.
// Test setup seeds rows directly.
#![allow(clippy::disallowed_methods)]

use std::path::Path;

use crate::common;
use sqlx::Row;
use uuid::Uuid;

fn bi_queries() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../infra/modules/bi/sql");
    let mut out: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "sql"))
        .map(|p| {
            let name = p.file_stem().unwrap().to_string_lossy().into_owned();
            (name, std::fs::read_to_string(&p).unwrap())
        })
        .collect();
    out.sort();
    assert!(!out.is_empty(), "no BI queries found in {}", dir.display());
    out
}

async fn seed_org(pool: &sqlx::PgPool) -> Uuid {
    let creator: Uuid =
        sqlx::query_scalar("INSERT INTO users (email) VALUES ('founder@acme.test') RETURNING id")
            .fetch_one(pool)
            .await
            .unwrap();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO orgs (name, slug, creator_user_id) VALUES ('Acme', 'acme-bi', $1) RETURNING id",
    )
    .bind(creator)
    .fetch_one(pool)
    .await
    .unwrap();
    let admin: Uuid = sqlx::query_scalar(
        "INSERT INTO identities (org_id, name, kind, email, is_org_admin)
         VALUES ($1, 'founder', 'user', 'founder@acme.test', true) RETURNING id",
    )
    .bind(org)
    .fetch_one(pool)
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
        .execute(pool)
        .await
        .unwrap();
    }
    org
}

#[tokio::test]
async fn bi_role_reads_the_allow_list_and_every_bi_query_runs_as_it() {
    let pool = common::test_pool().await;
    let org = seed_org(&pool).await;

    // No password configured = BI off = hands off.
    overslash_db::bi::reconcile_bi_user(&pool, None).await;

    // A second boot re-applies the allow-list from scratch.
    let password = overslash_db::bi::BiPassword::parse(&"a1".repeat(16)).unwrap();
    overslash_db::bi::reconcile_bi_user(&pool, Some(&password)).await;
    // A column or a whole table granted by an earlier allow-list (or by hand)
    // must not survive the next boot: the probes below expect both denied.
    sqlx::raw_sql(
        "GRANT SELECT (headless) ON orgs TO bi;
         GRANT SELECT ON secrets TO bi;",
    )
    .execute(&pool)
    .await
    .unwrap();
    overslash_db::bi::reconcile_bi_user(&pool, Some(&password)).await;
    let (login, memberships): (bool, i64) = sqlx::query_as(
        "SELECT r.rolcanlogin,
                (SELECT count(*) FROM pg_auth_members m WHERE m.member = r.oid)
         FROM pg_roles r WHERE r.rolname = 'bi'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(login, "bi must be able to log in");
    assert_eq!(memberships, 0, "bi must belong to no role");

    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL ROLE bi")
        .execute(&mut *tx)
        .await
        .unwrap();

    for (name, sql) in bi_queries() {
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
            .fetch_all(&mut *tx)
            .await
            .unwrap_or_else(|e| panic!("infra/modules/bi/sql/{name}.sql as bi: {e}"));
        if name == "org_summary" {
            let acme = rows
                .iter()
                .find(|r| r.get::<String, _>("id") == org.to_string())
                .expect("seeded org in org_summary");
            assert_eq!(acme.get::<String, _>("name"), "Acme");
            assert_eq!(acme.get::<String, _>("creator_email"), "founder@acme.test");
            assert_eq!(acme.get::<String, _>("admin_emails"), "founder@acme.test");
            assert_eq!(acme.get::<i64, _>("user_count"), 2);
            assert_eq!(acme.get::<i64, _>("agent_count"), 1);
        }
    }

    // Past the allow-list, both granted above and then reconciled away: a
    // column off it, and a table off it.
    for sql in [
        "SELECT headless FROM orgs LIMIT 1",
        "SELECT 1 FROM secrets LIMIT 1",
    ] {
        sqlx::query("SAVEPOINT probe")
            .execute(&mut *tx)
            .await
            .unwrap();
        let err = sqlx::query(sql).fetch_all(&mut *tx).await.expect_err(sql);
        assert!(
            err.to_string().contains("permission denied"),
            "{sql}: {err}"
        );
        sqlx::query("ROLLBACK TO SAVEPOINT probe")
            .execute(&mut *tx)
            .await
            .unwrap();
    }
}
