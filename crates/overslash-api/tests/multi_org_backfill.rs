//! Validates migration 040 (multi-org users) — schema shape and backfill SQL.
//!
//! Backfill is only triggered the moment 040 is applied. In the test template
//! it runs against an empty DB (nothing to backfill). To exercise the backfill
//! logic itself, we seed a `test_pool()` with legacy-shaped identities (no
//! `user_id`, no `users` row) and re-run the backfill snippet from
//! `040_multi_org_users.up.sql`. This lets us verify the SQL against the same
//! shape it sees in production (pre-040 data), not just the clean template.

// The assertions use dynamic SQL (information_schema reflection, a verbatim
// copy of the migration's backfill statements, and seed INSERTs that predate
// the repos this PR introduces). The compile-time-checked macros don't fit
// those shapes — match the pattern in `tests/common/mod.rs`.
#![allow(clippy::disallowed_methods)]

mod common;

use overslash_db::repos::{membership, user};
use uuid::Uuid;

const BACKFILL_SQL: &str = r#"
    -- Steps 5a–5e from 040_multi_org_users.up.sql, copied verbatim.
    INSERT INTO users (id, email, display_name, created_at, updated_at)
    SELECT gen_random_uuid(), email, name, created_at, updated_at
    FROM identities
    WHERE kind = 'user' AND email IS NOT NULL AND user_id IS NULL;

    UPDATE identities i
    SET user_id = u.id
    FROM users u
    WHERE i.kind = 'user'
      AND i.email IS NOT NULL
      AND i.user_id IS NULL
      AND i.email = u.email;

    UPDATE identities
    SET user_id = gen_random_uuid()
    WHERE kind = 'user' AND email IS NULL AND user_id IS NULL;

    INSERT INTO users (id, email, display_name, created_at, updated_at)
    SELECT user_id, NULL, name, created_at, updated_at
    FROM identities
    WHERE kind = 'user' AND email IS NULL AND user_id IS NOT NULL
      AND user_id NOT IN (SELECT id FROM users);

    INSERT INTO user_org_memberships (user_id, org_id, role, is_bootstrap, created_at)
    SELECT i.user_id,
           i.org_id,
           CASE WHEN i.is_org_admin THEN 'admin' ELSE 'member' END,
           false,
           i.created_at
    FROM identities i
    WHERE i.kind = 'user' AND i.user_id IS NOT NULL
      AND NOT EXISTS (
          SELECT 1 FROM user_org_memberships m
          WHERE m.user_id = i.user_id AND m.org_id = i.org_id
      );
"#;

#[tokio::test]
async fn schema_objects_exist() {
    let pool = common::test_pool().await;
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT table_name FROM information_schema.tables
         WHERE table_schema = 'public' AND table_name IN ('users', 'user_org_memberships')
         ORDER BY table_name",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(tables, vec!["user_org_memberships", "users"]);

    let columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name FROM information_schema.columns
         WHERE table_name = 'identities' AND column_name = 'user_id'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(columns, vec!["user_id"]);

    let is_personal: bool = sqlx::query_scalar(
        "SELECT column_default IS NOT NULL FROM information_schema.columns
         WHERE table_name = 'orgs' AND column_name = 'is_personal'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(is_personal, "orgs.is_personal must have a default");
}

#[tokio::test]
async fn backfill_links_seeded_legacy_identities() {
    let pool = common::test_pool().await;

    // Seed a pre-040-shaped org + 3 user-kind identities (varying email
    // states). Leave user_id NULL on all of them so the backfill has work to do.
    let org_id: Uuid =
        sqlx::query_scalar("INSERT INTO orgs (name, slug) VALUES ('Legacy', $1) RETURNING id")
            .bind(format!("legacy-{}", Uuid::new_v4().simple()))
            .fetch_one(&pool)
            .await
            .unwrap();

    for (name, email, is_admin) in [
        ("Alice", Some("alice@legacy.test"), true),
        ("Bob", Some("bob@legacy.test"), false),
        ("NoEmail", None::<&str>, false),
    ] {
        sqlx::query(
            "INSERT INTO identities (org_id, name, kind, email, is_org_admin, user_id)
             VALUES ($1, $2, 'user', $3, $4, NULL)",
        )
        .bind(org_id)
        .bind(name)
        .bind(email)
        .bind(is_admin)
        .execute(&pool)
        .await
        .unwrap();
    }

    // The real migration runs this backfill *before* adding the
    // identities.user_id → users.id FK — by design, so step 5c can stamp a
    // fresh UUID onto identities.user_id and step 5d can then insert the
    // matching users row. In the post-migration test DB that FK is already
    // installed, so we drop it, run the backfill verbatim, and re-install.
    sqlx::raw_sql("ALTER TABLE identities DROP CONSTRAINT identities_user_id_fkey")
        .execute(&pool)
        .await
        .unwrap();

    // Run the backfill SQL against the seeded state. Every statement in
    // BACKFILL_SQL is idempotent — repeated runs should converge to the same
    // state. We execute it twice to prove it.
    for pass in 0..2 {
        sqlx::raw_sql(BACKFILL_SQL).execute(&pool).await.unwrap();

        let unlinked: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM identities
             WHERE org_id = $1 AND kind = 'user' AND user_id IS NULL",
        )
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(unlinked, 0, "pass {pass}: all user-kind identities linked");

        let membership_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM user_org_memberships WHERE org_id = $1")
                .bind(org_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(membership_count, 3, "pass {pass}: 3 memberships produced");
    }

    // Alice had is_org_admin=true; her membership role should reflect that.
    let alice_role: String = sqlx::query_scalar(
        "SELECT m.role FROM user_org_memberships m
         JOIN identities i ON i.user_id = m.user_id AND i.org_id = m.org_id
         WHERE m.org_id = $1 AND i.name = 'Alice'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(alice_role, "admin");

    let bob_role: String = sqlx::query_scalar(
        "SELECT m.role FROM user_org_memberships m
         JOIN identities i ON i.user_id = m.user_id AND i.org_id = m.org_id
         WHERE m.org_id = $1 AND i.name = 'Bob'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(bob_role, "member");

    // The NULL-email user must be linked to a users row whose id matches
    // identities.user_id (the migration's UUID-passthrough path).
    let unmatched_null_email: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM identities i
         WHERE i.org_id = $1 AND i.kind = 'user' AND i.email IS NULL
           AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = i.user_id)",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(unmatched_null_email, 0);

    // Re-install the FK and confirm the backfilled data satisfies it.
    sqlx::raw_sql(
        "ALTER TABLE identities
         ADD CONSTRAINT identities_user_id_fkey
         FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL",
    )
    .execute(&pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn users_unique_constraint_allows_same_email_different_subjects() {
    // Threat model: two users with the same email but different IdP subjects
    // must coexist (one human / one impostor / two genuinely different
    // accounts). The partial UNIQUE on (provider, subject) must not spill into
    // an email uniqueness guard.
    let pool = common::test_pool().await;

    let a = user::create_overslash_backed(
        &pool,
        Some("collide@example.test"),
        Some("Alice"),
        "google",
        "subject-A",
    )
    .await
    .unwrap();

    let b = user::create_overslash_backed(
        &pool,
        Some("collide@example.test"),
        Some("Bob"),
        "google",
        "subject-B",
    )
    .await
    .unwrap();

    assert_ne!(
        a.id, b.id,
        "same email, different subjects -> distinct rows"
    );

    // But the same (provider, subject) must collide.
    let err = user::create_overslash_backed(
        &pool,
        Some("someone-else@example.test"),
        Some("impostor"),
        "google",
        "subject-A",
    )
    .await
    .expect_err("duplicate (provider, subject) must be rejected");
    let message = format!("{err}");
    assert!(
        message.contains("users_overslash_idp_unique") || message.contains("duplicate"),
        "expected unique-violation, got: {message}"
    );
}

#[tokio::test]
async fn membership_repo_round_trip() {
    let pool = common::test_pool().await;

    let org_id: Uuid =
        sqlx::query_scalar("INSERT INTO orgs (name, slug) VALUES ('Acme', $1) RETURNING id")
            .bind(format!("acme-{}", Uuid::new_v4().simple()))
            .fetch_one(&pool)
            .await
            .unwrap();

    let u = user::create_org_only(&pool, Some("m@example.test"), Some("Member"))
        .await
        .unwrap();

    let created = membership::create(&pool, u.id, org_id, membership::ROLE_MEMBER, false)
        .await
        .unwrap();
    assert_eq!(created.role, "member");
    assert!(!created.is_bootstrap);

    let found = membership::find(&pool, u.id, org_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.user_id, u.id);

    let all = membership::list_for_user(&pool, u.id).await.unwrap();
    assert_eq!(all.len(), 1);

    assert!(membership::delete(&pool, u.id, org_id).await.unwrap());
    assert!(
        membership::find(&pool, u.id, org_id)
            .await
            .unwrap()
            .is_none()
    );
}
