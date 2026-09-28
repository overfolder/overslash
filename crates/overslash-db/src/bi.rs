//! The BI login role (docs/runbooks/bi.md).
//!
//! BigQuery reads prod through `EXTERNAL_QUERY` as the Postgres role `bi`.
//! The queries themselves live in terraform (`infra/modules/bi/sql/`); what
//! lives here is the security boundary: the exact columns `bi` may read.
//!
//! The API owns the role rather than terraform: nothing that runs `tofu` can
//! reach the private-IP instance, and a user created through the Cloud SQL
//! API always joins `cloudsqlsuperuser`, which the app can't revoke. Created
//! here, `bi` is a plain LOGIN role with column-level SELECT and nothing else.

use sqlx::{AssertSqlSafe, PgPool};

/// Every column `bi` may read, per table. Nothing that is secret, encrypted
/// or configuration: identity, naming, ownership and activity only. A BI
/// query that needs more adds the column here, in review.
pub const READABLE_COLUMNS: &[(&str, &[&str])] = &[
    (
        "orgs",
        &[
            "id",
            "name",
            "slug",
            "is_personal",
            "plan",
            "trial_ends_at",
            "created_at",
            "creator_user_id",
        ],
    ),
    ("users", &["id", "email", "display_name", "created_at"]),
    (
        "identities",
        &[
            "id",
            "org_id",
            "name",
            "kind",
            "email",
            "is_org_admin",
            "created_at",
            "last_active_at",
            "archived_at",
        ],
    ),
];

/// Serializes concurrent boots (Cloud Run starts several instances at once);
/// `ALTER ROLE` and `GRANT` race on the catalog otherwise.
const LOCK_KEY: i64 = 0x0B1_0B1;

/// Shortest password accepted. Terraform generates 32.
const MIN_LEN: usize = 24;

/// The `bi` role's password, checked to be alphanumeric. Postgres can't
/// bind a parameter in `ALTER ROLE … PASSWORD`, so the value is spliced into
/// the statement, and this type is what makes that safe.
pub struct BiPassword(String);

impl BiPassword {
    pub fn parse(raw: &str) -> Result<Self, String> {
        if raw.len() < MIN_LEN || !raw.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(format!(
                "OVERSLASH_BI_DB_PASSWORD must be at least {MIN_LEN} ASCII letters or digits"
            ));
        }
        Ok(Self(raw.to_owned()))
    }
}

impl std::fmt::Debug for BiPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BiPassword(<redacted>)")
    }
}

/// Create or update `bi` and set its grants to exactly [`READABLE_COLUMNS`].
/// Does nothing when BI is off (no password configured). Never fails the
/// boot: a problem is logged and BI stays as it was.
pub async fn reconcile_bi_user(db: &PgPool, password: Option<&BiPassword>) {
    let Some(password) = password else { return };
    if let Err(e) = reconcile(db, password).await {
        tracing::error!(error = %e, "bi user reconcile failed; BI is not queryable");
    }
}

async fn reconcile(db: &PgPool, password: &BiPassword) -> Result<(), sqlx::Error> {
    let mut tx = db.begin().await?;
    sqlx::raw_sql(AssertSqlSafe(format!(
        "SELECT pg_advisory_xact_lock({LOCK_KEY})"
    )))
    .execute(&mut *tx)
    .await?;

    let mut sql = format!(
        "DO $$ BEGIN
             CREATE ROLE bi;
         EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;
         ALTER ROLE bi LOGIN PASSWORD '{}';",
        password.0
    );
    // Revoking a table privilege also revokes its column privileges, so a
    // column dropped from the list loses its grant on the next boot.
    for (table, columns) in READABLE_COLUMNS {
        sql.push_str(&format!(
            "REVOKE ALL ON public.{table} FROM bi;
             GRANT SELECT ({}) ON public.{table} TO bi;",
            columns.join(", ")
        ));
    }
    sqlx::raw_sql(AssertSqlSafe(sql)).execute(&mut *tx).await?;
    tx.commit().await
}

#[cfg(test)]
mod tests {
    use super::BiPassword;

    #[test]
    fn password_must_be_long_and_alphanumeric() {
        assert!(BiPassword::parse(&"a1".repeat(16)).is_ok());
        assert!(BiPassword::parse("short1").is_err());
        assert!(BiPassword::parse(&format!("{}'; DROP ROLE x; --", "a".repeat(24))).is_err());
    }
}
