//! The BI login user (docs/runbooks/bi.md).
//!
//! The API owns the `bi` role rather than terraform: a user created through
//! the Cloud SQL API is always a `cloudsqlsuperuser` member, and stripping
//! that needs an ADMIN OPTION the app's own user doesn't hold. Created here,
//! `bi` is a plain LOGIN role whose only membership is `bi_reader`. Terraform
//! just generates the password and hands the same value to both the API
//! (`OVERSLASH_BI_DB_PASSWORD`) and the BigQuery connection, so a single
//! `tofu apply` rolls a Cloud Run revision whose boot makes BI queryable.

use sqlx::{AssertSqlSafe, PgPool, Row};

/// Shortest password accepted. Terraform generates 32.
const MIN_LEN: usize = 24;

/// The `bi` role's password, checked to be alphanumeric. Postgres can't
/// bind a parameter in `CREATE/ALTER ROLE … PASSWORD`, so the value is
/// spliced into the statement, and this type is what makes that safe.
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

/// Create or update `bi` as a LOGIN role that is a member of `bi_reader` only.
/// Does nothing when BI is off (no password configured). Never fails the boot:
/// a problem is logged and BI stays as it was.
pub async fn reconcile_bi_user(db: &PgPool, password: Option<&BiPassword>) {
    let Some(password) = password else { return };
    if let Err(e) = reconcile(db, password).await {
        tracing::error!(error = %e, "bi user reconcile failed; BI is not queryable");
    }
}

async fn reconcile(db: &PgPool, password: &BiPassword) -> Result<(), sqlx::Error> {
    let row = sqlx::raw_sql(
        "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bi')        AS has_user,
                EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bi_reader') AS has_reader",
    )
    .fetch_one(db)
    .await?;
    if !row.get::<bool, _>("has_reader") {
        tracing::warn!("`bi_reader` is missing (migrating user lacks CREATEROLE?); BI stays off");
        return Ok(());
    }
    let pw = &password.0;
    if row.get::<bool, _>("has_user") {
        // Re-set every boot, so rotating the secret needs no other step.
        sqlx::raw_sql(AssertSqlSafe(format!(
            "ALTER ROLE bi LOGIN PASSWORD '{pw}'"
        )))
        .execute(db)
        .await?;
    } else {
        sqlx::raw_sql(AssertSqlSafe(format!(
            "CREATE ROLE bi LOGIN PASSWORD '{pw}'"
        )))
        .execute(db)
        .await?;
        tracing::info!("created the `bi` login role");
    }
    // Idempotent; Postgres only notices a repeat grant.
    sqlx::raw_sql("GRANT bi_reader TO bi").execute(db).await?;
    Ok(())
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
