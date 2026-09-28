//! Boot-time reconcile for the BI login user (docs/runbooks/bi.md).
//!
//! Terraform creates the `bi` Cloud SQL user after migration 126 has already
//! created `bi_reader`, so no migration can grant one to the other. And Cloud
//! SQL makes every API-created user a member of `cloudsqlsuperuser`, which is
//! far more than a dashboard needs. Every API boot closes both gaps, so a
//! forgotten manual step can't leave BI broken or over-privileged for longer
//! than one deploy.

use sqlx::{PgPool, Row};

const BI_USER: &str = "bi";

/// Grant `bi_reader` to `bi` and drop its `cloudsqlsuperuser` membership.
/// A no-op until terraform has created `bi` (or when BI is disabled); never
/// fails the boot — a problem is logged and BI stays as it was.
pub async fn reconcile_bi_user(db: &PgPool) {
    if let Err(e) = reconcile(db).await {
        tracing::warn!(error = %e, "bi user reconcile failed; BI may be unusable or over-privileged");
    }
}

async fn reconcile(db: &PgPool) -> Result<(), sqlx::Error> {
    // Direct memberships only: those are the ones GRANT/REVOKE act on.
    let row = sqlx::raw_sql(
        "SELECT
             EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bi')                 AS has_user,
             EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bi_reader')          AS has_reader,
             EXISTS (SELECT 1 FROM pg_auth_members m
                       JOIN pg_roles r ON r.oid = m.roleid
                       JOIN pg_roles u ON u.oid = m.member
                      WHERE u.rolname = 'bi' AND r.rolname = 'bi_reader')         AS granted,
             EXISTS (SELECT 1 FROM pg_auth_members m
                       JOIN pg_roles r ON r.oid = m.roleid
                       JOIN pg_roles u ON u.oid = m.member
                      WHERE u.rolname = 'bi' AND r.rolname = 'cloudsqlsuperuser') AS superuser",
    )
    .fetch_one(db)
    .await?;
    if !row.get::<bool, _>("has_user") {
        return Ok(());
    }
    // Strip the excess first: it matters even when there is no bi_reader to
    // grant, e.g. a deployment whose migration couldn't create the role.
    if row.get::<bool, _>("superuser") {
        sqlx::raw_sql("REVOKE cloudsqlsuperuser FROM bi")
            .execute(db)
            .await?;
        tracing::info!("revoked cloudsqlsuperuser from `{BI_USER}`");
    }
    if !row.get::<bool, _>("has_reader") {
        tracing::warn!("`{BI_USER}` exists but `bi_reader` does not; BI stays disabled");
    } else if !row.get::<bool, _>("granted") {
        sqlx::raw_sql("GRANT bi_reader TO bi").execute(db).await?;
        tracing::info!("granted bi_reader to `{BI_USER}`");
    }
    Ok(())
}
