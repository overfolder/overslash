//! Stored-reference invariants (docs/runbooks/data-integrity.md).
//!
//! The binding policies (D122) refuse a cross-user or cross-org reference on
//! write and on read, but they can't reach rows written before a fix, rows
//! edited by hand, or a path nobody listed. This sweep reads the database
//! directly and reports every stored reference that breaks one of the rules.
//!
//! Each invariant is a single read-only `SELECT` in `src/integrity/<label>.sql`
//! that returns the **offending rows**. A healthy database returns nothing, so
//! fetching the rows costs the same as counting them, and the caller can log
//! the ids for drill-down. The runbook points at the same files, so an
//! operator runs exactly the SQL that fired the alert (`\i` in psql).
//!
//! The metrics exporter runs [`sweep`] every tick and emits one gauge per
//! [`Invariant`]; `tests/integrity_invariants.rs` in `overslash-api` seeds one
//! violation per label.

use sqlx::PgPool;
use uuid::Uuid;

/// One stored reference that breaks an invariant. `detail` carries ids, a
/// slot key or a secret *path* — never a secret value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub org_id: Uuid,
    pub subject_table: String,
    pub subject_id: Uuid,
    pub detail: String,
}

/// Every invariant the sweep checks. `as_str` is the metric label and the
/// SQL file name, so it is stable: renaming one breaks the alert history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Invariant {
    BindingUnqualified,
    BindingNamespaceOutsideOrg,
    BindingForeignUserVault,
    PinOnOrgInstance,
    PinCrossOrg,
    PinNotOwner,
    ByocCrossOrg,
    ByocProviderMismatch,
    ByocNotOwner,
    SecretOwnerNotUser,
    OwnerCrossOrg,
    TemplateCrossOrg,
    TemplateCrossOwner,
    ApprovalCrossOrg,
    ApprovalResolverOutsideChain,
}

impl Invariant {
    pub const ALL: &[Invariant] = &[
        Invariant::BindingUnqualified,
        Invariant::BindingNamespaceOutsideOrg,
        Invariant::BindingForeignUserVault,
        Invariant::PinOnOrgInstance,
        Invariant::PinCrossOrg,
        Invariant::PinNotOwner,
        Invariant::ByocCrossOrg,
        Invariant::ByocProviderMismatch,
        Invariant::ByocNotOwner,
        Invariant::SecretOwnerNotUser,
        Invariant::OwnerCrossOrg,
        Invariant::TemplateCrossOrg,
        Invariant::TemplateCrossOwner,
        Invariant::ApprovalCrossOrg,
        Invariant::ApprovalResolverOutsideChain,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Invariant::BindingUnqualified => "binding_unqualified",
            Invariant::BindingNamespaceOutsideOrg => "binding_namespace_outside_org",
            Invariant::BindingForeignUserVault => "binding_foreign_user_vault",
            Invariant::PinOnOrgInstance => "pin_on_org_instance",
            Invariant::PinCrossOrg => "pin_cross_org",
            Invariant::PinNotOwner => "pin_not_owner",
            Invariant::ByocCrossOrg => "byoc_cross_org",
            Invariant::ByocProviderMismatch => "byoc_provider_mismatch",
            Invariant::ByocNotOwner => "byoc_not_owner",
            Invariant::SecretOwnerNotUser => "secret_owner_not_user",
            Invariant::OwnerCrossOrg => "owner_cross_org",
            Invariant::TemplateCrossOrg => "template_cross_org",
            Invariant::TemplateCrossOwner => "template_cross_owner",
            Invariant::ApprovalCrossOrg => "approval_cross_org",
            Invariant::ApprovalResolverOutsideChain => "approval_resolver_outside_chain",
        }
    }

    /// Run this invariant's query. `query_file_as!` needs a literal path, so
    /// the dispatch is one arm per file.
    pub async fn check(self, pool: &PgPool) -> Result<Vec<Violation>, sqlx::Error> {
        macro_rules! run {
            ($file:literal) => {
                sqlx::query_file_as!(Violation, $file).fetch_all(pool).await
            };
        }
        match self {
            Invariant::BindingUnqualified => run!("src/integrity/binding_unqualified.sql"),
            Invariant::BindingNamespaceOutsideOrg => {
                run!("src/integrity/binding_namespace_outside_org.sql")
            }
            Invariant::BindingForeignUserVault => {
                run!("src/integrity/binding_foreign_user_vault.sql")
            }
            Invariant::PinOnOrgInstance => run!("src/integrity/pin_on_org_instance.sql"),
            Invariant::PinCrossOrg => run!("src/integrity/pin_cross_org.sql"),
            Invariant::PinNotOwner => run!("src/integrity/pin_not_owner.sql"),
            Invariant::ByocCrossOrg => run!("src/integrity/byoc_cross_org.sql"),
            Invariant::ByocProviderMismatch => run!("src/integrity/byoc_provider_mismatch.sql"),
            Invariant::ByocNotOwner => run!("src/integrity/byoc_not_owner.sql"),
            Invariant::SecretOwnerNotUser => run!("src/integrity/secret_owner_not_user.sql"),
            Invariant::OwnerCrossOrg => run!("src/integrity/owner_cross_org.sql"),
            Invariant::TemplateCrossOrg => run!("src/integrity/template_cross_org.sql"),
            Invariant::TemplateCrossOwner => run!("src/integrity/template_cross_owner.sql"),
            Invariant::ApprovalCrossOrg => run!("src/integrity/approval_cross_org.sql"),
            Invariant::ApprovalResolverOutsideChain => {
                run!("src/integrity/approval_resolver_outside_chain.sql")
            }
        }
    }
}

/// Run every invariant, in [`Invariant::ALL`] order. Sequential on purpose:
/// the queries are small, and one connection keeps the sweep from competing
/// with the API's pool.
pub async fn sweep(pool: &PgPool) -> Result<Vec<(Invariant, Vec<Violation>)>, sqlx::Error> {
    let mut out = Vec::with_capacity(Invariant::ALL.len());
    for &inv in Invariant::ALL {
        out.push((inv, inv.check(pool).await?));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_invariant_has_its_sql_file() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/integrity");
        for inv in Invariant::ALL {
            assert!(
                dir.join(format!("{}.sql", inv.as_str())).is_file(),
                "missing src/integrity/{}.sql",
                inv.as_str()
            );
        }
        let files = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(
            files,
            Invariant::ALL.len(),
            "an .sql file with no Invariant"
        );
    }
}
