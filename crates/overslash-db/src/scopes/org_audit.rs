//! `OrgScope` SQL methods for the `audit_log` resource.
//!
//! The repo `AuditEntry` struct still carries an `org_id` field, but
//! `log_audit` overwrites it with `self.org_id()` before insertion — so
//! even if a caller mis-fills the field, the row is always written under
//! the scope's org. `query_audit_log` likewise rewrites the filter's
//! `org_id` so cross-org queries are impossible at this layer.

use crate::repos::audit::{AuditEntry, AuditFilter, AuditRow};
use crate::scopes::OrgScope;

impl OrgScope {
    /// Append an audit row in this org. The entry's `org_id` field is
    /// overwritten with `self.org_id()` so callers cannot accidentally
    /// (or maliciously) write into another tenant's log.
    pub async fn log_audit(&self, mut entry: AuditEntry<'_>) -> Result<(), sqlx::Error> {
        entry.org_id = self.org_id();
        crate::repos::audit::log(self.db(), &entry).await
    }

    /// Query this org's audit log. The filter's `org_id` field is
    /// overwritten with `self.org_id()` so callers cannot read another
    /// tenant's log even if they construct a misaligned filter.
    pub async fn query_audit_log(
        &self,
        mut filter: AuditFilter,
    ) -> Result<Vec<AuditRow>, sqlx::Error> {
        filter.org_id = self.org_id();
        crate::repos::audit::query_filtered(self.db(), &filter).await
    }
}
