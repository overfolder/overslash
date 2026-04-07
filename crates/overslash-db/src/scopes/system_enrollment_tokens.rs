//! `SystemScope` SQL methods for the `enrollment_tokens` resource.
//!
//! Enrollment token prefix lookups are intentionally cross-org. They
//! back the unauthenticated `POST /v1/enroll` endpoint: an enrolling
//! agent presents a token before any org context exists, and the token
//! row IS what tells us which org to mint the new identity into. This
//! is the only operation that lives on `SystemScope`; every other
//! enrollment-token operation belongs to `OrgScope`.

use crate::repos::enrollment_token::{self, EnrollmentTokenRow};
use crate::scopes::SystemScope;

impl SystemScope {
    /// Look up an unconsumed enrollment token by its public prefix.
    /// Cross-org by design — see the module doc.
    pub async fn find_enrollment_token_by_prefix(
        &self,
        prefix: &str,
    ) -> Result<Option<EnrollmentTokenRow>, sqlx::Error> {
        enrollment_token::find_by_prefix(self.db(), prefix).await
    }

    /// Atomically mark an enrollment token consumed by id. Returns true
    /// if a row was affected. Used immediately after a successful
    /// prefix lookup + hash verify in the unauthenticated `/v1/enroll`
    /// path, where there is still no caller-bound org context.
    pub async fn mark_enrollment_token_used(&self, id: uuid::Uuid) -> Result<bool, sqlx::Error> {
        enrollment_token::mark_used(self.db(), id).await
    }
}
