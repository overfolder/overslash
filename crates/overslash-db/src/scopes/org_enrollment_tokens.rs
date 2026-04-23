//! `OrgScope` SQL methods for the `enrollment_tokens` resource.
//!
//! CRUD lives here so a token id alone cannot reach across tenants.
//! The unauthenticated prefix lookup that the agent uses to claim a
//! token lives on `SystemScope` — there is no org context yet at that
//! point in the request lifecycle.

use uuid::Uuid;

use crate::repos::enrollment_token::{self, EnrollmentTokenRow};
use crate::scopes::OrgScope;

impl OrgScope {
    /// Create an enrollment token in this org for the given identity.
    pub async fn create_enrollment_token(
        &self,
        identity_id: Uuid,
        token_hash: &str,
        token_prefix: &str,
        expires_at: time::OffsetDateTime,
        created_by: Option<Uuid>,
    ) -> Result<EnrollmentTokenRow, sqlx::Error> {
        enrollment_token::create(
            self.db(),
            self.org_id(),
            identity_id,
            token_hash,
            token_prefix,
            expires_at,
            created_by,
        )
        .await
    }

    /// List active enrollment tokens for this org.
    pub async fn list_enrollment_tokens(&self) -> Result<Vec<EnrollmentTokenRow>, sqlx::Error> {
        enrollment_token::list_by_org(self.db(), self.org_id()).await
    }

    /// Revoke an enrollment token by id, scoped to this org. Returns true
    /// if a row was affected. A revoke for an id belonging to another
    /// tenant is a no-op.
    pub async fn revoke_enrollment_token(&self, id: Uuid) -> Result<bool, sqlx::Error> {
        enrollment_token::revoke(self.db(), id, self.org_id()).await
    }
}
