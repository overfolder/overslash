//! `SystemScope` SQL methods for the `api_keys` resource.
//!
//! API key prefix lookups are intentionally cross-org and live on
//! `SystemScope`. They back the request bootstrap path: when an HTTP
//! request arrives carrying a bearer token, the auth extractor has not
//! yet derived an org context — the API key row IS what tells us which
//! org the caller belongs to. Bounding this lookup to a specific org
//! would require knowing the org first, which is the very thing we are
//! trying to discover. This is the one place in the codebase where a
//! cross-tenant read is correct by construction.
//!
//! Every other api_key operation (list, revoke, mutate) lives on
//! `OrgScope`, so the row id alone is no longer sufficient to touch a
//! cross-tenant key.

use crate::repos::api_key::{self, ApiKeyRow};
use crate::scopes::SystemScope;

impl SystemScope {
    /// Look up an active API key by its public prefix. Cross-org by design:
    /// this is how the auth middleware bootstraps an `AuthContext` from a
    /// bearer token before any org context exists. Filters out revoked keys.
    pub async fn find_api_key_by_prefix(
        &self,
        prefix: &str,
    ) -> Result<Option<ApiKeyRow>, sqlx::Error> {
        api_key::find_by_prefix(self.db(), prefix).await
    }

    /// Variant of [`find_api_key_by_prefix`] that ALSO returns keys auto-revoked
    /// because their bound identity was archived. Lets the auth middleware
    /// surface a `403 identity_archived` (with restore hint) instead of the
    /// misleading `401 invalid api key` that the active-only lookup would
    /// return. Manually-revoked keys remain hidden — those are genuinely
    /// invalid. Cross-org for the same reason as `find_api_key_by_prefix`.
    pub async fn find_api_key_by_prefix_including_archived(
        &self,
        prefix: &str,
    ) -> Result<Option<ApiKeyRow>, sqlx::Error> {
        api_key::find_by_prefix_including_archived(self.db(), prefix).await
    }
}
