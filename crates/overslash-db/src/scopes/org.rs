use sqlx::PgPool;
use uuid::Uuid;

/// Capability proving the holder is authenticated as a member of `org_id`.
///
/// Hold this to perform any org-wide read or write. Cannot reach data in any
/// other org — every method on `OrgScope` filters its SQL by `self.org_id`.
///
/// Construct via `overslash_api::extractors`, never directly. The `new`
/// constructor is `pub` only because the extractor lives in a different crate.
#[derive(Debug, Clone)]
pub struct OrgScope {
    pub(crate) org_id: Uuid,
    pub(crate) db: PgPool,
    /// Set when the request was made via `X-Overslash-As` impersonation.
    /// Carried here so `log_audit` can inject it into every audit row without
    /// touching individual handler call sites.
    pub(crate) impersonated_by_identity_id: Option<Uuid>,
}

impl OrgScope {
    /// Construct a scope from a verified identity. Only `overslash_api::extractors`
    /// and `#[cfg(test)]` code should call this; handlers must receive scopes
    /// through Axum's extractor mechanism. Enforced by code review.
    pub fn new(org_id: Uuid, db: PgPool) -> Self {
        Self {
            org_id,
            db,
            impersonated_by_identity_id: None,
        }
    }

    /// Construct a scope for an impersonated request. The `impersonated_by`
    /// identity is the service-account caller; audit rows produced via this
    /// scope will record it automatically.
    pub fn new_impersonated(org_id: Uuid, db: PgPool, impersonated_by: Uuid) -> Self {
        Self {
            org_id,
            db,
            impersonated_by_identity_id: Some(impersonated_by),
        }
    }

    /// The org this scope is bound to. Exposed for logging / audit only —
    /// never pass it back into a query as a filter, because every scope
    /// method already does that.
    pub fn org_id(&self) -> Uuid {
        self.org_id
    }

    /// Raw pool accessor. Exposed for cross-crate code that must call
    /// helpers still taking `&PgPool` (e.g. permission-chain walks pre
    /// step 7, audit logging). Prefer scope methods where they exist.
    pub fn db(&self) -> &PgPool {
        &self.db
    }
}
