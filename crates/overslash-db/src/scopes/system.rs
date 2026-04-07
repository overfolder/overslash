use sqlx::PgPool;

/// Capability for cross-org / system-level operations: cron jobs, internal
/// maintenance, admin tooling, token-keyed lookups (which by definition cannot
/// be scoped to an org until the token is resolved).
///
/// Mintable only by internal callers — `new_internal` is `pub` because the
/// API extractor and the worker entrypoint live in other crates, but it
/// should never be called from a request handler. Enforced by code review.
#[derive(Debug, Clone)]
pub struct SystemScope {
    pub(crate) db: PgPool,
}

impl SystemScope {
    /// Mint a system scope. Restricted by convention to:
    /// - cron / worker entrypoints
    /// - the admin extractor in `overslash-api`
    /// - test setup
    pub fn new_internal(db: PgPool) -> Self {
        Self { db }
    }

    /// Raw pool accessor. Exposed for cross-crate background-job code that
    /// must call helpers still taking `&PgPool` (audit logging, identity
    /// chain walks pre-step-7). Do not introduce new call sites that bypass
    /// scope methods for resources that already have them.
    pub fn db(&self) -> &PgPool {
        &self.db
    }

    /// Bridge for background jobs that loop over rows from one org at a time
    /// (e.g. the auto-bubble sweep). Mints an `OrgScope` for the supplied
    /// org_id. Only callable on `SystemScope`, so the caller has already
    /// proven it has cross-org authority.
    pub fn scope_for_org(&self, org_id: uuid::Uuid) -> super::OrgScope {
        super::OrgScope::new(org_id, self.db.clone())
    }
}
