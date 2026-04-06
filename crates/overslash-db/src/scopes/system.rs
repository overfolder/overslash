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

    pub(crate) fn db(&self) -> &PgPool {
        &self.db
    }
}
