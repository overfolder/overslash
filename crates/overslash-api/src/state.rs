//! Shared application state and its per-request resource resolution.
//!
//! Split out of `lib.rs` at the seam the line-count gate pointed at, and it is
//! a real one: everything here answers "which resources does *this* request
//! use", which is a different question from wiring the router and the
//! background loops. Every name stays re-exported from the crate root, so
//! `overslash_api::AppState` is unchanged for callers.

use std::sync::Arc;

use axum::http::Extensions;
use sqlx::PgPool;

use crate::config::Config;
use crate::services;
use overslash_core::email::Mailer;
use overslash_core::embeddings::Embedder;
use overslash_core::registry::ServiceRegistry;

/// Application state shared across handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Config,
    pub http_client: reqwest::Client,
    pub registry: Arc<ServiceRegistry>,
    pub rate_limiter: Arc<dyn services::rate_limit::RateLimitStore>,
    pub rate_limit_cache: Arc<services::rate_limit::RateLimitConfigCache>,
    /// Caches per-org `plan` lookups so the rate-limit middleware can decide
    /// whether to bypass for `free_unlimited` orgs without hitting Postgres
    /// on every request. See `services::billing_tier`.
    pub free_unlimited_cache: Arc<services::billing_tier::FreeUnlimitedCache>,
    /// In-memory store for one-shot OAuth 2.1 authorization codes (60s TTL).
    /// Process-local for v1; promoted to Redis once horizontal replication
    /// is on the roadmap (tracked in `TECH_DEBT.md`).
    pub auth_code_store: services::oauth_as::AuthCodeStore,
    /// In-memory store for `/oauth/authorize` requests paused at the consent
    /// step, keyed by a single-use `request_id`. Same 60s TTL as auth codes.
    pub pending_authorize_store: services::oauth_as::PendingAuthorizeStore,
    /// Embedding backend for `/v1/search`. Holds [`DisabledEmbedder`] when
    /// `OVERSLASH_EMBEDDINGS=off` or when the pgvector preflight fails;
    /// otherwise the real `FastembedEmbedder`. Checked on every query via
    /// `embedder.is_enabled()` before touching the vector store.
    pub embedder: Arc<dyn Embedder>,
    /// Cached result of the pgvector preflight (see [`init_embeddings`]).
    /// `true` iff both the env flag is on *and* the extension is present
    /// in the connected Postgres. When `false`, the search endpoint
    /// short-circuits the cosine retrieval and blends only keyword +
    /// fuzzy scores.
    pub embeddings_available: bool,
    pub platform_registry: std::sync::Arc<services::platform_caller::PlatformRegistry>,
    /// Transactional-email sender. `NoopMailer` until `EMAIL_PROVIDER` is set;
    /// callers (billing, onboarding, DLQ digest) just `state.mailer.send(...)`
    /// and stay oblivious to provider wiring.
    pub mailer: Arc<dyn Mailer>,
    /// Process-local fan-out for `GET /v1/events/stream`. Fed exclusively by
    /// the Postgres listener task (see `services::events::bus`), so every
    /// replica sees every event regardless of which one produced it.
    pub event_bus: services::events::EventBus,
    /// Caches `x-overslash-resolve` answers so a display-name lookup is not a
    /// round trip on every call (D64). Valkey-backed when `REDIS_URL` is set,
    /// process-local otherwise; a backend failure is a miss, never an error.
    pub resolve_cache: Arc<dyn services::resolve_cache::ResolveCacheStore>,
    /// Per-request resource resolver. `None` in production: the field
    /// accessors below fall through to `self.db`, `self.rate_limit_cache`,
    /// etc. `Some(_)` only in test builds where multiple test pools share
    /// a single Axum router; the test-pool middleware stamps a
    /// `TestPoolId` into request extensions, and the resolver returns the
    /// per-test `TestResources` bundle so org_id-keyed caches and OAuth
    /// stores stay isolated across tests.
    pub test_resources: Option<Arc<dyn TestResourceResolver>>,
    /// Dedicated pool for work that outlives the request that started it.
    ///
    /// `None` in tests, where [`AppState::for_spawn`] falls through to the
    /// per-request pool. `Some` in production, holding the same
    /// `background_db` the sweep loop and the async worker run on — a spawned
    /// task must not borrow a request pool connection it may outlive.
    pub background_db: Option<PgPool>,
}

/// Per-test resource bundle for the shared-router test harness. Bundles
/// the six AppState fields that must be swapped per request to keep tests
/// isolated when they share an Axum router: the DB pool, the two OAuth
/// in-memory stores, and the three org-id-keyed rate-limit / billing
/// caches (which would otherwise alias across tests because
/// `BootstrapFixtures.org_id` is shared by every test cloning the
/// bootstrapped template).
pub struct TestResources {
    pub db: PgPool,
    pub auth_code_store: services::oauth_as::AuthCodeStore,
    pub pending_authorize_store: services::oauth_as::PendingAuthorizeStore,
    pub rate_limit_cache: Arc<services::rate_limit::RateLimitConfigCache>,
    pub free_unlimited_cache: Arc<services::billing_tier::FreeUnlimitedCache>,
    pub rate_limiter: Arc<dyn services::rate_limit::RateLimitStore>,
    /// Per-test event bus. Without this, every test cloning the bootstrapped
    /// template shares one org id, so one test's events would surface on
    /// another's stream.
    pub event_bus: services::events::EventBus,
    /// Per-test resolver cache: keyed on org + owner + credential, and
    /// `BootstrapFixtures.org_id` is shared, so one process-wide store would
    /// let one test's resolved names answer another's lookup.
    pub resolve_cache: Arc<dyn services::resolve_cache::ResolveCacheStore>,
}

/// Marker stamped into request `Extensions` by the test-pool middleware,
/// used by the resolver to look up the per-test `TestResources` bundle.
/// Production requests never carry this extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TestPoolId(pub uuid::Uuid);

/// Resolves the per-test resource bundle for a request. Implemented by
/// the test harness in `tests/common/shared_router.rs`. Always returns
/// `None` in production (the field accessors below short-circuit to the
/// static AppState fields).
pub trait TestResourceResolver: Send + Sync {
    fn resolve<'a>(&'a self, ext: &Extensions) -> Option<&'a TestResources>;
}

impl AppState {
    /// Returns the `PgPool` for this request. In production (and in
    /// per-test-router test helpers) this is `&self.db`. Under the
    /// shared-router test harness, the test-pool middleware stamped a
    /// `TestPoolId` into `ext` and this resolves to that test's pool.
    pub fn db<'a>(&'a self, ext: &'a Extensions) -> &'a PgPool {
        match self.test_resources.as_deref().and_then(|r| r.resolve(ext)) {
            Some(res) => &res.db,
            None => &self.db,
        }
    }

    /// Owned `PgPool` clone for `tokio::spawn` captures. PgPool is cheap
    /// to clone (Arc internally) — use this anywhere the spawned future
    /// outlives the request and can't borrow from `Extensions`.
    pub fn db_pool(&self, ext: &Extensions) -> PgPool {
        self.db(ext).clone()
    }

    /// Owned `AppState` for a task spawned off a request path.
    ///
    /// Two swaps, both load-bearing, and both easy to forget at a call site —
    /// which is why they live here rather than at each `tokio::spawn`.
    /// `db` moves to the background pool because the spawned future outlives
    /// the request whose pool connection it would otherwise hold. And
    /// `test_resources` is cleared because the resolver keys off a
    /// `TestPoolId` in request `Extensions`; a spawned task builds its own
    /// empty `Extensions`, so leaving the resolver attached would silently
    /// resolve to the *shared bootstrap* pool under the shared-router harness
    /// instead of the pool the test is using.
    ///
    /// Mirrors what `services::async_executor::run_with_shutdown` does for the
    /// worker loop.
    pub fn for_spawn(&self, ext: &Extensions) -> AppState {
        let mut spawned = self.clone();
        spawned.db = self
            .background_db
            .clone()
            .unwrap_or_else(|| self.db_pool(ext));
        spawned.test_resources = None;
        spawned
    }

    pub fn auth_code_store<'a>(
        &'a self,
        ext: &'a Extensions,
    ) -> &'a services::oauth_as::AuthCodeStore {
        match self.test_resources.as_deref().and_then(|r| r.resolve(ext)) {
            Some(res) => &res.auth_code_store,
            None => &self.auth_code_store,
        }
    }

    pub fn pending_authorize_store<'a>(
        &'a self,
        ext: &'a Extensions,
    ) -> &'a services::oauth_as::PendingAuthorizeStore {
        match self.test_resources.as_deref().and_then(|r| r.resolve(ext)) {
            Some(res) => &res.pending_authorize_store,
            None => &self.pending_authorize_store,
        }
    }

    pub fn rate_limit_cache<'a>(
        &'a self,
        ext: &'a Extensions,
    ) -> &'a services::rate_limit::RateLimitConfigCache {
        match self.test_resources.as_deref().and_then(|r| r.resolve(ext)) {
            Some(res) => &res.rate_limit_cache,
            None => &self.rate_limit_cache,
        }
    }

    pub fn free_unlimited_cache<'a>(
        &'a self,
        ext: &'a Extensions,
    ) -> &'a services::billing_tier::FreeUnlimitedCache {
        match self.test_resources.as_deref().and_then(|r| r.resolve(ext)) {
            Some(res) => &res.free_unlimited_cache,
            None => &self.free_unlimited_cache,
        }
    }

    pub fn resolve_cache<'a>(
        &'a self,
        ext: &'a Extensions,
    ) -> &'a dyn services::resolve_cache::ResolveCacheStore {
        match self.test_resources.as_deref().and_then(|r| r.resolve(ext)) {
            Some(res) => res.resolve_cache.as_ref(),
            None => self.resolve_cache.as_ref(),
        }
    }

    pub fn rate_limiter<'a>(
        &'a self,
        ext: &'a Extensions,
    ) -> &'a dyn services::rate_limit::RateLimitStore {
        match self.test_resources.as_deref().and_then(|r| r.resolve(ext)) {
            Some(res) => res.rate_limiter.as_ref(),
            None => self.rate_limiter.as_ref(),
        }
    }

    pub fn event_bus<'a>(&'a self, ext: &'a Extensions) -> &'a services::events::EventBus {
        match self.test_resources.as_deref().and_then(|r| r.resolve(ext)) {
            Some(res) => &res.event_bus,
            None => &self.event_bus,
        }
    }
}
