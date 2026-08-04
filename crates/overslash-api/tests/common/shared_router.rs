//! Shared-router test harness. Each test binary boots ONE Axum router
//! whose `AppState.test_resources` is wired to a `SharedRouterRegistry`.
//! Every `start_api_shared(pool)` call registers a fresh `TestResources`
//! (its own DB pool + the five org-id-keyed caches/stores that would
//! otherwise alias across tests) under a unique `TestPoolId`, returns
//! a `reqwest::Client` that stamps `X-Test-Pool-Id` on every request,
//! and a `ResourceGuard` that deregisters the entry on drop.
//!
//! The router is built once per test binary; subsequent tests reuse it.
//! That amortizes the per-test router-build / listener-bind cost across
//! all tests in the binary — the whole point of Stage 3.
//!
//! Carve-outs intentionally keep their own per-test router alongside
//! the shared one — OAuth-flow tests (auth-provider variants mount
//! different routes), `start_api_with` config-mutators (per-test
//! config flips), and the multi-org test families (per CLAUDE.md).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use reqwest::Client;
use sqlx::PgPool;
use tokio::net::TcpListener;
use tokio::sync::OnceCell;
use uuid::Uuid;

use overslash_api::middleware::test_pool::TEST_POOL_HEADER;
use overslash_api::{AppState, TestPoolId, TestResourceResolver, TestResources};

/// Resolver lookup table. Registered `TestResources` bundles are
/// leaked at registration time to give them `'static` lifetime — the
/// resolver returns `Option<&'a TestResources>` and the `'a` ties to
/// `&'a self`, so we need an upper bound on the storage that outlives
/// any borrow. Tests run in short-lived processes; per-binary
/// footprint is bounded by ~10–100 pools × a tiny `TestResources`
/// struct.
pub struct SharedRouterRegistry {
    resources: DashMap<TestPoolId, &'static TestResources>,
}

impl SharedRouterRegistry {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            resources: DashMap::new(),
        })
    }

    fn register(&self, id: TestPoolId, resources: TestResources) {
        let leaked: &'static TestResources = Box::leak(Box::new(resources));
        self.resources.insert(id, leaked);
    }

    fn deregister(&self, id: TestPoolId) -> Option<&'static TestResources> {
        // The `&'static` stays alive until process exit; we only
        // remove the map entry so a stray request after the test
        // ended can't resolve to the now-finished test's pool.
        self.resources.remove(&id).map(|(_, r)| r)
    }
}

impl TestResourceResolver for SharedRouterRegistry {
    fn resolve<'a>(&'a self, ext: &axum::http::Extensions) -> Option<&'a TestResources> {
        let id = ext.get::<TestPoolId>().copied()?;
        // `&'static TestResources` coerces to `&'a TestResources` for
        // any `'a`. Copying the inner reference out of the DashMap
        // guard returns a borrow independent of the guard's lifetime.
        self.resources.get(&id).map(|r| *r.value())
    }
}

/// RAII guard: deregisters this test's `TestResources` on drop and
/// hands its pool to the shared-router runtime for closing.
pub struct ResourceGuard {
    id: TestPoolId,
    registry: Arc<SharedRouterRegistry>,
    pool_closer: tokio::sync::mpsc::UnboundedSender<PgPool>,
}

impl Drop for ResourceGuard {
    fn drop(&mut self) {
        if let Some(resources) = self.registry.deregister(self.id) {
            // Close the finished test's pool. The leaked `TestResources`
            // keeps its `PgPool` — and that pool's open connections —
            // alive until process exit; across a large binary that
            // exhausts Postgres `max_connections` (default 100) and the
            // tail of the suite fails with `PoolTimedOut`. Closing must
            // happen on a live runtime, and this test's runtime is about
            // to shut down, so ship the pool to the shared-router thread.
            let _ = self.pool_closer.send(resources.db.clone());
        }
    }
}

struct SharedHarness {
    addr: SocketAddr,
    registry: Arc<SharedRouterRegistry>,
    pool_closer: tokio::sync::mpsc::UnboundedSender<PgPool>,
}

static HARNESS: OnceCell<SharedHarness> = OnceCell::const_new();

/// Boot the per-binary shared router (lazy, idempotent) and register
/// a fresh `TestResources` for this test. Returns the router's bound
/// address, a `reqwest::Client` whose `default_headers` stamp this
/// test's `X-Test-Pool-Id`, and a `ResourceGuard` that deregisters on
/// drop.
pub async fn start_api_shared(pool: PgPool) -> (SocketAddr, Client, ResourceGuard) {
    let harness = HARNESS.get_or_init(boot_shared_router).await;

    let id = TestPoolId(Uuid::new_v4());
    let resources = TestResources {
        db: pool,
        auth_code_store: overslash_api::services::oauth_as::AuthCodeStore::new(),
        pending_authorize_store: overslash_api::services::oauth_as::PendingAuthorizeStore::new(),
        rate_limit_cache: Arc::new(
            overslash_api::services::rate_limit::RateLimitConfigCache::new(Duration::from_secs(30)),
        ),
        free_unlimited_cache: Arc::new(
            overslash_api::services::billing_tier::FreeUnlimitedCache::new(Duration::from_secs(30)),
        ),
        rate_limiter: Arc::new(overslash_api::services::rate_limit::InMemoryRateLimitStore::new()),
        // Per-test bus: every test cloning the bootstrapped template shares an
        // org id, so a shared bus would surface one test's events on another's
        // stream. No listener is spawned here — the shared router deregisters
        // its resources on guard drop, which a long-lived stream would outlive;
        // event-stream tests use `start_api_with_event_stream` instead.
        event_bus: overslash_api::services::events::EventBus::new(),
    };
    harness.registry.register(id, resources);

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        TEST_POOL_HEADER,
        reqwest::header::HeaderValue::from_str(&id.0.to_string()).unwrap(),
    );
    let client = Client::builder()
        .default_headers(headers)
        .build()
        .expect("reqwest client builds");

    (
        harness.addr,
        client,
        ResourceGuard {
            id,
            registry: harness.registry.clone(),
            pool_closer: harness.pool_closer.clone(),
        },
    )
}

async fn boot_shared_router() -> SharedHarness {
    let registry = SharedRouterRegistry::new();
    let registry_for_state = registry.clone();
    // Bind synchronously so the address is known before the listener moves
    // to the server thread.
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    std_listener.set_nonblocking(true).unwrap();
    let addr = std_listener.local_addr().unwrap();
    let state = build_shared_state(registry_for_state, addr);
    let app = build_shared_router(state);
    let (pool_closer, mut pool_close_rx) = tokio::sync::mpsc::unbounded_channel::<PgPool>();
    // The shared server must outlive every test: `#[tokio::test]` drops its
    // runtime when the test fn returns, aborting any task spawned on it. A
    // plain `tokio::spawn` here would tie the server to whichever test won
    // the `get_or_init` race — once that test finished, every other test in
    // the binary would see its requests die with `IncompleteMessage`. Run
    // the server on a dedicated thread with its own runtime instead; it
    // lives until process exit.
    std::thread::Builder::new()
        .name("shared-router".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("shared-router runtime builds");
            rt.block_on(async move {
                // Drain pools handed over by `ResourceGuard::drop` so
                // finished tests release their Postgres connections.
                tokio::spawn(async move {
                    while let Some(pool) = pool_close_rx.recv().await {
                        pool.close().await;
                    }
                });
                let listener = TcpListener::from_std(std_listener).unwrap();
                axum::serve(listener, app).await.unwrap();
            });
        })
        .expect("shared-router thread spawns");
    SharedHarness {
        addr,
        registry,
        pool_closer,
    }
}

fn build_shared_router(state: AppState) -> axum::Router {
    use overslash_api::routes;
    axum::Router::new()
        .merge(routes::health::router())
        .merge(routes::version::router())
        .merge(routes::orgs::router())
        .merge(routes::identities::router())
        .merge(routes::api_keys::router())
        .merge(routes::secrets::router())
        .merge(routes::secret_requests::router())
        .merge(routes::permissions::router())
        .merge(routes::actions::router())
        .merge(routes::actions::validate_router())
        .merge(routes::approvals::router())
        .merge(routes::audit::router())
        .merge(routes::webhooks::router())
        .merge(routes::services::router())
        .merge(routes::search::router())
        .merge(routes::templates::router())
        .merge(routes::connections::router())
        .merge(routes::byoc_credentials::router())
        .merge(routes::oauth_providers::router())
        .merge(routes::auth::router())
        .merge(routes::dev_e2e::router())
        .merge(routes::events::router())
        .merge(routes::org_idp_configs::router())
        .merge(routes::org_invites::router())
        .merge(routes::org_oauth_credentials::router())
        .merge(routes::org_service_keys::router())
        .merge(routes::groups::router())
        .merge(routes::rate_limits::router())
        .merge(routes::preferences::router())
        .merge(routes::oauth_as::router())
        .merge(routes::oauth::router())
        .merge(routes::oauth::consent_router())
        .merge(routes::mcp::router())
        .merge(routes::oauth_mcp_clients::router())
        .merge(routes::unsubscribe::router())
        // Test-pool middleware runs BEFORE subdomain_middleware so
        // the subdomain resolver (which calls state.db(...)) picks
        // up the correct per-test pool.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            overslash_api::middleware::subdomain::subdomain_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            overslash_api::middleware::test_pool::test_pool_middleware,
        ))
        .with_state(state)
}

fn build_shared_state(registry: Arc<SharedRouterRegistry>, addr: SocketAddr) -> AppState {
    // The static `db` is a never-used placeholder. The test-pool
    // middleware rejects requests missing `X-Test-Pool-Id` before
    // they reach DB-touching code, and every test client stamps the
    // header automatically. A code path that bypasses both checks
    // fails on first query — the clearest "this would have been a
    // bug" signal we can wire in.
    AppState {
        db: PgPool::connect_lazy("postgres://127.0.0.1:1/__overslash_shared_router_unused__")
            .expect("connect_lazy never fails synchronously"),
        config: shared_config(addr),
        http_client: reqwest::Client::new(),
        registry: Arc::new(overslash_core::registry::ServiceRegistry::with_builtins()),
        rate_limiter: Arc::new(overslash_api::services::rate_limit::InMemoryRateLimitStore::new()),
        rate_limit_cache: Arc::new(
            overslash_api::services::rate_limit::RateLimitConfigCache::new(Duration::from_secs(30)),
        ),
        free_unlimited_cache: Arc::new(
            overslash_api::services::billing_tier::FreeUnlimitedCache::new(Duration::from_secs(30)),
        ),
        auth_code_store: overslash_api::services::oauth_as::AuthCodeStore::new(),
        pending_authorize_store: overslash_api::services::oauth_as::PendingAuthorizeStore::new(),
        embedder: Arc::new(overslash_core::embeddings::DisabledEmbedder),
        embeddings_available: false,
        platform_registry: Arc::new(overslash_api::services::platform_registry::build_registry()),
        mailer: Arc::new(overslash_core::email::NoopMailer),
        event_bus: overslash_api::services::events::EventBus::new(),
        test_resources: Some(registry),
    }
}

fn shared_config(addr: SocketAddr) -> overslash_api::config::Config {
    overslash_api::config::Config {
        host: "127.0.0.1".into(),
        port: 0,
        database_url: String::new(),
        db_max_connections: 5,
        db_min_connections: 1,
        db_acquire_timeout_secs: 10,
        events_stream_max_connection_secs: 30,
        db_background_max_connections: 2,
        secrets_encryption_key: "ab".repeat(32),
        secrets_encryption_key_previous: None,
        secrets_encryption_key_active_id: 1,
        secrets_encryption_key_previous_id: 0,
        signing_key: "cd".repeat(32),
        approval_expiry_secs: 1800,
        execution_pending_ttl_secs: 900,
        execution_replay_timeout_secs: 30,
        services_dir: "services".into(),
        google_auth_client_id: None,
        google_auth_client_secret: None,
        github_auth_client_id: None,
        github_auth_client_secret: None,
        public_url: format!("http://{addr}"),
        dev_auth_enabled: false,
        magic_link_enabled: true,
        max_response_body_bytes: 5_242_880,
        audit_response_body_max_bytes: 65_536,
        filter_timeout_ms: 2000,
        download_token_ttl_secs: 900,
        dashboard_url: "/".into(),
        dashboard_origin: "*localhost*".into(),
        mcp_extra_origins: String::new(),
        redis_url: None,
        default_rate_limit: 10000,
        default_rate_window_secs: 60,
        allow_org_creation: true,
        trial_default_duration_days: 30,
        single_org_mode: None,
        app_host_suffix: None,
        api_host_suffix: None,
        session_cookie_domain: None,
        cloud_billing: false,
        stripe_secret_key: None,
        stripe_webhook_secret: None,
        stripe_eur_price_id: None,
        stripe_usd_price_id: None,
        stripe_eur_lookup_key: "overslash_seat_eur".into(),
        stripe_usd_lookup_key: "overslash_seat_usd".into(),
        stripe_api_base: "https://api.stripe.com/v1".into(),
        service_base_overrides: std::collections::HashMap::new(),
        platform_credential: None,
        oversla_sh_base_url: None,
        oversla_sh_api_key: None,
        email_provider: None,
        email_from: None,
        email_reply_to: None,
        email_api_key: None,
        preview_origin_allowlist: None,
        overslash_env: None,
        connection_return_url_allowed_hosts: Vec::new(),
    }
}
