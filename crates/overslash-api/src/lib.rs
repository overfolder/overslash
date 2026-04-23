pub mod config;
pub mod error;
pub mod extractors;
pub mod middleware;
pub mod ownership;
pub mod routes;
pub mod services;

use std::sync::Arc;

use axum::Router;
use axum::http::{HeaderValue, Method, header};
use sqlx::PgPool;
use tower_http::{
    compression::CompressionLayer,
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};

use crate::config::Config;
use overslash_core::embeddings::{DisabledEmbedder, Embedder};
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
    /// Client for the overslash-mcp-runtime sidecar. `None` when the deployment
    /// has no runtime configured (MCP-runtime services then surface a
    /// `mcp_runtime_unavailable` error at execute time).
    pub mcp_runtime: Option<services::mcp_runtime_client::RuntimeClient>,
}

/// Create the application router with all routes and middleware.
pub async fn create_app(config: Config) -> anyhow::Result<Router> {
    let db = PgPool::connect(&config.database_url).await?;

    // Run migrations
    overslash_db::MIGRATOR.run(&db).await?;

    // Load service registry
    let registry = ServiceRegistry::load_from_dir(std::path::Path::new(&config.services_dir))
        .unwrap_or_else(|e| {
            tracing::warn!("Failed to load service registry: {e}");
            ServiceRegistry::default()
        });
    tracing::info!("Loaded {} service definitions", registry.len());

    let (rate_limiter, in_memory_store) =
        services::rate_limit::create_store_with_eviction(&config).await;
    let rate_limit_cache = Arc::new(services::rate_limit::RateLimitConfigCache::new(
        std::time::Duration::from_secs(30),
    ));

    let (embedder, embeddings_available) = init_embeddings(&db).await;

    let http_client = reqwest::Client::new();
    let mcp_runtime = config.mcp_runtime_url.as_ref().map(|url| {
        services::mcp_runtime_client::RuntimeClient::new(
            url.clone(),
            config.mcp_runtime_shared_secret.clone(),
            http_client.clone(),
        )
    });

    let state = AppState {
        db,
        config,
        http_client,
        registry: Arc::new(registry),
        rate_limiter,
        rate_limit_cache,
        auth_code_store: services::oauth_as::AuthCodeStore::new(),
        pending_authorize_store: services::oauth_as::PendingAuthorizeStore::new(),
        embedder,
        embeddings_available,
        mcp_runtime,
    };

    // Spawn background tasks
    {
        let db = state.db.clone();
        let system = overslash_db::scopes::SystemScope::new_internal(db.clone());
        tokio::spawn(async move {
            // Approval expiry loop: expire stale pending approvals every 60s
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                match system.expire_stale_approvals().await {
                    Ok(n) if n > 0 => tracing::info!("Expired {n} stale approvals"),
                    Err(e) => tracing::error!("Approval expiry error: {e}"),
                    _ => {}
                }
                match overslash_db::repos::pending_enrollment::expire_stale(&db).await {
                    Ok(n) if n > 0 => tracing::info!("Expired {n} stale pending enrollments"),
                    Err(e) => tracing::error!("Enrollment expiry error: {e}"),
                    _ => {}
                }
                match system.archive_idle_subagents().await {
                    Ok(n) if n > 0 => {
                        tracing::info!("Archived {n} idle sub-agent identities")
                    }
                    Err(e) => tracing::error!("Sub-agent archive error: {e}"),
                    _ => {}
                }
                match system.purge_archived_subagents().await {
                    Ok(n) if n > 0 => {
                        tracing::info!("Purged {n} archived sub-agent identities")
                    }
                    Err(e) => tracing::error!("Sub-agent purge error: {e}"),
                    _ => {}
                }
                match services::permission_chain::process_auto_bubble(&system).await {
                    Ok(n) if n > 0 => tracing::info!("Auto-bubbled {n} approvals"),
                    Err(e) => tracing::error!("Auto-bubble error: {e}"),
                    _ => {}
                }
            }
        });

        // Webhook retry loop
        tokio::spawn(services::webhook_dispatcher::spawn_retry_loop(
            state.db.clone(),
            state.http_client.clone(),
        ));

        // Rate limit eviction loop (in-memory store only)
        if let Some(store) = in_memory_store {
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    store.evict_expired();
                }
            });
        }

        // Embedding backfill — only runs when the preflight passed and the
        // embedder is real. Spawns detached; search stays usable while it
        // progresses because keyword+fuzzy covers gaps until vectors land.
        if state.embeddings_available {
            let db = state.db.clone();
            let registry = Arc::clone(&state.registry);
            let embedder = Arc::clone(&state.embedder);
            tokio::spawn(async move {
                services::embedding_backfill::run_once(db, registry, embedder).await;
            });
        }
    }

    let rate_limited_routes = Router::new()
        .merge(routes::orgs::router())
        .merge(routes::identities::router())
        .merge(routes::api_keys::router())
        .merge(routes::secrets::router())
        .merge(routes::secret_requests::router())
        .merge(routes::permissions::router())
        .merge(routes::actions::router())
        .merge(routes::approvals::router())
        .merge(routes::audit::router())
        .merge(routes::webhooks::router())
        .merge(routes::search::router())
        .merge(routes::services::router())
        .merge(routes::templates::router())
        .merge(routes::connections::router())
        .merge(routes::byoc_credentials::router())
        .merge(routes::oauth_providers::router())
        .merge(routes::auth::router())
        .merge(routes::preferences::router())
        .merge(routes::oauth_mcp_clients::router())
        .merge(routes::org_idp_configs::router())
        .merge(routes::org_oauth_credentials::router())
        .merge(routes::enrollment::router())
        .merge(routes::groups::router())
        .merge(routes::rate_limits::router())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::rate_limit::rate_limit_middleware,
        ));

    // Build allowed-origin matcher. `DASHBOARD_ORIGIN` accepts:
    //   - "*localhost*" (default): any http(s) localhost / 127.0.0.1 origin on any port
    //     — needed because worktrees pick dynamic dashboard ports.
    //   - a comma-separated list of explicit origins (e.g. "https://app.example.com")
    let allow_origin = {
        let raw = state.config.dashboard_origin.trim().to_string();
        if raw == "*localhost*" {
            AllowOrigin::predicate(|origin: &HeaderValue, _req| {
                origin
                    .to_str()
                    .map(|o| {
                        o.starts_with("http://localhost:")
                            || o.starts_with("http://127.0.0.1:")
                            || o == "http://localhost"
                            || o == "http://127.0.0.1"
                    })
                    .unwrap_or(false)
            })
        } else {
            let origins: Vec<HeaderValue> = raw
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| {
                    s.parse::<HeaderValue>()
                        .map_err(|e| anyhow::anyhow!("invalid DASHBOARD_ORIGIN entry {s:?}: {e}"))
                })
                .collect::<anyhow::Result<_>>()?;
            AllowOrigin::list(origins)
        }
    };

    let cors = CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_credentials(true)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]);

    let app = Router::new()
        .merge(routes::health::router())
        .merge(routes::oauth_as::router())
        .merge(routes::oauth::router())
        .merge(routes::mcp::router())
        .merge(rate_limited_routes)
        .with_state(state)
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(cors);

    Ok(app)
}

/// Construct the embedding backend for this process lifetime.
///
/// Order of precedence:
///   1. `OVERSLASH_EMBEDDINGS=off` → always return [`DisabledEmbedder`].
///      Honored even when pgvector is present so operators can explicitly
///      opt out without rebuilding.
///   2. Otherwise: probe pgvector availability via `pg_extension`. If
///      missing, warn and return [`DisabledEmbedder`] — the search
///      endpoint still works, just without the cosine signal.
///   3. If pgvector is present and embeddings are enabled, initialize the
///      real [`FastembedEmbedder`] (or fall through to disabled if the
///      model init itself fails — e.g. HuggingFace download in an
///      airgapped env).
///
/// Returns `(embedder, embeddings_available)`. `embeddings_available` is
/// `true` only when both the backend is real *and* the vector store exists
/// to write to — the endpoint uses this flag to decide whether the cosine
/// query is worth issuing at all.
pub async fn init_embeddings(db: &PgPool) -> (Arc<dyn Embedder>, bool) {
    let env_flag = std::env::var("OVERSLASH_EMBEDDINGS").unwrap_or_else(|_| "on".to_string());
    if env_flag.eq_ignore_ascii_case("off") {
        if has_pgvector(db).await {
            tracing::info!(
                "pgvector available but embeddings disabled via OVERSLASH_EMBEDDINGS=off"
            );
        } else {
            tracing::info!("embeddings disabled via OVERSLASH_EMBEDDINGS=off");
        }
        return (Arc::new(DisabledEmbedder) as Arc<dyn Embedder>, false);
    }

    if !has_pgvector(db).await {
        tracing::warn!(
            "pgvector extension not present; semantic search disabled, \
             falling back to keyword + fuzzy"
        );
        return (Arc::new(DisabledEmbedder) as Arc<dyn Embedder>, false);
    }

    #[cfg(feature = "embeddings")]
    {
        let cache_dir = std::env::var("OVERSLASH_EMBED_CACHE_DIR")
            .ok()
            .map(std::path::PathBuf::from);
        match overslash_core::embeddings::FastembedEmbedder::new(cache_dir) {
            Ok(e) => {
                tracing::info!("semantic search enabled (pgvector + fastembed/bge-small-en-v1.5)");
                (Arc::new(e) as Arc<dyn Embedder>, true)
            }
            Err(err) => {
                tracing::warn!("fastembed init failed; falling back to keyword + fuzzy: {err}");
                (Arc::new(DisabledEmbedder), false)
            }
        }
    }
    #[cfg(not(feature = "embeddings"))]
    {
        tracing::info!(
            "overslash-api built without `embeddings` feature; semantic search disabled"
        );
        (Arc::new(DisabledEmbedder), false)
    }
}

/// Probe whether the `vector` extension is installed in the connected
/// Postgres. Cheap single-row query; runs once at boot. Uses a runtime
/// sqlx call so it doesn't force the compile-time macro to know about the
/// vector extension — the rest of the embeddings machinery is similarly
/// macro-free (see `overslash_db::repos::service_action_embedding`).
#[allow(clippy::disallowed_methods)]
async fn has_pgvector(db: &PgPool) -> bool {
    match sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'vector')",
    )
    .fetch_one(db)
    .await
    {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("pgvector preflight failed: {e}");
            false
        }
    }
}
