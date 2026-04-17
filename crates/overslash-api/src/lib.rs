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

    let state = AppState {
        db,
        config,
        http_client: reqwest::Client::new(),
        registry: Arc::new(registry),
        rate_limiter,
        rate_limit_cache,
        auth_code_store: services::oauth_as::AuthCodeStore::new(),
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
