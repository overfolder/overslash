pub mod config;
pub mod error;
pub mod extractors;
pub mod middleware;
pub mod ownership;
pub mod routes;
pub mod services;

use std::sync::Arc;

use axum::Router;
use axum::http::{HeaderName, HeaderValue, Method, header};
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
}

/// Create the application router with all routes and middleware.
pub async fn create_app(mut config: Config) -> anyhow::Result<Router> {
    let metrics_handle = overslash_metrics::setup();
    overslash_metrics::webhooks::init();

    let db = PgPool::connect(&config.database_url).await?;

    // Run migrations
    overslash_db::MIGRATOR.run(&db).await?;

    // Resolve Stripe price IDs from lookup keys at startup so a misconfigured
    // billing deploy fails fast (not at first checkout). Skip when billing is
    // disabled or the secret key isn't set — the validation in `from_env`
    // already enforces that pairing.
    if config.cloud_billing {
        if let Some(secret_key) = config.stripe_secret_key.as_deref() {
            let http = reqwest::Client::new();
            config.stripe_eur_price_id = Some(
                routes::billing::resolve_stripe_price_by_lookup_key(
                    &http,
                    secret_key,
                    &config.stripe_eur_lookup_key,
                    &config.stripe_api_base,
                )
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "failed to resolve EUR Stripe price (lookup_key={}): {e}",
                        config.stripe_eur_lookup_key
                    )
                })?,
            );
            config.stripe_usd_price_id = Some(
                routes::billing::resolve_stripe_price_by_lookup_key(
                    &http,
                    secret_key,
                    &config.stripe_usd_lookup_key,
                    &config.stripe_api_base,
                )
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "failed to resolve USD Stripe price (lookup_key={}): {e}",
                        config.stripe_usd_lookup_key
                    )
                })?,
            );
            tracing::info!(
                eur_lookup = %config.stripe_eur_lookup_key,
                usd_lookup = %config.stripe_usd_lookup_key,
                "Resolved Stripe price IDs from lookup keys"
            );
        }
    }

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
    let free_unlimited_cache = Arc::new(services::billing_tier::FreeUnlimitedCache::new(
        std::time::Duration::from_secs(30),
    ));

    let (embedder, embeddings_available) = init_embeddings(&db).await;

    let state = AppState {
        db,
        config,
        http_client: reqwest::Client::new(),
        registry: Arc::new(registry),
        rate_limiter,
        rate_limit_cache,
        free_unlimited_cache,
        auth_code_store: services::oauth_as::AuthCodeStore::new(),
        pending_authorize_store: services::oauth_as::PendingAuthorizeStore::new(),
        embedder,
        embeddings_available,
        platform_registry: std::sync::Arc::new(services::platform_registry::build_registry()),
    };

    // Spawn background tasks
    {
        let db = state.db.clone();
        let system = overslash_db::scopes::SystemScope::new_internal(db.clone());
        tokio::spawn(async move {
            // Approval expiry loop: expire stale pending approvals every 60s
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                instrumented_step("approval_expiry", system.expire_stale_approvals(), |n| {
                    tracing::info!("Expired {n} stale approvals");
                    for _ in 0..n {
                        overslash_metrics::approvals::record_event("expired", "system");
                    }
                })
                .await;
                instrumented_step("execution_expiry", system.expire_stale_executions(), |n| {
                    tracing::info!("Expired {n} pending executions")
                })
                .await;
                // Orphaned `executing` rows — API crashed mid-replay. Grace
                // window is the replay timeout plus a minute of slack.
                let orphan_grace =
                    (state.config.execution_replay_timeout_secs as i64).saturating_add(60);
                instrumented_step(
                    "orphan_execution_reap",
                    system.expire_orphaned_executions(orphan_grace),
                    |n| tracing::info!("Reaped {n} orphaned executing executions"),
                )
                .await;
                instrumented_step("subagent_archive", system.archive_idle_subagents(), |n| {
                    tracing::info!("Archived {n} idle sub-agent identities")
                })
                .await;
                instrumented_step("subagent_purge", system.purge_archived_subagents(), |n| {
                    tracing::info!("Purged {n} archived sub-agent identities")
                })
                .await;
                instrumented_step(
                    "auto_bubble",
                    services::permission_chain::process_auto_bubble(&system),
                    |n| tracing::info!("Auto-bubbled {n} approvals"),
                )
                .await;
                // Reap expired gate-flow rows. Both `oauth_connection_flows`
                // and `mcp_upstream_flows` carry a 10-minute TTL but
                // accumulate indefinitely if the user never clicks the
                // gated URL — agents that retry an unauthenticated action
                // would otherwise grow this table without bound.
                instrumented_step(
                    "oauth_connection_flow_expiry",
                    async { overslash_db::repos::oauth_connection_flow::delete_expired(&db).await },
                    |n| tracing::info!("Expired {n} oauth_connection_flows"),
                )
                .await;
                instrumented_step(
                    "mcp_upstream_flow_expiry",
                    async { overslash_db::repos::mcp_upstream_flow::delete_expired(&db).await },
                    |n| tracing::info!("Expired {n} mcp_upstream_flows"),
                )
                .await;
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
                    let start = std::time::Instant::now();
                    store.evict_expired();
                    overslash_metrics::background::record_tick(
                        "rate_limit_evict",
                        "ok",
                        start.elapsed(),
                    );
                    overslash_metrics::background::set_last_success("rate_limit_evict");
                }
            });
        }

        // DB pool stats poller — emits gauge every 30s.
        {
            let db = state.db.clone();
            tokio::spawn(async move {
                let interval = std::time::Duration::from_secs(30);
                loop {
                    tokio::time::sleep(interval).await;
                    let start = std::time::Instant::now();
                    let active = db.size();
                    let idle = db.num_idle() as u32;
                    let active_only = active.saturating_sub(idle);
                    overslash_metrics::db::record_pool(active_only, idle);
                    overslash_metrics::background::record_tick(
                        "db_pool_poller",
                        "ok",
                        start.elapsed(),
                    );
                    overslash_metrics::background::set_last_success("db_pool_poller");
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

    let billing_api_routes = if state.config.cloud_billing {
        routes::billing::router()
    } else {
        Router::new()
    };

    // Stripe webhook lives outside rate limiting so bursts of Stripe retries
    // are never rejected, and the raw body is available for sig verification.
    let stripe_webhook_routes = if state.config.cloud_billing {
        routes::billing::webhook_router()
    } else {
        Router::new()
    };

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
        .merge(routes::dev_e2e::router())
        .merge(routes::preferences::router())
        .merge(routes::oauth_mcp_clients::router())
        .merge(routes::org_idp_configs::router())
        .merge(routes::org_oauth_credentials::router())
        .merge(routes::org_service_keys::router())
        .merge(routes::groups::router())
        .merge(routes::rate_limits::router())
        .merge(billing_api_routes)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::rate_limit::rate_limit_middleware,
        ));

    // CORS is split in two:
    //
    //   * `cors_global` — covers the dashboard API surface (`/v1/*`,
    //     auth, billing, etc.). Allows only the dashboard origin(s).
    //     `DASHBOARD_ORIGIN` accepts:
    //       - "*localhost*" (default): any http localhost / 127.0.0.1
    //         origin on any port — needed because worktrees pick
    //         dynamic dashboard ports.
    //       - a comma-separated list of explicit origins. Entries
    //         beginning with `https://*.` (or `http://*.`) are treated
    //         as single-label wildcard subdomain patterns
    //         (e.g. `https://*.app.overslash.com`) so per-org dashboard
    //         subdomains all match without enumerating every slug.
    //
    //   * `cors_mcp` — covers `/mcp` and the OAuth metadata / DCR /
    //     token endpoints. Allows the dashboard origin(s) PLUS any
    //     entries in `MCP_EXTRA_ORIGINS`. This is where we let a
    //     locally-run MCP Inspector (e.g. `http://localhost:6274`)
    //     complete the OAuth handshake without giving it the ability
    //     to read `/v1/*` cross-origin (which would expose secrets and
    //     connections from a logged-in user's session).
    let dashboard_allow_origin =
        build_allow_origin(&state.config.dashboard_origin, "DASHBOARD_ORIGIN")?;
    let mcp_allow_origin = {
        let combined = if state.config.mcp_extra_origins.trim().is_empty() {
            state.config.dashboard_origin.clone()
        } else {
            format!(
                "{},{}",
                state.config.dashboard_origin.trim(),
                state.config.mcp_extra_origins.trim()
            )
        };
        build_allow_origin(&combined, "DASHBOARD_ORIGIN+MCP_EXTRA_ORIGINS")?
    };

    let cors_global = base_cors_layer().allow_origin(dashboard_allow_origin);
    let cors_mcp = base_cors_layer().allow_origin(mcp_allow_origin);

    // MCP transport + OAuth handshake. `cors_mcp` is wider (allows the
    // Inspector origin); the layer is attached to this subrouter only.
    let mcp_oauth_routes = Router::new()
        .merge(routes::oauth_as::router())
        .merge(routes::oauth::router())
        .merge(routes::mcp::router())
        .layer(cors_mcp);

    // Everything else gets `cors_global`, scoped via a sibling subrouter
    // so the two CORS layers don't compose (an outer cors_global would
    // reject the Inspector origin during preflight before cors_mcp could
    // see it). `oauth::consent_router` lives here — even though it's
    // part of the OAuth flow, it serves dashboard-only `/v1/oauth/consent/*`
    // endpoints that leak pending-request metadata and must NOT be readable
    // from the Inspector origin.
    // `/v1/actions/validate` is a dry-run probe: cheap, side-effect-free,
    // and explicitly exempted from rate limiting so callers can pre-flight
    // bad params without burning quota. Same auth + CORS as the rest of
    // the dashboard API surface; only the rate-limit layer is dropped.
    let validate_routes = routes::actions::validate_router();

    let global_routes = Router::new()
        .merge(routes::health::router())
        .merge(routes::skill_md::router())
        .merge(routes::oauth_upstream::router())
        .merge(routes::oauth::consent_router())
        .merge(stripe_webhook_routes)
        .merge(validate_routes)
        .merge(rate_limited_routes)
        .layer(cors_global);

    let app = Router::new()
        .merge(mcp_oauth_routes)
        .merge(global_routes)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::subdomain::subdomain_middleware,
        ))
        .with_state(state)
        // /internal/metrics is mounted outside subdomain + rate-limit middleware
        // so the GMP / OTel sidecar can scrape it over loopback unconditionally.
        .merge(overslash_metrics::metrics_router(metrics_handle))
        .layer(CompressionLayer::new())
        .layer(axum::middleware::from_fn(
            overslash_metrics::http::middleware,
        ))
        .layer(TraceLayer::new_for_http());

    Ok(app)
}

/// Parse a comma-separated CORS origin spec into a tower-http `AllowOrigin`.
///
/// Accepts:
///   - the `*localhost*` sentinel (any http localhost / 127.0.0.1 origin on
///     any port — used in local/worktree dev where the dashboard port is
///     dynamic);
///   - explicit origins (e.g. `https://app.example.com`);
///   - single-label wildcard subdomain patterns (e.g.
///     `https://*.app.example.com`) — match any single DNS label between
///     scheme and suffix, so per-org subdomains like
///     `https://acme.app.example.com` are allowed without enumerating slugs,
///     while `https://evil.attacker.app.example.com` is rejected.
///
/// All three forms can be mixed in one spec.
fn build_allow_origin(raw: &str, env_var: &str) -> anyhow::Result<AllowOrigin> {
    let mut allow_localhost = false;
    let mut explicit: Vec<HeaderValue> = Vec::new();
    let mut wild: Vec<(String, String)> = Vec::new();
    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if entry == "*localhost*" {
            allow_localhost = true;
        } else if let Some(rest) = entry.strip_prefix("https://*.") {
            wild.push(("https://".into(), format!(".{rest}")));
        } else if let Some(rest) = entry.strip_prefix("http://*.") {
            wild.push(("http://".into(), format!(".{rest}")));
        } else {
            explicit.push(
                entry
                    .parse::<HeaderValue>()
                    .map_err(|e| anyhow::anyhow!("invalid {env_var} entry {entry:?}: {e}"))?,
            );
        }
    }
    Ok(AllowOrigin::predicate(move |origin: &HeaderValue, _req| {
        if explicit.iter().any(|e| e == origin) {
            return true;
        }
        let Ok(o) = origin.to_str() else {
            return false;
        };
        if allow_localhost
            && (o.starts_with("http://localhost:")
                || o.starts_with("http://127.0.0.1:")
                || o == "http://localhost"
                || o == "http://127.0.0.1")
        {
            return true;
        }
        wild.iter().any(|(scheme, suffix)| {
            let Some(rest) = o.strip_prefix(scheme.as_str()) else {
                return false;
            };
            let Some(label_end) = rest.find(suffix.as_str()) else {
                return false;
            };
            let label = &rest[..label_end];
            let tail = &rest[label_end + suffix.len()..];
            !label.is_empty() && !label.contains('.') && tail.is_empty()
        })
    }))
}

/// Shared `CorsLayer` config for both the global and MCP/OAuth route groups.
/// Only the allowed-origin set differs between the two — everything else
/// (methods, headers, credentials, exposed response headers) is identical.
fn base_cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_credentials(true)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            HeaderName::from_static("mcp-session-id"),
            HeaderName::from_static("mcp-protocol-version"),
            HeaderName::from_static("last-event-id"),
        ])
        // Browser-based MCP clients (e.g. MCP Inspector) need to read these
        // back across origins: `Mcp-Session-Id` is part of Streamable HTTP,
        // and `WWW-Authenticate` carries the `resource_metadata=` discovery
        // hint emitted by `/mcp` 401s.
        .expose_headers([
            HeaderName::from_static("mcp-session-id"),
            header::WWW_AUTHENTICATE,
        ])
}

/// Run one background-loop step and emit the matching metrics. `task` becomes
/// the metric label and the silent-hang alert key, so it must stay stable.
/// `on_change` only runs when the step did real work (`Ok(n)` with `n > 0`)
/// — keeping the existing log behavior identical to the pre-instrumented loop.
async fn instrumented_step<E: std::fmt::Display>(
    task: &'static str,
    fut: impl std::future::Future<Output = Result<u64, E>>,
    on_change: impl FnOnce(u64),
) {
    let start = std::time::Instant::now();
    let result = fut.await;
    let status = match &result {
        Ok(0) => "noop",
        Ok(_) => "ok",
        Err(_) => "err",
    };
    overslash_metrics::background::record_tick(task, status, start.elapsed());
    if result.is_ok() {
        overslash_metrics::background::set_last_success(task);
    }
    match result {
        Ok(n) if n > 0 => on_change(n),
        Ok(_) => {}
        Err(e) => tracing::error!("{task} error: {e}"),
    }
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
