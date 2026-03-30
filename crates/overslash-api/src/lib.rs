pub mod acl;
pub mod config;
pub mod error;
pub mod extractors;
pub mod routes;
pub mod services;

use std::sync::Arc;

use axum::Router;
use sqlx::PgPool;
use tower_http::{
    compression::CompressionLayer,
    cors::CorsLayer,
    services::{ServeDir, ServeFile},
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

    let state = AppState {
        db,
        config,
        http_client: reqwest::Client::new(),
        registry: Arc::new(registry),
    };

    // Spawn background tasks
    {
        let db = state.db.clone();
        tokio::spawn(async move {
            // Approval expiry loop: expire stale pending approvals every 60s
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                match overslash_db::repos::approval::expire_stale(&db).await {
                    Ok(n) if n > 0 => tracing::info!("Expired {n} stale approvals"),
                    Err(e) => tracing::error!("Approval expiry error: {e}"),
                    _ => {}
                }
                match overslash_db::repos::pending_enrollment::expire_stale(&db).await {
                    Ok(n) if n > 0 => tracing::info!("Expired {n} stale pending enrollments"),
                    Err(e) => tracing::error!("Enrollment expiry error: {e}"),
                    _ => {}
                }
            }
        });

        // Webhook retry loop
        tokio::spawn(services::webhook_dispatcher::spawn_retry_loop(
            state.db.clone(),
            state.http_client.clone(),
        ));
    }

    let app = Router::new()
        .merge(routes::health::router())
        .merge(routes::acl::router())
        .merge(routes::orgs::router())
        .merge(routes::identities::router())
        .merge(routes::api_keys::router())
        .merge(routes::secrets::router())
        .merge(routes::permissions::router())
        .merge(routes::actions::router())
        .merge(routes::approvals::router())
        .merge(routes::audit::router())
        .merge(routes::webhooks::router())
        .merge(routes::services::router())
        .merge(routes::connections::router())
        .merge(routes::byoc_credentials::router())
        .merge(routes::auth::router())
        .merge(routes::enrollment::router())
        .with_state(state.clone());

    // Serve dashboard static files if configured
    let app = if let Some(ref dashboard_dir) = state.config.dashboard_dir {
        let index = format!("{dashboard_dir}/index.html");
        if std::path::Path::new(dashboard_dir).exists() {
            tracing::info!("Serving dashboard from {dashboard_dir}");
            app.fallback_service(
                ServeDir::new(dashboard_dir).not_found_service(ServeFile::new(index)),
            )
        } else {
            tracing::warn!("Dashboard dir {dashboard_dir} not found, skipping static serving");
            app
        }
    } else {
        app
    };

    let app = app
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive());

    Ok(app)
}
