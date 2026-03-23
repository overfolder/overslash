pub mod config;
pub mod error;
pub mod extractors;
pub mod routes;
pub mod services;

use axum::Router;
use sqlx::PgPool;
use tower_http::{compression::CompressionLayer, cors::CorsLayer, trace::TraceLayer};

use crate::config::Config;

/// Application state shared across handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Config,
    pub http_client: reqwest::Client,
}

/// Create the application router with all routes and middleware.
pub async fn create_app(config: Config) -> anyhow::Result<Router> {
    let db = PgPool::connect(&config.database_url).await?;

    // Run migrations
    overslash_db::MIGRATOR.run(&db).await?;

    let state = AppState {
        db,
        config,
        http_client: reqwest::Client::new(),
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
        .merge(routes::orgs::router())
        .merge(routes::identities::router())
        .merge(routes::api_keys::router())
        .merge(routes::secrets::router())
        .merge(routes::permissions::router())
        .merge(routes::actions::router())
        .merge(routes::approvals::router())
        .merge(routes::audit::router())
        .merge(routes::webhooks::router())
        .with_state(state)
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive());

    Ok(app)
}
