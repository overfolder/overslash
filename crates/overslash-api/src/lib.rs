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

    let app = Router::new()
        .merge(routes::health::router())
        .merge(routes::orgs::router())
        .merge(routes::identities::router())
        .merge(routes::api_keys::router())
        .merge(routes::secrets::router())
        .merge(routes::permissions::router())
        .merge(routes::actions::router())
        .merge(routes::approvals::router())
        .with_state(state)
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive());

    Ok(app)
}
