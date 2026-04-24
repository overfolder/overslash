pub mod auth;
pub mod config;
pub mod error;
pub mod routes;
pub mod slug;
pub mod storage;

use axum::Router;
use tower_http::trace::TraceLayer;

pub use config::Config;
pub use storage::Storage;

/// Application state shared across handlers.
#[derive(Clone)]
pub struct AppState {
    pub storage: Storage,
    pub api_key: String,
    pub base_url: String,
    pub min_ttl_secs: u64,
    pub max_ttl_secs: u64,
}

impl AppState {
    pub fn from_config(config: &Config, storage: Storage) -> Self {
        Self {
            storage,
            api_key: config.api_key.clone(),
            base_url: config.base_url.clone(),
            min_ttl_secs: config.min_ttl_secs,
            max_ttl_secs: config.max_ttl_secs,
        }
    }
}

pub fn create_app(state: AppState) -> Router {
    Router::new()
        .merge(routes::health::router())
        .merge(routes::links::router())
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}
