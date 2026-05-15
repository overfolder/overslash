use std::net::SocketAddr;

use oversla_sh::{AppState, Config, Storage, create_app};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,oversla_sh=info")),
        )
        .init();

    let config = Config::from_env()?;
    let storage = Storage::connect(&config.valkey_url).await?;

    // Fail loudly on boot if Valkey isn't reachable — Cloud Run will retry
    // the instance rather than serve traffic we can't satisfy.
    storage.ping().await?;

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(addr = %addr, base_url = %config.base_url, "oversla-sh listening");

    let state = AppState::from_config(&config, storage);
    let app = create_app(state);
    axum::serve(listener, app).await?;
    Ok(())
}
