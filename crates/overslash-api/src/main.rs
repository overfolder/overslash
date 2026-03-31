use overslash_api::config::Config;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env
    let _ = dotenvy::dotenv();

    // Init tracing
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // Validate required env vars
    let missing = Config::validate_env();
    if !missing.is_empty() {
        tracing::error!("Missing required environment variables: {missing:?}");
        std::process::exit(1);
    }

    let config = Config::from_env();
    let addr = format!("{}:{}", config.host, config.port);
    tracing::info!("Starting Overslash on {addr}");
    tracing::info!(
        host = %config.host,
        port = %config.port,
        public_url = %config.public_url,
        dashboard_url = %config.dashboard_url,
        dev_auth = %config.dev_auth_enabled,
        google_oauth = %config.google_auth_client_id.is_some(),
        services_dir = %config.services_dir,
        approval_expiry_secs = %config.approval_expiry_secs,
        max_response_body_bytes = %config.max_response_body_bytes,
        "Config loaded"
    );

    let app = overslash_api::create_app(config).await?;

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Listening on {addr}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}
