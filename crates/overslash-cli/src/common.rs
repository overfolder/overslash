use axum::Router;
use overslash_api::config::Config;
use tracing_subscriber::EnvFilter;

fn init_tracing(to_stderr: bool) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if to_stderr {
        builder.with_writer(std::io::stderr).init();
    } else {
        builder.init();
    }
}

/// Bootstrap shared by `serve` and `web`: load .env and init stdout tracing.
pub fn bootstrap_server() {
    let _ = dotenvy::dotenv();
    init_tracing(false);
}

/// Bootstrap for `mcp` stdio: load .env and route tracing to stderr so it
/// does not corrupt the JSON-RPC stream on stdout.
pub fn bootstrap_mcp() {
    let _ = dotenvy::dotenv();
    init_tracing(true);
}

/// Bootstrap for interactive CLI helpers (`mcp setup`): load .env, no tracing
/// (the helper prints its own user-facing output).
pub fn bootstrap_cli() {
    let _ = dotenvy::dotenv();
}

/// Load and validate config from env, overriding host/port from CLI args.
/// Exits the process if required env vars are missing.
pub fn load_config(host: String, port: u16) -> Config {
    let missing = Config::validate_env();
    if !missing.is_empty() {
        tracing::error!("Missing required environment variables: {missing:?}");
        std::process::exit(1);
    }
    let mut config = Config::from_env();
    config.host = host;
    config.port = port;
    config
}

/// Bind and serve the given router at `host:port` with connect-info.
pub async fn serve_router(addr: &str, app: Router) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Listening on {addr}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}
