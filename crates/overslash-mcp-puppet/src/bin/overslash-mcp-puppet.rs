//! `overslash-mcp-puppet` — boot the puppet REST server on a free port and
//! print `MCP_PUPPET_URL=http://127.0.0.1:NNNN` to stdout. The harness
//! (`scripts/e2e-up.sh`) scrapes that line and appends it to
//! `.e2e/dashboard.env` so Playwright tests can drive MCP through HTTP.

use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "overslash-mcp-puppet", version, about)]
struct Cli {
    /// Bind host. Default `127.0.0.1`.
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    /// Bind port. Default `0` — let the OS pick.
    #[arg(long, default_value_t = 0)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "overslash_mcp_puppet=info,info".into()),
        )
        .init();

    let cli = Cli::parse();
    let addr = format!("{}:{}", cli.host, cli.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    let local = listener.local_addr()?;
    let url = format!("http://{}", local);
    println!("MCP_PUPPET_URL={url}");

    let app = overslash_mcp_puppet::server::router();
    tracing::info!(%url, "puppet ready");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };

    #[cfg(unix)]
    let term = async {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut s) = signal(SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}
