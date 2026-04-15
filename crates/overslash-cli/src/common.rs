use std::time::Duration;

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

/// Try to connect to Postgres with a short timeout before booting the full
/// app. The pool inside `create_app` has a multi-second connect timeout and
/// its default error is an opaque "pool timed out" — we want to surface a
/// clear, copy-pastable fix instead.
pub async fn preflight_database(database_url: &str) -> anyhow::Result<()> {
    use sqlx::postgres::PgConnectOptions;
    use sqlx::{ConnectOptions, Connection};
    use std::str::FromStr;

    let opts = PgConnectOptions::from_str(database_url)?
        .disable_statement_logging()
        .log_statements(tracing::log::LevelFilter::Off);

    match tokio::time::timeout(Duration::from_secs(3), opts.connect()).await {
        Ok(Ok(conn)) => {
            let _ = conn.close().await;
            Ok(())
        }
        Ok(Err(e)) => Err(db_hint(database_url, e.to_string())),
        Err(_) => Err(db_hint(
            database_url,
            "connection timed out after 3s".to_string(),
        )),
    }
}

fn db_hint(database_url: &str, cause: String) -> anyhow::Error {
    // Redact any password in the URL before echoing it back.
    let shown = redact_password(database_url);
    anyhow::anyhow!(
        "cannot reach Postgres at {shown}\n  cause: {}\n\n\
         fix: start a local Postgres, then re-run. From the repo root:\n\
         \n    make local\n\
         \n\
         or point DATABASE_URL at an existing instance:\n\
         \n    export DATABASE_URL=postgres://user:pass@host:5432/overslash\n",
        cause
    )
}

fn redact_password(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut u) => {
            if u.password().is_some() {
                let _ = u.set_password(Some("***"));
            }
            u.to_string()
        }
        Err(_) => url.to_string(),
    }
}

/// Print an executor-style startup banner with clickable URLs (OSC 8
/// hyperlinks on supporting terminals, plain text otherwise).
pub fn print_banner(mode: &str, public_url: &str, health_url: &str, embed_dashboard: bool) {
    let bar = "─".repeat(60);
    eprintln!();
    eprintln!(
        "  \x1b[1;35moverslash\x1b[0m {} — {mode} mode",
        env!("CARGO_PKG_VERSION")
    );
    eprintln!("  {bar}");
    eprintln!("  Dashboard  {}", link(public_url, public_url));
    eprintln!("  Health     {}", link(health_url, health_url));
    if mode == "web" && !embed_dashboard {
        eprintln!();
        eprintln!(
            "  \x1b[33m!\x1b[0m built without `embed-dashboard`; requests to /\n    \
             return a stub. Run `make web-build` for the real dashboard."
        );
    }
    eprintln!("  {bar}");
    eprintln!("  Press Ctrl+C to stop");
    eprintln!();
}

fn link(text: &str, url: &str) -> String {
    // OSC 8 hyperlink: `\e]8;;URL\e\\TEXT\e]8;;\e\\`. Terminals that don't
    // support it just render TEXT.
    format!("\x1b[36m\x1b]8;;{url}\x1b\\{text}\x1b]8;;\x1b\\\x1b[0m")
}
