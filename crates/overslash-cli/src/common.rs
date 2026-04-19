use std::time::Duration;

use axum::Router;
use overslash_api::config::{Config, default_public_url};
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

/// Bootstrap shared by `serve` and `web`: load dotenv files and init stdout
/// tracing. `.env.local` is loaded first so worktree overrides win over `.env`
/// (dotenvy never overwrites an existing env var).
pub fn bootstrap_server() {
    let _ = dotenvy::from_filename(".env.local");
    let _ = dotenvy::dotenv();
    init_tracing(false);
}

/// Bootstrap for `mcp` stdio: load dotenv files and route tracing to stderr
/// so it does not corrupt the JSON-RPC stream on stdout.
pub fn bootstrap_mcp() {
    let _ = dotenvy::from_filename(".env.local");
    let _ = dotenvy::dotenv();
    init_tracing(true);
}

/// Bootstrap for interactive CLI helpers (`mcp setup`): load dotenv files,
/// no tracing (the helper prints its own user-facing output).
pub fn bootstrap_cli() {
    let _ = dotenvy::from_filename(".env.local");
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
    // If PUBLIC_URL wasn't set explicitly, re-derive it from the final
    // host/port — otherwise CLI overrides like `--port 7676` would still
    // advertise the env-default URL (e.g. http://localhost:3000) in the
    // banner and inside redirect_uri / login_url responses.
    if std::env::var("PUBLIC_URL").is_err() {
        config.public_url = default_public_url(&config.host, config.port);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_password_masks_password_but_keeps_host() {
        let s = redact_password("postgres://alice:supersecret@db.example.com:5432/ovs");
        assert!(
            !s.contains("supersecret"),
            "expected password masked in {s}"
        );
        assert!(s.contains("alice"));
        assert!(s.contains("db.example.com"));
        assert!(s.contains("***"));
    }

    #[test]
    fn redact_password_noop_when_absent() {
        let s = redact_password("postgres://alice@db.example.com:5432/ovs");
        assert!(!s.contains("***"));
        assert!(s.contains("alice"));
    }

    #[test]
    fn redact_password_passthrough_on_bad_url() {
        let s = redact_password("not a url");
        assert_eq!(s, "not a url");
    }

    #[test]
    fn db_hint_message_includes_fix_commands() {
        let e = db_hint(
            "postgres://a:b@127.0.0.1:5432/ovs",
            "connection refused".into(),
        );
        let msg = format!("{e}");
        assert!(msg.contains("make local"));
        assert!(msg.contains("DATABASE_URL"));
        assert!(!msg.contains(":b@"), "password leaked: {msg}");
    }

    #[tokio::test]
    async fn preflight_bad_host_errors_fast() {
        // 127.0.0.1:1 is guaranteed-unreachable on typical hosts; if not, the
        // 3s timeout still bounds the test.
        let start = std::time::Instant::now();
        let err = preflight_database("postgres://a:b@127.0.0.1:1/ovs")
            .await
            .expect_err("expected connect failure");
        let elapsed = start.elapsed();
        assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}");
        let msg = format!("{err}");
        assert!(msg.contains("cannot reach Postgres"));
    }

    #[test]
    fn preflight_malformed_url_errors() {
        let fut = preflight_database("not a url");
        // Build a throwaway runtime; we just want the parse branch.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt.block_on(fut).expect_err("expected parse error");
        assert!(!format!("{err}").is_empty());
    }

    #[test]
    fn link_contains_osc8_sequence() {
        let s = link("label", "https://example.com");
        assert!(s.contains("\x1b]8;;https://example.com"));
        assert!(s.contains("label"));
    }

    #[test]
    fn print_banner_does_not_panic() {
        // No assertion beyond "doesn't panic"; the function writes to stderr.
        print_banner(
            "web",
            "http://localhost:8080",
            "http://localhost:8080/health",
            true,
        );
        print_banner(
            "web",
            "http://localhost:8080",
            "http://localhost:8080/health",
            false,
        );
        print_banner(
            "serve",
            "http://localhost:8080",
            "http://localhost:8080/health",
            false,
        );
    }
}
