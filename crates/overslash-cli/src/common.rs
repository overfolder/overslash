use std::time::Duration;

use anyhow::Context;
use axum::Router;
use overslash_api::config::{Config, DeploymentEnv, default_public_url, log_filter};
use overslash_mcp::config::McpConfig;

fn init_tracing(to_stderr: bool) {
    // Production refuses a debug/trace `RUST_LOG` and runs at info instead;
    // the warning can only be logged once the subscriber is up.
    let (filter, filter_warning) = log_filter(
        overslash_env::optional("RUST_LOG").as_deref(),
        &DeploymentEnv::from_env(),
    );
    // Prod (Cloud Run) sets `LOG_FORMAT=json` so logs land in Cloud Logging
    // as structured JSON; locally we default to the human-readable text
    // formatter so `make local` stays grep-friendly.
    let json_logs =
        overslash_env::optional("LOG_FORMAT").is_some_and(|v| v.eq_ignore_ascii_case("json"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    match (to_stderr, json_logs) {
        (true, true) => builder.with_writer(std::io::stderr).json().init(),
        (true, false) => builder.with_writer(std::io::stderr).init(),
        (false, true) => builder.json().init(),
        (false, false) => builder.init(),
    }
    if let Some(warning) = filter_warning {
        tracing::warn!("{warning}");
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
/// Exits the process if required env vars are missing, or if the config
/// fails a boot interlock (`Config::boot_policy`: DEV_AUTH in production, a
/// weak key outside a local checkout, …).
pub fn load_config(host: String, port: u16) -> Config {
    let missing = Config::validate_env();
    if !missing.is_empty() {
        tracing::error!("Missing required environment variables: {missing:?}");
        std::process::exit(1);
    }
    let mut config = Config::from_env();
    let report = config.boot_policy();
    for warning in &report.warnings {
        tracing::warn!(
            deployment_env = %config.deployment_env,
            "{warning} (allowed only because OVERSLASH_ENV is unset or local)"
        );
    }
    if !report.errors.is_empty() {
        for error in &report.errors {
            tracing::error!(deployment_env = %config.deployment_env, "{error}");
        }
        tracing::error!(
            "Refusing to start: {} boot check(s) failed",
            report.errors.len()
        );
        std::process::exit(1);
    }
    config.host = host;
    config.port = port;
    // If PUBLIC_URL wasn't set explicitly, re-derive it from the final
    // host/port — otherwise CLI overrides like `--port 7676` would still
    // advertise the env-default URL (e.g. http://localhost:3000) in the
    // banner and inside redirect_uri / login_url responses.
    if !overslash_env::is_set("PUBLIC_URL") {
        config.public_url = default_public_url(&config.host, config.port);
    }
    if config.trusted_proxies.is_configured() {
        tracing::info!(
            policy = %config.trusted_proxies.summary(),
            "client IP: X-Forwarded-For read right-to-left past the trusted proxies",
        );
    } else if config.deployment_env.is_prod() {
        // Safe (the socket peer is used) but almost certainly not intended:
        // behind a proxy, every audit row and per-IP throttle sees the proxy.
        tracing::warn!(
            "no trusted proxy configured: X-Forwarded-For is ignored and the socket peer is \
             the client IP. Set OVERSLASH_TRUSTED_PROXY_HOPS / OVERSLASH_TRUSTED_PROXIES \
             (see infra/README.md)."
        );
    }
    if !config.service_base_overrides.is_empty() {
        let mut entries: Vec<_> = config
            .service_base_overrides
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        entries.sort();
        tracing::info!(
            overrides = ?entries,
            "OVERSLASH_SERVICE_BASE_OVERRIDES active — upstream hosts rewritten before each call",
        );
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

// ── API client helpers ──────────────────────────────────────────────────
// Shared by every subcommand that talks to a running Overslash API
// (`watch`, `services`, `call`, `inbox`, `get-result`).

/// HTTP client for CLI→API calls.
///
/// The per-request timeout is the important one: it guards against a server
/// that accepts the connection and then hangs sending the response body,
/// which would otherwise slip past a user-facing `--timeout` flag entirely.
pub fn api_client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()?)
}

/// Load the stored MCP config, naming the fix when it isn't there.
pub fn load_mcp_config(config_path: &std::path::Path) -> anyhow::Result<McpConfig> {
    McpConfig::load(config_path).with_context(|| {
        format!(
            "failed to load MCP config from {} — run `overslash mcp login` first",
            config_path.display()
        )
    })
}

/// The 401 every API-calling subcommand can hit. One string so the remedy
/// stays identical no matter which command surfaced it.
pub fn unauthorized_error() -> anyhow::Error {
    anyhow::anyhow!("token expired or invalid — run `overslash mcp login`")
}

/// Whether stderr is a terminal. Progress and summary lines are suppressed
/// when it isn't, so piping a command's stdout stays clean.
pub fn is_stderr_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stderr().is_terminal()
}

/// Version reported by the binary: the release tag baked in at build time
/// (`OVERSLASH_VERSION`, set by the release workflow, no `v` prefix), or the
/// current release-manifest version with a `-dev` suffix for every other build.
///
/// Delegates to [`overslash_core::build_info`] so `--version`, the startup
/// banner, `/health` and `GET /v1/version` cannot drift apart.
pub fn version() -> &'static str {
    overslash_core::build_info::build_info().version
}

/// Print an executor-style startup banner with clickable URLs (OSC 8
/// hyperlinks on supporting terminals, plain text otherwise).
pub fn print_banner(mode: &str, public_url: &str, health_url: &str, embed_dashboard: bool) {
    let bar = "─".repeat(60);
    eprintln!();
    eprintln!("  \x1b[1;35moverslash\x1b[0m {} — {mode} mode", version());
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
