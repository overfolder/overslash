use crate::common;

#[cfg(feature = "embed-dashboard")]
mod embed {
    use axum::{
        Router,
        body::Body,
        extract::Path,
        http::{StatusCode, header},
        response::{IntoResponse, Response},
        routing::get,
    };
    #[derive(rust_embed::RustEmbed)]
    #[folder = "$CARGO_MANIFEST_DIR/../../dashboard/build/"]
    struct Asset;

    async fn serve_index() -> Response {
        serve("index.html").await
    }

    async fn serve_path(Path(path): Path<String>) -> Response {
        let clean = path.split(['?', '#']).next().unwrap_or("");
        let resp = serve(clean).await;
        if resp.status() == StatusCode::NOT_FOUND {
            serve("index.html").await
        } else {
            resp
        }
    }

    async fn serve(path: &str) -> Response {
        match Asset::get(path) {
            Some(content) => {
                let mime = mime_guess::from_path(path).first_or_octet_stream();
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, mime.as_ref())
                    .body(Body::from(content.data.into_owned()))
                    .unwrap()
            }
            None => StatusCode::NOT_FOUND.into_response(),
        }
    }

    pub fn fallback_router() -> Router {
        Router::new()
            .route("/", get(serve_index))
            .route("/{*path}", get(serve_path))
    }
}

#[cfg(not(feature = "embed-dashboard"))]
mod embed {
    use axum::{Router, response::IntoResponse, routing::get};

    async fn missing() -> impl IntoResponse {
        (
            axum::http::StatusCode::NOT_FOUND,
            "overslash was built without the `embed-dashboard` feature. \
             Rebuild with `cargo build -p overslash-cli --features embed-dashboard` \
             after running `make dashboard-static`.",
        )
    }

    pub fn fallback_router() -> Router {
        Router::new().fallback(get(missing))
    }
}

pub async fn run(host: String, port: u16, mcp_runtime: String) -> anyhow::Result<()> {
    let mut config = common::load_config(host, port);
    // Same-origin: the dashboard lives at /, the API lives at the same origin.
    config.dashboard_url = config.public_url.clone();

    // ── MCP runtime resolution ──────────────────────────────────────
    //
    // With the `mcp` feature off, the only accepted value is "off";
    // anything else logs a one-line hint and degrades to off. With the
    // feature on: `local` spawns a supervised child; `<url>` sets an
    // external runtime; `off` disables MCP. The supervisor's lifetime is
    // tied to `_mcp_sup` — dropping it kills the child.
    #[cfg(feature = "mcp")]
    let _mcp_sup = configure_mcp_runtime(&mut config, &mcp_runtime).await?;
    #[cfg(not(feature = "mcp"))]
    {
        if mcp_runtime != "off" && mcp_runtime != "local" {
            // "local" is the default; silently accept it on feature-off
            // builds so the flag's default doesn't break users. Anything
            // else (including an URL) is probably a misconfiguration.
            tracing::warn!(
                "--mcp-runtime={mcp_runtime} ignored: this binary was built without the \
                 `mcp` Cargo feature. Rebuild with `make build-web` (which enables it) \
                 or pass --mcp-runtime=off to silence this warning."
            );
        }
        config.mcp_runtime_url = None;
        config.mcp_runtime_shared_secret = None;
    }

    let addr = format!("{}:{}", config.host, config.port);
    tracing::info!(
        host = %config.host,
        port = %config.port,
        public_url = %config.public_url,
        embed_dashboard = cfg!(feature = "embed-dashboard"),
        mcp_feature = cfg!(feature = "mcp"),
        mcp_runtime_url = ?config.mcp_runtime_url,
        "Config loaded"
    );

    common::preflight_database(&config.database_url).await?;

    let public = config.public_url.clone();
    let app = overslash_api::create_app(config)
        .await?
        .merge(embed::fallback_router());

    let health = format!("{}/health", public.trim_end_matches('/'));
    common::print_banner("web", &public, &health, cfg!(feature = "embed-dashboard"));
    common::serve_router(&addr, app).await
}

#[cfg(feature = "mcp")]
async fn configure_mcp_runtime(
    config: &mut overslash_api::config::Config,
    mode: &str,
) -> anyhow::Result<Option<crate::mcp_runtime_supervisor::Supervisor>> {
    match mode {
        "off" => {
            config.mcp_runtime_url = None;
            config.mcp_runtime_shared_secret = None;
            Ok(None)
        }
        "local" => {
            let sup = crate::mcp_runtime_supervisor::spawn(
                crate::mcp_runtime_supervisor::default_config(),
            )
            .await?;
            config.mcp_runtime_url = Some(sup.url.clone());
            config.mcp_runtime_shared_secret = Some(sup.shared_secret.clone());
            tracing::info!("MCP runtime: local (supervised) at {}", sup.url);
            Ok(Some(sup))
        }
        url if url.starts_with("http://") || url.starts_with("https://") => {
            // External runtime — bearer secret must come from env.
            let secret = std::env::var("MCP_RUNTIME_SHARED_SECRET").ok();
            if secret.is_none() {
                tracing::warn!(
                    "--mcp-runtime=<url> set but MCP_RUNTIME_SHARED_SECRET is not — requests will \
                     be unauthenticated against the remote runtime."
                );
            }
            config.mcp_runtime_url = Some(url.to_string());
            config.mcp_runtime_shared_secret = secret;
            tracing::info!("MCP runtime: external at {url}");
            Ok(None)
        }
        other => {
            anyhow::bail!("--mcp-runtime must be `local`, `off`, or a http(s) URL; got {other:?}")
        }
    }
}
