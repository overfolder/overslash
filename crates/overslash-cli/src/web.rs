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

pub async fn run(host: String, port: u16) -> anyhow::Result<()> {
    let mut config = common::load_config(host, port);
    // Same-origin: the dashboard lives at /, the API lives at the same origin.
    config.dashboard_url = config.public_url.clone();

    let addr = format!("{}:{}", config.host, config.port);
    tracing::info!(
        host = %config.host,
        port = %config.port,
        public_url = %config.public_url,
        embed_dashboard = cfg!(feature = "embed-dashboard"),
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
