use crate::common;

pub async fn run(host: String, port: u16) -> anyhow::Result<()> {
    let config = common::load_config(host, port);
    let addr = format!("{}:{}", config.host, config.port);
    tracing::info!("Starting Overslash (serve mode) on {addr}");
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
    common::serve_router(&addr, app).await
}
