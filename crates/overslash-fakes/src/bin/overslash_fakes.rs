//! `overslash-fakes` — boots all fakes on OS-assigned ports and reports
//! their resolved URLs as a JSON map.
//!
//! Usage:
//!   overslash-fakes --state-file /tmp/fakes.json
//!
//! On boot, writes one JSON line to stdout *and* (when `--state-file` is set)
//! atomically writes the same map to the file. Holds the listeners until
//! SIGTERM / SIGINT, then shuts down gracefully.

use clap::Parser;
use serde_json::json;
use std::path::PathBuf;

use overslash_fakes::{
    idp::{self, IdpProfile, IdpVariant},
    mcp, oauth, openapi, stripe,
};

#[derive(Parser, Debug)]
#[command(name = "overslash-fakes", version, about)]
struct Cli {
    /// Write the resolved-URL JSON map to this path. The harness reads it to
    /// learn the OS-assigned ports.
    #[arg(long, env = "OVERSLASH_FAKES_STATE_FILE")]
    state_file: Option<PathBuf>,
    /// Bind address. Default `127.0.0.1` — port 0 (OS-assigned) per fake.
    #[arg(long, default_value = "127.0.0.1")]
    bind_host: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    let bind = |port: u16| format!("{}:{port}", cli.bind_host);

    let oauth = oauth::start_on(&bind(0)).await;
    let openapi = openapi::start_on(&bind(0)).await;
    let mcp = mcp::start_on(&bind(0)).await;
    let stripe = stripe::start_on(&bind(0)).await;

    // Per-org multi-IdP fixtures: Auth0-shaped tenant for Org A, Okta-shaped
    // tenant for Org B. The harness (`scripts/e2e-up.sh`) reads these URLs
    // from the state file and posts them to the dev-gated
    // `POST /auth/dev/seed-e2e-idps` endpoint, which registers the matching
    // `oauth_providers` + `org_idp_configs` rows.
    let auth0 = idp::boot(
        IdpVariant::Auth0,
        IdpProfile::auth0_default(),
        &cli.bind_host,
    )
    .await;
    let okta = idp::boot(IdpVariant::Okta, IdpProfile::okta_default(), &cli.bind_host).await;

    let map = json!({
        "oauth_as": oauth.url,
        "openapi": openapi.handle.url,
        "mcp": mcp.url,
        "stripe": stripe.url,
        "auth0": {
            "tenant_url": auth0.issuer_url,
            "discovery_url": auth0.discovery_url,
        },
        "okta": {
            "tenant_url": okta.issuer_url,
            "discovery_url": okta.discovery_url,
        },
    });

    let line = serde_json::to_string(&map)?;
    println!("{line}");

    if let Some(path) = cli.state_file.as_ref() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &line)?;
        std::fs::rename(&tmp, path)?;
        tracing::info!(path = %path.display(), "wrote fakes state file");
    }

    tracing::info!(
        oauth_as = %oauth.url,
        openapi = %openapi.handle.url,
        mcp = %mcp.url,
        stripe = %stripe.url,
        auth0 = %auth0.issuer_url,
        okta = %okta.issuer_url,
        "overslash-fakes ready",
    );

    // Wait for SIGTERM/SIGINT.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = wait_for_term() => {},
    }
    tracing::info!("shutting down");

    drop(oauth);
    drop(openapi);
    drop(mcp);
    drop(stripe);
    drop(auth0);
    drop(okta);

    if let Some(path) = cli.state_file.as_ref() {
        let _ = std::fs::remove_file(path);
    }
    Ok(())
}

#[cfg(unix)]
async fn wait_for_term() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut s = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    s.recv().await;
}

#[cfg(not(unix))]
async fn wait_for_term() {
    std::future::pending::<()>().await;
}
