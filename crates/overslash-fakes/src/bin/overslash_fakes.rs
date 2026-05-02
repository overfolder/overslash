//! `overslash-fakes` — boots all fakes on OS-assigned ports and reports
//! their resolved URLs as a JSON map.
//!
//! Usage:
//!   overslash-fakes --state-file /tmp/fakes.json
//!
//! On boot, writes one JSON line to stdout *and* (when `--state-file` is set)
//! atomically writes the same map to the file. Holds the listeners until
//! SIGTERM / SIGINT, then shuts down gracefully.
//!
//! For e2e scenarios, the binary boots one MCP fake per
//! [`overslash_fakes::scenarios::McpVariant`] simultaneously (each on its own
//! port). Tests can target whichever capability shape they need without
//! restarting the stack. The `mcp` field of the state file is the variant
//! selected by `--mcp-variant` (default), and `mcp_variants` is the full
//! map keyed by variant name.

use clap::Parser;
use serde_json::{Value, json};
use std::path::PathBuf;

use overslash_fakes::{
    idp::{self, IdpProfile, IdpVariant},
    mcp, oauth, openapi,
    scenarios::McpVariant,
    stripe,
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
    /// Capability shape advertised by the MCP fake. Selects which
    /// `initialize.capabilities`, `tools/list`, and `resources/list` shape
    /// the upstream returns. Defaults to `default` (tools-only with two
    /// tools), matching the foundation PR.
    #[arg(long, env = "OVERSLASH_FAKES_MCP_VARIANT", default_value = "default")]
    mcp_variant: McpVariant,
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

    // One MCP fake per variant, all running concurrently. Selecting which
    // shape a given test exercises is then just a matter of picking the
    // matching URL from the state file — no harness restart needed.
    let mut mcp_handles = Vec::new();
    let mut mcp_variants = serde_json::Map::new();
    for variant in [
        McpVariant::Default,
        McpVariant::NoElicitation,
        McpVariant::FullElicitation,
        McpVariant::PartialTools,
        McpVariant::ResourcesOnly,
    ] {
        let h = mcp::start_on_with(&bind(0), variant).await;
        let key = serde_json::to_value(variant)?
            .as_str()
            .expect("variant serialises to a string")
            .to_string();
        mcp_variants.insert(key, json!(h.url));
        mcp_handles.push(h);
    }
    // The selected variant's URL also goes under the legacy `mcp` key so
    // existing callers (e2e-up.sh, tests/common) keep working unchanged.
    let selected_variant_key = serde_json::to_value(cli.mcp_variant)?
        .as_str()
        .expect("variant serialises to a string")
        .to_string();
    let selected_mcp_url = mcp_variants
        .get(&selected_variant_key)
        .cloned()
        .expect("selected variant is in the map");

    let map = json!({
        "oauth_as": oauth.url,
        "openapi": openapi.handle.url,
        "mcp": selected_mcp_url,
        "mcp_variant": selected_variant_key,
        "mcp_variants": Value::Object(mcp_variants),
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
        mcp_selected = ?selected_mcp_url,
        mcp_variants = mcp_handles.len(),
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
    drop(mcp_handles);
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
