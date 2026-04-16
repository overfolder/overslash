//! `overslash-mcp` — MCP stdio server that wraps the Overslash REST API.
//!
//! Holds two credentials simultaneously (an agent key for execution and a
//! user token for inline approval resolution) so the LLM can resolve
//! `pending_approval` results in-band. See
//! [`docs/design/mcp-integration.md`](../../docs/design/mcp-integration.md)
//! and SPEC §3 *Integration Surfaces* for the rationale.

use std::path::PathBuf;

pub mod client;
pub mod config;
pub mod server;
pub mod setup;

/// Run the MCP stdio server using the config at `config_path`.
pub async fn serve_stdio(config_path: PathBuf) -> anyhow::Result<()> {
    use rmcp::{ServiceExt, transport::stdio};

    let cfg = config::McpConfig::load(&config_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to load MCP config from {}: {e}\n\
             Run `overslash mcp setup` first.",
            config_path.display()
        )
    })?;

    tracing::info!(server = %cfg.server_url, "starting overslash MCP stdio server");

    let server = server::OverslashMcp::new(cfg)?;
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
