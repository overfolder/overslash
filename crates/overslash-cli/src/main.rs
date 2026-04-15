use clap::{Parser, Subcommand};

mod common;
mod mcp;
mod serve;
mod web;

#[derive(Parser)]
#[command(
    name = "overslash",
    version,
    about = "Overslash — identity & authentication gateway for AI agents",
    long_about = "Overslash ships as a single binary with three integration surfaces: \
the REST API (`serve`), the API plus embedded dashboard (`web`), \
and the MCP stdio server (`mcp`)."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the REST API only (cloud mode — dashboard hosted separately).
    Serve {
        #[arg(long, env = "HOST", default_value = "0.0.0.0")]
        host: String,
        #[arg(long, env = "PORT", default_value = "8080")]
        port: u16,
    },
    /// Start the REST API and serve the embedded dashboard same-origin (self-hosted mode).
    Web {
        #[arg(long, env = "HOST", default_value = "0.0.0.0")]
        host: String,
        #[arg(long, env = "PORT", default_value = "8080")]
        port: u16,
    },
    /// MCP server and configuration helper.
    Mcp {
        #[command(subcommand)]
        command: Option<McpCommand>,
        /// Profile name (reads/writes `~/.config/overslash/mcp.<profile>.json`).
        #[arg(long, global = true)]
        profile: Option<String>,
        /// Override the config path entirely.
        #[arg(long, env = "OVERSLASH_MCP_CONFIG", global = true)]
        config: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
enum McpCommand {
    /// Interactive setup: OAuth login, agent key, write config, print snippet.
    Setup {
        /// Server URL (e.g. https://acme.overslash.dev). Prompted if omitted.
        #[arg(long)]
        server: Option<String>,
        /// Re-run only the user OAuth step against an existing config.
        #[arg(long)]
        re_auth: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve { host, port } => {
            common::bootstrap_server();
            serve::run(host, port).await
        }
        Command::Web { host, port } => {
            common::bootstrap_server();
            web::run(host, port).await
        }
        Command::Mcp {
            command,
            profile,
            config,
        } => {
            let path = mcp::resolve_config_path(profile, config)?;
            match command {
                None => {
                    common::bootstrap_mcp();
                    mcp::run_stdio(path).await
                }
                Some(McpCommand::Setup { server, re_auth }) => {
                    common::bootstrap_cli();
                    mcp::run_setup(path, server, re_auth).await
                }
            }
        }
    }
}
