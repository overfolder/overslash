use clap::{Parser, Subcommand};

mod common;
mod mcp;
mod serve;
mod web;

#[derive(Parser)]
#[command(
    name = "overslash",
    bin_name = "overslash",
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
    // Load .env BEFORE clap parses, so flags with `env = "…"` fallbacks
    // (e.g. --port / PORT) see values from the dotenv file. Otherwise clap
    // only sees the real process env, falls back to `default_value`, and
    // the CLI silently ignores .env overrides.
    let _ = dotenvy::dotenv();
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

#[cfg(test)]
mod cli_tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).unwrap_or_else(|e| panic!("parse {args:?}: {e}"))
    }

    #[test]
    fn serve_parses_with_defaults() {
        let cli = parse(&["overslash", "serve"]);
        if let Command::Serve { host, port } = cli.command {
            assert_eq!(host, "0.0.0.0");
            assert_eq!(port, 8080);
        } else {
            panic!("expected Serve");
        }
    }

    #[test]
    fn serve_parses_flags() {
        let cli = parse(&[
            "overslash",
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            "9001",
        ]);
        if let Command::Serve { host, port } = cli.command {
            assert_eq!(host, "127.0.0.1");
            assert_eq!(port, 9001);
        } else {
            panic!("expected Serve");
        }
    }

    #[test]
    fn web_parses() {
        let cli = parse(&["overslash", "web", "--port", "18080"]);
        if let Command::Web { port, .. } = cli.command {
            assert_eq!(port, 18080);
        } else {
            panic!("expected Web");
        }
    }

    #[test]
    fn mcp_bare_has_no_subcommand() {
        let cli = parse(&["overslash", "mcp"]);
        if let Command::Mcp {
            command, profile, ..
        } = cli.command
        {
            assert!(command.is_none());
            assert!(profile.is_none());
        } else {
            panic!("expected Mcp");
        }
    }

    #[test]
    fn mcp_setup_with_profile_and_server() {
        let cli = parse(&[
            "overslash",
            "mcp",
            "--profile",
            "work",
            "setup",
            "--server",
            "https://x.y",
        ]);
        if let Command::Mcp {
            command, profile, ..
        } = cli.command
        {
            assert_eq!(profile.as_deref(), Some("work"));
            match command {
                Some(McpCommand::Setup { server, re_auth }) => {
                    assert_eq!(server.as_deref(), Some("https://x.y"));
                    assert!(!re_auth);
                }
                _ => panic!("expected Setup"),
            }
        } else {
            panic!("expected Mcp");
        }
    }

    #[test]
    fn mcp_setup_reauth_flag() {
        let cli = parse(&["overslash", "mcp", "setup", "--re-auth"]);
        if let Command::Mcp {
            command: Some(McpCommand::Setup { re_auth, .. }),
            ..
        } = cli.command
        {
            assert!(re_auth);
        } else {
            panic!("expected Setup re-auth");
        }
    }

    #[test]
    fn bad_subcommand_errors() {
        let r = Cli::try_parse_from(["overslash", "bogus"]);
        assert!(r.is_err());
    }
}
