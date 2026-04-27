use clap::{Args, Parser, Subcommand};

mod common;
mod mcp;
mod mcp_login;
mod serve;
mod services;
mod watch;
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
        /// Port to bind on. Precedence: --port > OVERSLASH_WEB_PORT > PORT > 7171.
        #[arg(long)]
        port: Option<u16>,
    },
    /// Watch a pending approval until it resolves (or times out), then exit.
    ///
    /// Polls GET /v1/approvals/{id} and writes the final JSON to stdout.
    /// Exit code: 0 = allowed, 1 = denied/expired/timeout, 2 = error.
    Watch {
        /// Approval UUID to watch.
        approval_id: String,
        /// Maximum time to wait, e.g. "15m", "1h", "900s". Default: 15m.
        #[arg(long, default_value = "15m")]
        timeout: String,
        /// Poll interval, e.g. "3s", "10s". Default: 3s.
        #[arg(long, default_value = "3s")]
        poll: String,
        /// Profile name (reads `~/.config/overslash/mcp.<profile>.json`).
        #[arg(long)]
        profile: Option<String>,
        /// Override the config path entirely.
        #[arg(long, env = "OVERSLASH_MCP_CONFIG")]
        config: Option<std::path::PathBuf>,
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
    /// List and call services.
    Services {
        #[command(subcommand)]
        command: ServicesCommand,
        /// Profile name (reads `~/.config/overslash/mcp.<profile>.json`).
        #[arg(long)]
        profile: Option<String>,
        /// Override the config path entirely.
        #[arg(long, env = "OVERSLASH_MCP_CONFIG")]
        config: Option<std::path::PathBuf>,
    },
    /// Call a service action (shortcut for `services call`).
    Call {
        #[command(flatten)]
        fields: CallFields,
        /// Profile name (reads `~/.config/overslash/mcp.<profile>.json`).
        #[arg(long)]
        profile: Option<String>,
        /// Override the config path entirely.
        #[arg(long, env = "OVERSLASH_MCP_CONFIG")]
        config: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
enum ServicesCommand {
    /// List all service instances visible to this identity.
    List,
    /// Call a service action.
    Call {
        #[command(flatten)]
        fields: CallFields,
    },
}

/// Shared fields for `call` and `services call`.
#[derive(Args)]
struct CallFields {
    /// Service instance name or UUID (Mode C).
    #[arg(long)]
    service: Option<String>,
    /// Action key (Mode C).
    #[arg(long)]
    action: Option<String>,
    /// Action parameter as key=value (repeatable; value is JSON or plain string).
    #[arg(long = "param", value_name = "KEY=VALUE")]
    params: Vec<String>,
    /// Raw URL to call (Mode A).
    #[arg(long)]
    url: Option<String>,
    /// HTTP method for raw call (Mode A, default GET).
    #[arg(long)]
    method: Option<String>,
    /// Extra request header as key:value (repeatable, Mode A).
    #[arg(long = "header", value_name = "KEY:VALUE")]
    headers: Vec<String>,
    /// Raw request body string (Mode A).
    #[arg(long)]
    body: Option<String>,
    /// jq expression to filter the response body.
    #[arg(long)]
    filter: Option<String>,
}

#[derive(Subcommand)]
enum McpCommand {
    /// Authenticate against an Overslash deployment via OAuth 2.1 and
    /// persist the resulting token in `~/.config/overslash/mcp.json`.
    Login {
        /// Server URL (e.g. https://acme.overslash.dev). Prompted if omitted.
        #[arg(long)]
        server: Option<String>,
        /// Force a fresh client registration + consent even if a token is
        /// already configured.
        #[arg(long)]
        re_auth: bool,
    },
}

/// Parse a port env var, returning `None` when unset or unparseable.
fn env_port(name: &str) -> Option<u16> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env BEFORE clap parses, so flags with `env = "…"` fallbacks
    // (e.g. --port / PORT) see values from the dotenv file. Otherwise clap
    // only sees the real process env, falls back to `default_value`, and
    // the CLI silently ignores .env overrides.
    //
    // Load .env.local first and .env second: dotenvy is first-wins (it never
    // overwrites an existing env var), so a worktree's .env.local (written by
    // bin/worktree-env.sh) takes precedence over the repo-default .env.
    let _ = dotenvy::from_filename(".env.local");
    let _ = dotenvy::dotenv();
    let cli = Cli::parse();
    match cli.command {
        Command::Serve { host, port } => {
            common::bootstrap_server();
            serve::run(host, port).await
        }
        Command::Web { host, port } => {
            common::bootstrap_server();
            // Precedence (CLI convention: explicit flag wins over env):
            //   1. --port (from the user)
            //   2. OVERSLASH_WEB_PORT — worktree-isolated port written by
            //      bin/worktree-env.sh into .env.local so the bare binary
            //      doesn't collide with sibling worktrees or the Docker API
            //      container (which uses API_HOST_PORT / internal :3000).
            //   3. PORT — legacy fallback from .env / shell env.
            //   4. 7171 default.
            let effective_port = port
                .or_else(|| env_port("OVERSLASH_WEB_PORT"))
                .or_else(|| env_port("PORT"))
                .unwrap_or(7171);
            web::run(host, effective_port).await
        }
        Command::Watch {
            approval_id,
            timeout,
            poll,
            profile,
            config,
        } => {
            common::bootstrap_cli();
            let path = mcp::resolve_config_path(profile, config)?;
            watch::run(path, approval_id, timeout, poll).await
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
                Some(McpCommand::Login { server, re_auth }) => {
                    common::bootstrap_cli();
                    mcp_login::run(path, server, re_auth).await
                }
            }
        }
        Command::Services {
            command,
            profile,
            config,
        } => {
            common::bootstrap_cli();
            let path = mcp::resolve_config_path(profile, config)?;
            match command {
                ServicesCommand::List => services::list(path).await,
                ServicesCommand::Call { fields } => {
                    services::call(path, fields_into_call_args(fields)?).await
                }
            }
        }
        Command::Call {
            fields,
            profile,
            config,
        } => {
            common::bootstrap_cli();
            let path = mcp::resolve_config_path(profile, config)?;
            services::call(path, fields_into_call_args(fields)?).await
        }
    }
}

fn fields_into_call_args(fields: CallFields) -> anyhow::Result<services::CallArgs> {
    let params = fields
        .params
        .iter()
        .map(|s| services::parse_param(s))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let headers = fields
        .headers
        .iter()
        .map(|s| services::parse_header(s))
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(services::CallArgs {
        service: fields.service,
        action: fields.action,
        params,
        url: fields.url,
        method: fields.method,
        headers,
        body: fields.body,
        filter: fields.filter,
    })
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
            assert_eq!(port, Some(18080));
        } else {
            panic!("expected Web");
        }
    }

    #[test]
    fn web_port_defaults_to_none_so_env_can_participate() {
        let cli = parse(&["overslash", "web"]);
        if let Command::Web { port, .. } = cli.command {
            assert!(port.is_none(), "port must be None when --port is absent");
        } else {
            panic!("expected Web");
        }
    }

    // Precedence helper mirrors main(): --port > OVERSLASH_WEB_PORT > PORT > 7171.
    fn resolve_web_port(
        cli_port: Option<u16>,
        web_env: Option<&str>,
        port_env: Option<&str>,
    ) -> u16 {
        cli_port
            .or_else(|| web_env.and_then(|v| v.parse().ok()))
            .or_else(|| port_env.and_then(|v| v.parse().ok()))
            .unwrap_or(7171)
    }

    #[test]
    fn web_port_cli_flag_beats_env() {
        // The Sentry-flagged regression: an explicit --port must not be
        // silently overridden by OVERSLASH_WEB_PORT from .env.local.
        let got = resolve_web_port(Some(9001), Some("20425"), Some("3000"));
        assert_eq!(got, 9001);
    }

    #[test]
    fn web_port_overslash_web_port_beats_port_env() {
        let got = resolve_web_port(None, Some("20425"), Some("3000"));
        assert_eq!(got, 20425);
    }

    #[test]
    fn web_port_falls_back_to_port_env_then_default() {
        assert_eq!(resolve_web_port(None, None, Some("3000")), 3000);
        assert_eq!(resolve_web_port(None, None, None), 7171);
    }

    #[test]
    fn web_port_ignores_unparseable_env_values() {
        // If OVERSLASH_WEB_PORT is garbage, skip it and try PORT next.
        let got = resolve_web_port(None, Some("not-a-port"), Some("3000"));
        assert_eq!(got, 3000);
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
    fn mcp_login_with_profile_and_server() {
        let cli = parse(&[
            "overslash",
            "mcp",
            "--profile",
            "work",
            "login",
            "--server",
            "https://x.y",
        ]);
        if let Command::Mcp {
            command, profile, ..
        } = cli.command
        {
            assert_eq!(profile.as_deref(), Some("work"));
            match command {
                Some(McpCommand::Login { server, re_auth }) => {
                    assert_eq!(server.as_deref(), Some("https://x.y"));
                    assert!(!re_auth);
                }
                _ => panic!("expected Login"),
            }
        } else {
            panic!("expected Mcp");
        }
    }

    #[test]
    fn mcp_login_reauth_flag() {
        let cli = parse(&["overslash", "mcp", "login", "--re-auth"]);
        if let Command::Mcp {
            command: Some(McpCommand::Login { re_auth, .. }),
            ..
        } = cli.command
        {
            assert!(re_auth);
        } else {
            panic!("expected Login re-auth");
        }
    }

    #[test]
    fn bad_subcommand_errors() {
        let r = Cli::try_parse_from(["overslash", "bogus"]);
        assert!(r.is_err());
    }
}
