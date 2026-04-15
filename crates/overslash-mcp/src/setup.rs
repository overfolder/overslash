use std::io::{BufRead, Write};
use std::path::PathBuf;

use crate::client::{Cred, OverslashClient};
use crate::config::McpConfig;

/// Interactive setup. Three steps:
///   1. Pick / confirm the server URL.
///   2. Capture a user access token + refresh token (browser OAuth).
///   3. Capture or create an agent API key.
///
/// Then write the config file (mode 0600 on Unix) and print the snippet
/// for the user's MCP client config.
///
/// `re_auth` only re-runs step 2 against an existing config.
pub async fn run(
    config_path: PathBuf,
    server: Option<String>,
    re_auth: bool,
) -> anyhow::Result<()> {
    let existing = McpConfig::load(&config_path).ok();

    if re_auth {
        let mut cfg = existing.ok_or_else(|| {
            anyhow::anyhow!(
                "no existing config at {} — run `overslash mcp setup` without --re-auth first",
                config_path.display()
            )
        })?;
        let (token, refresh) = browser_oauth(&cfg.server_url)?;
        cfg.user_token = token;
        cfg.user_refresh_token = Some(refresh);
        cfg.save(&config_path)?;
        println!("Refreshed user credentials in {}", config_path.display());
        return Ok(());
    }

    let server_url = match server {
        Some(s) => s,
        None => prompt(
            "Overslash server URL (e.g. https://acme.overslash.dev)",
            existing.as_ref().map(|c| c.server_url.as_str()),
        )?,
    };

    let (user_token, user_refresh_token) = browser_oauth(&server_url)?;

    let agent_choice = prompt(
        "Use an existing agent API key, or create a new agent identity? (existing/new)",
        Some("new"),
    )?;
    let agent_key = match agent_choice.trim().to_ascii_lowercase().as_str() {
        "existing" => prompt("Paste the agent API key", None)?,
        _ => {
            let name = prompt("Agent name (e.g. claude-code-laptop)", Some("claude-code"))?;
            create_agent_identity(&server_url, &user_token, &name).await?
        }
    };

    let cfg = McpConfig {
        server_url,
        agent_key,
        user_token,
        user_refresh_token: Some(user_refresh_token),
    };
    cfg.save(&config_path)?;

    println!();
    println!("✓ Wrote {}", config_path.display());
    println!();
    println!("Add this to your MCP client config (Claude Desktop, Cursor, etc.):");
    println!();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "mcpServers": {
                "overslash": {
                    "command": "overslash",
                    "args": ["mcp"]
                }
            }
        }))
        .unwrap()
    );
    println!();
    Ok(())
}

fn prompt(label: &str, default: Option<&str>) -> anyhow::Result<String> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    match default {
        Some(d) => print!("{label} [{d}]: "),
        None => print!("{label}: "),
    }
    stdout.flush()?;
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    let trimmed = line.trim().to_string();
    if trimmed.is_empty() {
        if let Some(d) = default {
            return Ok(d.to_string());
        }
        anyhow::bail!("input required");
    }
    Ok(trimmed)
}

/// Placeholder for the browser-based OAuth flow. v1: prompt the user to
/// paste the tokens out of the dashboard's "MCP setup" page. The actual
/// browser flow (start a localhost listener, open a URL, capture the
/// callback) is a follow-up — the dashboard endpoint that mints these
/// tokens does not yet exist.
fn browser_oauth(server_url: &str) -> anyhow::Result<(String, String)> {
    println!();
    println!(
        "Open this URL in your browser to mint MCP credentials (interactive flow coming soon):\n  {server_url}/settings/mcp"
    );
    println!("Then paste the two tokens shown on that page.");
    let access = prompt("user access token", None)?;
    let refresh = prompt("user refresh token", None)?;
    Ok((access, refresh))
}

/// Create a fresh agent identity via the REST API using the user token.
async fn create_agent_identity(
    server_url: &str,
    user_token: &str,
    name: &str,
) -> anyhow::Result<String> {
    // Reuse the same REST client the MCP server uses. Agent key is a
    // placeholder here — only the user token side is exercised for
    // identity creation.
    let client = OverslashClient::new(&McpConfig {
        server_url: server_url.to_string(),
        agent_key: String::new(),
        user_token: user_token.to_string(),
        user_refresh_token: None,
    })?;
    let body = serde_json::json!({ "kind": "agent", "name": name });
    let v = client
        .post(Cred::User, "/v1/identities", &body)
        .await
        .map_err(|e| anyhow::anyhow!("create agent failed: {e}"))?;
    let key = v
        .get("api_key")
        .and_then(|k| k.as_str())
        .ok_or_else(|| anyhow::anyhow!("response missing `api_key`: {v}"))?
        .to_string();
    println!("✓ Created agent `{name}` and captured its API key.");
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn create_agent_identity_surfaces_network_error() {
        // Unreachable port: OverslashClient returns a reqwest error, which
        // `create_agent_identity` wraps as "create agent failed: …".
        let err = create_agent_identity("http://127.0.0.1:1", "user_token", "claude-code")
            .await
            .expect_err("expected network error");
        let msg = format!("{err}");
        assert!(msg.contains("create agent failed"), "msg={msg}");
    }

    #[tokio::test]
    async fn create_agent_identity_rejects_response_without_api_key() {
        // Spin up a tiny one-shot server that returns a 200 with JSON that
        // lacks `api_key`. create_agent_identity must error rather than
        // silently succeeding with an empty string.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}", addr);
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let body = r#"{"id":"abc","kind":"agent"}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        let err = create_agent_identity(&url, "user_token", "claude-code")
            .await
            .expect_err("expected missing-api_key error");
        assert!(format!("{err}").contains("api_key"), "{err}");
    }

    #[test]
    fn re_auth_against_missing_config_errors_clearly() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let missing = std::env::temp_dir().join("overslash-mcp-nonexistent-xyzzy.json");
        let _ = std::fs::remove_file(&missing);
        let err = rt
            .block_on(run(missing.clone(), None, true))
            .expect_err("re-auth on missing config should error");
        let msg = format!("{err}");
        assert!(msg.contains("no existing config"), "msg={msg}");
        assert!(msg.contains("setup"), "msg={msg}");
    }
}
