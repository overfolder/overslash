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

/// Create a fresh agent identity via the REST API using the user token,
/// then mint and return an API key bound to that new identity.
///
/// The REST API requires three calls because:
///   1. `POST /v1/identities` for `kind=agent` requires a `parent_id` —
///      the calling user's identity. We discover it via `GET /v1/whoami`
///      (Bearer-friendly; `/auth/me*` is cookie-only).
///   2. `POST /v1/identities` returns the identity row, **without** an
///      API key — keys are minted by `POST /v1/api-keys`.
async fn create_agent_identity(
    server_url: &str,
    user_token: &str,
    name: &str,
) -> anyhow::Result<String> {
    // Reuse the same REST client the MCP server uses. Agent key is a
    // placeholder here — only the user token side is exercised.
    let client = OverslashClient::new(&McpConfig {
        server_url: server_url.to_string(),
        agent_key: String::new(),
        user_token: user_token.to_string(),
        user_refresh_token: None,
    })?;

    // 1. whoami → caller's identity_id + org_id (we'll pass the identity_id
    //    as parent_id, and need org_id for the api-keys POST body).
    let me = client
        .get(Cred::User, "/v1/whoami")
        .await
        .map_err(|e| anyhow::anyhow!("whoami failed: {e}"))?;
    let parent_id = me
        .get("identity_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("whoami response missing `identity_id`: {me}"))?
        .to_string();
    let org_id = me
        .get("org_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("whoami response missing `org_id`: {me}"))?
        .to_string();

    // 2. Create the agent under the calling user.
    let identity_body = serde_json::json!({
        "kind": "agent",
        "name": name,
        "parent_id": parent_id,
    });
    let identity = client
        .post(Cred::User, "/v1/identities", &identity_body)
        .await
        .map_err(|e| anyhow::anyhow!("create agent failed: {e}"))?;
    let agent_id = identity
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("create-agent response missing `id`: {identity}"))?
        .to_string();

    // 3. Mint an API key bound to the new agent identity.
    let key_body = serde_json::json!({
        "org_id": org_id,
        "identity_id": agent_id,
        "name": format!("{name} (mcp)"),
    });
    let key_resp = client
        .post(Cred::User, "/v1/api-keys", &key_body)
        .await
        .map_err(|e| anyhow::anyhow!("mint api-key failed: {e}"))?;
    let key = key_resp
        .get("key")
        .and_then(|k| k.as_str())
        .ok_or_else(|| anyhow::anyhow!("api-key response missing `key`: {key_resp}"))?
        .to_string();
    println!("✓ Created agent `{name}` and minted its API key.");
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn create_agent_identity_surfaces_network_error() {
        // Unreachable port: OverslashClient returns a reqwest error on the
        // very first call (whoami), wrapped as "whoami failed: …".
        let err = create_agent_identity("http://127.0.0.1:1", "user_token", "claude-code")
            .await
            .expect_err("expected network error");
        let msg = format!("{err}");
        assert!(msg.contains("whoami failed"), "msg={msg}");
    }

    /// Spawn a minimal HTTP server that serves a fixed list of canned
    /// responses, one per incoming connection, in order. Each response is
    /// `(status_line, json_body)`. Any extra requests get a 500.
    async fn spawn_canned_server(responses: Vec<(&'static str, String)>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            for (status_line, body) in responses {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = [0u8; 8192];
                let _ = sock.read(&mut buf).await;
                let resp = format!(
                    "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn create_agent_identity_returns_api_key_on_happy_path() {
        // Three canned responses for whoami → POST /v1/identities → POST /v1/api-keys.
        let url = spawn_canned_server(vec![
            (
                "HTTP/1.1 200 OK",
                r#"{"identity_id":"11111111-1111-1111-1111-111111111111","org_id":"22222222-2222-2222-2222-222222222222","kind":"user","name":"alice","parent_id":null,"owner_id":null}"#.into(),
            ),
            (
                "HTTP/1.1 200 OK",
                r#"{"id":"33333333-3333-3333-3333-333333333333","kind":"agent","name":"claude-code"}"#.into(),
            ),
            (
                "HTTP/1.1 200 OK",
                r#"{"id":"44444444-4444-4444-4444-444444444444","key":"osk_deadbeef","key_prefix":"osk_deadbee","name":"claude-code (mcp)"}"#.into(),
            ),
        ])
        .await;
        let key = create_agent_identity(&url, "user_token", "claude-code")
            .await
            .expect("happy path should yield an api key");
        assert_eq!(key, "osk_deadbeef");
    }

    #[tokio::test]
    async fn create_agent_identity_errors_when_whoami_lacks_identity_id() {
        // whoami returns JSON missing `identity_id` — must not silently proceed.
        let url = spawn_canned_server(vec![("HTTP/1.1 200 OK", r#"{"org_id":"x"}"#.into())]).await;
        let err = create_agent_identity(&url, "user_token", "claude-code")
            .await
            .expect_err("expected missing-identity_id error");
        assert!(format!("{err}").contains("identity_id"), "{err}");
    }

    #[tokio::test]
    async fn create_agent_identity_errors_when_api_key_response_lacks_key() {
        // whoami + create-identity both succeed, but the api-key response is
        // missing `key`. Must error rather than return an empty string.
        let url = spawn_canned_server(vec![
            (
                "HTTP/1.1 200 OK",
                r#"{"identity_id":"11111111-1111-1111-1111-111111111111","org_id":"22222222-2222-2222-2222-222222222222"}"#.into(),
            ),
            (
                "HTTP/1.1 200 OK",
                r#"{"id":"33333333-3333-3333-3333-333333333333"}"#.into(),
            ),
            ("HTTP/1.1 200 OK", r#"{"id":"abc"}"#.into()),
        ])
        .await;
        let err = create_agent_identity(&url, "user_token", "claude-code")
            .await
            .expect_err("expected missing-key error");
        assert!(format!("{err}").contains("`key`"), "{err}");
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
