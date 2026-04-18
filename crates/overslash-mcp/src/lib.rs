//! `overslash-mcp` — stdio↔HTTP shim for editors that drive MCP over stdio.
//!
//! The primary MCP surface is `POST /mcp` on the Overslash API. This shim
//! exists as a thin pipe for MCP clients that only speak stdio. It reads
//! JSON-RPC frames on stdin, forwards them to `POST {server}/mcp` with
//! `Authorization: Bearer <token>`, and writes the response back on stdout.
//!
//! On HTTP 401 from the server, if a refresh token is configured, the shim
//! refreshes once and retries the frame transparently. Otherwise it returns
//! a JSON-RPC error that editors typically surface as "re-authenticate".
//!
//! See [`docs/design/mcp-oauth-transport.md`](../../docs/design/mcp-oauth-transport.md).

use std::path::{Path, PathBuf};

use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub mod client;
pub mod config;

use crate::client::{ClientError, OverslashClient};
use crate::config::McpConfig;

/// Run the stdio↔HTTP shim against the config at `config_path`.
pub async fn serve_stdio(config_path: PathBuf) -> anyhow::Result<()> {
    let mut cfg = McpConfig::load(&config_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to load MCP config from {}: {e}\n\
             Run `overslash mcp login` first.",
            config_path.display()
        )
    })?;
    let client = OverslashClient::new(&cfg.server_url)?;
    tracing::info!(server = %cfg.server_url, "starting overslash MCP stdio shim");

    let stdin = BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();
    let mut lines = stdin.lines();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let response = proxy_frame(&client, &mut cfg, &config_path, line.as_bytes()).await;
        stdout.write_all(response.as_bytes()).await?;
        stdout.write_all(b"\n").await?;
        stdout.flush().await?;
    }
    Ok(())
}

/// Forward one frame to the server, refreshing once on 401 if possible.
/// Returns a JSON-RPC response body ready to write to stdout.
async fn proxy_frame(
    client: &OverslashClient,
    cfg: &mut McpConfig,
    config_path: &Path,
    body: &[u8],
) -> String {
    match client.mcp_call(&cfg.token, body).await {
        Ok((status, bytes)) if status.is_success() => String::from_utf8_lossy(&bytes).into_owned(),
        Ok((StatusCode::NO_CONTENT, _)) => String::new(),
        Ok((StatusCode::UNAUTHORIZED, _)) => {
            try_refresh_and_retry(client, cfg, config_path, body).await
        }
        Ok((status, bytes)) => rpc_error_frame(
            parse_id(body),
            -32000,
            format!(
                "server returned {status}: {}",
                String::from_utf8_lossy(&bytes)
            ),
        ),
        Err(ClientError::Http(e)) => {
            rpc_error_frame(parse_id(body), -32000, format!("transport error: {e}"))
        }
        Err(e) => rpc_error_frame(parse_id(body), -32000, format!("client error: {e}")),
    }
}

async fn try_refresh_and_retry(
    client: &OverslashClient,
    cfg: &mut McpConfig,
    config_path: &Path,
    body: &[u8],
) -> String {
    let Some(refresh) = cfg.refresh_token.clone() else {
        return rpc_error_frame(
            parse_id(body),
            -32001,
            "server returned 401 and no refresh_token is configured — run `overslash mcp login`",
        );
    };
    match client.oauth_refresh(&refresh).await {
        Ok(pair) => {
            cfg.token = pair.access_token;
            if let Some(r) = pair.refresh_token {
                cfg.refresh_token = Some(r);
            }
            if let Err(e) = cfg.save(config_path) {
                tracing::error!("failed to persist refreshed tokens: {e}");
            }
            match client.mcp_call(&cfg.token, body).await {
                Ok((status, bytes)) if status.is_success() => {
                    String::from_utf8_lossy(&bytes).into_owned()
                }
                Ok((status, bytes)) => rpc_error_frame(
                    parse_id(body),
                    -32000,
                    format!(
                        "retry after refresh failed {status}: {}",
                        String::from_utf8_lossy(&bytes)
                    ),
                ),
                Err(e) => rpc_error_frame(
                    parse_id(body),
                    -32000,
                    format!("retry after refresh error: {e}"),
                ),
            }
        }
        Err(e) => rpc_error_frame(
            parse_id(body),
            -32001,
            format!("refresh failed ({e}) — run `overslash mcp login`"),
        ),
    }
}

fn parse_id(body: &[u8]) -> Value {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("id").cloned())
        .unwrap_or(Value::Null)
}

fn rpc_error_frame(id: Value, code: i32, message: impl Into<String>) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message.into() }
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_id_extracts_numeric() {
        assert_eq!(parse_id(br#"{"id":5}"#), Value::from(5));
    }

    #[test]
    fn parse_id_extracts_string() {
        assert_eq!(parse_id(br#"{"id":"abc"}"#), Value::from("abc"));
    }

    #[test]
    fn parse_id_null_for_malformed() {
        assert_eq!(parse_id(b"garbage"), Value::Null);
    }

    #[test]
    fn rpc_error_frame_has_shape() {
        let s = rpc_error_frame(Value::from(1), -32000, "oops");
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 1);
        assert_eq!(v["error"]["code"], -32000);
        assert_eq!(v["error"]["message"], "oops");
    }
}
