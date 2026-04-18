use reqwest::{Client, StatusCode};
use serde::Deserialize;

/// HTTP client for the MCP shim. Holds a single bearer token and talks to
/// `POST /mcp` for JSON-RPC frames and `POST /oauth/token` for refresh.
#[derive(Clone)]
pub struct OverslashClient {
    http: Client,
    base_url: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("API returned {status}: {body}")]
    Api { status: StatusCode, body: String },
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
}

impl OverslashClient {
    pub fn new(base_url: &str) -> anyhow::Result<Self> {
        let http = Client::builder()
            .user_agent(concat!("overslash-mcp/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
        })
    }

    /// Forward a JSON-RPC frame to `POST {base}/mcp`. The body is the raw
    /// frame bytes (so we don't re-serialize and potentially re-order
    /// fields). Returns the HTTP status and response body.
    pub async fn mcp_call(
        &self,
        token: &str,
        body: &[u8],
    ) -> Result<(StatusCode, Vec<u8>), ClientError> {
        let resp = self
            .http
            .post(format!("{}/mcp", self.base_url))
            .bearer_auth(token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_vec())
            .send()
            .await?;
        let status = resp.status();
        let bytes = resp.bytes().await?.to_vec();
        Ok((status, bytes))
    }

    /// Exchange a refresh token for a fresh access + refresh pair via
    /// `POST {base}/oauth/token`. Per RFC 6749 the body is
    /// form-url-encoded, and per OAuth 2.1 BCP each refresh is single-use
    /// so the returned refresh_token must replace the old one.
    pub async fn oauth_refresh(&self, refresh_token: &str) -> Result<TokenPair, ClientError> {
        let resp = self
            .http
            .post(format!("{}/oauth/token", self.base_url))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
            ])
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(ClientError::Api { status, body: text });
        }
        Ok(serde_json::from_str::<TokenPair>(&text)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_trims_trailing_slash() {
        let c = OverslashClient::new("https://api.example.com/").unwrap();
        assert_eq!(c.base_url, "https://api.example.com");
    }

    #[test]
    fn token_pair_deserializes_minimal() {
        let v: TokenPair = serde_json::from_str(r#"{"access_token":"a"}"#).unwrap();
        assert_eq!(v.access_token, "a");
        assert!(v.refresh_token.is_none());
    }

    #[test]
    fn token_pair_deserializes_full() {
        let v: TokenPair = serde_json::from_str(
            r#"{"access_token":"a","refresh_token":"r","expires_in":3600,"token_type":"Bearer"}"#,
        )
        .unwrap();
        assert_eq!(v.access_token, "a");
        assert_eq!(v.refresh_token.as_deref(), Some("r"));
        assert_eq!(v.expires_in, Some(3600));
    }

    #[tokio::test]
    async fn mcp_call_returns_http_error_for_unreachable_host() {
        let c = OverslashClient::new("http://127.0.0.1:1").unwrap();
        let err = c.mcp_call("t", b"{}").await.unwrap_err();
        assert!(matches!(err, ClientError::Http(_)), "{err:?}");
    }
}
