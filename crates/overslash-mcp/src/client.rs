use reqwest::{Client, Method, StatusCode};
use serde::Serialize;
use serde_json::Value;

use crate::config::McpConfig;

/// Thin REST client that holds both an agent key and a user token and
/// dispatches requests with the appropriate credential.
#[derive(Clone)]
pub struct OverslashClient {
    http: Client,
    base_url: String,
    agent_key: String,
    user_token: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("API returned {status}: {body}")]
    Api { status: StatusCode, body: String },
    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Cred {
    Agent,
    User,
}

impl OverslashClient {
    pub fn new(cfg: &McpConfig) -> anyhow::Result<Self> {
        let http = Client::builder()
            .user_agent(concat!("overslash-mcp/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            http,
            base_url: cfg.server_url.trim_end_matches('/').to_string(),
            agent_key: cfg.agent_key.clone(),
            user_token: cfg.user_token.clone(),
        })
    }

    fn token(&self, cred: Cred) -> &str {
        match cred {
            Cred::Agent => &self.agent_key,
            Cred::User => &self.user_token,
        }
    }

    pub async fn request<B: Serialize>(
        &self,
        cred: Cred,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<Value, ClientError> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self
            .http
            .request(method, &url)
            .bearer_auth(self.token(cred));
        if let Some(b) = body {
            req = req.json(b);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(ClientError::Api { status, body: text });
        }
        if text.is_empty() {
            return Ok(Value::Null);
        }
        Ok(serde_json::from_str(&text).unwrap_or(Value::String(text)))
    }

    pub async fn get(&self, cred: Cred, path: &str) -> Result<Value, ClientError> {
        self.request::<()>(cred, Method::GET, path, None).await
    }

    pub async fn post<B: Serialize>(
        &self,
        cred: Cred,
        path: &str,
        body: &B,
    ) -> Result<Value, ClientError> {
        self.request(cred, Method::POST, path, Some(body)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(agent: &str, user: &str) -> McpConfig {
        McpConfig {
            server_url: "https://api.example.com/".into(),
            agent_key: agent.into(),
            user_token: user.into(),
            user_refresh_token: None,
        }
    }

    #[test]
    fn new_trims_trailing_slash_from_base_url() {
        let c = OverslashClient::new(&cfg("ak", "ut")).unwrap();
        assert_eq!(c.base_url, "https://api.example.com");
    }

    #[test]
    fn token_routes_by_credential() {
        let c = OverslashClient::new(&cfg("agent_k", "user_t")).unwrap();
        assert_eq!(c.token(Cred::Agent), "agent_k");
        assert_eq!(c.token(Cred::User), "user_t");
    }

    #[test]
    fn cred_is_copy_and_comparable() {
        let a = Cred::Agent;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(Cred::Agent, Cred::User);
    }

    #[tokio::test]
    async fn request_returns_http_error_for_unreachable_host() {
        let c = OverslashClient::new(&McpConfig {
            server_url: "http://127.0.0.1:1".into(),
            agent_key: "k".into(),
            user_token: "u".into(),
            user_refresh_token: None,
        })
        .unwrap();
        let err = c.get(Cred::Agent, "/anything").await.unwrap_err();
        assert!(matches!(err, ClientError::Http(_)), "{err:?}");
    }

    #[test]
    fn client_error_display_has_status_and_body() {
        let e = ClientError::Api {
            status: reqwest::StatusCode::BAD_REQUEST,
            body: "oops".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("400"));
        assert!(s.contains("oops"));
    }
}
