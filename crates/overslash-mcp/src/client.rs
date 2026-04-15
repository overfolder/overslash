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
