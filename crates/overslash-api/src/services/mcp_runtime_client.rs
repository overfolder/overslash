//! Typed HTTP client for the `overslash-mcp-runtime` service. Mirrors the
//! TypeScript contract in `docker/mcp-runtime/src/contract.ts` — keep the
//! two in sync.
//!
//! Auth against the runtime:
//! - Dev: bearer shared secret (`MCP_RUNTIME_SHARED_SECRET`).
//! - Prod (Cloud Run, future): GCP ID token minted from the api's SA, with
//!   audience set to the runtime's URL. Not yet wired — tracked in Phase 7.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_core::types::McpLimits;

use crate::error::AppError;

#[derive(Debug, Clone)]
pub struct RuntimeClient {
    base_url: String,
    shared_secret: Option<String>,
    http: reqwest::Client,
}

impl RuntimeClient {
    pub fn new(base_url: String, shared_secret: Option<String>, http: reqwest::Client) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            shared_secret,
            http,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let mut b = self.http.request(method, self.url(path));
        if let Some(secret) = &self.shared_secret {
            b = b.header("Authorization", format!("Bearer {secret}"));
        }
        b
    }

    pub async fn invoke(&self, req: &InvokeRequest<'_>) -> Result<InvokeResponse, AppError> {
        let resp = self
            .request(reqwest::Method::POST, "/invoke")
            .json(req)
            .send()
            .await?;
        handle::<InvokeResponse>(resp).await
    }

    pub async fn ensure(&self, req: &EnsureRequest<'_>) -> Result<EnsureResponse, AppError> {
        let resp = self
            .request(reqwest::Method::POST, "/ensure")
            .json(req)
            .send()
            .await?;
        handle::<EnsureResponse>(resp).await
    }

    pub async fn shutdown(&self, service_instance_id: Uuid) -> Result<(), AppError> {
        let body = serde_json::json!({ "service_instance_id": service_instance_id });
        let resp = self
            .request(reqwest::Method::POST, "/shutdown")
            .json(&body)
            .send()
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(AppError::Internal(format!(
                "mcp runtime /shutdown returned {}",
                resp.status()
            )))
        }
    }

    pub async fn status(&self, service_instance_id: Uuid) -> Result<StatusResponse, AppError> {
        let path = format!("/status/{service_instance_id}");
        let resp = self.request(reqwest::Method::GET, &path).send().await?;
        handle::<StatusResponse>(resp).await
    }

    pub async fn logs(
        &self,
        service_instance_id: Uuid,
        lines: u32,
        levels: &[&str],
    ) -> Result<LogsResponse, AppError> {
        let path = format!(
            "/logs/{service_instance_id}?lines={lines}&level={}",
            levels.join(",")
        );
        let resp = self.request(reqwest::Method::GET, &path).send().await?;
        handle::<LogsResponse>(resp).await
    }
}

async fn handle<T: for<'de> Deserialize<'de>>(resp: reqwest::Response) -> Result<T, AppError> {
    let status = resp.status();
    let bytes = resp.bytes().await?;
    if status.is_success() {
        serde_json::from_slice::<T>(&bytes).map_err(AppError::from)
    } else {
        // Best-effort error message — fall back to raw bytes if JSON.
        let msg = serde_json::from_slice::<ErrorBody>(&bytes)
            .map(|e| e.error.message)
            .unwrap_or_else(|_| String::from_utf8_lossy(&bytes).into_owned());
        Err(AppError::Internal(format!(
            "mcp runtime error ({status}): {msg}"
        )))
    }
}

// ── wire types ───────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct EnsureRequest<'a> {
    pub service_instance_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<&'a [String]>,
    pub env: &'a HashMap<String, String>,
    pub env_hash: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<&'a McpLimits>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnsureResponse {
    pub state: String,
    pub pid: Option<u32>,
    pub since: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct InvokeRequest<'a> {
    pub service_instance_id: Uuid,
    pub tool: &'a str,
    pub arguments: &'a serde_json::Value,
    pub env: &'a HashMap<String, String>,
    pub env_hash: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<&'a [String]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<&'a McpLimits>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<&'a str>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InvokeResponse {
    pub result: serde_json::Value,
    pub warm: bool,
    pub duration_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub state: String,
    pub pid: Option<u32>,
    pub last_used: Option<String>,
    pub since: Option<String>,
    pub memory_mb: Option<u64>,
    pub env_hash: Option<String>,
    pub package: Option<String>,
    pub version: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogLine {
    pub ts: String,
    pub level: String,
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogsResponse {
    pub lines: Vec<LogLine>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Debug, Serialize, Deserialize)]
struct ErrorDetail {
    message: String,
}
