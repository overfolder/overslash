use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, anyhow};
use serde::Deserialize;

use overslash_mcp::config::McpConfig;

pub struct CallArgs {
    pub service: Option<String>,
    pub action: Option<String>,
    pub params: Vec<(String, serde_json::Value)>,
    pub url: Option<String>,
    pub method: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub filter: Option<String>,
}

pub async fn list(config_path: PathBuf) -> anyhow::Result<()> {
    let config = McpConfig::load(&config_path).with_context(|| {
        format!(
            "failed to load MCP config from {} — run `overslash mcp login` first",
            config_path.display()
        )
    })?;

    let client = build_client()?;
    let url = format!("{}/v1/services", config.server_url.trim_end_matches('/'));

    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", config.token))
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;

    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        eprintln!("error: token expired or invalid — run `overslash mcp login`");
        std::process::exit(2);
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        eprintln!("error: API returned {}: {}", status, body);
        std::process::exit(2);
    }

    let body_text = resp.text().await.context("read response body")?;
    println!("{body_text}");
    std::process::exit(0);
}

pub async fn call(config_path: PathBuf, args: CallArgs) -> anyhow::Result<()> {
    let config = McpConfig::load(&config_path).with_context(|| {
        format!(
            "failed to load MCP config from {} — run `overslash mcp login` first",
            config_path.display()
        )
    })?;

    let client = build_client()?;
    let url = format!(
        "{}/v1/actions/call",
        config.server_url.trim_end_matches('/')
    );

    let mut req_body = serde_json::Map::new();

    if let Some(service) = &args.service {
        req_body.insert("service".into(), serde_json::Value::String(service.clone()));
    }
    if let Some(action) = &args.action {
        req_body.insert("action".into(), serde_json::Value::String(action.clone()));
    }
    if !args.params.is_empty() {
        let params: serde_json::Map<String, serde_json::Value> = args.params.into_iter().collect();
        req_body.insert("params".into(), serde_json::Value::Object(params));
    }
    if let Some(url_val) = &args.url {
        req_body.insert("url".into(), serde_json::Value::String(url_val.clone()));
    }
    if let Some(method) = &args.method {
        req_body.insert("method".into(), serde_json::Value::String(method.clone()));
    }
    if !args.headers.is_empty() {
        let headers: serde_json::Map<String, serde_json::Value> = args
            .headers
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        req_body.insert("headers".into(), serde_json::Value::Object(headers));
    }
    if let Some(body) = &args.body {
        req_body.insert("body".into(), serde_json::Value::String(body.clone()));
    }
    if let Some(expr) = &args.filter {
        req_body.insert(
            "filter".into(),
            serde_json::json!({ "lang": "jq", "expr": expr }),
        );
    }

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", config.token))
        .json(&req_body)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;

    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        eprintln!("error: token expired or invalid — run `overslash mcp login`");
        std::process::exit(2);
    }
    // 403 FORBIDDEN carries a {"status":"denied",...} body — fall through to
    // the status-dispatch below rather than treating it as a generic error.
    if !status.is_success()
        && status != reqwest::StatusCode::ACCEPTED
        && status != reqwest::StatusCode::FORBIDDEN
    {
        let body = resp.text().await.unwrap_or_default();
        eprintln!("error: API returned {}: {}", status, body);
        std::process::exit(2);
    }

    let body_text = resp.text().await.context("read response body")?;
    let poll: CallStatusPoll = serde_json::from_str(&body_text).context("parse call response")?;

    match poll.status.as_str() {
        "called" => {
            println!("{body_text}");
            std::process::exit(0);
        }
        "pending_approval" => {
            if let Some(approval_id) = &poll.approval_id {
                if let Some(approval_url) = &poll.approval_url {
                    eprintln!(
                        "pending approval — id: {approval_id}\n  review at: {approval_url}\n  run: overslash watch {approval_id}"
                    );
                }
            }
            println!("{body_text}");
            std::process::exit(0);
        }
        "denied" => {
            println!("{body_text}");
            std::process::exit(1);
        }
        other => {
            eprintln!("error: unexpected status {other:?}");
            println!("{body_text}");
            std::process::exit(2);
        }
    }
}

/// Parse `key=value`. Value is JSON-parsed; falls back to a plain string.
pub fn parse_param(s: &str) -> anyhow::Result<(String, serde_json::Value)> {
    let (key, val_str) = s
        .split_once('=')
        .ok_or_else(|| anyhow!("--param must be key=value, got {s:?}"))?;
    let val = serde_json::from_str(val_str)
        .unwrap_or_else(|_| serde_json::Value::String(val_str.to_string()));
    Ok((key.to_string(), val))
}

/// Parse `key:value` (header).
pub fn parse_header(s: &str) -> anyhow::Result<(String, String)> {
    let (key, val) = s
        .split_once(':')
        .ok_or_else(|| anyhow!("--header must be key:value, got {s:?}"))?;
    Ok((key.trim().to_string(), val.trim().to_string()))
}

#[derive(Deserialize)]
struct CallStatusPoll {
    status: String,
    approval_id: Option<String>,
    approval_url: Option<String>,
}

fn build_client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_param_plain_string() {
        let (k, v) = parse_param("name=alice").unwrap();
        assert_eq!(k, "name");
        assert_eq!(v, serde_json::Value::String("alice".into()));
    }

    #[test]
    fn parse_param_json_number() {
        let (k, v) = parse_param("count=5").unwrap();
        assert_eq!(k, "count");
        assert_eq!(v, serde_json::json!(5));
    }

    #[test]
    fn parse_param_json_bool() {
        let (k, v) = parse_param("active=true").unwrap();
        assert_eq!(k, "active");
        assert_eq!(v, serde_json::json!(true));
    }

    #[test]
    fn parse_param_json_object() {
        let (k, v) = parse_param(r#"opts={"a":1}"#).unwrap();
        assert_eq!(k, "opts");
        assert_eq!(v, serde_json::json!({"a": 1}));
    }

    #[test]
    fn parse_param_value_contains_equals() {
        let (k, v) = parse_param("url=https://example.com?a=b").unwrap();
        assert_eq!(k, "url");
        assert_eq!(
            v,
            serde_json::Value::String("https://example.com?a=b".into())
        );
    }

    #[test]
    fn parse_param_no_equals_is_error() {
        assert!(parse_param("noequalssign").is_err());
    }

    #[test]
    fn parse_header_trims_whitespace() {
        let (k, v) = parse_header("Content-Type: application/json").unwrap();
        assert_eq!(k, "Content-Type");
        assert_eq!(v, "application/json");
    }

    #[test]
    fn parse_header_no_colon_is_error() {
        assert!(parse_header("NoColonHere").is_err());
    }

    // ---------------------------------------------------------------------------
    // Integration-style tests with a mock HTTP server
    // ---------------------------------------------------------------------------

    use axum::Router;
    use axum::routing::{get, post};
    use tokio::net::TcpListener;

    fn test_config(server_url: String) -> overslash_mcp::config::McpConfig {
        overslash_mcp::config::McpConfig {
            server_url,
            token: "test-token".into(),
            refresh_token: None,
            client_id: None,
            redirect_uri: None,
        }
    }

    fn test_http_client() -> reqwest::Client {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
    }

    async fn serve_json(path: &'static str, body: serde_json::Value) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            path,
            get(move || {
                let b = body.clone();
                async move { axum::Json(b) }
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        format!("http://{addr}")
    }

    async fn serve_post_json(path: &'static str, body: serde_json::Value) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            path,
            post(move || {
                let b = body.clone();
                async move { axum::Json(b) }
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        format!("http://{addr}")
    }

    async fn serve_post_status_json(
        path: &'static str,
        http_status: u16,
        body: serde_json::Value,
    ) -> String {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            path,
            post(move || {
                let b = body.clone();
                async move {
                    (StatusCode::from_u16(http_status).unwrap(), axum::Json(b)).into_response()
                }
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn list_endpoint_fetches_services() {
        let body = serde_json::json!([{"id": "abc", "name": "github", "status": "active"}]);
        let base_url = serve_json("/v1/services", body.clone()).await;

        let config = test_config(base_url);
        let client = test_http_client();
        let url = format!("{}/v1/services", config.server_url.trim_end_matches('/'));
        let resp = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", config.token))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let got: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(got, body);
    }

    #[tokio::test]
    async fn call_endpoint_posts_and_returns_result() {
        let response_body = serde_json::json!({
            "status": "called",
            "result": { "status_code": 200, "body": "ok", "headers": {}, "duration_ms": 42 }
        });
        let base_url = serve_post_json("/v1/actions/call", response_body.clone()).await;

        let config = test_config(base_url);
        let client = test_http_client();
        let url = format!(
            "{}/v1/actions/call",
            config.server_url.trim_end_matches('/')
        );
        let resp = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", config.token))
            .json(&serde_json::json!({"service": "github", "action": "list_repos"}))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let got: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(got["status"], "called");
    }

    #[tokio::test]
    async fn call_403_denied_body_is_parseable_as_denied() {
        // The API returns 403 FORBIDDEN with {"status":"denied","reason":"..."}.
        // Verify that the response parses correctly as a CallStatusPoll with
        // status "denied" so the CLI can exit with code 1 rather than 2.
        let denied_body =
            serde_json::json!({"status": "denied", "reason": "insufficient permissions"});
        let base_url = serve_post_status_json("/v1/actions/call", 403, denied_body.clone()).await;

        let config = test_config(base_url);
        let client = test_http_client();
        let url = format!(
            "{}/v1/actions/call",
            config.server_url.trim_end_matches('/')
        );
        let resp = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", config.token))
            .json(&serde_json::json!({"service": "github", "action": "delete_repo"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
        let body_text = resp.text().await.unwrap();
        let poll: CallStatusPoll = serde_json::from_str(&body_text).unwrap();
        assert_eq!(poll.status, "denied");
    }
}
