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
    match list_inner(&client, &config.server_url, &config.token).await {
        Ok(body) => {
            println!("{body}");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    }
}

pub async fn call(config_path: PathBuf, args: CallArgs) -> anyhow::Result<()> {
    let config = McpConfig::load(&config_path).with_context(|| {
        format!(
            "failed to load MCP config from {} — run `overslash mcp login` first",
            config_path.display()
        )
    })?;
    let client = build_client()?;
    let req_body = build_request_body(&args);
    match call_inner(&client, &config.server_url, &config.token, &req_body).await {
        Ok(CallOutcome::Called(body)) => {
            println!("{body}");
            std::process::exit(0);
        }
        Ok(CallOutcome::PendingApproval {
            approval_id,
            approval_url,
            body,
        }) => {
            if let (Some(id), Some(url)) = (&approval_id, &approval_url) {
                eprintln!(
                    "pending approval — id: {id}\n  review at: {url}\n  run: overslash watch {id}"
                );
            }
            println!("{body}");
            std::process::exit(0);
        }
        Ok(CallOutcome::Denied(body)) => {
            println!("{body}");
            std::process::exit(1);
        }
        Ok(CallOutcome::Unknown { status, body }) => {
            eprintln!("error: unexpected status {status:?}");
            println!("{body}");
            std::process::exit(2);
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    }
}

// ---------------------------------------------------------------------------
// Inner functions — tested directly with mock servers
// ---------------------------------------------------------------------------

async fn list_inner(
    client: &reqwest::Client,
    base_url: &str,
    token: &str,
) -> anyhow::Result<String> {
    let url = format!("{}/v1/services", base_url.trim_end_matches('/'));
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;

    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(anyhow!(
            "token expired or invalid — run `overslash mcp login`"
        ));
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow!("API returned {}: {}", status, body));
    }
    resp.text().await.context("read response body")
}

#[derive(Debug, PartialEq)]
enum CallOutcome {
    Called(String),
    PendingApproval {
        approval_id: Option<String>,
        approval_url: Option<String>,
        body: String,
    },
    Denied(String),
    Unknown {
        status: String,
        body: String,
    },
}

async fn call_inner(
    client: &reqwest::Client,
    base_url: &str,
    token: &str,
    req_body: &serde_json::Map<String, serde_json::Value>,
) -> anyhow::Result<CallOutcome> {
    let url = format!("{}/v1/actions/call", base_url.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {token}"))
        .json(req_body)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;

    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(anyhow!(
            "token expired or invalid — run `overslash mcp login`"
        ));
    }
    // 403 FORBIDDEN carries a {"status":"denied",...} body — fall through to
    // the status-dispatch below rather than treating it as a generic error.
    if !status.is_success()
        && status != reqwest::StatusCode::ACCEPTED
        && status != reqwest::StatusCode::FORBIDDEN
    {
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow!("API returned {}: {}", status, body));
    }

    let body_text = resp.text().await.context("read response body")?;
    // If a proxy/WAF returns a non-JSON 403, surface the status + raw body
    // rather than a confusing "parse call response" JSON error.
    let poll: CallStatusPoll = match serde_json::from_str(&body_text) {
        Ok(p) => p,
        Err(_) if status == reqwest::StatusCode::FORBIDDEN => {
            return Err(anyhow!("403 Forbidden: {}", body_text.trim()));
        }
        Err(e) => return Err(e.into()),
    };

    Ok(match poll.status.as_str() {
        "called" => CallOutcome::Called(body_text),
        "pending_approval" => CallOutcome::PendingApproval {
            approval_id: poll.approval_id,
            approval_url: poll.approval_url,
            body: body_text,
        },
        "denied" => CallOutcome::Denied(body_text),
        _ => CallOutcome::Unknown {
            status: poll.status,
            body: body_text,
        },
    })
}

fn build_request_body(args: &CallArgs) -> serde_json::Map<String, serde_json::Value> {
    let mut m = serde_json::Map::new();
    if let Some(v) = &args.service {
        m.insert("service".into(), serde_json::Value::String(v.clone()));
    }
    if let Some(v) = &args.action {
        m.insert("action".into(), serde_json::Value::String(v.clone()));
    }
    if !args.params.is_empty() {
        let params: serde_json::Map<String, serde_json::Value> =
            args.params.iter().cloned().collect();
        m.insert("params".into(), serde_json::Value::Object(params));
    }
    if let Some(v) = &args.url {
        m.insert("url".into(), serde_json::Value::String(v.clone()));
    }
    if let Some(v) = &args.method {
        m.insert("method".into(), serde_json::Value::String(v.clone()));
    }
    if !args.headers.is_empty() {
        let headers: serde_json::Map<String, serde_json::Value> = args
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect();
        m.insert("headers".into(), serde_json::Value::Object(headers));
    }
    if let Some(v) = &args.body {
        m.insert("body".into(), serde_json::Value::String(v.clone()));
    }
    if let Some(expr) = &args.filter {
        m.insert(
            "filter".into(),
            serde_json::json!({ "lang": "jq", "expr": expr }),
        );
    }
    m
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

    use axum::Router;
    use axum::routing::{get, post};
    use tokio::net::TcpListener;

    // ---------------------------------------------------------------------------
    // parse_param / parse_header unit tests
    // ---------------------------------------------------------------------------

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
    // build_request_body unit tests
    // ---------------------------------------------------------------------------

    #[test]
    fn build_request_body_mode_c() {
        let args = CallArgs {
            service: Some("github".into()),
            action: Some("list_repos".into()),
            params: vec![("org".into(), serde_json::json!("acme"))],
            url: None,
            method: None,
            headers: vec![],
            body: None,
            filter: None,
        };
        let m = build_request_body(&args);
        assert_eq!(m["service"], "github");
        assert_eq!(m["action"], "list_repos");
        assert_eq!(m["params"]["org"], "acme");
        assert!(!m.contains_key("url"));
    }

    #[test]
    fn build_request_body_mode_a() {
        let args = CallArgs {
            service: None,
            action: None,
            params: vec![],
            url: Some("https://api.example.com/v1".into()),
            method: Some("POST".into()),
            headers: vec![("X-Key".into(), "val".into())],
            body: Some(r#"{"foo":1}"#.into()),
            filter: Some(".data".into()),
        };
        let m = build_request_body(&args);
        assert_eq!(m["url"], "https://api.example.com/v1");
        assert_eq!(m["method"], "POST");
        assert_eq!(m["headers"]["X-Key"], "val");
        assert_eq!(m["body"], r#"{"foo":1}"#);
        assert_eq!(m["filter"]["lang"], "jq");
        assert_eq!(m["filter"]["expr"], ".data");
    }

    // ---------------------------------------------------------------------------
    // Mock server helpers
    // ---------------------------------------------------------------------------

    fn test_client() -> reqwest::Client {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
    }

    async fn serve_get_json(path: &'static str, body: serde_json::Value) -> String {
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

    async fn serve_get_status(path: &'static str, http_status: u16) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            path,
            get(move || async move {
                axum::http::Response::builder()
                    .status(http_status)
                    .body(axum::body::Body::empty())
                    .unwrap()
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        format!("http://{addr}")
    }

    async fn serve_post_status(path: &'static str, http_status: u16) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            path,
            post(move || async move {
                axum::http::Response::builder()
                    .status(http_status)
                    .body(axum::body::Body::empty())
                    .unwrap()
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        format!("http://{addr}")
    }

    // ---------------------------------------------------------------------------
    // list_inner tests
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn list_inner_returns_body_on_success() {
        let body = serde_json::json!([{"id": "abc", "name": "github", "status": "active"}]);
        let base_url = serve_get_json("/v1/services", body.clone()).await;
        let client = test_client();
        let result = list_inner(&client, &base_url, "tok").await.unwrap();
        let got: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(got, body);
    }

    #[tokio::test]
    async fn list_inner_401_returns_err() {
        let base_url = serve_get_status("/v1/services", 401).await;
        let client = test_client();
        let err = list_inner(&client, &base_url, "bad-tok").await.unwrap_err();
        assert!(err.to_string().contains("token expired"));
    }

    #[tokio::test]
    async fn list_inner_500_returns_err() {
        let base_url = serve_get_status("/v1/services", 500).await;
        let client = test_client();
        let err = list_inner(&client, &base_url, "tok").await.unwrap_err();
        assert!(err.to_string().contains("500"));
    }

    // ---------------------------------------------------------------------------
    // call_inner tests
    // ---------------------------------------------------------------------------

    fn empty_body() -> serde_json::Map<String, serde_json::Value> {
        serde_json::Map::new()
    }

    #[tokio::test]
    async fn call_inner_called_returns_called_outcome() {
        let resp = serde_json::json!({
            "status": "called",
            "result": {"status_code": 200, "body": "ok", "headers": {}, "duration_ms": 5}
        });
        let base_url = serve_post_json("/v1/actions/call", resp).await;
        let client = test_client();
        let outcome = call_inner(&client, &base_url, "tok", &empty_body())
            .await
            .unwrap();
        assert!(matches!(outcome, CallOutcome::Called(_)));
    }

    #[tokio::test]
    async fn call_inner_pending_approval_returns_pending_outcome() {
        let resp = serde_json::json!({
            "status": "pending_approval",
            "approval_id": "appr-123",
            "approval_url": "https://x.y/approvals/appr-123",
            "action_description": "delete repo",
            "expires_at": "2099-01-01T00:00:00Z"
        });
        let base_url = serve_post_json("/v1/actions/call", resp).await;
        let client = test_client();
        let outcome = call_inner(&client, &base_url, "tok", &empty_body())
            .await
            .unwrap();
        if let CallOutcome::PendingApproval {
            approval_id,
            approval_url,
            ..
        } = outcome
        {
            assert_eq!(approval_id.as_deref(), Some("appr-123"));
            assert!(approval_url.is_some());
        } else {
            panic!("expected PendingApproval, got {outcome:?}");
        }
    }

    #[tokio::test]
    async fn call_inner_denied_200_returns_denied_outcome() {
        let resp = serde_json::json!({"status": "denied", "reason": "no permission"});
        let base_url = serve_post_json("/v1/actions/call", resp).await;
        let client = test_client();
        let outcome = call_inner(&client, &base_url, "tok", &empty_body())
            .await
            .unwrap();
        assert!(matches!(outcome, CallOutcome::Denied(_)));
    }

    #[tokio::test]
    async fn call_inner_denied_403_returns_denied_outcome() {
        let resp = serde_json::json!({"status": "denied", "reason": "insufficient permissions"});
        let base_url = serve_post_status_json("/v1/actions/call", 403, resp).await;
        let client = test_client();
        let outcome = call_inner(&client, &base_url, "tok", &empty_body())
            .await
            .unwrap();
        assert!(matches!(outcome, CallOutcome::Denied(_)));
    }

    #[tokio::test]
    async fn call_inner_403_non_json_returns_clear_forbidden_err() {
        // Proxies and WAFs can return 403 with HTML/plain-text bodies.
        // Verify the error message names the 403 status rather than "parse
        // call response".
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/v1/actions/call",
            post(|| async {
                (
                    StatusCode::FORBIDDEN,
                    axum::http::header::HeaderMap::new(),
                    "<html>403 Forbidden</html>",
                )
                    .into_response()
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        let base_url = format!("http://{addr}");
        let client = test_client();
        let err = call_inner(&client, &base_url, "tok", &empty_body())
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("403"), "expected 403 in error, got: {msg}");
        assert!(
            !msg.contains("parse call response"),
            "should not leak parse error: {msg}"
        );
    }

    #[tokio::test]
    async fn call_inner_401_returns_err() {
        let base_url = serve_post_status("/v1/actions/call", 401).await;
        let client = test_client();
        let err = call_inner(&client, &base_url, "bad-tok", &empty_body())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("token expired"));
    }

    #[tokio::test]
    async fn call_inner_500_returns_err() {
        let base_url = serve_post_status("/v1/actions/call", 500).await;
        let client = test_client();
        let err = call_inner(&client, &base_url, "tok", &empty_body())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("500"));
    }
}
