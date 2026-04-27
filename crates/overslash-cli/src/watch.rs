use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};
use serde::Deserialize;

use overslash_mcp::config::McpConfig;

pub async fn run(
    config_path: PathBuf,
    approval_id: String,
    timeout_str: String,
    poll_str: String,
) -> anyhow::Result<()> {
    let config = McpConfig::load(&config_path).with_context(|| {
        format!(
            "failed to load MCP config from {} — run `overslash mcp login` first",
            config_path.display()
        )
    })?;

    let timeout = parse_duration(&timeout_str)
        .with_context(|| format!("invalid --timeout value: {timeout_str:?}"))?;
    let poll_interval =
        parse_duration(&poll_str).with_context(|| format!("invalid --poll value: {poll_str:?}"))?;

    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        // Per-request timeout guards against a server that accepts the
        // connection but then hangs sending the response body, which would
        // otherwise bypass the user-facing --timeout flag entirely.
        .timeout(Duration::from_secs(30))
        .build()?;

    let url = format!(
        "{}/v1/approvals/{}",
        config.server_url.trim_end_matches('/'),
        approval_id
    );

    eprint_progress(format!(
        "Watching approval {}… (timeout: {})",
        &approval_id[..approval_id.len().min(8)],
        timeout_str
    ));
    eprint_progress(format!("  polling every {} — Ctrl+C to abort", poll_str));

    let code = match watch_inner(
        &client,
        &url,
        &config.token,
        &approval_id,
        timeout,
        poll_interval,
    )
    .await
    {
        Ok(WatchOutcome::Allowed(v)) => {
            if is_stderr_tty() {
                eprintln!();
            }
            println!("{}", serde_json::to_string(&v).unwrap());
            0
        }
        Ok(WatchOutcome::Terminal(v)) => {
            if is_stderr_tty() {
                eprintln!();
            }
            println!("{}", serde_json::to_string(&v).unwrap());
            1
        }
        Ok(WatchOutcome::TimedOut { id, elapsed_secs }) => {
            let out = serde_json::json!({
                "status": "timeout",
                "id": id,
                "elapsed_secs": elapsed_secs,
            });
            println!("{}", serde_json::to_string(&out).unwrap());
            1
        }
        Err(e) => {
            eprintln!("error: {e}");
            2
        }
    };
    std::process::exit(code);
}

#[derive(Debug, PartialEq)]
enum WatchOutcome {
    Allowed(serde_json::Value),
    Terminal(serde_json::Value),
    TimedOut { id: String, elapsed_secs: u64 },
}

async fn watch_inner(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    approval_id: &str,
    timeout: Duration,
    poll_interval: Duration,
) -> anyhow::Result<WatchOutcome> {
    let started = Instant::now();
    loop {
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            return Ok(WatchOutcome::TimedOut {
                id: approval_id.to_string(),
                elapsed_secs: elapsed.as_secs(),
            });
        }

        let resp = client
            .get(url)
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
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(anyhow!("approval {approval_id} not found"));
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("API returned {}: {}", status, body));
        }

        // Keep the raw JSON so stdout output is lossless (includes execution.result).
        let body_text = resp.text().await.context("read response body")?;
        let raw: serde_json::Value =
            serde_json::from_str(&body_text).context("parse approval JSON")?;
        let poll: ApprovalPoll =
            serde_json::from_str(&body_text).context("parse approval status")?;

        match poll.status.as_str() {
            "pending" => {
                if is_stderr_tty() {
                    eprint!("\r  still pending… ({}s elapsed)   ", elapsed.as_secs());
                }
                tokio::time::sleep(poll_interval).await;
            }
            "allowed" => return Ok(WatchOutcome::Allowed(raw)),
            _ => return Ok(WatchOutcome::Terminal(raw)),
        }
    }
}

#[derive(Deserialize)]
struct ApprovalPoll {
    status: String,
}

/// Parse a duration string with an optional suffix: s, m, h. Plain integer = seconds.
fn parse_duration(s: &str) -> anyhow::Result<Duration> {
    let s = s.trim();
    let (digits, multiplier) = if let Some(rest) = s.strip_suffix('h') {
        (rest, 3600u64)
    } else if let Some(rest) = s.strip_suffix('m') {
        (rest, 60u64)
    } else if let Some(rest) = s.strip_suffix('s') {
        (rest, 1u64)
    } else {
        (s, 1u64)
    };
    let n: u64 = digits
        .parse()
        .map_err(|_| anyhow!("expected a number, got {digits:?}"))?;
    if n == 0 {
        return Err(anyhow!("duration must be greater than zero"));
    }
    Ok(Duration::from_secs(n * multiplier))
}

fn eprint_progress(msg: String) {
    eprintln!("{msg}");
}

fn is_stderr_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stderr().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::Router;
    use axum::routing::get;
    use tokio::net::TcpListener;

    // ---------------------------------------------------------------------------
    // parse_duration
    // ---------------------------------------------------------------------------

    #[test]
    fn parse_duration_seconds_suffix() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn parse_duration_minutes_suffix() {
        assert_eq!(parse_duration("15m").unwrap(), Duration::from_secs(900));
    }

    #[test]
    fn parse_duration_hours_suffix() {
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
    }

    #[test]
    fn parse_duration_plain_integer_is_seconds() {
        assert_eq!(parse_duration("60").unwrap(), Duration::from_secs(60));
    }

    #[test]
    fn parse_duration_trims_whitespace() {
        assert_eq!(parse_duration("  5m  ").unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn parse_duration_zero_is_error() {
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("0").is_err());
    }

    #[test]
    fn parse_duration_non_numeric_is_error() {
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("1x").is_err());
        assert!(parse_duration("").is_err());
    }

    // ---------------------------------------------------------------------------
    // watch_inner — mock HTTP server helpers
    // ---------------------------------------------------------------------------

    fn test_client() -> reqwest::Client {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
    }

    /// Spin up a local axum server that always responds with `body` and return
    /// the URL for `/v1/approvals/test-id`.
    async fn serve_static(body: serde_json::Value) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/v1/approvals/test-id",
            get(move || {
                let b = body.clone();
                async move { axum::Json(b) }
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        format!("http://{addr}/v1/approvals/test-id")
    }

    /// Spin up a server that returns `pending` for the first `pending_count`
    /// requests, then returns `final_body`.
    async fn serve_pending_then(pending_count: usize, final_body: serde_json::Value) -> String {
        use std::sync::{Arc, Mutex};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let counter = Arc::new(Mutex::new(0usize));
        let final_body = Arc::new(final_body);
        let app = Router::new().route(
            "/v1/approvals/test-id",
            get(move || {
                let counter = counter.clone();
                let final_body = final_body.clone();
                async move {
                    let mut c = counter.lock().unwrap();
                    let n = *c;
                    *c += 1;
                    drop(c);
                    if n < pending_count {
                        axum::Json(serde_json::json!({"status": "pending", "id": "test-id"}))
                    } else {
                        axum::Json((*final_body).clone())
                    }
                }
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        format!("http://{addr}/v1/approvals/test-id")
    }

    /// Spin up a server that returns the given HTTP status code (no JSON body).
    async fn serve_status(http_status: u16) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/v1/approvals/test-id",
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
        format!("http://{addr}/v1/approvals/test-id")
    }

    // ---------------------------------------------------------------------------
    // watch_inner — happy-path tests
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn watch_inner_allowed_resolves_immediately() {
        let body =
            serde_json::json!({"status": "allowed", "id": "test-id", "action_summary": "do thing"});
        let url = serve_static(body.clone()).await;
        let client = test_client();
        let outcome = watch_inner(
            &client,
            &url,
            "tok",
            "test-id",
            Duration::from_secs(60),
            Duration::from_millis(10),
        )
        .await
        .unwrap();
        assert!(matches!(outcome, WatchOutcome::Allowed(_)));
        if let WatchOutcome::Allowed(v) = outcome {
            assert_eq!(v["status"], "allowed");
        }
    }

    #[tokio::test]
    async fn watch_inner_denied_returns_terminal() {
        let body = serde_json::json!({"status": "denied", "id": "test-id"});
        let url = serve_static(body).await;
        let client = test_client();
        let outcome = watch_inner(
            &client,
            &url,
            "tok",
            "test-id",
            Duration::from_secs(60),
            Duration::from_millis(10),
        )
        .await
        .unwrap();
        assert!(matches!(outcome, WatchOutcome::Terminal(_)));
    }

    #[tokio::test]
    async fn watch_inner_expired_returns_terminal() {
        let body = serde_json::json!({"status": "expired", "id": "test-id"});
        let url = serve_static(body).await;
        let client = test_client();
        let outcome = watch_inner(
            &client,
            &url,
            "tok",
            "test-id",
            Duration::from_secs(60),
            Duration::from_millis(10),
        )
        .await
        .unwrap();
        assert!(matches!(outcome, WatchOutcome::Terminal(_)));
    }

    #[tokio::test]
    async fn watch_inner_polls_through_pending_then_allowed() {
        let final_body = serde_json::json!({"status": "allowed", "id": "test-id"});
        let url = serve_pending_then(2, final_body).await;
        let client = test_client();
        let outcome = watch_inner(
            &client,
            &url,
            "tok",
            "test-id",
            Duration::from_secs(60),
            Duration::from_millis(10),
        )
        .await
        .unwrap();
        assert!(matches!(outcome, WatchOutcome::Allowed(_)));
    }

    #[tokio::test]
    async fn watch_inner_timeout_when_always_pending() {
        let url = serve_static(serde_json::json!({"status": "pending", "id": "test-id"})).await;
        let client = test_client();
        let outcome = watch_inner(
            &client,
            &url,
            "tok",
            "test-id",
            Duration::from_millis(50), // very short timeout
            Duration::from_millis(10),
        )
        .await
        .unwrap();
        assert!(matches!(outcome, WatchOutcome::TimedOut { .. }));
        if let WatchOutcome::TimedOut { id, .. } = outcome {
            assert_eq!(id, "test-id");
        }
    }

    // ---------------------------------------------------------------------------
    // watch_inner — HTTP error path tests
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn watch_inner_401_returns_err() {
        let url = serve_status(401).await;
        let client = test_client();
        let err = watch_inner(
            &client,
            &url,
            "bad-tok",
            "test-id",
            Duration::from_secs(60),
            Duration::from_millis(10),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("token expired"));
    }

    #[tokio::test]
    async fn watch_inner_404_returns_err() {
        let url = serve_status(404).await;
        let client = test_client();
        let err = watch_inner(
            &client,
            &url,
            "tok",
            "test-id",
            Duration::from_secs(60),
            Duration::from_millis(10),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[tokio::test]
    async fn watch_inner_500_returns_err() {
        let url = serve_status(500).await;
        let client = test_client();
        let err = watch_inner(
            &client,
            &url,
            "tok",
            "test-id",
            Duration::from_secs(60),
            Duration::from_millis(10),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("500"));
    }
}
