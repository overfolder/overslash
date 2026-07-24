//! `overslash inbox` and `overslash get-result` — the CLI half of the agent
//! polling inbox.
//!
//! These mirror the MCP `overslash` platform actions `get_events` and
//! `get_result` exactly, and share their classification logic via
//! [`overslash_api::services::inbox`], so a shell-driven harness and an
//! MCP-driven one see the same thing. See that module for why an inbox is
//! needed at all (short version: under `auto_call_on_approve` the gateway
//! replays an approved action in the background and nothing ever tells the
//! requester what it returned).

use std::path::PathBuf;

use anyhow::{Context, anyhow};
use serde_json::Value;

use overslash_api::services::inbox as inbox_events;

use crate::common::{api_client, is_stderr_tty, load_mcp_config, unauthorized_error};

/// `overslash inbox` — print the event feed as JSON to stdout.
///
/// Exit codes follow the `watch` convention: 0 = ok (whether or not the feed
/// is empty), 2 = error. There is deliberately no "1 = nothing pending": a
/// quiet inbox is a normal, successful outcome and scripting `until` loops
/// around it should not have to special-case that.
pub async fn events(config_path: PathBuf, quiet: bool) -> anyhow::Result<()> {
    let config = load_mcp_config(&config_path)?;
    let client = api_client()?;
    match events_inner(&client, &config.server_url, &config.token).await {
        Ok(events) => {
            if !quiet && is_stderr_tty() {
                eprintln!("{}", summarize(&events));
            }
            println!("{}", serde_json::to_string(&events).unwrap());
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    }
}

/// `overslash get-result <approval_id>` — print one execution's outcome.
///
/// Exit codes: 0 = executed, 1 = terminal-but-not-successful (failed,
/// cancelled, expired) or still in flight, 2 = error. The split lets
/// `overslash get-result "$id" || handle_failure` work without parsing JSON.
pub async fn get_result(config_path: PathBuf, approval_id: String) -> anyhow::Result<()> {
    let config = load_mcp_config(&config_path)?;
    let client = api_client()?;
    match get_result_inner(&client, &config.server_url, &config.token, &approval_id).await {
        Ok(value) => {
            let status = value.get("status").and_then(Value::as_str).unwrap_or("");
            println!("{}", serde_json::to_string(&value).unwrap());
            // `pending` / `executing` are not failures — the caller polled too
            // early. Still non-zero so an `until` loop terminates on success.
            std::process::exit(if status == "executed" { 0 } else { 1 });
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

async fn events_inner(
    client: &reqwest::Client,
    base_url: &str,
    token: &str,
) -> anyhow::Result<Vec<Value>> {
    // Two listings, merged. A failure on either aborts rather than returning a
    // partial feed: "your inbox is empty" is the one wrong answer here, since
    // it is exactly what makes a caller stop polling.
    let actionable = get_json(client, base_url, token, "/v1/approvals?scope=actionable").await?;
    let mine = get_json(
        client,
        base_url,
        token,
        "/v1/approvals?scope=mine&status=allowed",
    )
    .await?;
    Ok(inbox_events::build_events(&actionable, &mine))
}

async fn get_result_inner(
    client: &reqwest::Client,
    base_url: &str,
    token: &str,
    approval_id: &str,
) -> anyhow::Result<Value> {
    let path = format!("/v1/approvals/{approval_id}/execution");
    get_json(client, base_url, token, &path).await
}

async fn get_json(
    client: &reqwest::Client,
    base_url: &str,
    token: &str,
    path: &str,
) -> anyhow::Result<Value> {
    let url = format!("{}{}", base_url.trim_end_matches('/'), path);
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(unauthorized_error());
    }
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(anyhow!(
            "not found — check the approval id, or the action may never have been approved"
        ));
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow!("API returned {}: {}", status, body));
    }
    let text = resp.text().await.context("read response body")?;
    serde_json::from_str(&text).context("parse response JSON")
}

/// One-line human summary for a TTY. Stdout stays pure JSON so the command
/// stays pipeable into `jq`.
fn summarize(events: &[Value]) -> String {
    if events.is_empty() {
        return "inbox empty".to_string();
    }
    let count = |t: &str| {
        events
            .iter()
            .filter(|e| e.get("type").and_then(Value::as_str) == Some(t))
            .count()
    };
    let parts = [
        (
            count(inbox_events::event_type::APPROVAL_NEEDED),
            "to resolve",
        ),
        (
            count(inbox_events::event_type::READY_TO_CALL),
            "to dispatch",
        ),
        (
            count(inbox_events::event_type::RESULT_UNREAD),
            "unread result",
        ),
    ];
    let body = parts
        .iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, label)| format!("{n} {label}{}", if *n == 1 { "" } else { "s" }))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{} event(s): {}", events.len(), body)
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::Router;
    use axum::extract::Query;
    use axum::routing::get;
    use serde_json::json;
    use std::collections::HashMap;
    use tokio::net::TcpListener;

    /// Serve the two approval listings the inbox merges, keyed on `scope`.
    async fn spawn_listing_server(actionable: Value, mine: Value) -> String {
        let app = Router::new().route(
            "/v1/approvals",
            get(move |Query(q): Query<HashMap<String, String>>| {
                let actionable = actionable.clone();
                let mine = mine.clone();
                async move {
                    match q.get("scope").map(String::as_str) {
                        Some("actionable") => axum::Json(actionable),
                        _ => axum::Json(mine),
                    }
                }
            }),
        );
        spawn(app).await
    }

    async fn spawn(app: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    fn approval(id: &str, exec: Option<Value>) -> Value {
        let mut v = json!({
            "id": id,
            "action_summary": "POST https://api.example.com/things",
            "risk": "write",
            "relationship": "self",
            "created_at": "2026-07-21T10:00:00Z",
        });
        if let Some(e) = exec {
            v.as_object_mut().unwrap().insert("execution".into(), e);
        }
        v
    }

    #[tokio::test]
    async fn events_merges_both_listings() {
        let base = spawn_listing_server(
            json!([approval("needs-me", None)]),
            json!([
                approval(
                    "read-me",
                    Some(json!({"status": "executed", "output_read": false}))
                ),
                approval(
                    "done",
                    Some(json!({"status": "executed", "output_read": true}))
                ),
            ]),
        )
        .await;
        let client = api_client().unwrap();
        let events = events_inner(&client, &base, "tok").await.unwrap();
        assert_eq!(
            events.len(),
            2,
            "settled row must be filtered out: {events:?}"
        );
        assert_eq!(events[0]["type"], "approval_needed");
        assert_eq!(events[1]["type"], "result_unread");
        assert_eq!(events[1]["approval_id"], "read-me");
    }

    #[tokio::test]
    async fn events_empty_when_nothing_pending() {
        let base = spawn_listing_server(json!([]), json!([])).await;
        let client = api_client().unwrap();
        assert!(
            events_inner(&client, &base, "tok")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn get_result_returns_execution_body() {
        let app = Router::new().route(
            "/v1/approvals/abc/execution",
            get(|| async {
                axum::Json(json!({
                    "id": "e1",
                    "status": "executed",
                    "http_status_code": 200,
                    "result": {"body": "{\"ok\":true}"},
                    "output_read": false,
                }))
            }),
        );
        let base = spawn(app).await;
        let client = api_client().unwrap();
        let v = get_result_inner(&client, &base, "tok", "abc")
            .await
            .unwrap();
        assert_eq!(v["status"], "executed");
        assert_eq!(v["result"]["body"], "{\"ok\":true}");
    }

    #[tokio::test]
    async fn unauthorized_names_the_login_command() {
        let app = Router::new().route(
            "/v1/approvals",
            get(|| async { (axum::http::StatusCode::UNAUTHORIZED, "nope") }),
        );
        let base = spawn(app).await;
        let client = api_client().unwrap();
        let err = events_inner(&client, &base, "tok").await.unwrap_err();
        assert!(err.to_string().contains("overslash mcp login"), "{err}");
    }

    #[test]
    fn summary_counts_each_type() {
        let events = vec![
            json!({"type": "approval_needed"}),
            json!({"type": "result_unread"}),
            json!({"type": "result_unread"}),
        ];
        let s = summarize(&events);
        assert!(s.contains("1 to resolve"), "{s}");
        assert!(s.contains("2 unread results"), "{s}");
        assert!(!s.contains("to dispatch"), "zero classes are omitted: {s}");
    }

    #[test]
    fn summary_of_empty_inbox() {
        assert_eq!(summarize(&[]), "inbox empty");
    }
}
