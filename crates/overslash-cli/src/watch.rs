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

    let started = Instant::now();

    loop {
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
        if status == reqwest::StatusCode::NOT_FOUND {
            eprintln!("error: approval {approval_id} not found");
            std::process::exit(2);
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            eprintln!("error: API returned {status}: {body}");
            std::process::exit(2);
        }

        // Keep the raw JSON so stdout output is lossless (includes execution.result).
        let body_text = resp.text().await.context("read response body")?;
        let raw: serde_json::Value =
            serde_json::from_str(&body_text).context("parse approval JSON")?;
        let poll: ApprovalPoll =
            serde_json::from_str(&body_text).context("parse approval status")?;

        match poll.status.as_str() {
            "pending" => {
                let elapsed = started.elapsed();
                if elapsed >= timeout {
                    let out = serde_json::json!({
                        "status": "timeout",
                        "id": approval_id,
                        "elapsed_secs": elapsed.as_secs(),
                    });
                    println!("{}", serde_json::to_string(&out).unwrap());
                    std::process::exit(1);
                }
                if is_stderr_tty() {
                    eprint!("\r  still pending… ({}s elapsed)   ", elapsed.as_secs());
                }
                tokio::time::sleep(poll_interval).await;

                // Check timeout again after sleep before next poll.
                if started.elapsed() >= timeout {
                    let elapsed = started.elapsed();
                    let out = serde_json::json!({
                        "status": "timeout",
                        "id": approval_id,
                        "elapsed_secs": elapsed.as_secs(),
                    });
                    println!("{}", serde_json::to_string(&out).unwrap());
                    std::process::exit(1);
                }
            }
            "allowed" => {
                if is_stderr_tty() {
                    eprintln!();
                }
                println!("{}", serde_json::to_string(&raw).unwrap());
                std::process::exit(0);
            }
            _ => {
                // denied | expired | any future terminal state
                if is_stderr_tty() {
                    eprintln!();
                }
                println!("{}", serde_json::to_string(&raw).unwrap());
                std::process::exit(1);
            }
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
}
