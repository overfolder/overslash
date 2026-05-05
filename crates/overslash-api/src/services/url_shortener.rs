//! Best-effort short-URL minting via the configured `oversla.sh` instance.
//!
//! The shortener is optional: callers always have a working canonical URL,
//! and the short form is purely a UX convenience for surfaces with tight
//! display budgets (chat messages, terminal output, MCP responses). Every
//! failure path returns `None` and emits a `tracing::warn` — never blocks
//! the parent flow.
//!
//! Configuration: `OVERSLA_SH_BASE_URL` + `OVERSLA_SH_API_KEY`. When either
//! is unset, this returns `None` immediately without a network call.

use std::time::Duration;

use axum::http::header;
use time::OffsetDateTime;

const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

/// Mint a short URL pointing at `url`, expiring no later than `expires_at`.
/// Returns `None` if the shortener isn't configured (`base_url` or `api_key`
/// is `None`), the request fails, or the response is malformed. The canonical
/// `url` remains the source of truth — a missing short URL never blocks the
/// caller.
pub async fn mint_short_url(
    http_client: &reqwest::Client,
    base_url: Option<&str>,
    api_key: Option<&str>,
    url: &str,
    expires_at: OffsetDateTime,
) -> Option<String> {
    let base = base_url?;
    let api_key = api_key?;
    let ttl_seconds = (expires_at - OffsetDateTime::now_utc())
        .whole_seconds()
        .max(60) as u64;
    let resp = match http_client
        .post(format!("{}/api/links", base.trim_end_matches('/')))
        .bearer_auth(api_key)
        .header(header::ACCEPT, "application/json")
        .json(&serde_json::json!({
            "url": url,
            "ttl_seconds": ttl_seconds,
        }))
        .timeout(HTTP_TIMEOUT)
        .send()
        .await
    {
        Ok(r) => r,
        Err(err) => {
            tracing::warn!(error = %err, "oversla.sh transport error; returning canonical URL only");
            return None;
        }
    };
    if !resp.status().is_success() {
        tracing::warn!(
            status = %resp.status(),
            "oversla.sh short URL mint failed; returning canonical URL only"
        );
        return None;
    }
    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(error = %err, "oversla.sh response was not valid JSON");
            return None;
        }
    };
    let short = body
        .get("short_url")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    if short.is_none() {
        tracing::warn!("oversla.sh response missing short_url field");
    }
    short
}
