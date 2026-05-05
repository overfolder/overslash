//! Best-effort short-URL minting via the `oversla.sh` service.
//!
//! Returns `None` if the service isn't configured or the request fails.
//! The proxied URL (always present in the response) is the source of
//! truth — a missing short URL never blocks the flow it's attached to.
//!
//! Used by both the upstream-MCP flow (`routes::oauth_upstream`) and the
//! HTTP-OAuth gated-authorize flow (`routes::connections`).

use std::time::Duration as StdDuration;

use reqwest::header;
use time::OffsetDateTime;

const HTTP_TIMEOUT: StdDuration = StdDuration::from_secs(15);

/// Mint a short URL aliasing `proxied`. Best-effort: returns `None` when
/// the shortener isn't configured (`base_url` / `api_key` `None`) or when
/// the upstream call fails. The shortener's TTL is clamped to at least
/// 60s so a near-expired flow doesn't generate an immediately-dead link.
pub async fn mint_short_url(
    http_client: &reqwest::Client,
    base_url: Option<&str>,
    api_key: Option<&str>,
    proxied: &str,
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
            "url": proxied,
            "ttl_seconds": ttl_seconds,
        }))
        .timeout(HTTP_TIMEOUT)
        .send()
        .await
    {
        Ok(r) => r,
        Err(err) => {
            tracing::warn!(error = %err, "oversla.sh transport error; returning proxied URL only");
            return None;
        }
    };
    if !resp.status().is_success() {
        tracing::warn!(
            status = %resp.status(),
            "oversla.sh short URL mint failed; returning proxied URL only"
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
