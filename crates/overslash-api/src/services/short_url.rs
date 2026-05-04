//! Best-effort short-link minting via the `oversla.sh` service.
//!
//! Used by flows that hand a deep link to a human (OAuth upstream capture,
//! approvals). The long URL is the source of truth — a missing short URL
//! never blocks the flow.
//!
//! Returns `None` if the service isn't configured or the request fails.
//! Callers fall back to the long URL.

use std::time::Duration as StdDuration;

use axum::http::header;
use time::OffsetDateTime;

use crate::AppState;

const HTTP_TIMEOUT: StdDuration = StdDuration::from_secs(15);

pub async fn mint(state: &AppState, long_url: &str, expires_at: OffsetDateTime) -> Option<String> {
    let base = state.config.oversla_sh_base_url.as_deref()?;
    let api_key = state.config.oversla_sh_api_key.as_deref()?;
    let ttl_seconds = (expires_at - OffsetDateTime::now_utc())
        .whole_seconds()
        .max(60) as u64;
    let resp = match state
        .http_client
        .post(format!("{}/api/links", base.trim_end_matches('/')))
        .bearer_auth(api_key)
        .header(header::ACCEPT, "application/json")
        .json(&serde_json::json!({
            "url": long_url,
            "ttl_seconds": ttl_seconds,
        }))
        .timeout(HTTP_TIMEOUT)
        .send()
        .await
    {
        Ok(r) => r,
        Err(err) => {
            tracing::warn!(error = %err, "oversla.sh transport error; returning long URL only");
            return None;
        }
    };
    if !resp.status().is_success() {
        tracing::warn!(
            status = %resp.status(),
            "oversla.sh short URL mint failed; returning long URL only"
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
