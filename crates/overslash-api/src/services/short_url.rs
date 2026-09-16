//! Best-effort short-link minting via the `oversla.sh` service.
//!
//! Used by flows that hand a deep link to a human (OAuth upstream capture,
//! HTTP-OAuth gated-authorize, approvals, secret requests). The long URL is
//! the source of truth — a missing short URL never blocks the flow.
//!
//! Two shapes, by surface:
//!
//! - **REST** keeps the pair — the canonical URL in the field partners already
//!   read, the short form beside it. Partners host-allow-list it, parse the
//!   flow id out of it, or simply don't want a second failure domain in their
//!   OAuth path, so the canonical URL must stay reachable. Mint with
//!   [`mint`] / [`mint_with_config`] and keep both.
//! - **MCP** gets one field. The collapse happens once, at the MCP forwarding
//!   boundary (`routes::mcp::collapse_link_pairs`): an agent hands the link to
//!   a human verbatim and should never have to choose between two.
//!
//! [`shorten`] is for the surfaces that are single-field on *both* sides —
//! today just the approval link, which has always replaced rather than
//! doubled.

use std::time::Duration as StdDuration;

use axum::http::header;
use time::OffsetDateTime;

use crate::AppState;

const HTTP_TIMEOUT: StdDuration = StdDuration::from_secs(15);

pub async fn mint(state: &AppState, long_url: &str, expires_at: OffsetDateTime) -> Option<String> {
    let base = state.config.oversla_sh_base_url.as_deref()?;
    let api_key = state.config.oversla_sh_api_key.as_deref()?;
    mint_with_client(&state.http_client, base, api_key, long_url, expires_at).await
}

/// [`mint_with_client`] for callers holding a `PlatformCallContext`: takes the
/// config pair straight off it and returns `None` when either half is unset,
/// so no caller has to hand-roll the "is it configured?" match.
pub async fn mint_with_config(
    http_client: &reqwest::Client,
    base_url: Option<&str>,
    api_key: Option<&str>,
    long_url: &str,
    expires_at: OffsetDateTime,
) -> Option<String> {
    let (Some(base), Some(key)) = (base_url, api_key) else {
        return None;
    };
    mint_with_client(http_client, base, key, long_url, expires_at).await
}

/// Shorten `long_url` for delivery to a human, falling back to `long_url`
/// itself when the shortener is unconfigured or the mint fails.
///
/// This is the entry point every user-facing link goes through. Callers hold
/// one URL field, and it is always usable.
pub async fn shorten(state: &AppState, long_url: String, expires_at: OffsetDateTime) -> String {
    match mint(state, &long_url, expires_at).await {
        Some(short) => short,
        None => long_url,
    }
}

/// Lower-level entry point that takes an explicit client + config so unit
/// tests can exercise the HTTP roundtrip without constructing an `AppState`.
pub async fn mint_with_client(
    http_client: &reqwest::Client,
    base_url: &str,
    api_key: &str,
    long_url: &str,
    expires_at: OffsetDateTime,
) -> Option<String> {
    let ttl_seconds = (expires_at - OffsetDateTime::now_utc())
        .whole_seconds()
        .max(60) as u64;
    let resp = match http_client
        .post(format!("{}/api/links", base_url.trim_end_matches('/')))
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
