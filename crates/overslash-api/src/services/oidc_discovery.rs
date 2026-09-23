//! OIDC Discovery for an org-admin-supplied issuer URL.
//!
//! The issuer is caller input, so every hop — the first request and each
//! redirect — goes through [`ssrf_guard::outbound_client_validated`]: resolve,
//! check every address, pin. On top of that, discovery requires `https`, with
//! a single exception: plain `http` to a loopback address, which the guard only
//! lets through when the operator allow-listed loopback (the test suite and
//! `scripts/e2e-up.sh`, whose IdP fakes bind there). The rule is shared with
//! webhook delivery and lives in [`crate::services::https_policy`]. `http` to a private range
//! is refused even when that range is allow-listed — a self-hosted IdP on the
//! operator's network still speaks TLS.
//!
//! Nothing learned from the network reaches the caller. Every failure past the
//! input check collapses to [`OidcDiscoveryError::Failed`], and the detail —
//! guard refusal, status, a body snippet — is logged instead. Echoing it would
//! let an admin use this endpoint to probe what resolves and what answers.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::AppError;
use crate::services::https_policy::{names_loopback, scheme_allowed};
use crate::services::ssrf_guard;

/// Parsed OIDC Discovery document from `.well-known/openid-configuration`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcDiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
    #[serde(default)]
    pub scopes_supported: Option<Vec<String>>,
    #[serde(default)]
    pub response_types_supported: Option<Vec<String>>,
    #[serde(default)]
    pub code_challenge_methods_supported: Option<Vec<String>>,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

#[derive(Debug, thiserror::Error)]
pub enum OidcDiscoveryError {
    /// The input itself is unusable. Describes only what the caller sent, so
    /// it is safe to echo.
    #[error("invalid issuer URL: {0}")]
    InvalidUrl(String),
    /// Anything that went wrong once we touched the network. Deliberately
    /// carries nothing — see the module docs.
    #[error("could not retrieve a valid discovery document from the issuer")]
    Failed,
}

/// Redirects followed, matching the template-import fetch.
const MAX_REDIRECTS: usize = 3;
/// Total deadline per hop. The pooled guard client has none of its own.
const HOP_TIMEOUT: Duration = Duration::from_secs(10);
/// A discovery document is a few KiB; anything near this is not one.
const MAX_BODY_BYTES: usize = 256 * 1024;
/// How much of an unexpected body makes it into the server log.
const LOG_SNIPPET_BYTES: usize = 512;

/// Fetch and parse an OIDC Discovery document from the issuer's
/// `.well-known/openid-configuration` endpoint.
pub async fn discover(issuer_url: &str) -> Result<OidcDiscoveryDocument, OidcDiscoveryError> {
    let parsed = Url::parse(issuer_url)
        .map_err(|e| OidcDiscoveryError::InvalidUrl(format!("does not parse ({e})")))?;
    // Plain `http` names a loopback host or it is refused here, from the
    // string alone, before any lookup. The per-hop check below still decides
    // on the *resolved* address, so a `localhost` that resolves elsewhere, or
    // a redirect, cannot get past it either.
    let acceptable = match parsed.scheme() {
        "https" => true,
        "http" => names_loopback(&parsed),
        _ => false,
    };
    if !acceptable {
        return Err(OidcDiscoveryError::InvalidUrl(
            "issuer URL must use HTTPS".into(),
        ));
    }

    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer_url.trim_end_matches('/')
    );
    let body = fetch(&url).await.map_err(|detail| {
        tracing::warn!(issuer_url, "OIDC discovery failed: {detail}");
        OidcDiscoveryError::Failed
    })?;

    let doc: OidcDiscoveryDocument = serde_json::from_slice(&body).map_err(|e| {
        tracing::warn!(
            issuer_url,
            "OIDC discovery document did not parse: {e}; body starts {:?}",
            snippet(&body)
        );
        OidcDiscoveryError::Failed
    })?;

    // Validate issuer matches (per OIDC Discovery spec §4.3)
    let expected = issuer_url.trim_end_matches('/');
    let actual = doc.issuer.trim_end_matches('/');
    if expected != actual {
        tracing::warn!(
            issuer_url,
            "OIDC discovery issuer mismatch: document names {actual:?}"
        );
        return Err(OidcDiscoveryError::Failed);
    }

    Ok(doc)
}

/// GET `url`, following redirects by hand with the guard re-run on every hop.
/// The `Err` is a server-side log line, never shown to the caller.
async fn fetch(url: &str) -> Result<Vec<u8>, String> {
    let mut current = url.to_string();

    for _hop in 0..=MAX_REDIRECTS {
        let (client, parsed, ip) = ssrf_guard::outbound_client_validated(&current)
            .await
            .map_err(|e| match e {
                AppError::BadRequest(msg) => format!("refused {current:?}: {msg}"),
                other => format!("guard failed for {current:?}: {other}"),
            })?;
        if !scheme_allowed(parsed.scheme(), &ip) {
            return Err(format!(
                "refused {current:?}: plain http is only accepted to loopback (resolved {ip})"
            ));
        }

        let resp = client
            .get(parsed.as_str())
            .timeout(HOP_TIMEOUT)
            .send()
            .await
            .map_err(|e| format!("request to {current:?} failed: {e}"))?;

        let status = resp.status();
        if status.is_redirection() {
            let loc = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|h| h.to_str().ok())
                .ok_or_else(|| format!("{status} from {current:?} without a Location"))?;
            let next = parsed
                .join(loc)
                .map_err(|e| format!("unusable redirect target {loc:?}: {e}"))?;
            current = next.to_string();
            continue;
        }

        let body = read_capped(resp).await?;
        if !status.is_success() {
            return Err(format!(
                "{current:?} returned {status}; body starts {:?}",
                snippet(&body)
            ));
        }
        return Ok(body);
    }

    Err(format!("more than {MAX_REDIRECTS} redirects"))
}

async fn read_capped(resp: reqwest::Response) -> Result<Vec<u8>, String> {
    use futures_util::StreamExt;

    let mut stream = resp.bytes_stream();
    let mut buf = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("reading body failed: {e}"))?;
        if buf.len() + chunk.len() > MAX_BODY_BYTES {
            return Err(format!("body larger than {MAX_BODY_BYTES} bytes"));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// The first [`LOG_SNIPPET_BYTES`] of a body, cut on a char boundary.
fn snippet(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let end = text.floor_char_boundary(LOG_SNIPPET_BYTES);
    text[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snippet_never_splits_a_codepoint() {
        let body = "é".repeat(LOG_SNIPPET_BYTES);
        let s = snippet(body.as_bytes());
        assert!(s.len() <= LOG_SNIPPET_BYTES);
        assert!(s.chars().all(|c| c == 'é'));
    }

    #[tokio::test]
    async fn bad_schemes_are_refused_before_any_network() {
        for url in [
            "ftp://issuer.example",
            "http://issuer.example",
            "http://10.0.0.1",
        ] {
            let err = discover(url).await.unwrap_err();
            assert!(
                matches!(err, OidcDiscoveryError::InvalidUrl(_)),
                "{url}: {err}"
            );
        }
    }
}
