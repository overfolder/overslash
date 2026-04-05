use std::net::IpAddr;

use serde::{Deserialize, Serialize};

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
    #[error("failed to fetch discovery document: {0}")]
    FetchError(String),
    #[error("failed to parse discovery document: {0}")]
    ParseError(String),
    #[error("issuer mismatch: expected {expected}, got {actual}")]
    IssuerMismatch { expected: String, actual: String },
    #[error("invalid issuer URL: {0}")]
    InvalidUrl(String),
}

/// Fetch and parse an OIDC Discovery document from the issuer's
/// `.well-known/openid-configuration` endpoint.
pub async fn discover(
    http_client: &reqwest::Client,
    issuer_url: &str,
) -> Result<OidcDiscoveryDocument, OidcDiscoveryError> {
    validate_issuer_url(issuer_url)?;

    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer_url.trim_end_matches('/')
    );

    let resp = http_client
        .get(&url)
        .send()
        .await
        .map_err(|e| OidcDiscoveryError::FetchError(e.to_string()))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(OidcDiscoveryError::FetchError(format!(
            "HTTP {status}: {body}"
        )));
    }

    let doc: OidcDiscoveryDocument = resp
        .json()
        .await
        .map_err(|e| OidcDiscoveryError::ParseError(e.to_string()))?;

    // Validate issuer matches (per OIDC Discovery spec §4.3)
    let expected = issuer_url.trim_end_matches('/');
    let actual = doc.issuer.trim_end_matches('/');
    if expected != actual {
        return Err(OidcDiscoveryError::IssuerMismatch {
            expected: expected.to_string(),
            actual: actual.to_string(),
        });
    }

    Ok(doc)
}

/// Validate that an issuer URL is safe to fetch (prevents SSRF to internal networks).
fn validate_issuer_url(issuer_url: &str) -> Result<(), OidcDiscoveryError> {
    // Must be HTTPS (OIDC Discovery spec requirement)
    let without_scheme = issuer_url
        .strip_prefix("https://")
        .ok_or_else(|| OidcDiscoveryError::InvalidUrl("issuer URL must use HTTPS".into()))?;

    // Extract host (before first / or :)
    let host = without_scheme
        .split('/')
        .next()
        .and_then(|h| h.split(':').next())
        .unwrap_or("");

    if host.is_empty() {
        return Err(OidcDiscoveryError::InvalidUrl("missing host".into()));
    }

    // Block requests to IP addresses that point to internal networks
    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip.is_loopback() || ip.is_unspecified() || is_private_ip(ip) || is_link_local(ip) {
            return Err(OidcDiscoveryError::InvalidUrl(
                "issuer URL must not point to internal/private addresses".into(),
            ));
        }
    }

    // Block known cloud metadata hostnames
    let blocked_hosts = ["169.254.169.254", "metadata.google.internal", "localhost"];
    if blocked_hosts.contains(&host) {
        return Err(OidcDiscoveryError::InvalidUrl(
            "issuer URL must not point to internal services".into(),
        ));
    }

    Ok(())
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
        }
        IpAddr::V6(_) => false,
    }
}

fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 169 && o[1] == 254
        }
        IpAddr::V6(_) => false,
    }
}
