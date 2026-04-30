//! Nested-OAuth client for upstream MCP servers.
//!
//! Overslash plays the OAuth 2.1 *client* role here. The upstream MCP server
//! is the resource server; its associated authorization server is discovered
//! per RFC 9728 + RFC 8414. Dynamic Client Registration (RFC 7591) yields a
//! `client_id`; PKCE S256 + the RFC 8707 `resource` parameter ride along on
//! every authorize/token call.
//!
//! This module is the wire-format layer (HTTP, URL-building, parsing). The
//! flow lifecycle (mint flow row → gate → callback → store token) lives in
//! `routes::oauth_upstream`.

use rand::RngExt;
use serde::Deserialize;

pub use crate::services::oauth::{PkcePair, generate_pkce};

/// Opaque flow identifier — base62-encoded 16 random bytes (~22 chars).
/// Used as both the URL short-id and the OAuth `state` parameter, with the
/// trusted fields (identity, expiry, PKCE verifier) stored server-side in
/// the `mcp_upstream_flows` row keyed by this id.
pub fn mint_flow_id() -> String {
    let mut buf = [0u8; 16];
    rand::rng().fill(&mut buf);
    // base62 over the canonical alphabet — URL-safe without `-` or `_`.
    const ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut n = u128::from_be_bytes(buf);
    let mut out = Vec::with_capacity(22);
    while n > 0 {
        out.push(ALPHABET[(n % 62) as usize]);
        n /= 62;
    }
    while out.len() < 22 {
        out.push(b'0');
    }
    out.reverse();
    String::from_utf8(out).expect("base62 alphabet is ASCII")
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// RFC 9728 §3 — `oauth-protected-resource` metadata.
#[derive(Debug, Deserialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    #[serde(default)]
    pub authorization_servers: Vec<String>,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
}

/// RFC 8414 §2 — `oauth-authorization-server` metadata. We pull the fields
/// the MCP nested-OAuth flow actually uses.
#[derive(Debug, Deserialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: Option<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
}

/// Fetch the protected-resource-metadata document. The URL is whatever the
/// upstream MCP server returns in the `resource_metadata` parameter of its
/// `WWW-Authenticate: Bearer …` 401 response.
pub async fn discover_protected_resource(
    http: &reqwest::Client,
    url: &str,
) -> Result<ProtectedResourceMetadata, UpstreamOAuthError> {
    let resp = http
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| UpstreamOAuthError::Discovery(format!("GET {url}: {e}")))?;
    if !resp.status().is_success() {
        let status = resp.status();
        return Err(UpstreamOAuthError::Discovery(format!(
            "GET {url} returned {status}"
        )));
    }
    resp.json::<ProtectedResourceMetadata>()
        .await
        .map_err(|e| UpstreamOAuthError::Discovery(format!("parse {url}: {e}")))
}

/// Fetch the AS metadata document by trying the standard well-known suffixes
/// in MCP-spec order: oauth-authorization-server then openid-configuration.
///
/// Validates `issuer` per RFC 8414 §3.3 / OIDC Discovery §4.3 — the issuer
/// returned in the metadata MUST match the URL prefix we used. Without this
/// check, an attacker who substitutes the metadata document can swing the
/// authorize / token endpoints to a host they control.
pub async fn discover_authorization_server(
    http: &reqwest::Client,
    issuer: &str,
) -> Result<AuthorizationServerMetadata, UpstreamOAuthError> {
    let issuer_trimmed = issuer.trim_end_matches('/');
    let candidates = [
        format!("{issuer_trimmed}/.well-known/oauth-authorization-server"),
        format!("{issuer_trimmed}/.well-known/openid-configuration"),
    ];
    let mut last_err = None;
    for url in &candidates {
        match http
            .get(url)
            .header("Accept", "application/json")
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                let doc: AuthorizationServerMetadata = resp
                    .json()
                    .await
                    .map_err(|e| UpstreamOAuthError::Discovery(format!("parse {url}: {e}")))?;
                let actual = doc.issuer.trim_end_matches('/');
                if actual != issuer_trimmed {
                    return Err(UpstreamOAuthError::IssuerMismatch {
                        expected: issuer_trimmed.to_string(),
                        actual: actual.to_string(),
                    });
                }
                return Ok(doc);
            }
            Ok(resp) => {
                last_err = Some(format!("{url} → {}", resp.status()));
            }
            Err(e) => {
                last_err = Some(format!("{url}: {e}"));
            }
        }
    }
    Err(UpstreamOAuthError::Discovery(format!(
        "no AS metadata at {issuer}: {}",
        last_err.unwrap_or_default()
    )))
}

// ---------------------------------------------------------------------------
// Dynamic Client Registration (RFC 7591)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RegisteredClient {
    pub client_id: String,
}

/// Register a public client (PKCE only, no secret) at the upstream AS.
///
/// We register with `token_endpoint_auth_method: "none"` per the MCP spec.
/// Confidential-client upstreams (those that insist on returning a
/// `client_secret`) are rejected — we have no place to store the secret
/// (`mcp_upstream_connections` only carries `upstream_client_id`) and
/// silently dropping it would mean every subsequent token call fails
/// authentication. Forcing the error surface keeps the misconfiguration
/// visible.
pub async fn register_client(
    http: &reqwest::Client,
    registration_endpoint: &str,
    redirect_uri: &str,
    client_name: &str,
) -> Result<RegisteredClient, UpstreamOAuthError> {
    let body = serde_json::json!({
        "client_name": client_name,
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "application_type": "web",
    });
    let resp = http
        .post(registration_endpoint)
        .header("Accept", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| UpstreamOAuthError::Dcr(format!("POST {registration_endpoint}: {e}")))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(UpstreamOAuthError::Dcr(format!(
            "{registration_endpoint} returned {status}: {body}"
        )));
    }
    let raw: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| UpstreamOAuthError::Dcr(format!("parse: {e}")))?;
    if raw.get("client_secret").and_then(|v| v.as_str()).is_some() {
        return Err(UpstreamOAuthError::ConfidentialClientUnsupported);
    }
    let client_id = raw
        .get("client_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| UpstreamOAuthError::Dcr("missing client_id in response".into()))?;
    Ok(RegisteredClient {
        client_id: client_id.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Authorize URL construction
// ---------------------------------------------------------------------------

/// Build the upstream authorize URL with PKCE S256 and RFC 8707 `resource`.
/// Produces `U_raw` — the URL the upstream issues codes against.
pub fn build_authorize_url(
    authorization_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    code_challenge: &str,
    resource: &str,
    scopes: &[String],
) -> String {
    // Use `Url::query_pairs_mut()` so endpoints that already carry a query
    // string (e.g. `https://as.example/authorize?prompt=consent`) get our
    // parameters appended with `&`, not clobbered with a second `?`.
    let mut url = match url::Url::parse(authorization_endpoint) {
        Ok(u) => u,
        // Fall back if the endpoint isn't parseable — the SSRF guard will
        // reject this anyway, but emit something debuggable rather than
        // panic.
        Err(_) => return authorization_endpoint.to_string(),
    };
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code");
        q.append_pair("client_id", client_id);
        q.append_pair("redirect_uri", redirect_uri);
        q.append_pair("state", state);
        q.append_pair("code_challenge", code_challenge);
        q.append_pair("code_challenge_method", "S256");
        q.append_pair("resource", resource);
        if !scopes.is_empty() {
            q.append_pair("scope", &scopes.join(" "));
        }
    }
    url.into()
}

// ---------------------------------------------------------------------------
// Token exchange + refresh
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct UpstreamTokenResponse {
    pub access_token: String,
    pub token_type: Option<String>,
    pub expires_in: Option<i64>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

pub async fn exchange_code(
    http: &reqwest::Client,
    token_endpoint: &str,
    client_id: &str,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
    resource: &str,
) -> Result<UpstreamTokenResponse, UpstreamOAuthError> {
    let form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", code_verifier),
        ("resource", resource),
    ];
    post_form(http, token_endpoint, &form).await
}

pub async fn refresh(
    http: &reqwest::Client,
    token_endpoint: &str,
    client_id: &str,
    refresh_token: &str,
    resource: &str,
) -> Result<UpstreamTokenResponse, UpstreamOAuthError> {
    let form: Vec<(&str, &str)> = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
        ("resource", resource),
    ];
    post_form(http, token_endpoint, &form).await
}

async fn post_form(
    http: &reqwest::Client,
    token_endpoint: &str,
    form: &[(&str, &str)],
) -> Result<UpstreamTokenResponse, UpstreamOAuthError> {
    let resp = http
        .post(token_endpoint)
        .header("Accept", "application/json")
        .form(form)
        .send()
        .await
        .map_err(|e| UpstreamOAuthError::Token(format!("POST {token_endpoint}: {e}")))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(UpstreamOAuthError::Token(format!(
            "{token_endpoint} returned {status}: {body}"
        )));
    }
    resp.json::<UpstreamTokenResponse>()
        .await
        .map_err(|e| UpstreamOAuthError::Token(format!("parse: {e}")))
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum UpstreamOAuthError {
    #[error("discovery failed: {0}")]
    Discovery(String),
    #[error("authorization server issuer mismatch: expected {expected}, got {actual}")]
    IssuerMismatch { expected: String, actual: String },
    #[error("dynamic client registration failed: {0}")]
    Dcr(String),
    #[error(
        "upstream returned a confidential client (client_secret); only public clients with PKCE are supported"
    )]
    ConfidentialClientUnsupported,
    #[error("token endpoint failed: {0}")]
    Token(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_id_is_base62_and_22_chars() {
        for _ in 0..100 {
            let id = mint_flow_id();
            assert_eq!(id.len(), 22, "id={id}");
            assert!(id.chars().all(|c| c.is_ascii_alphanumeric()), "id={id}");
        }
    }

    #[test]
    fn pkce_pair_is_url_safe_and_distinct() {
        let p1 = generate_pkce();
        let p2 = generate_pkce();
        assert_ne!(p1.verifier, p2.verifier);
        assert_ne!(p1.challenge, p2.challenge);
        for s in [&p1.verifier, &p1.challenge, &p2.verifier, &p2.challenge] {
            assert!(
                s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "not URL-safe: {s}"
            );
        }
        // S256 challenge length: SHA-256 = 32 bytes → 43 base64url-no-pad chars.
        assert_eq!(p1.challenge.len(), 43);
    }

    #[test]
    fn authorize_url_includes_required_oauth21_mcp_params() {
        let u = build_authorize_url(
            "https://as.example.com/authorize",
            "client_abc",
            "https://overslash.example/cb",
            "state_xyz",
            "challenge_def",
            "https://upstream.example/mcp",
            &["read".into(), "write".into()],
        );
        assert!(u.contains("response_type=code"));
        assert!(u.contains("client_id=client_abc"));
        assert!(u.contains("code_challenge=challenge_def"));
        assert!(u.contains("code_challenge_method=S256"));
        assert!(u.contains("state=state_xyz"));
        assert!(u.contains("resource=https%3A%2F%2Fupstream.example%2Fmcp"));
        assert!(u.contains("scope=read+write") || u.contains("scope=read%20write"));
    }

    #[test]
    fn authorize_url_preserves_existing_query_string() {
        // Some upstream ASes pre-bake parameters (tenant routing, prompt,
        // ui_locales) into their authorize endpoint. Appending ours with `?`
        // would clobber them; we use `&`.
        let u = build_authorize_url(
            "https://login.example.com/authorize?prompt=consent&tenant=acme",
            "client_abc",
            "https://overslash.example/cb",
            "state_xyz",
            "challenge_def",
            "https://upstream.example/mcp",
            &[],
        );
        assert!(u.contains("prompt=consent"), "lost prompt param: {u}");
        assert!(u.contains("tenant=acme"), "lost tenant param: {u}");
        assert!(u.contains("client_id=client_abc"), "missing client_id: {u}");
        // Exactly one `?` separating path from query.
        assert_eq!(u.matches('?').count(), 1, "expected one `?`, got: {u}");
    }
}
