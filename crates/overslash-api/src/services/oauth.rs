use base64::Engine;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use overslash_core::crypto;
use overslash_db::repos::{connection, oauth_provider};

/// A PKCE pair: the verifier (sent during token exchange) and the challenge
/// (sent in the authorization URL).
pub struct PkcePair {
    pub verifier: String,
    pub challenge: String,
}

/// Generate a PKCE code verifier and its S256 challenge.
pub fn generate_pkce() -> PkcePair {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
    let challenge = {
        let digest = Sha256::digest(verifier.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    };
    PkcePair {
        verifier,
        challenge,
    }
}

/// Build an OAuth authorization URL for the given provider.
/// Pass a `code_challenge` when the provider requires PKCE — the caller is
/// responsible for generating the PKCE pair via `generate_pkce()` and keeping
/// the verifier for `exchange_code`.
pub fn build_auth_url(
    provider: &oauth_provider::OAuthProviderRow,
    client_id: &str,
    redirect_uri: &str,
    scopes: &[String],
    state: &str,
    code_challenge: Option<&str>,
) -> String {
    let scope_str = scopes.join(" ");
    let extra: std::collections::HashMap<String, String> =
        serde_json::from_value(provider.extra_auth_params.clone()).unwrap_or_default();

    let mut params = vec![
        ("client_id", client_id.to_string()),
        ("redirect_uri", redirect_uri.to_string()),
        ("response_type", "code".to_string()),
        ("scope", scope_str),
        ("state", state.to_string()),
    ];

    for (k, v) in &extra {
        params.push((k.as_str(), v.clone()));
    }

    if let Some(challenge) = code_challenge {
        params.push(("code_challenge", challenge.to_string()));
        params.push(("code_challenge_method", "S256".to_string()));
    }

    let query = params
        .iter()
        .map(|(k, v)| format!("{k}={}", urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    format!("{}?{}", provider.authorization_endpoint, query)
}

/// Build a token request with the correct auth method for the provider.
/// `client_secret_basic` sends credentials as HTTP Basic Auth header.
/// `client_secret_post` (default) sends them as form body fields.
fn token_request(
    http_client: &reqwest::Client,
    provider: &oauth_provider::OAuthProviderRow,
    client_id: &str,
    client_secret: &str,
    form: &[(&str, &str)],
) -> reqwest::RequestBuilder {
    let req = http_client.post(&provider.token_endpoint);
    if provider.token_auth_method == "client_secret_basic" {
        req.basic_auth(client_id, Some(client_secret)).form(form)
    } else {
        // client_secret_post: include credentials in form body
        let mut full_form: Vec<(&str, &str)> = form.to_vec();
        full_form.push(("client_id", client_id));
        full_form.push(("client_secret", client_secret));
        req.form(&full_form)
    }
}

/// Exchange an authorization code for tokens.
/// When the provider uses PKCE, `code_verifier` must be the verifier that was
/// generated alongside the code challenge during `build_auth_url`.
pub async fn exchange_code(
    http_client: &reqwest::Client,
    provider: &oauth_provider::OAuthProviderRow,
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
    code_verifier: Option<&str>,
) -> Result<TokenResponse, OAuthError> {
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
    ];
    if let Some(verifier) = code_verifier {
        form.push(("code_verifier", verifier));
    }
    let resp = token_request(http_client, provider, client_id, client_secret, &form)
        .send()
        .await
        .map_err(|e| OAuthError::HttpError(e.to_string()))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(OAuthError::TokenExchangeFailed(body));
    }

    resp.json::<TokenResponse>()
        .await
        .map_err(|e| OAuthError::ParseError(e.to_string()))
}

/// Refresh an access token using a refresh token.
pub async fn refresh_token(
    http_client: &reqwest::Client,
    provider: &oauth_provider::OAuthProviderRow,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) -> Result<TokenResponse, OAuthError> {
    let form: Vec<(&str, &str)> = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
    ];
    let resp = token_request(http_client, provider, client_id, client_secret, &form)
        .send()
        .await
        .map_err(|e| OAuthError::HttpError(e.to_string()))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(OAuthError::RefreshFailed(body));
    }

    resp.json::<TokenResponse>()
        .await
        .map_err(|e| OAuthError::ParseError(e.to_string()))
}

/// Resolve the access token for a connection, refreshing if expired.
pub async fn resolve_access_token(
    pool: &PgPool,
    http_client: &reqwest::Client,
    enc_key: &[u8; 32],
    conn: &connection::ConnectionRow,
    client_id: &str,
    client_secret: &str,
) -> Result<String, OAuthError> {
    let access_token = String::from_utf8(
        crypto::decrypt(enc_key, &conn.encrypted_access_token)
            .map_err(|e| OAuthError::CryptoError(e.to_string()))?,
    )
    .map_err(|_| OAuthError::CryptoError("invalid utf-8".into()))?;

    // Check if token is expired (with 60s buffer)
    let is_expired = conn
        .token_expires_at
        .map(|exp| exp < time::OffsetDateTime::now_utc() + time::Duration::seconds(60))
        .unwrap_or(false);

    if !is_expired {
        return Ok(access_token);
    }

    // Need to refresh
    let refresh_token_encrypted = conn
        .encrypted_refresh_token
        .as_ref()
        .ok_or(OAuthError::NoRefreshToken)?;

    let refresh_tok = String::from_utf8(
        crypto::decrypt(enc_key, refresh_token_encrypted)
            .map_err(|e| OAuthError::CryptoError(e.to_string()))?,
    )
    .map_err(|_| OAuthError::CryptoError("invalid utf-8".into()))?;

    let provider = oauth_provider::get_by_key(pool, &conn.provider_key)
        .await
        .map_err(|e| OAuthError::DbError(e.to_string()))?
        .ok_or_else(|| OAuthError::ProviderNotFound(conn.provider_key.clone()))?;

    let tokens = refresh_token(
        http_client,
        &provider,
        client_id,
        client_secret,
        &refresh_tok,
    )
    .await?;

    // Encrypt and store new tokens
    let new_access = crypto::encrypt(enc_key, tokens.access_token.as_bytes())
        .map_err(|e| OAuthError::CryptoError(e.to_string()))?;

    let new_refresh = if let Some(ref rt) = tokens.refresh_token {
        Some(
            crypto::encrypt(enc_key, rt.as_bytes())
                .map_err(|e| OAuthError::CryptoError(e.to_string()))?,
        )
    } else {
        None
    };

    let new_expires = tokens
        .expires_in
        .map(|secs| time::OffsetDateTime::now_utc() + time::Duration::seconds(secs));

    connection::update_tokens(
        pool,
        conn.id,
        &new_access,
        new_refresh.as_deref(),
        new_expires,
    )
    .await
    .map_err(|e| OAuthError::DbError(e.to_string()))?;

    Ok(tokens.access_token)
}

#[derive(Debug, serde::Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
    pub token_type: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    #[error("http error: {0}")]
    HttpError(String),
    #[error("token exchange failed: {0}")]
    TokenExchangeFailed(String),
    #[error("token refresh failed: {0}")]
    RefreshFailed(String),
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("crypto error: {0}")]
    CryptoError(String),
    #[error("db error: {0}")]
    DbError(String),
    #[error("no refresh token available")]
    NoRefreshToken,
    #[error("provider not found: {0}")]
    ProviderNotFound(String),
}
