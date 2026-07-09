use base64::Engine;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use overslash_core::crypto;
use overslash_db::repos::{connection, oauth_provider};
use overslash_db::scopes::OrgScope;

/// A PKCE pair: the verifier (sent during token exchange) and the challenge
/// (sent in the authorization URL).
pub struct PkcePair {
    pub verifier: String,
    pub challenge: String,
}

/// Generate a PKCE code verifier and its S256 challenge.
pub fn generate_pkce() -> PkcePair {
    use rand::RngExt;
    let mut buf = [0u8; 32];
    rand::rng().fill(&mut buf);
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
    let extra: std::collections::HashMap<String, String> =
        serde_json::from_value(provider.extra_auth_params.clone()).unwrap_or_default();

    let mut params = vec![
        ("client_id", client_id.to_string()),
        ("redirect_uri", redirect_uri.to_string()),
        ("response_type", "code".to_string()),
        ("state", state.to_string()),
    ];

    // Only include `scope` when we have scopes — Google rejects an empty
    // `scope=` with "Missing required parameter: scope", and providers that
    // don't need one (e.g. Eventbrite historically) are happiest when the
    // parameter is omitted entirely.
    if !scopes.is_empty() {
        params.push(("scope", scopes.join(" ")));
    }

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
    // Always request JSON responses — required for GitHub (defaults to
    // application/x-www-form-urlencoded), harmless for all other providers.
    let req = http_client
        .post(&provider.token_endpoint)
        .header("Accept", "application/json");
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
///
/// The `scope` argument bounds the refresh-write to the connection's org —
/// callers must pass an `OrgScope` whose `org_id` matches `conn.org_id`.
/// (`OrgScope::update_connection_tokens` is itself an `(id, org_id)`
/// double-key update, so a mismatched scope is a silent no-op rather than
/// a cross-tenant write.)
pub async fn resolve_access_token(
    scope: &OrgScope,
    http_client: &reqwest::Client,
    enc_key: &crypto::Keyring,
    conn: &connection::ConnectionRow,
    client_id: &str,
    client_secret: &str,
) -> Result<String, OAuthError> {
    let pool: &PgPool = scope.db();
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

    // Reconcile the recorded scope set against what the refresh response
    // echoed. A refresh must only *widen or heal* the recorded set — never
    // narrow it. See `reconcile_refresh_scopes` for the full rationale; the
    // short version is that a stale/metadata-scoped refresh token echoes a
    // *subset* of the grant the connection was last (re-)imported with, and
    // writing that subset back down would silently downgrade the connection
    // to match a token that can no longer do what the recorded scopes claim.
    let granted_scopes = tokens.granted_scopes();
    let scopes_to_write = reconcile_refresh_scopes(conn.scopes.as_deref(), &granted_scopes);

    match scopes_to_write {
        Some(scopes) => {
            scope
                .update_connection_tokens_and_scopes(
                    conn.id,
                    &new_access,
                    new_refresh.as_deref(),
                    new_expires,
                    Some(&scopes),
                    None,
                )
                .await
                .map_err(|e| OAuthError::DbError(e.to_string()))?;
        }
        None => {
            // Nothing to change about the recorded scopes (either the refresh
            // echoed no scope, or it echoed a subset we must not narrow to).
            // Persist only the fresh tokens.
            scope
                .update_connection_tokens(conn.id, &new_access, new_refresh.as_deref(), new_expires)
                .await
                .map_err(|e| OAuthError::DbError(e.to_string()))?;
        }
    }

    Ok(tokens.access_token)
}

/// Decide what scope set (if any) a `refresh_token` exchange may write back to
/// a connection's recorded `scopes` column.
///
/// **A refresh must never NARROW the recorded scopes.** This is the fix for a
/// production loop (connection `85844f1a`): a partner reconnected and re-imported
/// full `gmail.readonly` scopes, but the stored refresh token was still a
/// *metadata-only* token from an earlier grant (Google reuses one refresh token
/// per client+user and returns `None` on re-consent, so a re-import can advance
/// the recorded scopes while preserving the old refresh token — see
/// `platform_connections::kernel_import_connection`). On the next self-refresh
/// Google echoed only the metadata scopes; the old code wrote that subset back
/// *unconditionally*, downgrading the recorded set to `calendar/openid/email/
/// profile` (no gmail). The scope-gate then failed `list_messages`, but the
/// connection had already "healed" in the wrong direction — a forever loop.
///
/// Returns:
/// - `Some(union)` — the refresh echoed scopes that *widen or heal* the recorded
///   set (or the recorded set was unknown/`None`). Persist the union so a legacy
///   NULL connection becomes known and a genuinely broadened grant is recorded.
/// - `None` — either the refresh echoed no scopes at all (must not clobber a
///   known set with the empty set), or it echoed only a *subset* of what we
///   already recorded (a stale-refresh-token signal — do not narrow). The caller
///   leaves the recorded `scopes` column untouched.
///
/// The union (rather than "recorded verbatim") lets an incremental-consent
/// refresh that legitimately adds a scope still land, while the subset guard
/// blocks the downgrade.
fn reconcile_refresh_scopes(
    recorded: Option<&[String]>,
    granted: &[String],
) -> Option<Vec<String>> {
    use std::collections::BTreeSet;

    // No scope echoed → nothing to heal, and we must not clobber a known set.
    if granted.is_empty() {
        return None;
    }

    let granted_set: BTreeSet<&str> = granted.iter().map(String::as_str).collect();

    match recorded {
        // Unknown recorded set (legacy import that didn't declare scopes):
        // adopt the echoed grant so the connection becomes known.
        None => Some(granted.to_vec()),
        Some(recorded) => {
            let recorded_set: BTreeSet<&str> = recorded.iter().map(String::as_str).collect();
            // If the refresh echoed everything we already had (possibly more),
            // record the union — this is the widen/heal case. Otherwise the
            // refresh dropped scopes we know were granted: a stale/downgraded
            // refresh token. Never narrow — leave the recorded set as-is.
            if recorded_set.is_subset(&granted_set) {
                let union: Vec<String> = recorded_set
                    .union(&granted_set)
                    .map(|s| s.to_string())
                    .collect();
                Some(union)
            } else {
                None
            }
        }
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
    pub token_type: Option<String>,
    pub scope: Option<String>,
}

impl TokenResponse {
    /// Parse the `scope` field into a normalized Vec. OAuth providers return
    /// granted scopes as a space-separated string (RFC 6749 §5.1); some
    /// (GitHub) use commas instead. We accept either.
    pub fn granted_scopes(&self) -> Vec<String> {
        match &self.scope {
            None => vec![],
            Some(raw) => raw
                .split(|c: char| c.is_whitespace() || c == ',')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect(),
        }
    }

    /// Granted scopes for a connect-time exchange. RFC 6749 §5.1 makes the
    /// `scope` field OPTIONAL when the granted set is identical to what the
    /// client requested — HubSpot, for one, never echoes it. Recording `[]`
    /// in that case turns "provider said nothing" into "known-empty grant",
    /// which the scope gate then enforces; falling back to the requested set
    /// keeps the recorded scopes truthful. A present-but-empty `scope` is
    /// still honored verbatim: the provider explicitly said "no scopes".
    pub fn granted_scopes_or_requested(&self, requested: &[String]) -> Vec<String> {
        match &self.scope {
            None => requested.to_vec(),
            Some(_) => self.granted_scopes(),
        }
    }
}

/// Fetch the user's profile from the provider's userinfo endpoint and extract
/// their email address, if any. Never fails the overall flow: a missing
/// userinfo URL, a non-2xx response, or a response without a recognised email
/// field all return `Ok(None)` — the connection still lands, just unlabeled.
///
/// Response shapes vary per provider:
/// - Google / generic OIDC: `{"email": "..."}`
/// - GitHub: `{"email": null, "login": "..."}` when email is private — fall
///   back to `login@users.noreply.github.com` for a stable label.
/// - Slack (users.identity): `{"user": {"email": "..."}}`
pub async fn fetch_account_email(
    http_client: &reqwest::Client,
    provider: &oauth_provider::OAuthProviderRow,
    access_token: &str,
) -> Result<Option<String>, OAuthError> {
    let Some(url) = provider.userinfo_endpoint.as_deref() else {
        return Ok(None);
    };

    let resp = http_client
        .get(url)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .header("User-Agent", "overslash")
        .send()
        .await
        .map_err(|e| OAuthError::HttpError(e.to_string()))?;

    if !resp.status().is_success() {
        return Ok(None);
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| OAuthError::ParseError(e.to_string()))?;

    Ok(extract_email(&body, &provider.key))
}

fn extract_email(body: &serde_json::Value, provider_key: &str) -> Option<String> {
    // Direct hits at the root — covers Google, Microsoft, most OIDC.
    // Microsoft Graph /me returns `userPrincipalName` for every account but
    // `mail` only when a mailbox is licensed, so keep it in the fallback chain.
    for field in [
        "email",
        "mail",
        "emailAddress",
        "userPrincipalName",
        "preferred_username",
    ] {
        if let Some(s) = body.get(field).and_then(|v| v.as_str()) {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    // Slack's users.identity nests it.
    if let Some(s) = body
        .get("user")
        .and_then(|u| u.get("email"))
        .and_then(|v| v.as_str())
    {
        if !s.is_empty() {
            return Some(s.to_string());
        }
    }
    // GitHub returns `email: null` when the user has hidden it; fall back to
    // a synthesized noreply address so the UI still shows something
    // meaningful rather than a UUID.
    if provider_key == "github" {
        if let Some(login) = body.get("login").and_then(|v| v.as_str()) {
            if !login.is_empty() {
                return Some(format!("{login}@users.noreply.github.com"));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn granted_scopes_parses_space_delimited() {
        let t = TokenResponse {
            access_token: "a".into(),
            refresh_token: None,
            expires_in: None,
            token_type: None,
            scope: Some("openid email profile".into()),
        };
        assert_eq!(t.granted_scopes(), vec!["openid", "email", "profile"]);
    }

    #[test]
    fn granted_scopes_parses_comma_delimited_github() {
        let t = TokenResponse {
            access_token: "a".into(),
            refresh_token: None,
            expires_in: None,
            token_type: None,
            scope: Some("repo,read:user".into()),
        };
        assert_eq!(t.granted_scopes(), vec!["repo", "read:user"]);
    }

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn reconcile_refresh_never_narrows_recorded_scopes() {
        // The production loop: recorded set carries gmail.readonly (a fresh
        // re-import), but the stale metadata refresh token echoes only the
        // metadata subset. Must NOT narrow — leave recorded untouched.
        let recorded = v(&["gmail.readonly", "calendar", "openid", "email", "profile"]);
        let granted = v(&["calendar", "openid", "email", "profile"]);
        assert_eq!(reconcile_refresh_scopes(Some(&recorded), &granted), None);
    }

    #[test]
    fn reconcile_refresh_empty_response_does_not_clobber() {
        let recorded = v(&["gmail.readonly", "calendar"]);
        assert_eq!(reconcile_refresh_scopes(Some(&recorded), &[]), None);
    }

    #[test]
    fn reconcile_refresh_heals_unknown_recorded_set() {
        // Legacy import with NULL scopes: adopt the echoed grant.
        let granted = v(&["gmail.readonly", "calendar"]);
        assert_eq!(
            reconcile_refresh_scopes(None, &granted),
            Some(v(&["gmail.readonly", "calendar"]))
        );
    }

    #[test]
    fn reconcile_refresh_widens_on_broader_grant() {
        // Incremental consent legitimately added a scope: record the union.
        let recorded = v(&["calendar", "openid"]);
        let granted = v(&["calendar", "openid", "gmail.readonly"]);
        let out = reconcile_refresh_scopes(Some(&recorded), &granted).expect("should widen");
        let mut sorted = out;
        sorted.sort();
        assert_eq!(sorted, v(&["calendar", "gmail.readonly", "openid"]));
    }

    #[test]
    fn reconcile_refresh_identical_set_is_noop_union() {
        let recorded = v(&["calendar", "openid"]);
        let granted = v(&["openid", "calendar"]);
        let out = reconcile_refresh_scopes(Some(&recorded), &granted).expect("subset holds");
        let mut sorted = out;
        sorted.sort();
        assert_eq!(sorted, v(&["calendar", "openid"]));
    }

    #[test]
    fn granted_scopes_empty_when_missing() {
        let t = TokenResponse {
            access_token: "a".into(),
            refresh_token: None,
            expires_in: None,
            token_type: None,
            scope: None,
        };
        assert!(t.granted_scopes().is_empty());
    }

    fn token_with_scope(scope: Option<&str>) -> TokenResponse {
        TokenResponse {
            access_token: "a".into(),
            refresh_token: None,
            expires_in: None,
            token_type: None,
            scope: scope.map(String::from),
        }
    }

    #[test]
    fn granted_scopes_or_requested_falls_back_when_scope_omitted() {
        // HubSpot-shaped response: no `scope` field at all → RFC 6749 §5.1
        // says granted == requested.
        let requested = v(&["crm.objects.contacts.read", "crm.objects.deals.read"]);
        let t = token_with_scope(None);
        assert_eq!(t.granted_scopes_or_requested(&requested), requested);
    }

    #[test]
    fn granted_scopes_or_requested_honors_echoed_scope() {
        // Provider echoed a narrower grant than requested — record what it said.
        let requested = v(&["openid", "email", "gmail.readonly"]);
        let t = token_with_scope(Some("openid email"));
        assert_eq!(
            t.granted_scopes_or_requested(&requested),
            v(&["openid", "email"])
        );
    }

    #[test]
    fn granted_scopes_or_requested_honors_explicit_empty_scope() {
        // A present-but-empty `scope` is an explicit "nothing granted".
        let requested = v(&["repo"]);
        let t = token_with_scope(Some(""));
        assert!(t.granted_scopes_or_requested(&requested).is_empty());
    }

    #[test]
    fn extract_email_google_shape() {
        let body = serde_json::json!({"sub": "1", "email": "alice@example.com"});
        assert_eq!(
            extract_email(&body, "google"),
            Some("alice@example.com".into())
        );
    }

    #[test]
    fn extract_email_slack_nested() {
        let body = serde_json::json!({"ok": true, "user": {"email": "bob@slack.com"}});
        assert_eq!(extract_email(&body, "slack"), Some("bob@slack.com".into()));
    }

    #[test]
    fn extract_email_github_falls_back_to_login() {
        let body = serde_json::json!({"login": "octocat", "email": null});
        assert_eq!(
            extract_email(&body, "github"),
            Some("octocat@users.noreply.github.com".into())
        );
    }

    #[test]
    fn extract_email_github_uses_real_email_when_public() {
        let body = serde_json::json!({"login": "octocat", "email": "real@octocat.dev"});
        assert_eq!(
            extract_email(&body, "github"),
            Some("real@octocat.dev".into())
        );
    }

    #[test]
    fn extract_email_returns_none_when_no_hint() {
        let body = serde_json::json!({"name": "Alice"});
        assert_eq!(extract_email(&body, "google"), None);
    }
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
