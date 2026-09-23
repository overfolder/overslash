//! IdP credential resolution and provider userinfo fetching.

use super::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve auth credentials for a provider.
///
/// When no org is in scope (root apex sign-up / personal-org creation), the
/// deployment's env vars are the only path. When an org **is** in scope
/// (corp subdomain, or legacy `?org=<slug>` on the apex), the whole decision
/// — which providers the org can sign in with, and whose OAuth app backs
/// each — belongs to `services::org_signin`, so this path can't drift from
/// what `/auth/providers` advertises on the login page.
pub(super) async fn resolve_auth_credentials(
    state: &AppState,
    ext: &axum::http::Extensions,
    provider_key: &str,
    org_slug: Option<&str>,
) -> Result<(String, String), AppError> {
    // No org in scope → env-only path. This is the apex (root) login surface
    // for personal orgs / org-creator bootstrap.
    if org_slug.is_none() {
        return state
            .config
            .env_auth_credentials(provider_key)
            .ok_or_else(|| {
                AppError::NotFound(format!(
                    "provider {provider_key} is not configured at the root level"
                ))
            });
    }

    // Org in scope → whatever `services::org_signin` says the org can sign in
    // with. A dedicated `org_idp_configs` row wins; Overslash-managed sign-in
    // covers the rest when the org opted in.
    if let Some(slug) = org_slug {
        let org_row = org::get_by_slug(state.db(ext), slug)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("org not found: {slug}")))?;

        // The two unavailable cases point an admin at different fixes: add an
        // IdP, or re-enable the one that's there.
        return match org_signin::resolve_org_signin_credentials(
            state,
            ext,
            org_row.id,
            provider_key,
        )
        .await?
        {
            org_signin::CredentialLookup::Found(client_id, client_secret) => {
                Ok((client_id, client_secret))
            }
            org_signin::CredentialLookup::Disabled => Err(AppError::NotFound(format!(
                "provider {provider_key} is disabled for org {slug}"
            ))),
            org_signin::CredentialLookup::NotConfigured => Err(AppError::NotFound(format!(
                "provider {provider_key} not configured for org {slug}"
            ))),
        };
    }

    Err(AppError::NotFound(format!(
        "no credentials configured for provider {provider_key}"
    )))
}

/// Return the appropriate scopes for a provider.
pub(super) fn scopes_for_provider(provider_key: &str) -> Vec<String> {
    match provider_key {
        "google" => vec![
            "openid".to_string(),
            "email".to_string(),
            "profile".to_string(),
        ],
        "github" => vec!["read:user".to_string(), "user:email".to_string()],
        // Generic OIDC providers — request standard scopes
        _ => vec![
            "openid".to_string(),
            "email".to_string(),
            "profile".to_string(),
        ],
    }
}

/// Fetch user info from the IdP, normalizing across providers.
pub(super) async fn fetch_userinfo(
    http_client: &reqwest::Client,
    provider: &oauth_provider::OAuthProviderRow,
    provider_key: &str,
    access_token: &str,
    id_token: Option<&str>,
    expected_nonce: Option<&str>,
) -> Result<NormalizedUserInfo, AppError> {
    let mut info = match provider_key {
        "github" => fetch_github_userinfo(http_client, provider_key, access_token).await?,
        _ => fetch_oidc_userinfo(http_client, provider, provider_key, access_token).await?,
    };

    // Merge in the ID token's claims. Needed because release policy differs by
    // IdP: Okta and Auth0 can put groups on `/userinfo`, Entra will not put
    // them there at all. `/userinfo` wins on conflict — it is the fresher of
    // the two and is fetched with the access token we just obtained.
    if let Some(raw) = id_token {
        for (k, v) in id_token_claims(raw, expected_nonce) {
            info.claims.entry(k).or_insert(v);
        }
    }

    Ok(info)
}

/// Claims from an ID token, or empty if it is unusable.
///
/// The signature is **not** verified, which OIDC Core §3.1.3.7 permits for
/// exactly this situation: the token came back over TLS on our own direct
/// call to the provider's token endpoint, in response to a code we generated
/// and bound with PKCE. There is no third party in the path to forge it.
///
/// What is checked is `nonce`, against the value minted at login and held in
/// the `oss_auth_nonce` cookie. That is the anti-replay binding — it rejects
/// an ID token lifted from some other login. A token with the wrong nonce is
/// discarded entirely rather than partially trusted.
///
/// Hardening to full `jwks_uri` signature verification is tracked in
/// TECH_DEBT.md; `oauth_providers.jwks_uri` is already populated for the
/// builtin providers and unused.
fn id_token_claims(
    id_token: &str,
    expected_nonce: Option<&str>,
) -> serde_json::Map<String, serde_json::Value> {
    let empty = serde_json::Map::new();

    // header.payload.signature — we want the middle segment.
    let Some(payload_b64) = id_token.split('.').nth(1) else {
        return empty;
    };
    let Ok(bytes) = base64_url_decode(payload_b64) else {
        return empty;
    };
    let Ok(serde_json::Value::Object(claims)) = serde_json::from_slice(&bytes) else {
        return empty;
    };

    if let Some(expected) = expected_nonce {
        // A missing `nonce` is tolerated: not every provider echoes it, and
        // the ID token's provenance does not rest on it. A *present but
        // different* nonce is a replay signal and voids the whole token.
        if let Some(actual) = claims.get("nonce").and_then(|v| v.as_str())
            && actual != expected
        {
            tracing::warn!("id_token nonce mismatch; ignoring its claims");
            return empty;
        }
    }

    claims
}

/// Decode one base64url segment of a JWT (no padding, per RFC 7515 §2).
fn base64_url_decode(segment: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(segment)
}

/// Fetch user info from GitHub's API (non-OIDC).
async fn fetch_github_userinfo(
    http_client: &reqwest::Client,
    provider_key: &str,
    access_token: &str,
) -> Result<NormalizedUserInfo, AppError> {
    // GET /user for profile
    let user: GitHubUser = http_client
        .get("https://api.github.com/user")
        .bearer_auth(access_token)
        .header("User-Agent", "Overslash")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await?
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("github user fetch failed: {e}")))?;

    // GET /user/emails for primary verified email
    let emails: Vec<GitHubEmail> = http_client
        .get("https://api.github.com/user/emails")
        .bearer_auth(access_token)
        .header("User-Agent", "Overslash")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await?
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("github emails fetch failed: {e}")))?;

    let primary_email = emails
        .iter()
        .find(|e| e.primary && e.verified)
        .or_else(|| emails.iter().find(|e| e.verified))
        .map(|e| e.email.clone())
        .ok_or_else(|| AppError::BadRequest("no verified email found on GitHub account".into()))?;

    Ok(NormalizedUserInfo {
        provider_key: provider_key.to_string(),
        external_id: user.id.to_string(),
        email: primary_email,
        name: user.name.or(Some(user.login)),
        picture: user.avatar_url,
        // GitHub is not OIDC and exposes no group claim on this endpoint.
        claims: serde_json::Map::new(),
    })
}

/// Fetch user info from a standard OIDC userinfo endpoint.
async fn fetch_oidc_userinfo(
    http_client: &reqwest::Client,
    provider: &oauth_provider::OAuthProviderRow,
    provider_key: &str,
    access_token: &str,
) -> Result<NormalizedUserInfo, AppError> {
    let userinfo_url = provider.userinfo_endpoint.as_deref().ok_or_else(|| {
        AppError::Internal(format!("{provider_key} provider missing userinfo endpoint"))
    })?;

    let info: OidcUserInfo = http_client
        .get(userinfo_url)
        .bearer_auth(access_token)
        .send()
        .await?
        .json()
        .await
        .map_err(|e| {
            AppError::Internal(format!("failed to fetch userinfo from {provider_key}: {e}"))
        })?;

    let email = info
        .email
        .ok_or_else(|| AppError::BadRequest("IdP did not return an email address".into()))?;

    Ok(NormalizedUserInfo {
        provider_key: provider_key.to_string(),
        external_id: info.sub,
        email,
        name: info.name,
        picture: info.picture,
        claims: info.extra,
    })
}

// ---------------------------------------------------------------------------
// Provider-specific response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct GitHubUser {
    id: u64,
    login: String,
    name: Option<String>,
    avatar_url: Option<String>,
}

#[derive(Deserialize)]
struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

#[derive(Deserialize)]
struct OidcUserInfo {
    sub: String,
    email: Option<String>,
    name: Option<String>,
    picture: Option<String>,
    /// Everything else the IdP returned. Previously discarded; kept so an
    /// org's own IdP can assert group membership under a claim name the admin
    /// configures.
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}
