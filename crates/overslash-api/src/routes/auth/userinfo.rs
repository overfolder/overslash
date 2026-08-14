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
) -> Result<NormalizedUserInfo, AppError> {
    match provider_key {
        "github" => fetch_github_userinfo(http_client, provider_key, access_token).await,
        _ => fetch_oidc_userinfo(http_client, provider, provider_key, access_token).await,
    }
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
}
