//! IdP credential resolution and provider userinfo fetching.

use super::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve auth credentials for a provider. Trust-domain rule
/// (DECISIONS.md D12, docs/design/multi_org_auth.md): when an org is in
/// scope (corp subdomain or legacy `?org=<slug>` on the apex), only the
/// org's own `org_idp_configs` row may grant admission — Overslash-managed
/// env-var creds are root-apex-only. When no org is in scope, env vars are
/// the only path (root sign-up / personal-org creation).
///
/// Exception (migration 066): when `orgs.allow_overslash_managed_signin`
/// is true AND the org has no dedicated `org_idp_configs` row for the
/// provider, fall through to the server's env-var creds. A dedicated
/// config always wins — it's an explicit admin setup. Admission is
/// gated separately in `provision_org_subdomain` via `org_invites`, so
/// the IdP's email claim alone cannot admit a stranger.
///
/// When the IdP config has NULL `encrypted_client_*` fields, it defers to
/// the org's OAuth App Credentials (org secrets `OAUTH_{PROVIDER}_CLIENT_ID/SECRET`).
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

    // Org in scope → DB-config-only. Strict isolation.
    if let Some(slug) = org_slug {
        let org_row = org::get_by_slug(state.db(ext), slug)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("org not found: {slug}")))?;

        // Login bootstrap: org resolved from a public slug, no scope yet.
        let bootstrap_scope = overslash_db::OrgScope::new(org_row.id, state.db_pool(ext));
        let config_opt = bootstrap_scope
            .get_org_idp_config_by_provider(provider_key)
            .await?;

        let enc_key = state
            .config
            .keyring()
            .map_err(|e| AppError::Internal(format!("invalid encryption key: {e}")))?;

        // Managed-signin path: the org has no dedicated IdP row for this
        // provider. Org-level OAuth App Credentials are an explicit admin
        // override and win over the operator-shared env creds, so check them
        // first; the `{PROVIDER}_AUTH_*` env vars are the fallback when no org
        // credentials are configured. When neither is set, fall through to the
        // dedicated-IdP path (returns the same helpful 404 as before if absent).
        if org_row.allow_overslash_managed_signin && config_opt.is_none() {
            if let Some(creds) = crate::services::client_credentials::resolve_org_oauth_secrets(
                &bootstrap_scope,
                &enc_key,
                provider_key,
            )
            .await?
            {
                return Ok((creds.client_id, creds.client_secret));
            }
            if let Some(creds) = state.config.env_auth_credentials(provider_key) {
                return Ok(creds);
            }
        }

        let config = config_opt.ok_or_else(|| {
            AppError::NotFound(format!(
                "provider {provider_key} not configured for org {slug}"
            ))
        })?;

        if !config.enabled {
            return Err(AppError::NotFound(format!(
                "provider {provider_key} is disabled for org {slug}"
            )));
        }

        // IdP uses its own dedicated credentials — decrypt them directly.
        if let (Some(enc_id), Some(enc_secret)) = (
            config.encrypted_client_id.as_deref(),
            config.encrypted_client_secret.as_deref(),
        ) {
            let client_id = String::from_utf8(
                crypto::decrypt(&enc_key, enc_id)
                    .map_err(|e| AppError::Internal(format!("decrypt client_id: {e}")))?,
            )
            .map_err(|_| AppError::Internal("invalid client_id utf-8".into()))?;
            let client_secret = String::from_utf8(
                crypto::decrypt(&enc_key, enc_secret)
                    .map_err(|e| AppError::Internal(format!("decrypt client_secret: {e}")))?,
            )
            .map_err(|_| AppError::Internal("invalid client_secret utf-8".into()))?;
            return Ok((client_id, client_secret));
        }

        // IdP defers to org-level OAuth App Credentials (SPEC §3).
        let creds = crate::services::client_credentials::resolve_org_oauth_secrets(
            &bootstrap_scope,
            &enc_key,
            provider_key,
        )
        .await?
        .ok_or_else(|| {
            AppError::BadRequest(format!(
                "IdP for provider '{provider_key}' is configured to use org OAuth App \
                 Credentials, but no org-level credentials are set. \
                 Add them in Org Settings → OAuth App Credentials, or reconfigure \
                 the IdP with dedicated credentials."
            ))
        })?;
        return Ok((creds.client_id, creds.client_secret));
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
