use axum::{
    Router,
    extract::{Path, Query, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{
    AppState,
    error::AppError,
    services::{jwt, oauth},
};
use overslash_core::crypto;
use overslash_db::repos::{oauth_provider, org};
use overslash_db::{OrgScope, SystemScope};

pub fn router() -> Router<AppState> {
    Router::new()
        // Generic provider auth
        .route("/auth/login/{provider_key}", get(provider_login))
        .route("/auth/callback/{provider_key}", get(provider_callback))
        .route("/auth/providers", get(list_auth_providers))
        // Backward compat — Google callback must remain a real handler (not redirect)
        // because existing Google OAuth apps have this URL registered as redirect_uri
        .route("/auth/google/login", get(google_login_compat))
        .route("/auth/google/callback", get(google_callback_compat))
        // Session endpoints
        .route("/auth/me", get(me))
        .route("/auth/me/identity", get(me_identity))
        .route("/auth/dev/token", get(dev_token))
        .route("/auth/logout", post(logout))
}

async fn logout() -> impl IntoResponse {
    let clear = "oss_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0";
    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, clear.parse().unwrap());
    (headers, axum::Json(json!({ "status": "logged_out" })))
}

// ---------------------------------------------------------------------------
// Query params
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct LoginQuery {
    /// Org slug — required for enterprise SSO, optional for social providers.
    org: Option<String>,
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: String,
    state: String,
}

#[derive(Deserialize)]
struct ProvidersQuery {
    org: Option<String>,
}

// ---------------------------------------------------------------------------
// Normalized user info (provider-agnostic)
// ---------------------------------------------------------------------------

struct NormalizedUserInfo {
    provider_key: String,
    external_id: String,
    email: String,
    name: Option<String>,
    picture: Option<String>,
}

// ---------------------------------------------------------------------------
// Generic provider login
// ---------------------------------------------------------------------------

async fn provider_login(
    State(state): State<AppState>,
    Path(provider_key): Path<String>,
    Query(query): Query<LoginQuery>,
) -> Result<Response, AppError> {
    let provider = oauth_provider::get_by_key(&state.db, &provider_key)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("unknown provider: {provider_key}")))?;

    let (client_id, _client_secret) =
        resolve_auth_credentials(&state, &provider_key, query.org.as_deref()).await?;

    let pkce = if provider.supports_pkce {
        Some(oauth::generate_pkce())
    } else {
        None
    };

    let nonce = Uuid::new_v4().to_string();
    let state_param = format!("login:{provider_key}:{nonce}");

    let redirect_uri = format!("{}/auth/callback/{}", state.config.public_url, provider_key);

    let scopes = scopes_for_provider(&provider_key);

    let auth_url = oauth::build_auth_url(
        &provider,
        &client_id,
        &redirect_uri,
        &scopes,
        &state_param,
        pkce.as_ref().map(|p| p.challenge.as_str()),
    );

    let nonce_cookie = format!(
        "oss_auth_nonce={}; HttpOnly; SameSite=Lax; Path=/auth; Max-Age=600",
        nonce
    );
    let verifier_value = pkce.as_ref().map_or("none", |p| p.verifier.as_str());
    let verifier_cookie = format!(
        "oss_auth_verifier={}; HttpOnly; SameSite=Lax; Path=/auth; Max-Age=600",
        verifier_value
    );
    // Persist org slug across the OAuth redirect so the callback can resolve
    // DB-stored credentials. Value is "none" when org context isn't needed
    // (env-var social providers). Sanitize to prevent header injection.
    let org_slug_value = query
        .org
        .as_deref()
        .filter(|s| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.'))
        })
        .unwrap_or("none");
    let org_cookie = format!(
        "oss_auth_org={}; HttpOnly; SameSite=Lax; Path=/auth; Max-Age=600",
        org_slug_value
    );

    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, nonce_cookie.parse().unwrap());
    headers.append(header::SET_COOKIE, verifier_cookie.parse().unwrap());
    headers.append(header::SET_COOKIE, org_cookie.parse().unwrap());

    Ok((headers, Redirect::to(&auth_url)).into_response())
}

// ---------------------------------------------------------------------------
// Generic provider callback
// ---------------------------------------------------------------------------

async fn provider_callback(
    State(state): State<AppState>,
    Path(provider_key): Path<String>,
    Query(params): Query<CallbackQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    // Parse state: "login:<provider_key>:<nonce>"
    let state_parts: Vec<&str> = params.state.splitn(3, ':').collect();
    if state_parts.len() != 3 || state_parts[0] != "login" {
        return Err(AppError::BadRequest("invalid state parameter".into()));
    }
    let state_provider = state_parts[1];
    let nonce = state_parts[2];

    if state_provider != provider_key {
        return Err(AppError::BadRequest("provider mismatch in state".into()));
    }

    // Verify CSRF nonce
    let cookie_nonce = extract_cookie(&headers, "oss_auth_nonce")
        .ok_or_else(|| AppError::BadRequest("missing auth nonce cookie".into()))?;
    if cookie_nonce != nonce {
        return Err(AppError::BadRequest("nonce mismatch".into()));
    }

    let provider = oauth_provider::get_by_key(&state.db, &provider_key)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("unknown provider: {provider_key}")))?;

    // Recover org slug from cookie (set during provider_login)
    let org_slug = extract_cookie(&headers, "oss_auth_org").filter(|s| s != "none");

    let (client_id, client_secret) =
        resolve_auth_credentials(&state, &provider_key, org_slug.as_deref()).await?;

    // PKCE verifier (may be "none" if provider doesn't support PKCE)
    let code_verifier = extract_cookie(&headers, "oss_auth_verifier");
    let verifier_ref = code_verifier.as_deref().filter(|v| *v != "none");

    let redirect_uri = format!("{}/auth/callback/{}", state.config.public_url, provider_key);

    let tokens = oauth::exchange_code(
        &state.http_client,
        &provider,
        &client_id,
        &client_secret,
        &params.code,
        &redirect_uri,
        verifier_ref,
    )
    .await
    .map_err(|e| AppError::Internal(format!("token exchange failed: {e}")))?;

    // Fetch user info (provider-specific)
    let userinfo = fetch_userinfo(
        &state.http_client,
        &provider,
        &provider_key,
        &tokens.access_token,
    )
    .await?;

    // Find or provision user + update profile
    let (org_id, identity_id, email) = find_or_provision_user(&state, &userinfo).await?;

    // Mint JWT
    let jwt_secret = signing_key_bytes(&state.config.signing_key);
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let claims = jwt::Claims {
        sub: identity_id,
        org: org_id,
        email: email.clone(),
        iat: now,
        exp: now + 7 * 24 * 3600,
    };
    let token = jwt::mint(&jwt_secret, &claims)
        .map_err(|e| AppError::Internal(format!("jwt mint failed: {e}")))?;

    // Set session cookie + clear auth cookies
    let session_cookie = format!(
        "oss_session={}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800",
        token
    );
    let clear_nonce = "oss_auth_nonce=; HttpOnly; SameSite=Lax; Path=/auth; Max-Age=0";
    let clear_verifier = "oss_auth_verifier=; HttpOnly; SameSite=Lax; Path=/auth; Max-Age=0";
    let clear_org = "oss_auth_org=; HttpOnly; SameSite=Lax; Path=/auth; Max-Age=0";

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(header::SET_COOKIE, session_cookie.parse().unwrap());
    resp_headers.append(header::SET_COOKIE, clear_nonce.parse().unwrap());
    resp_headers.append(header::SET_COOKIE, clear_verifier.parse().unwrap());
    resp_headers.append(header::SET_COOKIE, clear_org.parse().unwrap());

    Ok((resp_headers, Redirect::to(&state.config.dashboard_url)).into_response())
}

// ---------------------------------------------------------------------------
// Backward-compat Google routes
// ---------------------------------------------------------------------------

async fn google_login_compat(
    state: State<AppState>,
    query: Query<LoginQuery>,
) -> Result<Response, AppError> {
    provider_login(state, Path("google".to_string()), query).await
}

async fn google_callback_compat(
    state: State<AppState>,
    Query(mut params): Query<CallbackQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    // Handle old state format "login:<nonce>" from in-flight sessions
    // started before this deployment. Convert to new format "login:google:<nonce>".
    if params.state.starts_with("login:") {
        let parts: Vec<&str> = params.state.splitn(3, ':').collect();
        if parts.len() == 2 {
            params.state = format!("login:google:{}", parts[1]);
        }
    }
    provider_callback(state, Path("google".to_string()), Query(params), headers).await
}

// ---------------------------------------------------------------------------
// List available auth providers (for login page)
// ---------------------------------------------------------------------------

async fn list_auth_providers(
    State(state): State<AppState>,
    Query(query): Query<ProvidersQuery>,
) -> Result<impl IntoResponse, AppError> {
    let mut providers = Vec::new();

    // Always include env-var-configured social providers
    if state.config.google_auth_client_id.is_some()
        && state.config.google_auth_client_secret.is_some()
    {
        providers.push(json!({
            "key": "google",
            "display_name": "Google",
            "source": "env",
        }));
    }
    if state.config.github_auth_client_id.is_some()
        && state.config.github_auth_client_secret.is_some()
    {
        providers.push(json!({
            "key": "github",
            "display_name": "GitHub",
            "source": "env",
        }));
    }

    // If org slug provided, also include DB-configured IdPs for that org
    if let Some(slug) = &query.org {
        if let Some(org_row) = org::get_by_slug(&state.db, slug).await? {
            // Login bootstrap: the user has not authenticated yet, but the
            // org has been resolved from a public slug. Mint an OrgScope to
            // use the scope-bound enabled-IdP listing helper.
            let bootstrap_scope = overslash_db::OrgScope::new(org_row.id, state.db.clone());
            let configs = bootstrap_scope.list_enabled_org_idp_configs().await?;
            for config in configs {
                // Skip if already added from env vars
                if providers.iter().any(|p| p["key"] == config.provider_key) {
                    continue;
                }
                let display_name = oauth_provider::get_by_key(&state.db, &config.provider_key)
                    .await?
                    .map(|p| p.display_name)
                    .unwrap_or_else(|| config.provider_key.clone());
                providers.push(json!({
                    "key": config.provider_key,
                    "display_name": display_name,
                    "source": "db",
                }));
            }
        }
    }

    // Dev login indicator
    if state.config.dev_auth_enabled {
        providers.push(json!({
            "key": "dev",
            "display_name": "Dev Login",
            "source": "env",
        }));
    }

    Ok(axum::Json(json!({ "providers": providers })))
}

// ---------------------------------------------------------------------------
// Session endpoints (unchanged)
// ---------------------------------------------------------------------------

async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let token = extract_cookie(&headers, "oss_session")
        .ok_or_else(|| AppError::Unauthorized("not authenticated".into()))?;

    let jwt_secret = signing_key_bytes(&state.config.signing_key);
    let claims = jwt::verify(&jwt_secret, &token)
        .map_err(|_| AppError::Unauthorized("invalid or expired session".into()))?;

    // Resolve the user's ACL level from group grants. Construct an OrgScope
    // inline from the verified JWT claims so the ceiling lookup is bounded
    // by the caller's org at the SQL boundary.
    let scope = overslash_db::OrgScope::new(claims.org, state.db.clone());
    let ceiling = scope.get_ceiling_for_user(claims.sub).await?;
    let acl_level = ceiling
        .grants
        .iter()
        .filter(|g| g.template_key == "overslash")
        .filter_map(|g| overslash_core::permissions::AccessLevel::parse(&g.access_level))
        .max()
        .map(|l| l.to_string());

    Ok(axum::Json(json!({
        "identity_id": claims.sub,
        "org_id": claims.org,
        "email": claims.email,
        "acl_level": acl_level,
    })))
}

async fn me_identity(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let token = extract_cookie(&headers, "oss_session")
        .ok_or_else(|| AppError::Unauthorized("not authenticated".into()))?;

    let jwt_secret = signing_key_bytes(&state.config.signing_key);
    let claims = jwt::verify(&jwt_secret, &token)
        .map_err(|_| AppError::Unauthorized("invalid or expired session".into()))?;

    let scope = OrgScope::new(claims.org, state.db.clone());
    let ident = scope
        .get_identity(claims.sub)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;

    Ok(axum::Json(json!({
        "identity_id": ident.id,
        "org_id": ident.org_id,
        "email": claims.email,
        "name": ident.name,
        "kind": ident.kind,
        "external_id": ident.external_id,
    })))
}

// ---------------------------------------------------------------------------
// Dev token (unchanged)
// ---------------------------------------------------------------------------

async fn dev_token(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    if !state.config.dev_auth_enabled {
        return Err(AppError::NotFound("not found".into()));
    }

    let dev_email = "dev@overslash.local";
    let system = SystemScope::new_internal(state.db.clone());
    let (org_id, identity_id) =
        if let Some(existing) = system.find_user_identity_by_email(dev_email).await? {
            (existing.org_id, existing.id)
        } else {
            match org::create(&state.db, "Dev Org", "dev-org").await {
                Ok(new_org) => {
                    let new_scope = OrgScope::new(new_org.id, state.db.clone());
                    let new_identity = new_scope
                        .create_identity_with_email(
                            "Dev User",
                            "user",
                            Some("dev-local"),
                            Some(dev_email),
                            json!({"dev": true}),
                        )
                        .await?;
                    // Bootstrap system assets and add dev user as admin
                    overslash_db::repos::org_bootstrap::bootstrap_org(
                        &state.db,
                        new_org.id,
                        Some(new_identity.id),
                    )
                    .await?;
                    (new_org.id, new_identity.id)
                }
                Err(sqlx::Error::Database(ref e)) if e.is_unique_violation() => {
                    let existing = system
                        .find_user_identity_by_email(dev_email)
                        .await?
                        .ok_or_else(|| AppError::Internal("dev race: identity missing".into()))?;
                    (existing.org_id, existing.id)
                }
                Err(e) => return Err(e.into()),
            }
        };

    let jwt_secret = signing_key_bytes(&state.config.signing_key);
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let claims = jwt::Claims {
        sub: identity_id,
        org: org_id,
        email: dev_email.into(),
        iat: now,
        exp: now + 7 * 24 * 3600,
    };
    let token = jwt::mint(&jwt_secret, &claims)
        .map_err(|e| AppError::Internal(format!("jwt mint failed: {e}")))?;

    let session_cookie = format!(
        "oss_session={}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800",
        token
    );

    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, session_cookie.parse().unwrap());

    Ok((
        headers,
        axum::Json(json!({
            "status": "authenticated",
            "org_id": org_id,
            "identity_id": identity_id,
            "email": dev_email,
            "token": token,
        })),
    ))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve auth credentials for a provider. Precedence:
/// 1. Environment variables (e.g. GOOGLE_AUTH_CLIENT_ID)
/// 2. DB-stored org_idp_config (requires org context via slug)
async fn resolve_auth_credentials(
    state: &AppState,
    provider_key: &str,
    org_slug: Option<&str>,
) -> Result<(String, String), AppError> {
    // 1. Env vars take precedence
    if let Some(creds) = state.config.env_auth_credentials(provider_key) {
        return Ok(creds);
    }

    // 2. DB config — need org context
    if let Some(slug) = org_slug {
        let org_row = org::get_by_slug(&state.db, slug)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("org not found: {slug}")))?;

        // Login bootstrap: org resolved from a public slug, no scope yet.
        let bootstrap_scope = overslash_db::OrgScope::new(org_row.id, state.db.clone());
        let config = bootstrap_scope
            .get_org_idp_config_by_provider(provider_key)
            .await?
            .ok_or_else(|| {
                AppError::NotFound(format!(
                    "provider {provider_key} not configured for org {slug}"
                ))
            })?;

        if !config.enabled {
            return Err(AppError::NotFound(format!(
                "provider {provider_key} is disabled for org {slug}"
            )));
        }

        let enc_key = crypto::parse_hex_key(&state.config.secrets_encryption_key)
            .map_err(|e| AppError::Internal(format!("invalid encryption key: {e}")))?;
        let client_id = String::from_utf8(
            crypto::decrypt(&enc_key, &config.encrypted_client_id)
                .map_err(|e| AppError::Internal(format!("decrypt client_id: {e}")))?,
        )
        .map_err(|_| AppError::Internal("invalid client_id utf-8".into()))?;
        let client_secret = String::from_utf8(
            crypto::decrypt(&enc_key, &config.encrypted_client_secret)
                .map_err(|e| AppError::Internal(format!("decrypt client_secret: {e}")))?,
        )
        .map_err(|_| AppError::Internal("invalid client_secret utf-8".into()))?;

        return Ok((client_id, client_secret));
    }

    Err(AppError::NotFound(format!(
        "no credentials configured for provider {provider_key}"
    )))
}

/// Return the appropriate scopes for a provider.
fn scopes_for_provider(provider_key: &str) -> Vec<String> {
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
async fn fetch_userinfo(
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

/// Find an existing user or provision a new one. On subsequent logins, updates
/// the user's profile (name, avatar) from IdP claims.
async fn find_or_provision_user(
    state: &AppState,
    userinfo: &NormalizedUserInfo,
) -> Result<(Uuid, Uuid, String), AppError> {
    let system = SystemScope::new_internal(state.db.clone());
    // Check if identity already exists by email
    if let Some(existing) = system.find_user_identity_by_email(&userinfo.email).await? {
        // Update profile on subsequent login
        let display_name = userinfo.name.as_deref().unwrap_or(&userinfo.email);
        let metadata = json!({
            "provider": userinfo.provider_key,
            "external_id": userinfo.external_id,
            "name": userinfo.name,
            "picture": userinfo.picture,
        });
        let existing_scope = OrgScope::new(existing.org_id, state.db.clone());
        if let Err(e) = existing_scope
            .update_identity_profile(existing.id, display_name, metadata)
            .await
        {
            tracing::warn!(identity_id = %existing.id, error = %e, "failed to update profile on login");
        }
        return Ok((existing.org_id, existing.id, userinfo.email.clone()));
    }

    // New user — try to match by email domain to an existing org
    let email_domain = userinfo
        .email
        .rsplit('@')
        .next()
        .unwrap_or("")
        .to_lowercase();

    let display_name = userinfo.name.as_deref().unwrap_or(&userinfo.email);
    let metadata = json!({
        "provider": userinfo.provider_key,
        "external_id": userinfo.external_id,
        "name": userinfo.name,
        "picture": userinfo.picture,
    });

    // Check if any org has this email domain configured for the same provider.
    // This is a true cross-org lookup (no scope yet — we don't know which
    // org the user belongs to), so it goes through SystemScope.
    let system = overslash_db::SystemScope::new_internal(state.db.clone());
    let domain_matches = system
        .find_idp_configs_by_email_domain(&email_domain)
        .await?;
    let matched_config = domain_matches
        .iter()
        .find(|c| c.provider_key == userinfo.provider_key);
    if let Some(matched_config) = matched_config {
        // Provision user in the matched org
        let matched_scope = OrgScope::new(matched_config.org_id, state.db.clone());
        match matched_scope
            .create_identity_with_email(
                display_name,
                "user",
                Some(&userinfo.external_id),
                Some(&userinfo.email),
                metadata,
            )
            .await
        {
            Ok(new_identity) => {
                // Auto-join the Everyone group
                overslash_db::repos::org_bootstrap::add_to_everyone_group(
                    &state.db,
                    matched_config.org_id,
                    new_identity.id,
                )
                .await?;
                return Ok((
                    matched_config.org_id,
                    new_identity.id,
                    userinfo.email.clone(),
                ));
            }
            Err(sqlx::Error::Database(ref e)) if e.is_unique_violation() => {
                // Race — another request created this identity
                let existing = system
                    .find_user_identity_by_email(&userinfo.email)
                    .await?
                    .ok_or_else(|| AppError::Internal("race: identity vanished".into()))?;
                return Ok((existing.org_id, existing.id, userinfo.email.clone()));
            }
            Err(e) => return Err(e.into()),
        }
    }

    // No domain match — create new org + identity (default behavior)
    let new_org = {
        let mut attempts = 0;
        loop {
            let slug = generate_slug(&userinfo.email);
            match org::create(&state.db, display_name, &slug).await {
                Ok(o) => break o,
                Err(sqlx::Error::Database(ref e)) if e.is_unique_violation() && attempts < 3 => {
                    attempts += 1;
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
    };

    let new_org_scope = OrgScope::new(new_org.id, state.db.clone());
    match new_org_scope
        .create_identity_with_email(
            display_name,
            "user",
            Some(&userinfo.external_id),
            Some(&userinfo.email),
            metadata,
        )
        .await
    {
        Ok(new_identity) => {
            // Bootstrap system assets and add creator as admin
            overslash_db::repos::org_bootstrap::bootstrap_org(
                &state.db,
                new_org.id,
                Some(new_identity.id),
            )
            .await?;
            Ok((new_org.id, new_identity.id, userinfo.email.clone()))
        }
        Err(sqlx::Error::Database(ref e)) if e.is_unique_violation() => {
            let existing = system
                .find_user_identity_by_email(&userinfo.email)
                .await?
                .ok_or_else(|| AppError::Internal("race: identity vanished".into()))?;
            Ok((existing.org_id, existing.id, userinfo.email.clone()))
        }
        Err(e) => Err(e.into()),
    }
}

fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix(&format!("{name}=")) {
            return Some(value.to_string());
        }
    }
    None
}

fn signing_key_bytes(signing_key: &str) -> Vec<u8> {
    hex::decode(signing_key).unwrap_or_else(|_| signing_key.as_bytes().to_vec())
}

fn generate_slug(email: &str) -> String {
    let local = email.split('@').next().unwrap_or("user");
    let clean: String = local
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect();
    let suffix: u32 = rand::random::<u32>() % 10000;
    format!("{}-{:04}", clean.to_lowercase(), suffix)
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
