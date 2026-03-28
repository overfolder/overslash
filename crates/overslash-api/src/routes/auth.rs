use axum::{
    Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{
    AppState,
    error::AppError,
    services::{jwt, oauth},
};
use overslash_db::repos::{identity, oauth_provider, org};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/google/login", get(google_login))
        .route("/auth/google/callback", get(google_callback))
        .route("/auth/me", get(me))
        .route("/auth/dev/token", get(dev_token))
}

/// Initiate Google OAuth login flow.
async fn google_login(State(state): State<AppState>) -> Result<Response, AppError> {
    let (client_id, _) = google_credentials(&state)?;

    let provider = oauth_provider::get_by_key(&state.db, "google")
        .await?
        .ok_or_else(|| AppError::Internal("google oauth provider not configured".into()))?;

    let pkce = oauth::generate_pkce();

    // State contains only the CSRF nonce — verifier goes in a cookie
    let nonce = Uuid::new_v4().to_string();
    let state_param = format!("login:{nonce}");

    let redirect_uri = format!("{}/auth/google/callback", state.config.public_url);
    let scopes = vec![
        "openid".to_string(),
        "email".to_string(),
        "profile".to_string(),
    ];

    let auth_url = oauth::build_auth_url(
        &provider,
        &client_id,
        &redirect_uri,
        &scopes,
        &state_param,
        Some(&pkce.challenge),
    );

    // Set CSRF nonce cookie + PKCE verifier cookie (HttpOnly, never exposed in URL)
    let nonce_cookie = format!(
        "oss_auth_nonce={}; HttpOnly; SameSite=Lax; Path=/auth; Max-Age=600",
        nonce
    );
    let verifier_cookie = format!(
        "oss_auth_verifier={}; HttpOnly; SameSite=Lax; Path=/auth; Max-Age=600",
        pkce.verifier
    );

    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, nonce_cookie.parse().unwrap());
    headers.append(header::SET_COOKIE, verifier_cookie.parse().unwrap());

    Ok((headers, Redirect::to(&auth_url)).into_response())
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: String,
    state: String,
}

/// Handle Google OAuth callback — exchange code, find-or-create user, set session.
async fn google_callback(
    State(state): State<AppState>,
    Query(params): Query<CallbackQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (client_id, client_secret) = google_credentials(&state)?;

    // Parse state: "login:<nonce>"
    let nonce = params
        .state
        .strip_prefix("login:")
        .ok_or_else(|| AppError::BadRequest("invalid state parameter".into()))?;

    // Verify CSRF nonce from cookie
    let cookie_nonce = extract_cookie(&headers, "oss_auth_nonce")
        .ok_or_else(|| AppError::BadRequest("missing auth nonce cookie".into()))?;
    if cookie_nonce != nonce {
        return Err(AppError::BadRequest("nonce mismatch".into()));
    }

    // Retrieve PKCE verifier from cookie (never exposed in URL)
    let code_verifier = extract_cookie(&headers, "oss_auth_verifier")
        .ok_or_else(|| AppError::BadRequest("missing auth verifier cookie".into()))?;

    let provider = oauth_provider::get_by_key(&state.db, "google")
        .await?
        .ok_or_else(|| AppError::Internal("google oauth provider not configured".into()))?;

    let redirect_uri = format!("{}/auth/google/callback", state.config.public_url);

    // Exchange authorization code for tokens
    let tokens = oauth::exchange_code(
        &state.http_client,
        &provider,
        &client_id,
        &client_secret,
        &params.code,
        &redirect_uri,
        Some(&code_verifier),
    )
    .await
    .map_err(|e| AppError::Internal(format!("token exchange failed: {e}")))?;

    // Fetch user info from Google
    let userinfo_url = provider
        .userinfo_endpoint
        .as_deref()
        .ok_or_else(|| AppError::Internal("google provider missing userinfo endpoint".into()))?;

    let userinfo: GoogleUserInfo = state
        .http_client
        .get(userinfo_url)
        .bearer_auth(&tokens.access_token)
        .send()
        .await?
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("failed to fetch userinfo: {e}")))?;

    // Find or create org + identity
    let (org_id, identity_id, email) = find_or_create_user(&state, &userinfo).await?;

    // Mint JWT (7-day expiry)
    let jwt_secret = jwt_secret(&state.config.secrets_encryption_key);
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

    // Set session cookie + clear nonce cookie
    let session_cookie = format!(
        "oss_session={}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800",
        token
    );
    let clear_nonce = "oss_auth_nonce=; HttpOnly; SameSite=Lax; Path=/auth; Max-Age=0";
    let clear_verifier = "oss_auth_verifier=; HttpOnly; SameSite=Lax; Path=/auth; Max-Age=0";

    let body = json!({
        "status": "authenticated",
        "org_id": org_id,
        "identity_id": identity_id,
        "email": email,
    });

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(header::SET_COOKIE, session_cookie.parse().unwrap());
    resp_headers.append(header::SET_COOKIE, clear_nonce.parse().unwrap());
    resp_headers.append(header::SET_COOKIE, clear_verifier.parse().unwrap());

    Ok((StatusCode::OK, resp_headers, axum::Json(body)).into_response())
}

/// Return current session user info from JWT cookie.
async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let token = extract_cookie(&headers, "oss_session")
        .ok_or_else(|| AppError::Unauthorized("not authenticated".into()))?;

    let jwt_secret = jwt_secret(&state.config.secrets_encryption_key);
    let claims = jwt::verify(&jwt_secret, &token)
        .map_err(|_| AppError::Unauthorized("invalid or expired session".into()))?;

    Ok(axum::Json(json!({
        "identity_id": claims.sub,
        "org_id": claims.org,
        "email": claims.email,
    })))
}

/// Dev-only: issue a JWT for a test user+org. Requires DEV_AUTH env var.
async fn dev_token(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    if !state.config.dev_auth_enabled {
        return Err(AppError::NotFound("not found".into()));
    }

    // Find or create a deterministic dev user
    let dev_email = "dev@overslash.local";
    let (org_id, identity_id) =
        if let Some(existing) = identity::find_by_email(&state.db, dev_email).await? {
            (existing.org_id, existing.id)
        } else {
            let new_org = org::create(&state.db, "Dev Org", "dev-org").await?;
            let new_identity = identity::create_with_email(
                &state.db,
                new_org.id,
                "Dev User",
                "user",
                Some("dev-local"),
                Some(dev_email),
                json!({"dev": true}),
            )
            .await?;
            (new_org.id, new_identity.id)
        };

    let jwt_secret = jwt_secret(&state.config.secrets_encryption_key);
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

// --- helpers ---

fn google_credentials(state: &AppState) -> Result<(String, String), AppError> {
    let client_id = state
        .config
        .google_auth_client_id
        .as_ref()
        .ok_or_else(|| AppError::NotFound("google login not configured".into()))?
        .clone();
    let client_secret = state
        .config
        .google_auth_client_secret
        .as_ref()
        .ok_or_else(|| AppError::NotFound("google login not configured".into()))?
        .clone();
    Ok((client_id, client_secret))
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

fn jwt_secret(encryption_key: &str) -> Vec<u8> {
    // Use first 32 bytes of the hex-encoded encryption key as JWT signing secret
    let bytes = hex::decode(encryption_key).unwrap_or_else(|_| encryption_key.as_bytes().to_vec());
    bytes[..32.min(bytes.len())].to_vec()
}

#[derive(Deserialize)]
struct GoogleUserInfo {
    sub: String,
    email: String,
    name: Option<String>,
    picture: Option<String>,
}

async fn find_or_create_user(
    state: &AppState,
    userinfo: &GoogleUserInfo,
) -> Result<(Uuid, Uuid, String), AppError> {
    // Check if identity already exists by email
    if let Some(existing) = identity::find_by_email(&state.db, &userinfo.email).await? {
        return Ok((existing.org_id, existing.id, userinfo.email.clone()));
    }

    // Create new org + identity. If a concurrent request raced us and already
    // created the identity (unique constraint on email), retry the lookup.
    let display_name = userinfo.name.as_deref().unwrap_or(&userinfo.email);
    let slug = generate_slug(&userinfo.email);
    let new_org = org::create(&state.db, display_name, &slug).await?;

    let metadata = json!({
        "google_sub": userinfo.sub,
        "name": userinfo.name,
        "picture": userinfo.picture,
    });
    match identity::create_with_email(
        &state.db,
        new_org.id,
        display_name,
        "user",
        Some(&userinfo.sub),
        Some(&userinfo.email),
        metadata,
    )
    .await
    {
        Ok(new_identity) => Ok((new_org.id, new_identity.id, userinfo.email.clone())),
        Err(sqlx::Error::Database(ref e)) if e.is_unique_violation() => {
            // Another request won the race — use the identity they created.
            // The orphaned org is harmless and can be cleaned up later.
            let existing = identity::find_by_email(&state.db, &userinfo.email)
                .await?
                .ok_or_else(|| AppError::Internal("race: identity vanished".into()))?;
            Ok((existing.org_id, existing.id, userinfo.email.clone()))
        }
        Err(e) => Err(e.into()),
    }
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
