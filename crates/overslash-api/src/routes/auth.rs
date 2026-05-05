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
use overslash_db::repos::{membership, oauth_provider, org, user as user_repo};
use overslash_db::{OrgScope, SystemScope};

/// How long a `oauth_preview_origins` row lives — must comfortably exceed
/// the slowest realistic IdP round-trip (Google login can take 30 s if MFA
/// is involved, plus an unhurried human picking an account).
const PREVIEW_ORIGIN_TTL_SECS: i64 = 600;
/// One-time handoff codes are exchanged for a session cookie within seconds
/// of the OAuth callback. A short TTL keeps the redemption window tight if
/// the redirect URL is ever logged or intercepted.
const PREVIEW_HANDOFF_CODE_TTL_SECS: i64 = 60;

pub fn router() -> Router<AppState> {
    Router::new()
        // Generic provider auth
        .route("/auth/login/{provider_key}", get(provider_login))
        .route("/auth/callback/{provider_key}", get(provider_callback))
        .route("/auth/providers", get(list_auth_providers))
        // Vercel preview-deployment handoff. 404s unless the feature is
        // explicitly enabled (OVERSLASH_ENV=dev + PREVIEW_ORIGIN_ALLOWLIST).
        // Production must never serve this — the response sets a session
        // cookie keyed to a one-time code minted in the OAuth callback.
        .route("/auth/handoff", get(handoff_consume))
        // Backward compat — Google callback must remain a real handler (not redirect)
        // because existing Google OAuth apps have this URL registered as redirect_uri
        .route("/auth/google/login", get(google_login_compat))
        .route("/auth/google/callback", get(google_callback_compat))
        // Session endpoints
        .route("/auth/me", get(me))
        .route("/auth/me/identity", get(me_identity))
        .route("/auth/dev/token", get(dev_token))
        .route("/auth/logout", post(logout))
        // Multi-org switching + account surface. See docs/design/multi_org_auth.md.
        .route("/auth/switch-org", post(switch_org))
        .route("/v1/account/memberships", get(list_account_memberships))
        .route(
            "/v1/account/memberships/{org_id}",
            axum::routing::delete(drop_account_membership),
        )
}

async fn logout(State(state): State<AppState>) -> impl IntoResponse {
    // Clear on the same Domain the session was set with so browsers actually
    // drop the cookie (missing-Domain clear won't match a Domain-scoped
    // cookie and the session persists visually).
    let mut clear = String::from("oss_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
    if let Some(domain) = state.config.session_cookie_domain.as_deref() {
        clear.push_str(&format!("; Domain={domain}"));
    }
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
    /// Where to send the user after login succeeds. Must be same-origin
    /// (path-only redirect). Used by `/oauth/authorize` to resume after the
    /// IdP bounce.
    next: Option<String>,
    /// Vercel preview-deployment OAuth handoff. Set by the dashboard when
    /// running on a preview host so the API can route the user back to the
    /// preview after the OAuth round-trip instead of landing them on the
    /// configured `dashboard_url`. Honored only when
    /// `Config::is_preview_handoff_enabled()` AND the value matches
    /// `PREVIEW_ORIGIN_ALLOWLIST`. Silently ignored otherwise — the feature
    /// must remain invisible on prod.
    preview_origin: Option<String>,
}

#[derive(Deserialize)]
struct HandoffQuery {
    code: String,
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
    ctx: Option<axum::extract::Extension<crate::middleware::subdomain::RequestOrgContext>>,
    Query(query): Query<LoginQuery>,
) -> Result<Response, AppError> {
    let provider = oauth_provider::get_by_key(&state.db, &provider_key)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("unknown provider: {provider_key}")))?;

    // Subdomain context is authoritative for which IdP to use. If the
    // caller hits `<slug>.app.overslash.com/auth/login/google` we MUST
    // resolve credentials against that org's `org_idp_configs` — using
    // env-var Overslash-level creds would let a corp-subdomain login
    // provision a personal-org account, bypassing the corp org's IdP.
    // `?org=` is still accepted on the root apex (legacy dashboards pass
    // it); when set, it must match the subdomain if we're on one.
    let ctx = ctx
        .map(|axum::extract::Extension(c)| c)
        .unwrap_or(crate::middleware::subdomain::RequestOrgContext::Root);
    let effective_org_slug: Option<String> = match (&ctx, query.org.as_deref()) {
        (crate::middleware::subdomain::RequestOrgContext::Org { slug, .. }, Some(q_slug))
            if q_slug != slug =>
        {
            return Err(AppError::BadRequest(
                "org param does not match subdomain".into(),
            ));
        }
        (crate::middleware::subdomain::RequestOrgContext::Org { slug, .. }, _) => {
            Some(slug.clone())
        }
        (crate::middleware::subdomain::RequestOrgContext::Root, Some(q)) => Some(q.to_string()),
        (crate::middleware::subdomain::RequestOrgContext::Root, None) => None,
    };

    let (client_id, _client_secret) =
        resolve_auth_credentials(&state, &provider_key, effective_org_slug.as_deref()).await?;

    let pkce = if provider.supports_pkce {
        Some(oauth::generate_pkce())
    } else {
        None
    };

    let nonce = Uuid::new_v4().to_string();

    // Sanitized org slug to persist across the IdP round-trip so the
    // callback can resolve DB-stored credentials. Value is "none" when
    // there's no org context (env-var social providers). Sanitization
    // doubles as header-injection protection for the cookie path.
    let org_slug_value = effective_org_slug
        .as_deref()
        .filter(|s| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.'))
        })
        .unwrap_or("none");
    let sanitized_next = query.next.as_deref().and_then(sanitize_next);

    // Optionally append a preview-handoff id to the OAuth `state` so the
    // callback can route the user back to a Vercel preview origin instead
    // of `dashboard_url`. Gated by `is_preview_handoff_enabled()` AND the
    // origin matching `PREVIEW_ORIGIN_ALLOWLIST` — when off, the
    // `preview_origin` query param is silently ignored. The id is opaque
    // (random UUID); the actual origin lives server-side in
    // `oauth_preview_origins` so we don't leak the URL into IdP logs.
    //
    // We also stash the nonce / PKCE verifier / org slug / next path on
    // the row. The cookie-domain gap between `*.vercel.app` and the API
    // means the browser rejects the `oss_auth_*` cookies on previews; the
    // callback reads these values from the row instead when `preview_id`
    // is present in `state`.
    let preview_id = match query.preview_origin.as_deref() {
        Some(origin) if state.config.preview_origin_allowed(origin) => {
            let id = Uuid::new_v4();
            let verifier_for_row = pkce.as_ref().map(|p| p.verifier.as_str());
            let org_slug_for_row = effective_org_slug.as_deref().filter(|s| !s.is_empty());
            overslash_db::repos::oauth_preview_handoff::insert_preview_origin(
                &state.db,
                id,
                origin,
                &nonce,
                verifier_for_row,
                org_slug_for_row,
                sanitized_next.as_deref(),
                PREVIEW_ORIGIN_TTL_SECS,
            )
            .await?;
            Some(id)
        }
        _ => None,
    };

    let state_param = match preview_id {
        Some(id) => format!("login:{provider_key}:{nonce}:{id}"),
        None => format!("login:{provider_key}:{nonce}"),
    };

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

    let mut headers = HeaderMap::new();

    // Auth-state cookies are only meaningful on the non-preview path: when
    // login starts on a Vercel preview, the response's effective host is
    // `*.vercel.app` and the browser would reject any `Set-Cookie` with
    // `Domain=.app.<apex>`. The preview branch reads its state from the
    // `oauth_preview_origins` row instead — set above.
    if preview_id.is_none() {
        // The OAuth callback always lands on `public_url/auth/callback/<provider>`
        // (typically the root apex), so when login kicks off from a corp
        // subdomain the auth-state cookies MUST be set on the shared parent
        // domain (`session_cookie_domain`, e.g. `.app.overslash.com`) or the
        // browser won't send them to the callback host. Without this, login
        // from a subdomain silently fails with "missing auth nonce cookie".
        let nonce_cookie = auth_cookie(&state, "oss_auth_nonce", &nonce);
        let verifier_value = pkce.as_ref().map_or("none", |p| p.verifier.as_str());
        let verifier_cookie = auth_cookie(&state, "oss_auth_verifier", verifier_value);
        let org_cookie = auth_cookie(&state, "oss_auth_org", org_slug_value);

        headers.insert(header::SET_COOKIE, nonce_cookie.parse().unwrap());
        headers.append(header::SET_COOKIE, verifier_cookie.parse().unwrap());
        headers.append(header::SET_COOKIE, org_cookie.parse().unwrap());

        // Persist `next` across the IdP round-trip so the callback can resume
        // wherever the caller wanted (used by `/oauth/authorize` to bounce
        // through login). Only accept path-only targets to keep this from
        // turning into an open redirect.
        if let Some(next) = sanitized_next.as_deref() {
            let next_cookie = auth_cookie(&state, "oss_auth_next", next);
            headers.append(header::SET_COOKIE, next_cookie.parse().unwrap());
        }
    }

    Ok((headers, Redirect::to(&auth_url)).into_response())
}

/// Build a Set-Cookie for the short-lived OAuth auth-state cookies (nonce,
/// PKCE verifier, org slug, `next`). Scoped to `Path=/auth` so they only
/// hitch along to auth endpoints. Domain comes from the same config knob
/// as the session cookie — when set, both the login kickoff host and the
/// callback host share the cookie.
fn auth_cookie(state: &AppState, name: &str, value: &str) -> String {
    let mut out = format!("{name}={value}; HttpOnly; SameSite=Lax; Path=/auth; Max-Age=600");
    if let Some(domain) = state.config.session_cookie_domain.as_deref() {
        out.push_str(&format!("; Domain={domain}"));
    }
    out
}

/// Matching clear for the auth-state cookies. Must emit the same `Domain`
/// attribute, or the browser keeps a cross-subdomain copy around.
fn clear_auth_cookie(state: &AppState, name: &str) -> String {
    let mut out = format!("{name}=; HttpOnly; SameSite=Lax; Path=/auth; Max-Age=0");
    if let Some(domain) = state.config.session_cookie_domain.as_deref() {
        out.push_str(&format!("; Domain={domain}"));
    }
    out
}

// ---------------------------------------------------------------------------
// Generic provider callback
// ---------------------------------------------------------------------------

async fn provider_callback(
    State(state): State<AppState>,
    Path(provider_key): Path<String>,
    ctx: Option<axum::extract::Extension<crate::middleware::subdomain::RequestOrgContext>>,
    Query(params): Query<CallbackQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    // Parse state: "login:<provider_key>:<nonce>" or, for the Vercel
    // preview-deployment handoff, "login:<provider_key>:<nonce>:<preview_id>".
    // The 4-segment form is only honored when the feature is enabled — a
    // non-dev deployment that somehow receives a 4-segment state must
    // reject it (defense in depth: don't let a logged URL be replayed
    // into a prod environment).
    let state_parts: Vec<&str> = params.state.splitn(4, ':').collect();
    if state_parts.len() < 3 || state_parts[0] != "login" {
        return Err(AppError::BadRequest("invalid state parameter".into()));
    }
    let state_provider = state_parts[1];
    let nonce = state_parts[2];
    let preview_id_str = state_parts.get(3).copied();

    if preview_id_str.is_some() && !state.config.is_preview_handoff_enabled() {
        return Err(AppError::BadRequest("invalid state parameter".into()));
    }

    if state_provider != provider_key {
        return Err(AppError::BadRequest("provider mismatch in state".into()));
    }

    let preview_id = match preview_id_str {
        Some(s) => Some(
            Uuid::parse_str(s)
                .map_err(|_| AppError::BadRequest("invalid state parameter".into()))?,
        ),
        None => None,
    };

    // Source the auth-state. On the non-preview path it lives in cookies
    // set during `provider_login`. On the preview path the cookies don't
    // survive the cookie-domain gap (`*.vercel.app` ↔ `api.<apex>`), so the
    // values were stashed on the `oauth_preview_origins` row instead. We
    // load them here before any cookie checks so the preview branch never
    // 400s with "missing auth nonce cookie".
    let (
        state_nonce_expected,
        code_verifier,
        slug_from_state,
        next_from_state,
        preview_origin_for_handoff,
    ) = if let Some(pid) = preview_id {
        let row = overslash_db::repos::oauth_preview_handoff::get_preview_origin(&state.db, pid)
            .await?
            .ok_or_else(|| AppError::BadRequest("preview origin expired or unknown".into()))?;
        // Re-check against the live allowlist so a tightened policy
        // takes effect even on in-flight logins minted under the old
        // rules.
        if !state.config.preview_origin_allowed(&row.origin) {
            return Err(AppError::Forbidden(
                "preview origin not in allowlist".into(),
            ));
        }
        (
            row.nonce.clone(),
            row.pkce_verifier.clone(),
            row.org_slug.clone(),
            row.next_path.clone(),
            Some(row.origin),
        )
    } else {
        // CSRF anti-replay: the nonce in `state` must match the cookie
        // we set during login. The preview branch substitutes a
        // server-side row for this cookie because it can't be set
        // cross-domain.
        let cookie_nonce = extract_cookie(&headers, "oss_auth_nonce")
            .ok_or_else(|| AppError::BadRequest("missing auth nonce cookie".into()))?;
        let verifier = extract_cookie(&headers, "oss_auth_verifier").filter(|v| v != "none");
        let slug = extract_cookie(&headers, "oss_auth_org").filter(|s| s != "none");
        let next = extract_cookie(&headers, "oss_auth_next").and_then(|v| sanitize_next(&v));
        (cookie_nonce, verifier, slug, next, None)
    };

    if state_nonce_expected != nonce {
        return Err(AppError::BadRequest("nonce mismatch".into()));
    }

    let provider = oauth_provider::get_by_key(&state.db, &provider_key)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("unknown provider: {provider_key}")))?;

    // Subdomain context is authoritative — even if the stored slug says
    // otherwise, a callback hitting `<slug>.app.overslash.com` must be
    // treated as that org's login path.
    let ctx = ctx
        .map(|axum::extract::Extension(c)| c)
        .unwrap_or(crate::middleware::subdomain::RequestOrgContext::Root);
    let org_slug = match ctx {
        crate::middleware::subdomain::RequestOrgContext::Org { slug, .. } => Some(slug),
        crate::middleware::subdomain::RequestOrgContext::Root => slug_from_state,
    };

    let (client_id, client_secret) =
        resolve_auth_credentials(&state, &provider_key, org_slug.as_deref()).await?;

    // PKCE verifier (None if provider doesn't support PKCE).
    let verifier_ref = code_verifier.as_deref();

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

    // Find or provision user + update profile. Passes the org slug context
    // so the provisioner can tell a root-domain login (→ Overslash-backed
    // user + personal org) apart from an org-subdomain login (→ org-only
    // user, gated by `allowed_email_domains`).
    let (org_id, identity_id, resolved_user_id, email) =
        find_or_provision_user(&state, &userinfo, org_slug.as_deref()).await?;

    // Mint JWT
    let jwt_secret = signing_key_bytes(&state.config.signing_key);
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let claims = jwt::Claims {
        sub: identity_id,
        org: org_id,
        email: email.clone(),
        aud: jwt::AUD_SESSION.into(),
        iat: now,
        exp: now + 7 * 24 * 3600,
        user_id: Some(resolved_user_id),
        mcp_client_id: None,
    };
    let token = jwt::mint(&jwt_secret, &claims)
        .map_err(|e| AppError::Internal(format!("jwt mint failed: {e}")))?;

    // Vercel preview-deployment handoff branch. The session cookie can't
    // be set on `api.dev.overslash.com` and read on `<preview>.vercel.app`
    // (no shared parent domain), so we mint a one-time code, hand it to
    // the preview, and let the preview adopt the JWT via a host-only
    // cookie set on the proxied response. The `preview_id` carried in
    // `state` is the tamper-resistant binding to the preview origin we
    // stashed server-side at login time.
    if let Some(origin) = preview_origin_for_handoff {
        let handoff_code = preview_handoff_code();
        // `next_from_state` was already sanitized at login time; re-check
        // it defensively in case anyone hand-edits the row. No fallback to
        // `dashboard_url` — that points at the corp host, not the preview
        // origin. Missing → handoff endpoint defaults to `/` on the
        // preview, which is the correct landing for someone whose login
        // had no specific intent.
        let safe_next = next_from_state.as_deref().and_then(sanitize_next);
        overslash_db::repos::oauth_preview_handoff::insert_handoff_code(
            &state.db,
            &handoff_code,
            &token,
            &origin,
            safe_next.as_deref(),
            PREVIEW_HANDOFF_CODE_TTL_SECS,
        )
        .await?;
        let target = format!(
            "{}/auth/handoff?code={}",
            origin.trim_end_matches('/'),
            urlencoding::encode(&handoff_code),
        );
        // No clear-cookie headers: the preview path never set the
        // `oss_auth_*` cookies (browser would have rejected them anyway),
        // so there's nothing to clear.
        return Ok(Redirect::to(&target).into_response());
    }

    // Non-preview path: set the session cookie on the API origin and bounce
    // to the dashboard / org subdomain as before. Always clear the auth-state
    // cookies we set during login — same Domain attribute, otherwise the
    // browser keeps a stale copy.
    let clear_nonce = clear_auth_cookie(&state, "oss_auth_nonce");
    let clear_verifier = clear_auth_cookie(&state, "oss_auth_verifier");
    let clear_org = clear_auth_cookie(&state, "oss_auth_org");
    let clear_next = clear_auth_cookie(&state, "oss_auth_next");

    let session_cookie = session_cookie(&state, &token)?;
    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(header::SET_COOKIE, session_cookie);
    resp_headers.append(header::SET_COOKIE, clear_nonce.parse().unwrap());
    resp_headers.append(header::SET_COOKIE, clear_verifier.parse().unwrap());
    resp_headers.append(header::SET_COOKIE, clear_org.parse().unwrap());
    resp_headers.append(header::SET_COOKIE, clear_next.parse().unwrap());

    // Non-preview path: fall back to the configured dashboard URL when the
    // caller had no explicit `next`. (The preview branch above handles its
    // own fallback because `dashboard_url` is the wrong host for a preview.)
    let next_path = next_from_state.unwrap_or_else(|| state.config.dashboard_url.clone());

    // When login kicks off on `<slug>.<apex>` but the OAuth callback lands
    // at `state.config.public_url/auth/callback/<provider>` (typical: a
    // single Google OAuth app's redirect_uri is the API apex), a path-only
    // redirect resolves against the apex and leaves the user stranded
    // outside the org subdomain. The `oss_auth_org` cookie was carried
    // across the bounce on the shared `session_cookie_domain`; combine it
    // with `app_host_suffix` to reconstruct the original origin and turn
    // the redirect absolute.
    let redirect_target = absolute_redirect_for_org(&state, &headers, &next_path);
    Ok((resp_headers, Redirect::to(&redirect_target)).into_response())
}

/// If login originated on a corp subdomain, build an absolute redirect to
/// `<scheme>://<slug>.<app-apex><path>` so the user lands back where they
/// started. Returns `path` unchanged when there's no subdomain context.
///
/// Mirrors `public_url`'s port suffix when present so the e2e harness
/// (which boots the API on a random loopback port) lands on the right
/// listener. In prod `public_url` has no port (default 443/80) so this is
/// a no-op.
fn absolute_redirect_for_org(state: &AppState, headers: &HeaderMap, path: &str) -> String {
    let Some(slug) = extract_cookie(headers, "oss_auth_org").filter(|s| s != "none") else {
        return path.to_string();
    };
    let Some(apex) = state.config.app_host_suffix.as_deref() else {
        return path.to_string();
    };
    let scheme = if state.config.public_url.starts_with("https://") {
        "https"
    } else {
        "http"
    };
    let port_suffix = state
        .config
        .public_url
        .rsplit_once('/')
        .map(|(_, host)| host)
        .unwrap_or(state.config.public_url.as_str())
        .rsplit_once(':')
        .map(|(_, port)| format!(":{port}"))
        .unwrap_or_default();
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    format!("{scheme}://{slug}.{apex}{port_suffix}{path}")
}

// ---------------------------------------------------------------------------
// Vercel preview-deployment OAuth handoff
// ---------------------------------------------------------------------------

/// Random 32-byte handoff token, hex-encoded. Used as the one-time code
/// the preview presents at `/auth/handoff?code=` to swap for a session.
fn preview_handoff_code() -> String {
    let buf: [u8; 32] = rand::random();
    hex::encode(buf)
}

/// `GET /auth/handoff?code=<token>` — the redemption side of the Vercel
/// preview handoff. Hits the API via the preview's Vercel proxy: Vercel
/// forwards `X-Forwarded-Host: <preview>.vercel.app` and the API's response
/// (with a `Domain`-less `Set-Cookie`) is pasted back through, scoping the
/// cookie to the preview origin the browser sees.
///
/// 404 unless the feature is on. Otherwise: peek at the row, run host +
/// allowlist validations, *then* atomically consume — only after we know
/// the request is legitimate. Reverse order would let a probe (crawler,
/// retry, misconfigured proxy) burn a code with the wrong host header
/// and force a real user to restart their OAuth round-trip.
async fn handoff_consume(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HandoffQuery>,
) -> Result<Response, AppError> {
    if !state.config.is_preview_handoff_enabled() {
        return Err(AppError::NotFound("not found".into()));
    }

    // Peek first so failed validations leave the row consumable by a
    // retry that gets the host right.
    let row = overslash_db::repos::oauth_preview_handoff::peek_handoff_code(&state.db, &q.code)
        .await?
        .ok_or_else(|| AppError::BadRequest("invalid or expired handoff code".into()))?;

    // Bind redemption to the original preview origin so a leaked code
    // can't be redeemed against a different host.
    let actual_host = crate::middleware::subdomain::effective_host(&headers).unwrap_or_default();
    let origin_url = url::Url::parse(&row.origin)
        .map_err(|e| AppError::Internal(format!("stored origin not parseable: {e}")))?;
    let origin_host = origin_url
        .host_str()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if actual_host != origin_host {
        return Err(AppError::BadRequest("handoff origin mismatch".into()));
    }

    // Live allowlist re-check — if `PREVIEW_ORIGIN_ALLOWLIST` got
    // tightened between mint and redeem, honor the new policy.
    if !state.config.preview_origin_allowed(&row.origin) {
        return Err(AppError::Forbidden(
            "preview origin not in allowlist".into(),
        ));
    }

    // Now consume. Race-with-self window: another concurrent request
    // that also passed validation could win the UPDATE, in which case
    // this caller sees `None` and gets a 400 — same outcome as a
    // replay, which is correct.
    let consumed =
        overslash_db::repos::oauth_preview_handoff::consume_handoff_code(&state.db, &q.code)
            .await?
            .ok_or_else(|| AppError::BadRequest("invalid or expired handoff code".into()))?;

    // Host-only session cookie: no `Domain` so the browser scopes it to
    // the preview origin. `.vercel.app` is shared across tenants — sharing
    // a cookie there would be a cross-tenant data leak.
    let cookie = format!(
        "oss_session={}; HttpOnly; SameSite=Lax; Path=/; Secure; Max-Age=604800",
        consumed.jwt
    );

    let next = consumed
        .next_path
        .as_deref()
        .and_then(sanitize_next)
        .unwrap_or_else(|| "/".to_string());

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(
        header::SET_COOKIE,
        cookie
            .parse()
            .map_err(|e| AppError::Internal(format!("build session cookie: {e}")))?,
    );
    Ok((resp_headers, Redirect::to(&next)).into_response())
}

// ---------------------------------------------------------------------------
// Backward-compat Google routes
// ---------------------------------------------------------------------------

async fn google_login_compat(
    state: State<AppState>,
    ctx: Option<axum::extract::Extension<crate::middleware::subdomain::RequestOrgContext>>,
    query: Query<LoginQuery>,
) -> Result<Response, AppError> {
    provider_login(state, Path("google".to_string()), ctx, query).await
}

async fn google_callback_compat(
    state: State<AppState>,
    ctx: Option<axum::extract::Extension<crate::middleware::subdomain::RequestOrgContext>>,
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
    provider_callback(
        state,
        Path("google".to_string()),
        ctx,
        Query(params),
        headers,
    )
    .await
}

// ---------------------------------------------------------------------------
// List available auth providers (for login page)
// ---------------------------------------------------------------------------

async fn list_auth_providers(
    State(state): State<AppState>,
    ctx: Option<axum::extract::Extension<crate::middleware::subdomain::RequestOrgContext>>,
    Query(query): Query<ProvidersQuery>,
) -> Result<impl IntoResponse, AppError> {
    // Older test harnesses mount the router without the subdomain
    // middleware; treat the missing extension as Root so those paths still
    // list providers correctly.
    let ctx = ctx
        .map(|axum::extract::Extension(c)| c)
        .unwrap_or(crate::middleware::subdomain::RequestOrgContext::Root);
    // Trust-domain rule (docs/design/multi_org_auth.md §Flow 2):
    //   - On a corp-org subdomain, list ONLY that org's IdPs — Overslash-
    //     level IdPs cannot grant membership to a corp org, so offering them
    //     would be misleading.
    //   - On the root apex, list ONLY env-configured Overslash-level IdPs.
    //   - Back-compat: if the caller passed `?org=<slug>` on the root apex
    //     (pre-multi-org dashboards still do), honor it and list that org's
    //     IdPs — equivalent to hitting the subdomain.
    let mut providers = Vec::new();

    let resolved_org_id = match &ctx {
        crate::middleware::subdomain::RequestOrgContext::Org { org_id, .. } => Some(*org_id),
        crate::middleware::subdomain::RequestOrgContext::Root => {
            if let Some(slug) = &query.org {
                org::get_by_slug(&state.db, slug).await?.map(|o| o.id)
            } else {
                None
            }
        }
    };

    if let Some(org_id) = resolved_org_id {
        let bootstrap_scope = overslash_db::OrgScope::new(org_id, state.db.clone());
        let configs = bootstrap_scope.list_enabled_org_idp_configs().await?;
        for config in configs {
            let display_name = oauth_provider::get_by_key(&state.db, &config.provider_key)
                .await?
                .map(|p| p.display_name)
                .unwrap_or_else(|| config.provider_key.clone());
            providers.push(json!({
                "key": config.provider_key,
                "display_name": display_name,
                "source": "db",
                "is_default": config.is_default,
            }));
        }
        // Intentional: no env-level providers here. The org IdP is the only
        // admission path to a corp org. See DECISIONS.md D12.
        //
        // `scope = "org"` tells the dashboard to render the corp-org empty
        // state ("contact the org creator") when the org hasn't configured
        // an IdP yet. Root-level empty states read differently.
        return Ok(axum::Json(json!({
            "providers": providers,
            "scope": "org",
        })));
    }

    // Root apex — Overslash-level providers only.
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
    // Dev login indicator — only surfaces on root, not on corp subdomains.
    if state.config.dev_auth_enabled {
        providers.push(json!({
            "key": "dev",
            "display_name": "Dev Login",
            "source": "env",
        }));
    }

    Ok(axum::Json(
        json!({ "providers": providers, "scope": "root" }),
    ))
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
    let claims = jwt::verify(&jwt_secret, &token, jwt::AUD_SESSION)
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
    session: crate::extractors::SessionAuth,
) -> Result<impl IntoResponse, AppError> {
    // Was: manual cookie + jwt::verify without the RequestOrgContext cross-
    // check, so a session scoped to the caller's personal org still
    // answered `/auth/me/identity` when the request came in on a corp
    // subdomain — leaking personal-org profile data across trust domains.
    // `SessionAuth` enforces `jwt.org == subdomain.org` via
    // `check_subdomain_matches_jwt`.
    let scope = OrgScope::new(session.org_id, state.db.clone());
    let ident = scope
        .get_identity(session.identity_id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
    let is_org_admin = scope.is_identity_in_admins(ident.id).await?;

    let org_row = org::get_by_id(&state.db, ident.org_id).await?;
    let picture = ident
        .metadata
        .get("picture")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Multi-org surface: memberships + personal-org pointer live on the
    // `users` row. Legacy tokens (no `user_id` claim) fall back to the
    // identity's FK. Fetch the user once and reuse for instance-admin too.
    let user_id = session.user_id.or(ident.user_id);
    let (memberships, personal_org_id, is_instance_admin) = if let Some(uid) = user_id {
        let user = user_repo::get_by_id(&state.db, uid).await?;
        (
            list_membership_summaries(&state, uid).await?,
            user.as_ref().and_then(|u| u.personal_org_id),
            user.as_ref().map(|u| u.is_instance_admin).unwrap_or(false),
        )
    } else {
        (Vec::new(), None, false)
    };

    let email = ident.email.clone().unwrap_or_default();

    Ok(axum::Json(json!({
        "identity_id": ident.id,
        "org_id": ident.org_id,
        "org_name": org_row.as_ref().map(|o| o.name.clone()),
        "org_slug": org_row.as_ref().map(|o| o.slug.clone()),
        "email": email,
        "name": ident.name,
        "kind": ident.kind,
        "external_id": ident.external_id,
        "is_org_admin": is_org_admin,
        "is_instance_admin": is_instance_admin,
        "picture": picture,
        "user_id": user_id,
        "personal_org_id": personal_org_id,
        "memberships": memberships,
    })))
}

/// Shape returned by `/auth/me/identity.memberships[]` and `/v1/account/memberships`.
#[derive(Debug, serde::Serialize)]
struct MembershipSummary {
    org_id: Uuid,
    slug: String,
    name: String,
    role: String,
    is_personal: bool,
}

async fn list_membership_summaries(
    state: &AppState,
    user_id: Uuid,
) -> Result<Vec<MembershipSummary>, AppError> {
    let memberships = membership::list_for_user(&state.db, user_id).await?;
    let mut out = Vec::with_capacity(memberships.len());
    for m in memberships {
        let Some(o) = org::get_by_id(&state.db, m.org_id).await? else {
            continue; // Org was deleted; stale membership — CASCADE will sweep it.
        };
        out.push(MembershipSummary {
            org_id: o.id,
            slug: o.slug,
            name: o.name,
            role: m.role,
            is_personal: o.is_personal,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Multi-org account routes
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SwitchOrgRequest {
    org_id: Uuid,
}

/// POST /auth/switch-org — mint a new session JWT scoped to `org_id` after
/// verifying the caller has a membership there. Returns `{ redirect_to }`
/// so the dashboard can hard-reload onto the target subdomain (or the root
/// apex for personal orgs). Uses `SessionAuth` so the cross-subdomain guard
/// runs — switch-org must be called from the caller's *current* subdomain
/// (or root), not from the target.
async fn switch_org(
    State(state): State<AppState>,
    session: crate::extractors::SessionAuth,
    axum::Json(req): axum::Json<SwitchOrgRequest>,
) -> Result<impl IntoResponse, AppError> {
    let jwt_secret = signing_key_bytes(&state.config.signing_key);

    let current_scope = OrgScope::new(session.org_id, state.db.clone());
    let current_ident = current_scope
        .get_identity(session.identity_id)
        .await?
        .ok_or_else(|| AppError::NotFound("current identity not found".into()))?;
    let user_id = match session.user_id {
        Some(uid) => uid,
        None => current_ident.user_id.ok_or_else(|| {
            AppError::Unauthorized("session has no resolvable user; sign in again".into())
        })?,
    };

    // Membership guard.
    let target_membership = membership::find(&state.db, user_id, req.org_id)
        .await?
        .ok_or_else(|| AppError::Forbidden("not a member of that org".into()))?;
    let target_org = org::get_by_id(&state.db, req.org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("org not found".into()))?;

    // Resolve the target identity — there is at most one user-kind identity
    // per (org_id, user_id) (enforced by the partial UNIQUE in migration 040).
    let target_identity =
        overslash_db::repos::identity::find_by_org_and_user(&state.db, req.org_id, user_id)
            .await?
            .ok_or_else(|| {
                AppError::Internal(
                    "membership exists but no user identity in target org (invariant violation)"
                        .into(),
                )
            })?;
    let target_identity_id = target_identity.id;

    // Prefer the target identity's email so the new JWT reflects how the
    // target org sees this human; fall back to the current identity's email
    // for users who had no email on the target side.
    let claim_email = target_identity
        .email
        .clone()
        .or(current_ident.email.clone())
        .unwrap_or_default();

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let new_claims = jwt::Claims {
        sub: target_identity_id,
        org: req.org_id,
        email: claim_email,
        aud: jwt::AUD_SESSION.into(),
        iat: now,
        exp: now + 7 * 24 * 3600,
        user_id: Some(user_id),
        mcp_client_id: None,
    };
    let new_token = jwt::mint(&jwt_secret, &new_claims)
        .map_err(|e| AppError::Internal(format!("jwt mint failed: {e}")))?;

    let redirect_to = build_org_redirect(&state, &target_org);

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(header::SET_COOKIE, session_cookie(&state, &new_token)?);
    Ok((
        resp_headers,
        axum::Json(json!({
            "org_id": target_org.id,
            "slug": target_org.slug,
            "is_personal": target_org.is_personal,
            "role": target_membership.role,
            "redirect_to": redirect_to,
        })),
    ))
}

/// GET /v1/account/memberships — list the caller's memberships, same shape
/// as `/auth/me/identity.memberships[]` but reachable as a discrete endpoint
/// so the dashboard can refresh the switcher without re-loading identity.
async fn list_account_memberships(
    State(state): State<AppState>,
    session: crate::extractors::SessionAuth,
) -> Result<impl IntoResponse, AppError> {
    let user_id = resolve_session_user_id(&state, &session).await?;
    let summaries = list_membership_summaries(&state, user_id).await?;
    Ok(axum::Json(json!({ "memberships": summaries })))
}

/// DELETE /v1/account/memberships/{org_id} — drop the caller's own
/// membership. Refuses to drop a personal-org membership (that'd orphan
/// the account) or the last admin of a non-personal org.
///
/// The "last admin" check and the delete run in a single transaction. A
/// naive two-step lock (caller's row, then all admin rows) can deadlock
/// when two admins drop concurrently — each acquires their own row lock
/// first, then blocks waiting for the other's. We avoid that by issuing
/// a single `SELECT ... FOR UPDATE ORDER BY user_id`, which locks every
/// admin row of the org in a deterministic order. Both concurrent txs
/// contend for the same ordered lock set; the second waits for the
/// first to commit and then reads the post-delete world.
async fn drop_account_membership(
    State(state): State<AppState>,
    session: crate::extractors::SessionAuth,
    Path(org_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let user_id = resolve_session_user_id(&state, &session).await?;

    let org_row = org::get_by_id(&state.db, org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("org not found".into()))?;

    if org_row.is_personal {
        return Err(AppError::BadRequest(
            "cannot drop membership of your own personal org".into(),
        ));
    }

    let mut tx = state.db.begin().await?;

    // Lock every admin row of the org in user_id order. This includes the
    // caller's row if (and only if) they are an admin — which is the only
    // case where we care about the count guard. Deterministic order across
    // concurrent txs rules out deadlock; both serialize on the same lock
    // set instead of each grabbing a different row first.
    #[allow(clippy::disallowed_methods)]
    let admin_user_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM user_org_memberships
         WHERE org_id = $1 AND role = 'admin'
         ORDER BY user_id FOR UPDATE",
    )
    .bind(org_id)
    .fetch_all(&mut *tx)
    .await?;

    let caller_is_admin = admin_user_ids.contains(&user_id);

    // Separately lock the caller's row so a NOT-FOUND ("already left")
    // check and the subsequent DELETE can proceed even when the caller
    // is a regular member (not in admin_user_ids).
    #[allow(clippy::disallowed_methods)]
    let existing_role: Option<String> = sqlx::query_scalar(
        "SELECT role FROM user_org_memberships
         WHERE user_id = $1 AND org_id = $2 FOR UPDATE",
    )
    .bind(user_id)
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await?;
    existing_role.ok_or_else(|| AppError::NotFound("no such membership".into()))?;

    if caller_is_admin {
        let admin_count = admin_user_ids.len();
        if admin_count <= 1 {
            return Err(AppError::BadRequest(
                "cannot drop the last admin of a non-personal org".into(),
            ));
        }
    }

    #[allow(clippy::disallowed_methods)]
    sqlx::query("DELETE FROM user_org_memberships WHERE user_id = $1 AND org_id = $2")
        .bind(user_id)
        .bind(org_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(axum::Json(json!({ "status": "dropped", "org_id": org_id })))
}

/// Resolve the human behind a `SessionAuth`. Prefers the JWT's `user_id`
/// claim (hot path); falls back to the identity's FK for legacy tokens.
async fn resolve_session_user_id(
    state: &AppState,
    session: &crate::extractors::SessionAuth,
) -> Result<Uuid, AppError> {
    if let Some(uid) = session.user_id {
        return Ok(uid);
    }
    let scope = OrgScope::new(session.org_id, state.db.clone());
    let ident = scope
        .get_identity(session.identity_id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
    ident.user_id.ok_or_else(|| {
        AppError::Unauthorized("session has no resolvable user; sign in again".into())
    })
}

/// Build the absolute URL the dashboard should hard-reload to after a
/// successful switch. Personal orgs live at the apex; corp orgs live at
/// `<slug>.<apex>`. When no apex is configured (self-hosted single-host),
/// fall back to `dashboard_url` so the caller stays on the current origin.
fn build_org_redirect(state: &AppState, org: &overslash_db::repos::org::OrgRow) -> String {
    let scheme = if state.config.public_url.starts_with("https://") {
        "https"
    } else {
        "http"
    };
    if let Some(apex) = state.config.app_host_suffix.as_deref() {
        if org.is_personal {
            format!("{scheme}://{apex}/")
        } else {
            format!("{scheme}://{}.{apex}/", org.slug)
        }
    } else {
        // No subdomain deployment — keep the caller on the configured
        // dashboard URL, same as logout/redirect elsewhere.
        state.config.dashboard_url_for("/")
    }
}

/// Construct the `Set-Cookie` value for the session token, honoring the
/// configured cookie Domain for cross-subdomain sessions.
pub(crate) fn session_cookie(
    state: &AppState,
    token: &str,
) -> Result<header::HeaderValue, AppError> {
    let mut value = format!("oss_session={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800");
    if let Some(domain) = state.config.session_cookie_domain.as_deref() {
        value.push_str(&format!("; Domain={domain}"));
    }
    value
        .parse()
        .map_err(|e| AppError::Internal(format!("build session cookie: {e}")))
}

// ---------------------------------------------------------------------------
// Dev token (unchanged)
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
struct DevTokenQuery {
    next: Option<String>,
    /// `admin` (default), `member`, or `readonly`. Each maps to a deterministic
    /// dev identity inside Dev Org so e2e fixtures can sign in as different
    /// roles. Unknown values fall back to `admin` for forward compatibility.
    profile: Option<String>,
}

#[derive(Clone, Copy)]
enum DevProfile {
    Admin,
    Member,
    Readonly,
}

impl DevProfile {
    fn parse(s: Option<&str>) -> Self {
        match s.unwrap_or("admin") {
            "member" => Self::Member,
            "readonly" => Self::Readonly,
            _ => Self::Admin,
        }
    }
    fn email(self) -> &'static str {
        match self {
            Self::Admin => "dev@overslash.local",
            Self::Member => "member@overslash.local",
            Self::Readonly => "readonly@overslash.local",
        }
    }
    fn display_name(self) -> &'static str {
        match self {
            Self::Admin => "Dev User",
            Self::Member => "Dev Member",
            Self::Readonly => "Dev Readonly",
        }
    }
    fn external_id(self) -> &'static str {
        match self {
            Self::Admin => "dev-local",
            Self::Member => "dev-local-member",
            Self::Readonly => "dev-local-readonly",
        }
    }
}

async fn dev_token(
    State(state): State<AppState>,
    Query(query): Query<DevTokenQuery>,
) -> Result<Response, AppError> {
    if !state.config.dev_auth_enabled {
        return Err(AppError::NotFound("not found".into()));
    }

    let profile = DevProfile::parse(query.profile.as_deref());
    let admin_email = DevProfile::Admin.email();
    let system = SystemScope::new_internal(state.db.clone());

    // Step 1: ensure Dev Org exists. Look up the admin identity to find the
    // org or create one. We always run org_bootstrap (idempotent) so
    // Everyone/Admins groups + the overslash service instance exist.
    let admin_org_id = match system.find_user_identity_by_email(admin_email).await? {
        Some(existing) => existing.org_id,
        None => match org::create(&state.db, "Dev Org", "dev-org", "standard").await {
            Ok(new_org) => new_org.id,
            Err(sqlx::Error::Database(ref e)) if e.is_unique_violation() => {
                org::get_by_slug(&state.db, "dev-org")
                    .await?
                    .ok_or_else(|| AppError::Internal("dev race: dev-org missing".into()))?
                    .id
            }
            Err(e) => return Err(e.into()),
        },
    };
    overslash_db::repos::org_bootstrap::bootstrap_org(&state.db, admin_org_id, None).await?;

    // Step 2: resolve (or lazily create) the requested profile's identity
    // inside Dev Org. Every profile gets the same provisioning the
    // production OIDC callback applies — `users` row, `user_id` on the
    // identity, Everyone + Myself groups, membership row — so `/account`,
    // the org switcher, group ceilings, and is_admin all behave. Admin
    // additionally joins the Admins group via `bootstrap_org(.., Some(id))`.
    let profile_email = profile.email();
    let identity_id =
        if let Some(existing) = system.find_user_identity_by_email(profile_email).await? {
            // Re-assert admin group membership on every admin login. Without
            // this, an admin removed from the Admins group manually (or by a
            // test that toggled it off) silently loses admin powers on the
            // next sign-in. bootstrap_org is idempotent, so this is cheap.
            if matches!(profile, DevProfile::Admin) {
                overslash_db::repos::org_bootstrap::bootstrap_org(
                    &state.db,
                    admin_org_id,
                    Some(existing.id),
                )
                .await?;
            }
            existing.id
        } else {
            let scope = OrgScope::new(admin_org_id, state.db.clone());
            let new_identity = scope
                .create_identity_with_email(
                    profile.display_name(),
                    "user",
                    Some(profile.external_id()),
                    Some(profile_email),
                    json!({"dev": true, "profile": match profile {
                        DevProfile::Admin => "admin",
                        DevProfile::Member => "member",
                        DevProfile::Readonly => "readonly",
                    }}),
                )
                .await?;

            let user = user_repo::create_org_only(
                &state.db,
                Some(profile_email),
                Some(profile.display_name()),
            )
            .await?;
            overslash_db::repos::identity::set_user_id(
                &state.db,
                admin_org_id,
                new_identity.id,
                Some(user.id),
            )
            .await?;

            let role = if matches!(profile, DevProfile::Admin) {
                // Admins join the Admins group AND get an admin membership row,
                // matching what POST /v1/orgs and the org-creator IdP path do.
                overslash_db::repos::org_bootstrap::bootstrap_org(
                    &state.db,
                    admin_org_id,
                    Some(new_identity.id),
                )
                .await?;
                membership::ROLE_ADMIN
            } else {
                overslash_db::repos::org_bootstrap::bootstrap_user_in_org(
                    &state.db,
                    admin_org_id,
                    new_identity.id,
                )
                .await?;
                membership::ROLE_MEMBER
            };

            match membership::create(&state.db, user.id, admin_org_id, role).await {
                Ok(_) => {}
                Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {}
                Err(e) => return Err(e.into()),
            }

            new_identity.id
        };
    let org_id = admin_org_id;
    let dev_email = profile_email;

    // Dev login was single-org pre-multi-org. Post-040 we still back every
    // `kind='user'` identity with a `users` row; resolve it here so the dev
    // session participates in the multi-org surface (`/account`, switcher,
    // `POST /v1/orgs` bootstrap admin).
    let dev_user_id = overslash_db::repos::identity::get_by_id(&state.db, org_id, identity_id)
        .await?
        .and_then(|row| row.user_id);
    if dev_user_id.is_none() {
        tracing::warn!(
            "dev identity {identity_id} has no user_id; /account and switch-org will be limited"
        );
    }

    let jwt_secret = signing_key_bytes(&state.config.signing_key);
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let claims = jwt::Claims {
        sub: identity_id,
        org: org_id,
        email: dev_email.into(),
        aud: jwt::AUD_SESSION.into(),
        iat: now,
        exp: now + 7 * 24 * 3600,
        user_id: dev_user_id,
        mcp_client_id: None,
    };
    let token = jwt::mint(&jwt_secret, &claims)
        .map_err(|e| AppError::Internal(format!("jwt mint failed: {e}")))?;

    let session_cookie = session_cookie(&state, &token)?;

    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, session_cookie);

    // When `?next=` is set (e.g. by /oauth/authorize bouncing through dev
    // login), redirect instead of returning JSON so the OAuth flow resumes.
    if let Some(next) = query.next.as_deref().and_then(sanitize_next) {
        return Ok((headers, Redirect::to(&next)).into_response());
    }

    Ok((
        headers,
        axum::Json(json!({
            "status": "authenticated",
            "org_id": org_id,
            "identity_id": identity_id,
            "email": dev_email,
            "token": token,
        })),
    )
        .into_response())
}

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
/// When the IdP config has NULL `encrypted_client_*` fields, it defers to
/// the org's OAuth App Credentials (org secrets `OAUTH_{PROVIDER}_CLIENT_ID/SECRET`).
async fn resolve_auth_credentials(
    state: &AppState,
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

/// Find or provision a user across two distinct trust domains. See
/// `docs/design/multi_org_auth.md` §Authentication Flows.
///
/// - `org_slug = None` — **root login**: the caller hit `app.overslash.com`
///   and signed in via an Overslash-level IdP (env-var-configured Google /
///   GitHub). Lookup keys `(users.overslash_idp_provider, subject)`. If
///   missing, provision an Overslash-backed `users` row + personal org +
///   admin membership + identity.
/// - `org_slug = Some(slug)` — **org-subdomain login**: the caller hit
///   `<slug>.app.overslash.com` and signed in via that org's own IdP. Lookup
///   keys `(identities.org_id, external_id)`. If missing, gate on the org's
///   `allowed_email_domains`; on match, provision an org-only `users` row +
///   identity + member-role membership. On miss, reject with
///   `not_permitted_by_org_idp`.
///
/// In either case we return `(org_id, identity_id, user_id, email)`, which
/// callers shape into session claims.
async fn find_or_provision_user(
    state: &AppState,
    userinfo: &NormalizedUserInfo,
    org_slug: Option<&str>,
) -> Result<(Uuid, Uuid, Uuid, String), AppError> {
    match org_slug {
        None => provision_root(state, userinfo).await,
        Some(slug) => provision_org_subdomain(state, userinfo, slug).await,
    }
}

async fn provision_root(
    state: &AppState,
    userinfo: &NormalizedUserInfo,
) -> Result<(Uuid, Uuid, Uuid, String), AppError> {
    let display_name = userinfo.name.as_deref().unwrap_or(&userinfo.email);

    // Hot path: existing Overslash-backed user → refresh profile and return.
    if let Some(user) =
        user_repo::find_by_overslash_idp(&state.db, &userinfo.provider_key, &userinfo.external_id)
            .await?
    {
        let _ = user_repo::refresh_profile(
            &state.db,
            user.id,
            Some(&userinfo.email),
            Some(display_name),
        )
        .await;
        let personal_org_id = user.personal_org_id.ok_or_else(|| {
            AppError::Internal(
                "Overslash-backed user has no personal_org_id; backfill incomplete".into(),
            )
        })?;
        let identity = overslash_db::repos::identity::find_by_org_and_user(
            &state.db,
            personal_org_id,
            user.id,
        )
        .await?
        .ok_or_else(|| AppError::Internal("personal org exists but has no user identity".into()))?;
        // Keep the identity's displayed email/name roughly current too.
        let scope = OrgScope::new(personal_org_id, state.db.clone());
        let metadata = userinfo_metadata(userinfo);
        let _ = scope
            .update_identity_profile(identity.id, display_name, metadata)
            .await;
        return Ok((
            personal_org_id,
            identity.id,
            user.id,
            userinfo.email.clone(),
        ));
    }

    // First-time root login → provision personal org + Overslash-backed user.
    let slug = generate_personal_slug();
    let org = {
        let mut attempts = 0u32;
        loop {
            let candidate = if attempts == 0 {
                slug.clone()
            } else {
                generate_personal_slug()
            };
            match org::create(&state.db, display_name, &candidate, "standard").await {
                Ok(mut row) => {
                    // Flip is_personal=true. The column was added in 040 with
                    // DEFAULT false; personal orgs are marked explicitly so the
                    // subdomain middleware refuses to route them.
                    sqlx::query!("UPDATE orgs SET is_personal = true WHERE id = $1", row.id)
                        .execute(&state.db)
                        .await?;
                    row.is_personal = true;
                    break row;
                }
                Err(sqlx::Error::Database(ref e)) if e.is_unique_violation() && attempts < 5 => {
                    attempts += 1;
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
    };

    // Everything from here on — user creation, identity, bootstrap,
    // membership — runs inside `provision_root_contents`. Any error
    // (other than the unique-violation race, which returns Ok(winner) after
    // manually cleaning up the org) bubbles up here, and we compensate by
    // deleting the personal-org shell to avoid leaking an empty row.
    match provision_root_contents(state, userinfo, &org, display_name).await {
        Ok(tuple) => Ok(tuple),
        Err(e) => {
            if let Err(cleanup_err) = sqlx::query!("DELETE FROM orgs WHERE id = $1", org.id)
                .execute(&state.db)
                .await
            {
                tracing::error!(
                    org_id = %org.id,
                    error = %e,
                    cleanup_error = %cleanup_err,
                    "provision_root rollback failed; orphan personal org left in DB"
                );
            }
            Err(e)
        }
    }
}

async fn provision_root_contents(
    state: &AppState,
    userinfo: &NormalizedUserInfo,
    org: &overslash_db::repos::org::OrgRow,
    display_name: &str,
) -> Result<(Uuid, Uuid, Uuid, String), AppError> {
    // Concurrent-first-login race: another request for the same
    // (provider, subject) may have already created the users row + personal
    // org + identity + membership. We detect the race via the partial
    // UNIQUE on `users.(overslash_idp_provider, overslash_idp_subject)` and
    // fall through to the winner's state. In that case we delete *our* org
    // ourselves (the caller's outer cleanup won't run because we're
    // returning Ok) and return the winner's (org, identity, user_id).
    let new_user = match user_repo::create_overslash_backed(
        &state.db,
        Some(&userinfo.email),
        Some(display_name),
        &userinfo.provider_key,
        &userinfo.external_id,
    )
    .await
    {
        Ok(u) => u,
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            let _ = sqlx::query!("DELETE FROM orgs WHERE id = $1", org.id)
                .execute(&state.db)
                .await;
            let winner = user_repo::find_by_overslash_idp(
                &state.db,
                &userinfo.provider_key,
                &userinfo.external_id,
            )
            .await?
            .ok_or_else(|| {
                AppError::Internal(
                    "race: user row vanished between unique-violation and re-read".into(),
                )
            })?;
            // personal_org_id is set by the winner after user insert, so it
            // may be NULL if we read the row before the winner's transaction
            // commits. Retry with exponential backoff (50ms → ~1.5s total).
            let personal_org_id = {
                let mut maybe = winner.personal_org_id;
                let mut attempts = 0u32;
                while maybe.is_none() && attempts < 5 {
                    tokio::time::sleep(std::time::Duration::from_millis(50 * 2u64.pow(attempts)))
                        .await;
                    attempts += 1;
                    if let Ok(Some(refreshed)) = user_repo::find_by_overslash_idp(
                        &state.db,
                        &userinfo.provider_key,
                        &userinfo.external_id,
                    )
                    .await
                    {
                        maybe = refreshed.personal_org_id;
                    }
                }
                maybe.ok_or_else(|| {
                    AppError::Internal(
                        "race: winner's users row still has no personal_org_id after retries"
                            .into(),
                    )
                })?
            };
            let identity = overslash_db::repos::identity::find_by_org_and_user(
                &state.db,
                personal_org_id,
                winner.id,
            )
            .await?
            .ok_or_else(|| {
                AppError::Internal("race: winner has no identity in their personal org yet".into())
            })?;
            let _ = user_repo::refresh_profile(
                &state.db,
                winner.id,
                Some(&userinfo.email),
                Some(display_name),
            )
            .await;
            return Ok((
                personal_org_id,
                identity.id,
                winner.id,
                userinfo.email.clone(),
            ));
        }
        Err(e) => return Err(e.into()),
    };
    user_repo::set_personal_org(&state.db, new_user.id, org.id).await?;

    let metadata = userinfo_metadata(userinfo);
    let scope = OrgScope::new(org.id, state.db.clone());
    let identity_row = scope
        .create_identity_with_email(
            display_name,
            "user",
            Some(&userinfo.external_id),
            Some(&userinfo.email),
            metadata,
        )
        .await?;
    overslash_db::repos::identity::set_user_id(
        &state.db,
        org.id,
        identity_row.id,
        Some(new_user.id),
    )
    .await?;

    overslash_db::repos::org_bootstrap::bootstrap_org(&state.db, org.id, Some(identity_row.id))
        .await?;

    membership::create(&state.db, new_user.id, org.id, membership::ROLE_ADMIN).await?;

    Ok((org.id, identity_row.id, new_user.id, userinfo.email.clone()))
}

async fn provision_org_subdomain(
    state: &AppState,
    userinfo: &NormalizedUserInfo,
    slug: &str,
) -> Result<(Uuid, Uuid, Uuid, String), AppError> {
    let target_org = org::get_by_slug(&state.db, slug)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("org not found: {slug}")))?;
    if target_org.is_personal {
        return Err(AppError::BadRequest(
            "personal orgs do not accept IdP logins".into(),
        ));
    }

    // Existing org-identity? refresh + return.
    let scope = OrgScope::new(target_org.id, state.db.clone());
    if let Some(existing) = overslash_db::repos::identity::find_user_by_external_id_in_org(
        &state.db,
        target_org.id,
        &userinfo.external_id,
    )
    .await?
    {
        let display_name = userinfo.name.as_deref().unwrap_or(&userinfo.email);
        let metadata = userinfo_metadata(userinfo);
        let _ = scope
            .update_identity_profile(existing.id, display_name, metadata)
            .await;
        let user_id = existing.user_id.ok_or_else(|| {
            AppError::Internal(
                "org-identity missing user_id; migration 040 backfill incomplete".into(),
            )
        })?;
        let _ = user_repo::refresh_profile(
            &state.db,
            user_id,
            Some(&userinfo.email),
            Some(display_name),
        )
        .await;
        return Ok((target_org.id, existing.id, user_id, userinfo.email.clone()));
    }

    // First-time sign-in for this (org, IdP-subject). Gate on the org's
    // `allowed_email_domains` — the org admin controls who's auto-provisioned.
    //
    // Semantic: an empty list means "trust the IdP entirely" (the admin
    // already constrained who can authenticate by provisioning the IdP's
    // client_id / tenant). A non-empty list is a whitelist — only those
    // exact domains may provision. The IdP config itself must exist —
    // absence means this org hasn't enabled this provider, so we reject
    // with the same `not_permitted_by_org_idp` error as a domain mismatch.
    //
    // SINGLE_ORG_MODE exception: self-hosted operators typically use the
    // env-var Overslash-level IdPs (`GOOGLE_AUTH_CLIENT_ID`, etc.), which
    // have no `org_idp_configs` row. In that mode the operator IS the org
    // admin — the env creds they provisioned ARE the trust boundary, so
    // the per-org gate doesn't apply. Without this branch, every new
    // social-auth login under SINGLE_ORG_MODE fails with 403.
    let single_org_bypass = state
        .config
        .single_org_mode
        .as_deref()
        .map(|pinned| pinned == slug)
        .unwrap_or(false);
    if !single_org_bypass {
        let email_domain = userinfo
            .email
            .rsplit('@')
            .next()
            .unwrap_or("")
            .to_lowercase();
        let idp_config = overslash_db::repos::org_idp_config::get_by_org_and_provider(
            &state.db,
            target_org.id,
            &userinfo.provider_key,
        )
        .await?
        .ok_or_else(|| AppError::Forbidden("not_permitted_by_org_idp".into()))?;
        if !idp_config.allowed_email_domains.is_empty()
            && !idp_config
                .allowed_email_domains
                .iter()
                .any(|d| d.eq_ignore_ascii_case(&email_domain))
        {
            return Err(AppError::Forbidden("not_permitted_by_org_idp".into()));
        }
    }

    let display_name = userinfo.name.as_deref().unwrap_or(&userinfo.email);
    let metadata = userinfo_metadata(userinfo);

    // Before creating a brand-new `users` row, check whether this
    // `(provider, subject)` already corresponds to an Overslash-backed
    // user (this is the SINGLE_ORG_MODE case: env-var IdP is both the
    // Overslash IdP and the org IdP, so the same pair shows up on both
    // paths). Attach the new identity to the existing row instead of
    // creating a duplicate. In cloud multi-tenant mode the org IdP
    // uses its own client_id, so subjects don't collide with env ones
    // and this lookup returns None — same flow as before.
    let user_id = match user_repo::find_by_overslash_idp(
        &state.db,
        &userinfo.provider_key,
        &userinfo.external_id,
    )
    .await?
    {
        Some(u) => {
            let _ = user_repo::refresh_profile(
                &state.db,
                u.id,
                Some(&userinfo.email),
                Some(display_name),
            )
            .await;
            u.id
        }
        None => {
            user_repo::create_org_only(&state.db, Some(&userinfo.email), Some(display_name))
                .await?
                .id
        }
    };

    let identity_row = scope
        .create_identity_with_email(
            display_name,
            "user",
            Some(&userinfo.external_id),
            Some(&userinfo.email),
            metadata,
        )
        .await?;
    overslash_db::repos::identity::set_user_id(
        &state.db,
        target_org.id,
        identity_row.id,
        Some(user_id),
    )
    .await?;
    overslash_db::repos::org_bootstrap::bootstrap_user_in_org(
        &state.db,
        target_org.id,
        identity_row.id,
    )
    .await?;
    // `membership::create` is idempotent-friendly-enough via the PK on
    // (user_id, org_id) — but in the SINGLE_ORG_MODE reuse-user path, an
    // earlier sign-in could have left the same `(user_id, org_id)` row
    // already in place (e.g., bootstrap admin from POST /v1/orgs). Swallow
    // the unique-violation so a repeat login doesn't fail.
    match membership::create(&state.db, user_id, target_org.id, membership::ROLE_MEMBER).await {
        Ok(_) => {}
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {}
        Err(e) => return Err(e.into()),
    }

    Ok((
        target_org.id,
        identity_row.id,
        user_id,
        userinfo.email.clone(),
    ))
}

fn userinfo_metadata(userinfo: &NormalizedUserInfo) -> serde_json::Value {
    json!({
        "provider": userinfo.provider_key,
        "external_id": userinfo.external_id,
        "name": userinfo.name,
        "picture": userinfo.picture,
    })
}

fn generate_personal_slug() -> String {
    // Personal orgs never surface publicly (the subdomain middleware refuses
    // to route them), so the slug just needs to be unique across orgs.
    // `rand::random::<u64>()` gives 64 bits of entropy — collision vanishingly
    // unlikely even across millions of orgs.
    let suffix = rand::random::<u64>();
    format!("personal-{suffix:016x}")
}

/// Only allow same-origin path redirects to prevent open-redirect abuse
/// via the `?next=` parameter on IdP login.
fn sanitize_next(raw: &str) -> Option<String> {
    if raw.starts_with('/') && !raw.starts_with("//") && !raw.contains('\r') && !raw.contains('\n')
    {
        Some(raw.to_string())
    } else {
        None
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

pub(crate) fn signing_key_bytes(signing_key: &str) -> Vec<u8> {
    crate::services::jwt::signing_key_bytes(signing_key)
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
