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

    // The OAuth callback always lands on `public_url/auth/callback/<provider>`
    // (typically the root apex), so when login kicks off from a corp
    // subdomain the auth-state cookies MUST be set on the shared parent
    // domain (`session_cookie_domain`, e.g. `.app.overslash.com`) or the
    // browser won't send them to the callback host. Without this, login
    // from a subdomain silently fails with "missing auth nonce cookie".
    let nonce_cookie = auth_cookie(&state, "oss_auth_nonce", &nonce);
    let verifier_value = pkce.as_ref().map_or("none", |p| p.verifier.as_str());
    let verifier_cookie = auth_cookie(&state, "oss_auth_verifier", verifier_value);
    // Persist org slug across the OAuth redirect so the callback can resolve
    // DB-stored credentials. Value is "none" when org context isn't needed
    // (env-var social providers). Sanitize to prevent header injection.
    let org_slug_value = effective_org_slug
        .as_deref()
        .filter(|s| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.'))
        })
        .unwrap_or("none");
    let org_cookie = auth_cookie(&state, "oss_auth_org", org_slug_value);

    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, nonce_cookie.parse().unwrap());
    headers.append(header::SET_COOKIE, verifier_cookie.parse().unwrap());
    headers.append(header::SET_COOKIE, org_cookie.parse().unwrap());

    // Persist `next` across the IdP round-trip so the callback can resume
    // wherever the caller wanted (used by `/oauth/authorize` to bounce
    // through login). Only accept path-only targets to keep this from
    // turning into an open redirect.
    if let Some(next) = query.next.as_deref().and_then(sanitize_next) {
        let next_cookie = auth_cookie(&state, "oss_auth_next", &next);
        headers.append(header::SET_COOKIE, next_cookie.parse().unwrap());
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

    // Recover org slug from cookie (set during provider_login). Subdomain
    // context is authoritative and takes precedence — even if the cookie
    // says otherwise, a callback hitting `<slug>.app.overslash.com` must
    // be treated as that org's login path.
    let cookie_slug = extract_cookie(&headers, "oss_auth_org").filter(|s| s != "none");
    let ctx = ctx
        .map(|axum::extract::Extension(c)| c)
        .unwrap_or(crate::middleware::subdomain::RequestOrgContext::Root);
    let org_slug = match ctx {
        crate::middleware::subdomain::RequestOrgContext::Org { slug, .. } => Some(slug),
        crate::middleware::subdomain::RequestOrgContext::Root => cookie_slug,
    };

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
    };
    let token = jwt::mint(&jwt_secret, &claims)
        .map_err(|e| AppError::Internal(format!("jwt mint failed: {e}")))?;

    // Set session cookie + clear auth cookies
    let session_cookie = session_cookie(&state, &token)?;
    // Clear with the same Domain attribute we set them with — otherwise the
    // browser keeps the cross-subdomain copy around and the next login round
    // picks up stale nonce/verifier state.
    let clear_nonce = clear_auth_cookie(&state, "oss_auth_nonce");
    let clear_verifier = clear_auth_cookie(&state, "oss_auth_verifier");
    let clear_org = clear_auth_cookie(&state, "oss_auth_org");
    let clear_next = clear_auth_cookie(&state, "oss_auth_next");

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(header::SET_COOKIE, session_cookie);
    resp_headers.append(header::SET_COOKIE, clear_nonce.parse().unwrap());
    resp_headers.append(header::SET_COOKIE, clear_verifier.parse().unwrap());
    resp_headers.append(header::SET_COOKIE, clear_org.parse().unwrap());
    resp_headers.append(header::SET_COOKIE, clear_next.parse().unwrap());

    let redirect_target = extract_cookie(&headers, "oss_auth_next")
        .and_then(|v| sanitize_next(&v))
        .unwrap_or_else(|| state.config.dashboard_url.clone());
    Ok((resp_headers, Redirect::to(&redirect_target)).into_response())
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
    // identity's FK.
    let user_id = session.user_id.or(ident.user_id);
    let (memberships, personal_org_id) = if let Some(uid) = user_id {
        (
            list_membership_summaries(&state, uid).await?,
            user_repo::get_by_id(&state.db, uid)
                .await?
                .and_then(|u| u.personal_org_id),
        )
    } else {
        (Vec::new(), None)
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
}

async fn dev_token(
    State(state): State<AppState>,
    Query(query): Query<DevTokenQuery>,
) -> Result<Response, AppError> {
    if !state.config.dev_auth_enabled {
        return Err(AppError::NotFound("not found".into()));
    }

    let dev_email = "dev@overslash.local";
    let system = SystemScope::new_internal(state.db.clone());
    let (org_id, identity_id) =
        if let Some(existing) = system.find_user_identity_by_email(dev_email).await? {
            // Re-run bootstrap so the dev user is always an org admin, even if it
            // pre-existed the bootstrap logic or was created before joining Admins.
            // bootstrap_org is idempotent.
            overslash_db::repos::org_bootstrap::bootstrap_org(
                &state.db,
                existing.org_id,
                Some(existing.id),
            )
            .await?;
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
                    overslash_db::repos::org_bootstrap::bootstrap_org(
                        &state.db,
                        existing.org_id,
                        Some(existing.id),
                    )
                    .await?;
                    (existing.org_id, existing.id)
                }
                Err(e) => return Err(e.into()),
            }
        };

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

/// Resolve auth credentials for a provider. Precedence:
/// 1. Environment variables (e.g. GOOGLE_AUTH_CLIENT_ID)
/// 2. DB-stored org_idp_config (requires org context via slug). When the
///    config has NULL `encrypted_client_*` fields, it defers to the org's
///    OAuth App Credentials (org secrets `OAUTH_{PROVIDER}_CLIENT_ID/SECRET`).
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
            match org::create(&state.db, display_name, &candidate).await {
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
            let personal_org_id = winner.personal_org_id.ok_or_else(|| {
                AppError::Internal(
                    "race: winner's users row has no personal_org_id yet; retry after the other request commits".into(),
                )
            })?;
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
    overslash_db::repos::org_bootstrap::add_to_everyone_group(
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
    hex::decode(signing_key).unwrap_or_else(|_| signing_key.as_bytes().to_vec())
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
