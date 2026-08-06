//! Provider OAuth login/callback, Vercel preview handoff, and provider listing.

use super::*;
use super::{provisioning::*, userinfo::*};

// ---------------------------------------------------------------------------
// Query params
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct LoginQuery {
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
pub(super) struct HandoffQuery {
    code: String,
}

#[derive(Deserialize)]
pub(super) struct CallbackQuery {
    code: String,
    state: String,
}

#[derive(Deserialize)]
pub(super) struct ProvidersQuery {
    org: Option<String>,
}

// ---------------------------------------------------------------------------
// Generic provider login
// ---------------------------------------------------------------------------

pub(super) async fn provider_login(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    Path(provider_key): Path<String>,
    ctx: Option<axum::extract::Extension<crate::middleware::subdomain::RequestOrgContext>>,
    Query(query): Query<LoginQuery>,
) -> Result<Response, AppError> {
    let provider = oauth_provider::get_by_key(state.db(&ext), &provider_key)
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
        resolve_auth_credentials(&state, &ext, &provider_key, effective_org_slug.as_deref())
            .await?;

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
                state.db(&ext),
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
        // Dashboard sign-in, not a connection: whoever is hitting `/auth/login`
        // has not identified themselves yet, so there is no account to hint at.
        None,
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

pub(super) async fn provider_callback(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
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
        let row =
            overslash_db::repos::oauth_preview_handoff::get_preview_origin(state.db(&ext), pid)
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

    let provider = oauth_provider::get_by_key(state.db(&ext), &provider_key)
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
        resolve_auth_credentials(&state, &ext, &provider_key, org_slug.as_deref()).await?;

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
        find_or_provision_user(&state, &ext, &userinfo, org_slug.as_deref()).await?;

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
            state.db(&ext),
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
pub(super) async fn handoff_consume(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    headers: HeaderMap,
    Query(q): Query<HandoffQuery>,
) -> Result<Response, AppError> {
    if !state.config.is_preview_handoff_enabled() {
        return Err(AppError::NotFound("not found".into()));
    }

    // Peek first so failed validations leave the row consumable by a
    // retry that gets the host right.
    let row =
        overslash_db::repos::oauth_preview_handoff::peek_handoff_code(state.db(&ext), &q.code)
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
        overslash_db::repos::oauth_preview_handoff::consume_handoff_code(state.db(&ext), &q.code)
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

pub(super) async fn google_login_compat(
    state: State<AppState>,
    ext: ReqExt,
    ctx: Option<axum::extract::Extension<crate::middleware::subdomain::RequestOrgContext>>,
    query: Query<LoginQuery>,
) -> Result<Response, AppError> {
    provider_login(state, ext, Path("google".to_string()), ctx, query).await
}

pub(super) async fn google_callback_compat(
    state: State<AppState>,
    ext: ReqExt,
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
        ext,
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

pub(super) async fn list_auth_providers(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    ctx: Option<axum::extract::Extension<crate::middleware::subdomain::RequestOrgContext>>,
    Query(query): Query<ProvidersQuery>,
) -> Result<impl IntoResponse, AppError> {
    // Older test harnesses mount the router without the subdomain
    // middleware; treat the missing extension as Root so those paths still
    // list providers correctly.
    let ctx = ctx
        .map(|axum::extract::Extension(c)| c)
        .unwrap_or(crate::middleware::subdomain::RequestOrgContext::Root);
    // Which list to render (docs/design/multi_org_auth.md §Flow 2):
    //   - On a corp-org subdomain, whatever `services::org_signin` says that
    //     org can sign in with — its own IdPs, plus the Overslash-managed
    //     providers if it opted into them.
    //   - On the root apex, the Overslash-level providers only. A corp org's
    //     IdP is its own trust domain and has nothing to offer here.
    //   - Back-compat: if the caller passed `?org=<slug>` on the root apex
    //     (pre-multi-org dashboards still do), honor it and list that org's
    //     providers — equivalent to hitting the subdomain.
    let mut providers = Vec::new();

    let resolved_org_id = match &ctx {
        crate::middleware::subdomain::RequestOrgContext::Org { org_id, .. } => Some(*org_id),
        crate::middleware::subdomain::RequestOrgContext::Root => {
            if let Some(slug) = &query.org {
                org::get_by_slug(state.db(&ext), slug).await?.map(|o| o.id)
            } else {
                None
            }
        }
    };

    if let Some(org_id) = resolved_org_id {
        // Listing the managed providers here doesn't weaken D12: admission is
        // a separate gate in `provision_org_subdomain` (a pending invite
        // identity, or the org's `managed_signin_allowed_domains`), so an
        // uninvited stranger authenticates and then fails with `not_invited`.
        for provider in org_signin::list_org_signin_providers(&state, &ext, org_id).await? {
            let display_name =
                org_signin::display_name_for(&state, &ext, &provider.provider_key).await?;
            let managed = provider.is_managed();
            providers.push(json!({
                "key": provider.provider_key,
                "display_name": display_name,
                "source": if managed { "env" } else { "db" },
                "managed": managed,
                "is_default": provider.is_default,
            }));
        }

        // `scope = "org"` tells the dashboard to render the corp-org empty
        // state ("contact the org creator") when the org hasn't configured
        // an IdP yet. Root-level empty states read differently.
        return Ok(axum::Json(json!({
            "providers": providers,
            "scope": "org",
        })));
    }

    // Root apex — Overslash-level providers only, from the same key list the
    // managed org path uses so a new provider is added in one place.
    for key in org_signin::MANAGED_PROVIDER_KEYS {
        if state.config.env_auth_credentials(key).is_none() {
            continue;
        }
        providers.push(json!({
            "key": key,
            "display_name": org_signin::display_name_for(&state, &ext, key).await?,
            "source": "env",
        }));
    }
    // Passwordless email magic-link — built-in, needs no external IdP config,
    // so it's the default working login on a fresh self-hosted deploy. Root
    // only: corp subdomains admit members through their own IdP + invites.
    if state.config.magic_link_enabled {
        providers.push(json!({
            "key": "email",
            "display_name": "Email",
            "source": "builtin",
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
