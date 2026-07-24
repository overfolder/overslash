//! Passwordless email magic-link login (root apex).

use super::provisioning::*;
use super::*;

// ---------------------------------------------------------------------------
// Passwordless email magic-link login (root apex)
// ---------------------------------------------------------------------------

// Anti-abuse throttles for the anonymous `POST /auth/magic-link/request`
// endpoint (the API-key-keyed global middleware doesn't cover it). Generous
// per-IP backstop against volumetric abuse; tighter per-email cap against
// inbox-bombing a single victim. Buckets live in the shared rate-limit store
// (in-memory, or Redis when configured).
const MAGIC_LINK_REQ_IP_MAX: u32 = 30;
const MAGIC_LINK_REQ_IP_WINDOW_SECS: u32 = 600;
const MAGIC_LINK_REQ_EMAIL_MAX: u32 = 5;
const MAGIC_LINK_REQ_EMAIL_WINDOW_SECS: u32 = 900;

#[derive(Deserialize)]
pub(super) struct MagicLinkRequestBody {
    email: String,
    /// Same-origin post-login redirect, sanitized before it's stored.
    next: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct MagicLinkVerifyQuery {
    token: String,
}

/// Normalize an email for use as the stable login key: trim surrounding
/// whitespace and lowercase. Returns `None` for anything that isn't a
/// minimally plausible `local@domain` (we don't do full RFC 5322 — the only
/// consequence of a bad address is an undeliverable email, and we never
/// reveal validity to the caller anyway).
fn normalize_login_email(raw: &str) -> Option<String> {
    let e = raw.trim().to_lowercase();
    let (local, domain) = e.split_once('@')?;
    if local.is_empty()
        || domain.is_empty()
        || !domain.contains('.')
        || e.contains(char::is_whitespace)
    {
        return None;
    }
    Some(e)
}

/// `POST /auth/magic-link/request` — mint a single-use, short-TTL, hashed
/// token and email the sign-in link. Always responds `200 {"sent": true}`
/// regardless of whether the email maps to an existing user, so the endpoint
/// can't be used to enumerate accounts. When `dev_auth_enabled` (local dev /
/// the test harness, where the NoopMailer drops the body) the verify URL is
/// echoed back as `dev_verify_url` so the link is reachable without an inbox.
pub(super) async fn request_magic_link(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    ClientIp(client_ip): ClientIp,
    axum::Json(body): axum::Json<MagicLinkRequestBody>,
) -> Result<Response, AppError> {
    if !state.config.magic_link_enabled {
        return Err(AppError::NotFound("magic-link login is disabled".into()));
    }

    let opaque_ok = || axum::Json(json!({ "sent": true })).into_response();

    // Anti-abuse. This endpoint is anonymous (no API key), so the global
    // rate-limit middleware — which keys on the API-key prefix — skips it
    // entirely. Throttle here on the shared store directly (in-memory by
    // default, Redis when `REDIS_URL` is set). Two independent buckets:
    //   - per-IP: a DoS / volumetric backstop → surfaced as 429.
    //   - per-email: stops bombing a victim's inbox (and burning Resend
    //     quota) → handled *silently* below so a 429 can't reveal that a
    //     given address is being targeted.
    let ip = client_ip.as_deref().unwrap_or("unknown");
    let ip_rl = state
        .rate_limiter(&ext)
        .check_and_increment(
            &format!("ml:req:ip:{ip}"),
            MAGIC_LINK_REQ_IP_MAX,
            MAGIC_LINK_REQ_IP_WINDOW_SECS,
        )
        .await;
    if !ip_rl.allowed {
        let retry_after = ip_rl
            .reset_at
            .saturating_sub(crate::services::rate_limit::now_unix());
        return Err(AppError::RateLimited {
            limit: ip_rl.limit,
            reset_at: ip_rl.reset_at,
            retry_after,
        });
    }

    let Some(email) = normalize_login_email(&body.email) else {
        // Don't 400 on a malformed address either — that's still a signal.
        // Silently succeed without minting a token.
        return Ok(opaque_ok());
    };
    let next = body.next.as_deref().and_then(sanitize_next);

    // Per-email throttle. On trip, drop silently (no token, no email, opaque
    // success) so the response is indistinguishable from a normal send.
    let email_rl = state
        .rate_limiter(&ext)
        .check_and_increment(
            &format!("ml:req:email:{email}"),
            MAGIC_LINK_REQ_EMAIL_MAX,
            MAGIC_LINK_REQ_EMAIL_WINDOW_SECS,
        )
        .await;
    if !email_rl.allowed {
        tracing::info!("magic-link request throttled (per-email)");
        return Ok(opaque_ok());
    }

    // 32 random bytes → URL-safe token; store only its SHA-256 hash.
    let mut buf = [0u8; 32];
    rand::rng().fill(&mut buf);
    let raw_token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
    let token_hash = Sha256::digest(raw_token.as_bytes()).to_vec();

    let row = magic_link_token::create(
        state.db(&ext),
        &token_hash,
        &email,
        next.as_deref(),
        crate::services::magic_link_email::MAGIC_LINK_TOKEN_TTL_SECS,
    )
    .await?;

    let api_base = state.config.public_url.trim_end_matches('/');
    let verify_url = format!(
        "{api_base}/auth/magic-link/verify?token={}",
        urlencoding::encode(&raw_token)
    );

    let send_ok = match crate::services::magic_link_email::send(&state, &email, &verify_url).await {
        Ok(()) => true,
        Err(e) => {
            // Drop the orphaned token so a transient mailer failure doesn't
            // leave a valid login link no one received. Best-effort cleanup.
            tracing::warn!(error = %e, "magic-link email send failed");
            let _ = magic_link_token::delete(state.db(&ext), row.id).await;
            false
        }
    };

    // Only echo the dev link when the token is actually live — on a send
    // failure we just deleted it, so returning the URL would hand the
    // developer a link that 404s at verify. Fall through to the opaque
    // success instead. (Surfacing the failure itself would leak mailer state.)
    if send_ok && state.config.dev_auth_enabled {
        tracing::info!(%verify_url, "magic-link dev: verify URL (dev_auth_enabled)");
        return Ok(
            axum::Json(json!({ "sent": true, "dev_verify_url": verify_url })).into_response(),
        );
    }

    Ok(opaque_ok())
}

/// `GET /auth/magic-link/verify?token=…` — claim the token (single-use,
/// unexpired), provision/load the Overslash-backed `email` user via the shared
/// root provisioning path, mint a session JWT, set the cookie, and redirect to
/// the dashboard. Invalid/expired/used tokens bounce to the login page.
pub(super) async fn verify_magic_link(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    Query(q): Query<MagicLinkVerifyQuery>,
) -> Result<Response, AppError> {
    if !state.config.magic_link_enabled {
        return Err(AppError::NotFound("magic-link login is disabled".into()));
    }

    let token_hash = Sha256::digest(q.token.as_bytes()).to_vec();
    let Some(row) = magic_link_token::consume(state.db(&ext), &token_hash).await? else {
        return Ok(Redirect::to("/login?reason=magic_link_invalid").into_response());
    };

    // Reuse the OAuth root-provisioning path: an `email`-provider user keyed on
    // (provider='email', subject=normalized email). Idempotent — the same
    // email always resolves to the same user + personal org.
    let userinfo = NormalizedUserInfo {
        provider_key: "email".into(),
        external_id: row.email.clone(),
        email: row.email.clone(),
        name: None,
        picture: None,
    };
    let (org_id, identity_id, user_id, email) =
        find_or_provision_user(&state, &ext, &userinfo, None).await?;

    let jwt_secret = signing_key_bytes(&state.config.signing_key);
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let claims = jwt::Claims {
        sub: identity_id,
        org: org_id,
        email,
        aud: jwt::AUD_SESSION.into(),
        iat: now,
        exp: now + 7 * 24 * 3600,
        user_id: Some(user_id),
        mcp_client_id: None,
    };
    let token = jwt::mint(&jwt_secret, &claims)
        .map_err(|e| AppError::Internal(format!("jwt mint failed: {e}")))?;

    let session_cookie = session_cookie(&state, &token)?;
    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(header::SET_COOKIE, session_cookie);

    // Magic-link is a root-apex-only flow that always mints a personal-org
    // session, so redirect straight to the configured root dashboard. Do NOT
    // route through `absolute_redirect_for_org` — that honors the
    // `oss_auth_org` cookie left by an OAuth login on a corp subdomain, which
    // would bounce this personal-org session onto that subdomain and trip the
    // subdomain↔JWT org-match guard (`org_mismatch`).
    let next_path = row
        .next_path
        .unwrap_or_else(|| state.config.dashboard_url.clone());
    Ok((resp_headers, Redirect::to(&next_path)).into_response())
}
