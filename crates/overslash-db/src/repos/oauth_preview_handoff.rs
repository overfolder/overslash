//! Storage for the Vercel preview-deployment OAuth handoff. Two tables, both
//! short-lived: `oauth_preview_origins` carries the original preview URL
//! across the Google round-trip (referenced by an opaque UUID embedded in
//! the OAuth `state` param), and `oauth_handoff_codes` is a one-time-use
//! ticket the API hands the preview after callback so it can adopt the
//! session via a host-only cookie set in the proxied response.
//!
//! Only ever populated when `PREVIEW_ORIGIN_ALLOWLIST` is set; on prod both
//! tables stay empty.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct PreviewOriginRow {
    pub preview_id: Uuid,
    pub origin: String,
    pub expires_at: OffsetDateTime,
    /// CSRF nonce echoed in the OAuth `state` param. Validated against
    /// `state` on callback in lieu of a cookie — the auth-state cookies
    /// would carry `Domain=.app.<apex>` and the browser rejects them on a
    /// `*.vercel.app` preview origin (no shared parent).
    pub nonce: String,
    /// PKCE verifier minted alongside the challenge. None when the
    /// provider doesn't support PKCE.
    pub pkce_verifier: Option<String>,
    /// Org slug carried across the IdP bounce so DB-stored credentials
    /// resolve correctly on subdomain-initiated logins.
    pub org_slug: Option<String>,
    /// Path-only `next` to redirect to after handoff redemption.
    pub next_path: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct HandoffCodeRow {
    pub code: String,
    pub jwt: String,
    pub origin: String,
    pub next_path: Option<String>,
    pub expires_at: OffsetDateTime,
    pub consumed_at: Option<OffsetDateTime>,
}

/// Persist a preview origin keyed by `preview_id` for `ttl_secs` from now.
/// `preview_id` is the opaque token embedded in the OAuth state param;
/// `nonce`, `pkce_verifier`, `org_slug`, and `next_path` are the auth-state
/// the callback would normally pull from `oss_auth_*` cookies — those don't
/// survive the `*.vercel.app` ↔ `api.<apex>` cookie-domain gap, so we keep
/// them server-side instead.
#[allow(clippy::too_many_arguments)]
pub async fn insert_preview_origin(
    pool: &PgPool,
    preview_id: Uuid,
    origin: &str,
    nonce: &str,
    pkce_verifier: Option<&str>,
    org_slug: Option<&str>,
    next_path: Option<&str>,
    ttl_secs: i64,
) -> Result<(), sqlx::Error> {
    let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(ttl_secs);
    // Lazy GC: every insert prunes expired rows. Cheap given the table only
    // grows during active logins; in prod (feature off) it stays empty.
    sqlx::query!("DELETE FROM oauth_preview_origins WHERE expires_at < now()")
        .execute(pool)
        .await?;
    sqlx::query!(
        "INSERT INTO oauth_preview_origins
            (preview_id, origin, nonce, pkce_verifier, org_slug, next_path, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
        preview_id,
        origin,
        nonce,
        pkce_verifier,
        org_slug,
        next_path,
        expires_at,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Fetch a preview origin if not yet expired. Doesn't delete the row — the
/// callback is allowed to look it up; the lazy GC on insert keeps the table
/// trim.
pub async fn get_preview_origin(
    pool: &PgPool,
    preview_id: Uuid,
) -> Result<Option<PreviewOriginRow>, sqlx::Error> {
    sqlx::query_as!(
        PreviewOriginRow,
        "SELECT preview_id, origin, expires_at, nonce, pkce_verifier, org_slug, next_path
         FROM oauth_preview_origins
         WHERE preview_id = $1 AND expires_at > now()",
        preview_id,
    )
    .fetch_optional(pool)
    .await
}

/// Mint a handoff code. The caller passes a freshly generated random token,
/// the JWT we want the preview to adopt, the origin the code is bound to,
/// and the optional path we want the preview to redirect to after cookie
/// set. TTL is in seconds.
pub async fn insert_handoff_code(
    pool: &PgPool,
    code: &str,
    jwt: &str,
    origin: &str,
    next_path: Option<&str>,
    ttl_secs: i64,
) -> Result<(), sqlx::Error> {
    let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(ttl_secs);
    sqlx::query!("DELETE FROM oauth_handoff_codes WHERE expires_at < now()")
        .execute(pool)
        .await?;
    sqlx::query!(
        "INSERT INTO oauth_handoff_codes (code, jwt, origin, next_path, expires_at)
         VALUES ($1, $2, $3, $4, $5)",
        code,
        jwt,
        origin,
        next_path,
        expires_at,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Read a handoff code without consuming it. Used for pre-consume
/// validation (host binding, allowlist re-check) so a probe / crawler
/// can't burn a legitimate user's code by hitting the handoff URL with
/// a wrong host header. Returns None if missing, expired, or already
/// consumed — callers don't need to distinguish.
pub async fn peek_handoff_code(
    pool: &PgPool,
    code: &str,
) -> Result<Option<HandoffCodeRow>, sqlx::Error> {
    sqlx::query_as!(
        HandoffCodeRow,
        "SELECT code, jwt, origin, next_path, expires_at, consumed_at
         FROM oauth_handoff_codes
         WHERE code = $1 AND consumed_at IS NULL AND expires_at > now()",
        code,
    )
    .fetch_optional(pool)
    .await
}

/// Atomically consume a handoff code: marks it `consumed_at = now()` and
/// returns the row only when the code exists, hasn't been consumed, and
/// hasn't expired. Replays return None.
///
/// Pre-validate via `peek_handoff_code` and only call this once you know
/// the request is legitimate; after this call the code is gone whether
/// or not the surrounding response succeeds.
pub async fn consume_handoff_code(
    pool: &PgPool,
    code: &str,
) -> Result<Option<HandoffCodeRow>, sqlx::Error> {
    sqlx::query_as!(
        HandoffCodeRow,
        "UPDATE oauth_handoff_codes
         SET consumed_at = now()
         WHERE code = $1 AND consumed_at IS NULL AND expires_at > now()
         RETURNING code, jwt, origin, next_path, expires_at, consumed_at",
        code,
    )
    .fetch_optional(pool)
    .await
}
