//! Server-side dashboard sessions (CASA 2.2.1–2.2.3).
//!
//! The session cookie stays a signed JWT with the 7-day lifetime the
//! dashboard has always had, but every one we mint now carries a `jti` naming
//! a `user_sessions` row, and [`crate::middleware::session_gate`] checks that
//! row on every request. So:
//!
//! - **Logout** revokes the row — the cookie is dead even if a copy survives.
//! - **Terminate** (one session, or all but this one) is self-service from the
//!   account page.
//! - **Identity change** — the IdP reporting a different email at sign-in, an
//!   admin rewriting a member's email — revokes every session of that human.
//! - **Admin removal / archive** revokes the sessions scoped to that member's
//!   identity in the org.
//!
//! A session JWT with no `jti` is stateless and therefore non-revocable, which
//! CASA 2.2.3 allows only for tokens living under 24 hours. The gate accepts
//! one exactly when its lifetime is within [`STATELESS_MAX_LIFETIME_SECS`]:
//! the 10-minute loopback token `mcp_session` mints for itself, and nothing a
//! browser holds. Every pre-jti 7-day cookie is turned away, once, on deploy.
//!
//! Minting: [`start`] for a sign-in (a fresh row, and the browser's previous
//! session, if any, revoked as replaced), [`rescope`] for re-pointing the
//! current session at another org of the same human (switch-org and friends
//! — same row, so the sessions list shows devices, not org hops).

pub mod cache;

use std::time::Duration;

use axum::http::{Extensions, HeaderMap, header};
use time::OffsetDateTime;
use uuid::Uuid;

use overslash_db::repos::user_session as repo;

use crate::AppState;
use crate::cookies;
use crate::error::AppError;
use crate::extractors::ClientIp;
use crate::services::jwt;

pub use cache::SessionCache;

/// Session lifetime: the 7-day UX, unchanged. Matches the cookie `Max-Age`.
pub const SESSION_TTL_SECS: i64 = cookies::SESSION_MAX_AGE;
/// Longest lifetime a session JWT may have without a `jti` (CASA 2.2.3).
pub const STATELESS_MAX_LIFETIME_SECS: i64 = 24 * 3600;
/// How long a live answer is cached. Also the worst case for a revocation
/// whose cache delete failed.
pub const CACHE_TTL: Duration = Duration::from_secs(30);
/// How long a dead verdict is cached. Death is terminal — a revoked, expired
/// or deleted row never comes back, and a `jti` is never reissued — so this
/// can be long. It matters because the gate runs *before* the rate limiters
/// (a revoked cookie must not spend its former owner's bucket), which leaves
/// a replayed dead token unmetered: without this every replay is a lookup.
pub const DEAD_CACHE_TTL: Duration = Duration::from_secs(3600);
/// Cache value standing for "dead". No identity has the nil id.
const DEAD: Uuid = Uuid::nil();
/// `last_seen_at` is refreshed at most this often.
const TOUCH_INTERVAL_SECS: i64 = 300;
/// Revoked and expired rows are kept this long, then purged.
pub const RETENTION_SECS: i64 = 30 * 24 * 3600;
/// Display-only columns are cut to this many bytes.
const MAX_ORIGIN_LEN: usize = 512;

pub mod reason {
    pub const LOGOUT: &str = "logout";
    pub const REPLACED: &str = "replaced";
    pub const TERMINATED: &str = "terminated";
    pub const TERMINATED_BY_OTHER: &str = "terminated_by_other_session";
    pub const IDENTITY_CHANGED: &str = "identity_changed";
    pub const MEMBER_REMOVED: &str = "member_removed";
    pub const IDENTITY_ARCHIVED: &str = "identity_archived";
}

/// Who a session is for.
pub struct Subject {
    pub identity_id: Uuid,
    pub org_id: Uuid,
    pub user_id: Option<Uuid>,
    /// Display/audit only; authz is `org` + `sub` + `user_id`.
    pub email: String,
}

/// The gate's answer for one session JWT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Live,
    /// Revoked, expired, deleted, or a stateless token that lives too long.
    /// The browser's cookie should be cleared.
    Dead,
    /// The row is live but has since been re-scoped to another identity — an
    /// older copy of a cookie the browser has already replaced. Refused, but
    /// not cleared: the clear would wipe the replacement.
    Superseded,
}

/// Is this (signature-verified) session JWT still a session?
pub async fn check(
    state: &AppState,
    ext: &Extensions,
    claims: &jwt::Claims,
) -> Result<Verdict, sqlx::Error> {
    let Some(jti) = claims.jti else {
        return Ok(if claims.exp - claims.iat <= STATELESS_MAX_LIFETIME_SECS {
            Verdict::Live
        } else {
            Verdict::Dead
        });
    };
    let verdict = |identity_id: Uuid| {
        if identity_id == DEAD {
            Verdict::Dead
        } else if identity_id == claims.sub {
            Verdict::Live
        } else {
            Verdict::Superseded
        }
    };
    if let Some(identity_id) = state.session_cache.get(jti).await {
        return Ok(verdict(identity_id));
    }
    let db = state.db(ext);
    let now = OffsetDateTime::now_utc();
    let row = repo::get(db, jti).await?;
    let Some(row) = row.filter(|r| r.is_live(now)) else {
        // Past the JWT's own expiry every reader rejects it anyway.
        let remaining = (claims.exp - now.unix_timestamp()).max(1) as u64;
        state
            .session_cache
            .put(
                jti,
                DEAD,
                DEAD_CACHE_TTL.min(Duration::from_secs(remaining)),
            )
            .await;
        return Ok(Verdict::Dead);
    };
    if (now - row.last_seen_at).whole_seconds() >= TOUCH_INTERVAL_SECS
        && let Err(e) = repo::touch(db, jti).await
    {
        tracing::warn!(%jti, "session last_seen_at refresh failed: {e}");
    }
    let remaining = Duration::from_secs((row.expires_at - now).whole_seconds().max(1) as u64);
    state
        .session_cache
        .put(jti, row.identity_id, CACHE_TTL.min(remaining))
        .await;
    Ok(verdict(row.identity_id))
}

/// Mint the session JWT for a fresh sign-in. Revokes whatever session the
/// browser presented, so re-authenticating never leaves the old one alive.
pub async fn start(
    state: &AppState,
    ext: &Extensions,
    headers: &HeaderMap,
    subject: Subject,
) -> Result<String, AppError> {
    if let Some(prev) = current_jti(state, headers) {
        revoke_one(state, ext, prev, None, reason::REPLACED).await?;
    }
    let (user_agent, ip) = origin(state, ext, headers);
    let row = repo::create(
        state.db(ext),
        repo::NewUserSession {
            user_id: subject.user_id,
            identity_id: subject.identity_id,
            org_id: subject.org_id,
            ttl_secs: SESSION_TTL_SECS,
            user_agent: user_agent.as_deref(),
            ip_address: ip.as_deref(),
        },
    )
    .await?;
    mint(state, subject, row.id)
}

/// Mint the session JWT re-pointing the caller's current session at another
/// org/identity of the same human. Falls back to [`start`] when the request
/// carries no live session of that human.
pub async fn rescope(
    state: &AppState,
    ext: &Extensions,
    headers: &HeaderMap,
    subject: Subject,
) -> Result<String, AppError> {
    if let (Some(prev), Some(user_id)) = (current_jti(state, headers), subject.user_id)
        && let Some(row) = repo::rescope(
            state.db(ext),
            prev,
            user_id,
            subject.identity_id,
            subject.org_id,
            SESSION_TTL_SECS,
        )
        .await?
    {
        state.session_cache.invalidate(&[prev]).await;
        return mint(state, subject, row.id);
    }
    start(state, ext, headers, subject).await
}

/// Revoke one session. `owner` limits it to that human's sessions.
pub async fn revoke_one(
    state: &AppState,
    ext: &Extensions,
    id: Uuid,
    owner: Option<Uuid>,
    reason: &str,
) -> Result<bool, AppError> {
    let revoked = repo::revoke(state.db(ext), id, owner, reason).await?;
    state.session_cache.invalidate(&[id]).await;
    Ok(revoked)
}

/// Revoke every session of a human, except `except`. Returns how many.
pub async fn revoke_all_for_user(
    state: &AppState,
    ext: &Extensions,
    user_id: Uuid,
    except: Option<Uuid>,
    reason: &str,
) -> Result<usize, AppError> {
    let ids = repo::revoke_all_for_user(state.db(ext), user_id, except, reason).await?;
    state.session_cache.invalidate(&ids).await;
    Ok(ids.len())
}

/// Revoke the sessions scoped to these identities of `org_id`. Returns how many.
pub async fn revoke_for_identities(
    state: &AppState,
    ext: &Extensions,
    org_id: Uuid,
    identity_ids: &[Uuid],
    reason: &str,
) -> Result<usize, AppError> {
    let ids = repo::revoke_for_identities(state.db(ext), org_id, identity_ids, reason).await?;
    state.session_cache.invalidate(&ids).await;
    Ok(ids.len())
}

/// The `jti` of the session cookie on this request, if it verifies. By the
/// time a handler runs, the gate has already stripped a dead one.
pub fn current_jti(state: &AppState, headers: &HeaderMap) -> Option<Uuid> {
    let token = cookies::read_session(headers, state)?;
    jwt::verify(
        &jwt::signing_key_bytes(&state.config.signing_key),
        &token,
        jwt::AUD_SESSION,
    )
    .ok()?
    .jti
}

fn mint(state: &AppState, subject: Subject, jti: Uuid) -> Result<String, AppError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = jwt::Claims {
        sub: subject.identity_id,
        org: subject.org_id,
        email: subject.email,
        aud: jwt::AUD_SESSION.into(),
        iat: now,
        exp: now + SESSION_TTL_SECS,
        user_id: subject.user_id,
        mcp_client_id: None,
        jti: Some(jti),
    };
    jwt::mint(&jwt::signing_key_bytes(&state.config.signing_key), &claims)
        .map_err(|e| AppError::Internal(format!("jwt mint failed: {e}")))
}

/// User agent and client IP, for the sessions list.
fn origin(
    state: &AppState,
    ext: &Extensions,
    headers: &HeaderMap,
) -> (Option<String>, Option<String>) {
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| truncate(s.trim()))
        .filter(|s| !s.is_empty());
    let ip = ClientIp::resolve_from(headers, ext, state).0;
    (user_agent, ip)
}

fn truncate(s: &str) -> String {
    s[..s.floor_char_boundary(MAX_ORIGIN_LEN)].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_snaps_to_a_char_boundary() {
        let s = "é".repeat(MAX_ORIGIN_LEN);
        let t = truncate(&s);
        assert!(t.len() <= MAX_ORIGIN_LEN);
        assert!(t.chars().all(|c| c == 'é'));
    }
}
