//! Shared session-gate primitives for OAuth-flow proxied URLs.
//!
//! Both `oauth_upstream` (nested OAuth, MCP-client role) and `connections`
//! (first-party HTTP OAuth) hand out URLs of the form
//! `https://app.overslash.com/<gate>?id=<flow>`. Each gate handler reads
//! the dashboard session cookie, looks up its own flow row, and
//! fail-fasts on a mismatch. The session-reading and HTML-rendering
//! parts are identical across the two; live here once.
//!
//! Caller-owned: each gate handler reads its own flow table and decides
//! whether the parsed session is authorized for that specific flow. We
//! only provide the generic `(org_id, identity_id)` permit check —
//! flow-specific shape stays in the call site.

use axum::{
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
};
use time::OffsetDateTime;
use uuid::Uuid;

use overslash_db::repos::oauth_connection_flow::OauthConnectionFlowRow;
use overslash_db::repos::{identity, membership};

use crate::AppState;
use crate::error::AppError;
use crate::extractors::extract_cookie;
use crate::routes::auth::{session_cookie, signing_key_bytes};
use crate::services::jwt;

#[derive(Debug)]
pub struct ParsedSession {
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub user_id: Option<Uuid>,
}

pub enum SessionError {
    Missing,
    Invalid,
}

pub fn read_session(state: &AppState, headers: &HeaderMap) -> Result<ParsedSession, SessionError> {
    let token = extract_cookie(headers, "oss_session").ok_or(SessionError::Missing)?;
    let signing_key = signing_key_bytes(&state.config.signing_key);
    let claims =
        jwt::verify(&signing_key, &token, jwt::AUD_SESSION).map_err(|_| SessionError::Invalid)?;
    Ok(ParsedSession {
        org_id: claims.org,
        identity_id: claims.sub,
        user_id: claims.user_id,
    })
}

/// Generic permit check: `true` iff the session is in the same org as
/// the flow target and either *is* that target or sits above it in the
/// identity owner chain (so the parent user authorizing on behalf of
/// their owned agent is fine).
pub async fn session_authorized_for_org_identity(
    state: &AppState,
    ext: &axum::http::Extensions,
    session: &ParsedSession,
    flow_org_id: Uuid,
    flow_identity_id: Uuid,
) -> Result<bool, AppError> {
    if session.org_id != flow_org_id {
        return Ok(false);
    }
    if session.identity_id == flow_identity_id {
        return Ok(true);
    }
    let chain = identity::get_ancestor_chain(state.db(ext), flow_org_id, flow_identity_id).await?;
    Ok(chain.iter().any(|row| row.id == session.identity_id))
}

/// Outcome of the connect-gate authorization check for a flow.
pub enum ConnectGateOutcome {
    /// The session is authorized to proceed straight to the provider. When
    /// `set_cookie` is `Some`, the caller MUST attach it to the redirect so
    /// the browser session is transparently re-scoped to the flow's org first
    /// (the same-human cross-org auto-switch — mirrors `/auth/switch-org`).
    Allow { set_cookie: Option<HeaderValue> },
    /// The session is NOT the flow's owner, but the acting identity is an org
    /// admin of the flow's org or the flow's `actor` — so it MAY proceed after
    /// an explicit, loud confirmation that names whose account is being linked.
    /// The caller renders [`admin_consent_html`]; the confirm POST re-runs this
    /// evaluation (never trusting the client) and treats this variant as
    /// "proceed". `set_cookie` carries the cross-org remint, applied on confirm.
    NeedsConsent {
        set_cookie: Option<HeaderValue>,
        owner_label: String,
        provider: String,
    },
    /// Not authorized — caller renders `mismatch_html()`.
    Deny,
}

/// Resolve the user-kind identity in `target_org` that is the SAME human as
/// `session`, matching by **same user-id OR same IdP identity**
/// (provider + subject). Returns `None` when the human has no conservatively
/// matchable presence in `target_org`.
///
/// `users.id` is deduplicated only by `(idp_provider, idp_subject)` (migration
/// 040), so the same person who joined two orgs via *different* IdPs has
/// *different* `user_id`s — the IdP fallback recovers those. Email is never a
/// match key: an IdP can report an address it does not control, so an
/// email match would let one IdP vouch for a user on another (DECISIONS.md
/// D12).
async fn resolve_same_human_in_org(
    state: &AppState,
    ext: &axum::http::Extensions,
    session: &ParsedSession,
    target_org: Uuid,
) -> Result<Option<identity::IdentityRow>, AppError> {
    // 1. Same user-id — at most one user-kind identity per `(org, user)`.
    if let Some(user_id) = session.user_id
        && let Some(row) =
            identity::find_by_org_and_user(state.db(ext), target_org, user_id).await?
    {
        return Ok(Some(row));
    }
    // 2. Same IdP — match the session identity's `(provider, subject)` against
    //    a user-kind identity in the target org. Both the subject
    //    (`external_id`) and the provider (`metadata.provider`) must agree, so
    //    a bare subject collision across providers cannot match.
    let Some(session_ident) =
        identity::get_by_id(state.db(ext), session.org_id, session.identity_id).await?
    else {
        return Ok(None);
    };
    let Some(subject) = session_ident.external_id.as_deref() else {
        return Ok(None);
    };
    let session_provider = idp_provider(&session_ident);
    if session_provider.is_none() {
        return Ok(None);
    }
    let Some(candidate) =
        identity::find_user_by_external_id_in_org(state.db(ext), target_org, subject).await?
    else {
        return Ok(None);
    };
    if idp_provider(&candidate) == session_provider {
        return Ok(Some(candidate));
    }
    Ok(None)
}

/// The IdP provider key recorded on a user-kind identity at login
/// (`metadata.provider`), if any.
fn idp_provider(ident: &identity::IdentityRow) -> Option<String> {
    ident
        .metadata
        .get("provider")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
}

/// Mint a fresh `oss_session` Set-Cookie scoped to `org_id` + `identity`,
/// mirroring `switch_org`. The identity's email is non-authoritative (display
/// / audit only — all authz is `org` + `sub` + `user_id`).
fn mint_switch_cookie(
    state: &AppState,
    org_id: Uuid,
    identity: &identity::IdentityRow,
) -> Result<HeaderValue, AppError> {
    let secret = signing_key_bytes(&state.config.signing_key);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = jwt::Claims {
        sub: identity.id,
        org: org_id,
        email: identity.email.clone().unwrap_or_default(),
        aud: jwt::AUD_SESSION.into(),
        iat: now,
        exp: now + 7 * 24 * 3600,
        user_id: identity.user_id,
        mcp_client_id: None,
    };
    let token = jwt::mint(&secret, &claims)
        .map_err(|e| AppError::Internal(format!("jwt mint failed: {e}")))?;
    session_cookie(state, &token)
}

/// A human-readable label for the flow's owning identity, for the consent page.
async fn owner_label(
    state: &AppState,
    ext: &axum::http::Extensions,
    flow: &OauthConnectionFlowRow,
) -> Result<String, AppError> {
    let owner = identity::get_by_id(state.db(ext), flow.org_id, flow.identity_id).await?;
    Ok(owner
        .map(|o| match o.email {
            Some(e) if !e.is_empty() => format!("{} ({})", o.name, e),
            _ => o.name,
        })
        .unwrap_or_else(|| "another identity".to_string()))
}

/// Evaluate the connect gate for a flow. Three tiers, most-trusted first:
///
/// 1. **Owner / ancestor** of the flow's identity in its org → proceed.
/// 2. **Same human** (matched by user-id OR IdP) who is owner/ancestor in the
///    flow's org via a *different* active session → proceed with a transparent
///    org auto-switch (`set_cookie`). Reproduces locally (no subdomains) the
///    alignment production gets from the subdomain↔JWT enforcement.
/// 3. **Org admin of the flow's org, or the flow's `actor`** → `NeedsConsent`:
///    may proceed only after a loud confirmation, because the external account
///    they authorize with on the provider will be stapled onto the *owner's*
///    connection (a deliberate, consented credential substitution).
///
/// `allow_remint = false` pins everything to the same-org path (e.g. on an
/// explicit org subdomain, where silently re-scoping the cookie would fight the
/// subdomain the browser is on).
pub async fn evaluate_connect_gate(
    state: &AppState,
    ext: &axum::http::Extensions,
    session: &ParsedSession,
    flow: &OauthConnectionFlowRow,
    allow_remint: bool,
) -> Result<ConnectGateOutcome, AppError> {
    // Tier 1 — same-org owner/ancestor. Unchanged behaviour, cookie untouched.
    if session_authorized_for_org_identity(state, ext, session, flow.org_id, flow.identity_id)
        .await?
    {
        return Ok(ConnectGateOutcome::Allow { set_cookie: None });
    }

    // Resolve the identity that is acting in the flow's org, plus the remint
    // cookie needed to get there. Same org → the session identity, no cookie.
    // Cross org → the same human's identity (id-or-IdP), with a remint cookie,
    // but only when reminting is permitted.
    let (acting, set_cookie) = if session.org_id == flow.org_id {
        match identity::get_by_id(state.db(ext), flow.org_id, session.identity_id).await? {
            Some(acting) => (acting, None),
            None => return Ok(ConnectGateOutcome::Deny),
        }
    } else if allow_remint {
        match resolve_same_human_in_org(state, ext, session, flow.org_id).await? {
            Some(acting) => {
                let cookie = mint_switch_cookie(state, flow.org_id, &acting)?;
                (acting, Some(cookie))
            }
            None => return Ok(ConnectGateOutcome::Deny),
        }
    } else {
        return Ok(ConnectGateOutcome::Deny);
    };

    // Tier 2 — the acting identity is the flow's owner or an ancestor of it.
    // Tiers 2 and the admin arm of 3 both require a *live* membership in the
    // flow's org — `is_org_admin` on a stale identity row whose membership was
    // later removed must NOT authorize (there is no DB constraint tying the two,
    // so we enforce it here rather than trust the invariant).
    let mut admin_in_org = false;
    if let Some(user_id) = acting.user_id
        && membership::find(state.db(ext), user_id, flow.org_id)
            .await?
            .is_some()
    {
        // Tier 2 — the acting identity is the flow's owner or an ancestor.
        let owner_or_ancestor = acting.id == flow.identity_id || {
            let chain =
                identity::get_ancestor_chain(state.db(ext), flow.org_id, flow.identity_id).await?;
            chain.iter().any(|row| row.id == acting.id)
        };
        if owner_or_ancestor {
            return Ok(ConnectGateOutcome::Allow { set_cookie });
        }
        admin_in_org = acting.is_org_admin;
    }

    // Tier 3 — override behind a loud consent page; the confirm POST re-runs
    // this same evaluation before consuming the flow. Two ways in:
    //   * a membership-verified org admin (above), or
    //   * the flow's own `actor` re-clicking its link (self-authorization;
    //     harmless even for an agent-kind actor with no `user_id`/membership).
    if admin_in_org || acting.id == flow.actor_identity_id {
        return Ok(ConnectGateOutcome::NeedsConsent {
            set_cookie,
            owner_label: owner_label(state, ext, flow).await?,
            provider: flow.provider_key.clone(),
        });
    }

    Ok(ConnectGateOutcome::Deny)
}

// ── HTML helpers ──────────────────────────────────────────────────────────
// Minimal, server-rendered. The dashboard owns rich UX; these pages are
// only reached when the session check fails or the URL is gone. Any
// caller-controlled data MUST go through `html_escape` before
// interpolation.

pub fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

pub fn gone_html(msg: &str) -> Response {
    let body = format!(
        "<!doctype html><meta charset=utf-8><title>OAuth link unavailable</title>\
         <body style='font-family:system-ui;max-width:480px;margin:4rem auto;padding:0 1rem'>\
         <h1>Link unavailable</h1><p>{}</p></body>",
        html_escape(msg)
    );
    (StatusCode::GONE, Html(body)).into_response()
}

pub fn mismatch_html() -> Response {
    let body = "<!doctype html><meta charset=utf-8><title>Wrong account</title>\
                <body style='font-family:system-ui;max-width:480px;margin:4rem auto;padding:0 1rem'>\
                <h1>Wrong account</h1>\
                <p>This OAuth link was created for a different Overslash account. \
                If you believe this is an error, sign out and sign in as the correct user, \
                then click the link again.</p></body>";
    (StatusCode::FORBIDDEN, Html(body)).into_response()
}

/// The loud admin/actor consent interstitial. Shown when the signed-in
/// identity is *not* the flow's owner but is an org admin (or the flow's
/// actor) and so may proceed on the owner's behalf. It must name **whose**
/// account is being linked, because the provider account they authorize with
/// next is stored on the owner's connection — not theirs. The confirm form
/// POSTs back to `/connect-authorize/confirm`, which re-validates the override
/// before consuming the flow (so this page is advisory, not the security
/// boundary). `SameSite=Lax` on `oss_session` keeps a cross-site forge of the
/// POST from carrying the victim's session.
pub fn admin_consent_html(owner_label: &str, provider: &str, flow_id: &str) -> Response {
    let owner = html_escape(owner_label);
    let prov = html_escape(provider);
    let id = html_escape(flow_id);
    let body = format!(
        "<!doctype html><meta charset=utf-8><title>Connect on someone's behalf</title>\
         <body style='font-family:system-ui;max-width:480px;margin:4rem auto;padding:0 1rem'>\
         <h1>Connect {prov} for {owner}?</h1>\
         <p>This connection belongs to <strong>{owner}</strong>, not to you. \
         You can authorize it because you are an administrator of their org.</p>\
         <p style='border-left:3px solid #b45309;background:#fffbeb;padding:.75rem 1rem;border-radius:4px'>\
         ⚠ The {prov} account you sign in with on the next screen will be linked to \
         <strong>{owner}</strong>'s connection. Those credentials will be used by \
         <strong>{owner}</strong> — including any agents acting as them — not by you.</p>\
         <form method='post' action='/connect-authorize/confirm' style='margin-top:1.5rem'>\
         <input type='hidden' name='id' value='{id}'>\
         <button type='submit' style='padding:.6rem 1.1rem;font-size:1rem;cursor:pointer'>\
         Continue to {prov}</button>\
         <button type='button' onclick='window.close()' \
         style='margin-left:.5rem;padding:.6rem 1.1rem;font-size:1rem;cursor:pointer'>Cancel</button>\
         </form></body>"
    );
    (StatusCode::OK, Html(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::html_escape;

    #[test]
    fn html_escape_handles_xss_payloads() {
        assert_eq!(
            html_escape("<script>alert('x')</script>"),
            "&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;"
        );
        assert_eq!(html_escape("a&b\"c"), "a&amp;b&quot;c");
    }
}
