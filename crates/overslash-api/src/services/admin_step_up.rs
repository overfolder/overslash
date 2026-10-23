//! Admin-class mutations need a fresh IdP sign-in (CASA 3.3.1, 2.4.1; D-NEXT
//! "Admin-class mutations need a fresh IdP sign-in").
//!
//! Overslash has no second factor of its own and does not grow one: it
//! delegates authentication to IdPs, and an org's IdP (Workspace, Entra,
//! Okta, GitHub with 2FA required) is where MFA is enforced. The hole was the
//! paths that do not go through that IdP — a magic link proves control of a
//! mailbox, nothing more — and sessions old enough that the IdP's challenge
//! is days behind them. So a **dashboard session** performing an
//! **admin-class mutation** in a **shared org** must be:
//!
//! 1. an IdP sign-in (`user_sessions.auth_method = 'idp'`) — never a magic
//!    link, never unrecorded; `dev` only while `DEV_AUTH` is on, which the
//!    boot policy keeps out of production;
//! 2. through a provider the org signs in with (its enabled `org_idp_configs`
//!    plus managed providers if it allows them). An org with none configured
//!    accepts any IdP — its members arrive from the root login. A deployment
//!    with no IdP at all (a self-hosted, magic-link-only install) accepts a
//!    fresh magic link instead: there is no IdP whose MFA to defer to, and
//!    refusing would leave its admins unable to add the first one;
//! 3. no older than `ADMIN_STEP_UP_MAX_AGE_SECS` (default 1 h). A switch-org
//!    re-scope keeps the original `authenticated_at`: it is not a sign-in.
//!
//! Otherwise the answer is 403 `step_up_required` naming the providers that
//! would do; the dashboard sends the human through `/auth/login/{key}` with
//! `step_up=1`, which asks the IdP to re-authenticate (`max_age=0`) and
//! starts a new session.
//!
//! Out of scope by construction: safe methods (reading an admin page is not
//! an admin action), personal orgs (their only member is their admin, and
//! nothing there reaches anyone else), API keys and MCP tokens (bearer
//! credentials, minted by a session that passed this gate or scoped to an
//! agent), and the stateless session JWTs the API mints for its own loopback
//! calls (no `jti`, under 24 h, never handed to a browser).

use axum::http::{Extensions, HeaderMap, Method};
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

use overslash_db::repos::user_session::{self as repo, UserSessionRow, auth_method};

use crate::AppState;
use crate::cookies;
use crate::error::AppError;
use crate::services::{jwt, org_signin};

/// A sign-in that would satisfy the gate, for the dashboard's prompt.
#[derive(Debug, Clone, Serialize)]
pub struct StepUpProvider {
    pub key: String,
    pub display_name: String,
    /// Where the dashboard sends the human (plus its own `next`): the login
    /// with `step_up=true`, against the org when the org names its IdPs.
    pub login_path: String,
}

/// What the admin action is scoped to.
#[derive(Debug, Clone, Copy)]
pub enum Target {
    /// An org admin acting in `org_id`.
    Org(Uuid),
    /// An instance admin — any IdP will do, but a magic link will not.
    Instance,
}

/// Which sign-ins count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Allowed {
    /// Any IdP: an org with no sign-in providers of its own, or an instance
    /// admin.
    Any,
    /// Only these provider keys: the org's own sign-in providers.
    Only(Vec<String>),
    /// The deployment offers no IdP to step up through, so a fresh magic link
    /// is the strongest sign-in there is.
    NoIdp,
}

/// Refuse the request unless it is a step-up-fresh session, or out of scope.
pub async fn require(
    state: &AppState,
    ext: &Extensions,
    method: &Method,
    headers: &HeaderMap,
    target: Target,
) -> Result<(), AppError> {
    if is_safe(method) {
        return Ok(());
    }
    let Some(jti) = session_jti(state, headers) else {
        return Ok(());
    };
    let (allowed, org_slug) = match target {
        Target::Org(org_id) => {
            let org = overslash_db::repos::org::get_by_id(state.db(ext), org_id)
                .await?
                .ok_or_else(|| AppError::NotFound("org not found".into()))?;
            if org.is_personal {
                return Ok(());
            }
            let keys: Vec<String> = org_signin::list_org_signin_providers(state, ext, org_id)
                .await?
                .into_iter()
                .map(|p| p.provider_key)
                .collect();
            if keys.is_empty() {
                (any_idp(state), None)
            } else {
                (Allowed::Only(keys), Some(org.slug))
            }
        }
        Target::Instance => (any_idp(state), None),
    };
    let row = repo::get(state.db(ext), jti).await?;
    let max_age = state.config.admin_step_up_max_age_secs;
    let verdict = evaluate(
        row.as_ref(),
        &allowed,
        OffsetDateTime::now_utc(),
        max_age,
        state.config.dev_auth_enabled,
    );
    match verdict {
        Ok(()) => Ok(()),
        Err(reason) => Err(AppError::StepUpRequired {
            reason,
            providers: offered(state, ext, &allowed, org_slug.as_deref()).await?,
            max_age_secs: max_age,
        }),
    }
}

/// The rule, without I/O. `Err` carries the `reason` the 403 reports.
pub fn evaluate(
    row: Option<&UserSessionRow>,
    allowed: &Allowed,
    now: OffsetDateTime,
    max_age_secs: i64,
    dev_auth_enabled: bool,
) -> Result<(), &'static str> {
    let Some(row) = row else {
        return Err("idp_required");
    };
    match row.auth_method.as_deref() {
        Some(auth_method::IDP) => {
            if let Allowed::Only(keys) = allowed {
                let provider = row.auth_provider.as_deref().unwrap_or_default();
                if !keys.iter().any(|k| k == provider) {
                    return Err("provider_not_allowed");
                }
            }
        }
        Some(auth_method::MAGIC_LINK) if *allowed == Allowed::NoIdp => {}
        Some(auth_method::DEV) if dev_auth_enabled => {}
        _ => return Err("idp_required"),
    }
    match row.authenticated_at {
        Some(at) if (now - at).whole_seconds() <= max_age_secs => Ok(()),
        _ => Err("stale"),
    }
}

/// The deployment's root IdPs — what a member of an org with no providers of
/// its own signs in with.
fn root_idps(state: &AppState) -> Vec<String> {
    org_signin::MANAGED_PROVIDER_KEYS
        .iter()
        .filter(|k| state.config.env_auth_credentials(k).is_some())
        .map(|k| k.to_string())
        .collect()
}

fn any_idp(state: &AppState) -> Allowed {
    if root_idps(state).is_empty() {
        Allowed::NoIdp
    } else {
        Allowed::Any
    }
}

fn is_safe(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// The `jti` of a session cookie that authenticates this request. `None`
/// when there is no session cookie (API key, MCP token) or it carries no
/// `jti` (a server-minted stateless token).
fn session_jti(state: &AppState, headers: &HeaderMap) -> Option<Uuid> {
    let token = cookies::read_session(headers, state)?;
    jwt::verify(
        &jwt::signing_key_bytes(&state.config.signing_key),
        &token,
        jwt::AUD_SESSION,
    )
    .ok()?
    .jti
}

/// `org_slug` is set when the org names its providers: the login must then
/// resolve them against the org. With `Allowed::Any` it is the root login.
async fn offered(
    state: &AppState,
    ext: &Extensions,
    allowed: &Allowed,
    org_slug: Option<&str>,
) -> Result<Vec<StepUpProvider>, AppError> {
    let keys: Vec<String> = match allowed {
        Allowed::Only(keys) => keys.clone(),
        Allowed::Any => root_idps(state),
        Allowed::NoIdp if state.config.magic_link_enabled => {
            return Ok(vec![StepUpProvider {
                key: "email".into(),
                display_name: "an email link".into(),
                login_path: "/login?reason=step_up".into(),
            }]);
        }
        Allowed::NoIdp => Vec::new(),
    };
    let mut out = Vec::with_capacity(keys.len());
    for key in keys {
        let mut login_path = format!("/auth/login/{}?step_up=true", urlencoding::encode(&key));
        if let Some(slug) = org_slug {
            login_path.push_str(&format!("&org={}", urlencoding::encode(slug)));
        }
        out.push(StepUpProvider {
            display_name: org_signin::display_name_for(state, ext, &key).await?,
            key,
            login_path,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(method: Option<&str>, provider: Option<&str>, age_secs: i64) -> UserSessionRow {
        let now = OffsetDateTime::now_utc();
        UserSessionRow {
            id: Uuid::new_v4(),
            user_id: None,
            identity_id: Uuid::new_v4(),
            org_id: Uuid::new_v4(),
            created_at: now,
            last_seen_at: now,
            expires_at: now + time::Duration::days(7),
            revoked_at: None,
            revoked_reason: None,
            user_agent: None,
            ip_address: None,
            auth_method: method.map(str::to_owned),
            auth_provider: provider.map(str::to_owned),
            authenticated_at: method.map(|_| now - time::Duration::seconds(age_secs)),
            idp_amr: None,
            idp_acr: None,
        }
    }

    fn eval(r: &UserSessionRow, allowed: &Allowed, dev: bool) -> Result<(), &'static str> {
        evaluate(Some(r), allowed, OffsetDateTime::now_utc(), 3600, dev)
    }

    #[test]
    fn a_fresh_idp_sign_in_passes() {
        let r = row(Some("idp"), Some("google"), 60);
        assert_eq!(eval(&r, &Allowed::Any, false), Ok(()));
        assert_eq!(
            eval(&r, &Allowed::Only(vec!["google".into()]), false),
            Ok(())
        );
    }

    #[test]
    fn a_magic_link_does_not_pass_where_an_idp_exists() {
        let r = row(Some("magic_link"), None, 0);
        assert_eq!(eval(&r, &Allowed::Any, true), Err("idp_required"));
    }

    #[test]
    fn an_unrecorded_or_missing_session_needs_an_idp() {
        assert_eq!(
            eval(&row(None, None, 0), &Allowed::Any, false),
            Err("idp_required")
        );
        assert_eq!(
            evaluate(None, &Allowed::Any, OffsetDateTime::now_utc(), 3600, false),
            Err("idp_required")
        );
    }

    #[test]
    fn the_provider_must_be_one_the_org_signs_in_with() {
        let r = row(Some("idp"), Some("github"), 60);
        assert_eq!(
            eval(&r, &Allowed::Only(vec!["okta-1234".into()]), false),
            Err("provider_not_allowed")
        );
    }

    #[test]
    fn an_old_sign_in_is_stale() {
        let r = row(Some("idp"), Some("google"), 3601);
        assert_eq!(eval(&r, &Allowed::Any, false), Err("stale"));
    }

    #[test]
    fn a_magic_link_counts_only_where_there_is_no_idp() {
        let r = row(Some("magic_link"), None, 60);
        assert_eq!(eval(&r, &Allowed::NoIdp, false), Ok(()));
        let stale = row(Some("magic_link"), None, 3601);
        assert_eq!(eval(&stale, &Allowed::NoIdp, false), Err("stale"));
    }

    #[test]
    fn dev_counts_only_while_dev_auth_is_on() {
        let r = row(Some("dev"), None, 60);
        assert_eq!(
            eval(&r, &Allowed::Only(vec!["google".into()]), true),
            Ok(())
        );
        assert_eq!(eval(&r, &Allowed::Any, false), Err("idp_required"));
    }
}
