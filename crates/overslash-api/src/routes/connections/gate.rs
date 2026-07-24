//! Public-facing `/connect-authorize` fail-fast UX gate for the HTTP-OAuth
//! flow, plus its consent-confirmation POST.

use super::*;

// ---------------------------------------------------------------------------
// GET /connect-authorize?id=F
// ---------------------------------------------------------------------------
//
// Public-facing fail-fast UX gate for the HTTP-OAuth flow. Mirrors
// `oauth_upstream::gated_authorize`: reads the dashboard session, looks up
// the flow row, and only redirects to the provider when the session
// actually matches. This is the chat-delivery hardening described in
// `docs/design/agent-mcp-bootstrap-story.md` §3 ("Is this vulnerable to
// the Obsidian pitfalls?") — without this gate, an agent could hand a
// raw provider URL to the user with no Overslash-branded checkpoint.

#[derive(Debug, Deserialize)]
pub(super) struct ConnectAuthorizeParams {
    id: String,
}

pub(super) async fn connect_authorize(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    headers: HeaderMap,
    Query(params): Query<ConnectAuthorizeParams>,
) -> Result<Response> {
    let Some(flow) = oauth_connection_flow::get_by_id(state.db(&ext), &params.id).await? else {
        return Ok(gone_html("This OAuth link is invalid or has been revoked."));
    };
    if flow.consumed_at.is_some() {
        return Ok(gone_html(
            "This OAuth link has already been used. Initiate the connection again to retry.",
        ));
    }
    if flow.expires_at <= OffsetDateTime::now_utc() {
        return Ok(gone_html(
            "This OAuth link has expired. Initiate the connection again to retry.",
        ));
    }

    let session = match read_session(&state, &headers) {
        Ok(s) => s,
        Err(SessionError::Missing) => {
            // Out-of-band delivery (Slack/email/agent chat) clicked
            // without an active session. Bounce through login and
            // resume.
            let return_to = format!(
                "{}/connect-authorize?id={}",
                state.config.public_url.trim_end_matches('/'),
                flow.id
            );
            let login_url = state.config.dashboard_url_for(&format!(
                "/auth/login?next={}",
                urlencoding::encode(&return_to)
            ));
            return Ok(Redirect::to(&login_url).into_response());
        }
        Err(SessionError::Invalid) => {
            return Err(AppError::Unauthorized("invalid session cookie".into()));
        }
    };

    match evaluate_connect_gate(&state, &ext, &session, &flow, allow_remint(&ext)).await? {
        ConnectGateOutcome::Deny => Ok(mismatch_html()),
        // Admin/actor who is not the owner: render the loud consent page. The
        // flow is NOT consumed here — the confirm POST is the boundary that
        // re-validates and consumes. `set_cookie` is recomputed on confirm.
        ConnectGateOutcome::NeedsConsent {
            owner_label,
            provider,
            ..
        } => Ok(admin_consent_html(&owner_label, &provider, &flow.id)),
        ConnectGateOutcome::Allow { set_cookie } => {
            consume_and_redirect(&state, &ext, &flow.id, set_cookie).await
        }
    }
}

#[derive(Deserialize)]
pub(super) struct ConfirmParams {
    id: String,
}

/// POST target of the admin/actor consent interstitial ([`admin_consent_html`]).
/// The consent page is advisory; this handler is the boundary — it re-runs the
/// full gate evaluation server-side (never trusting the page) and only then
/// consumes the flow and redirects to the provider. `SameSite=Lax` on the
/// session cookie blocks a cross-site forge of this POST.
pub(super) async fn connect_authorize_confirm(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    headers: HeaderMap,
    Form(params): Form<ConfirmParams>,
) -> Result<Response> {
    let Some(flow) = oauth_connection_flow::get_by_id(state.db(&ext), &params.id).await? else {
        return Ok(gone_html("This OAuth link is invalid or has been revoked."));
    };
    if flow.consumed_at.is_some() {
        return Ok(gone_html(
            "This OAuth link has already been used. Initiate the connection again to retry.",
        ));
    }
    if flow.expires_at <= OffsetDateTime::now_utc() {
        return Ok(gone_html(
            "This OAuth link has expired. Initiate the connection again to retry.",
        ));
    }
    let session = match read_session(&state, &headers) {
        Ok(s) => s,
        Err(SessionError::Missing) => return Err(AppError::Unauthorized("missing session".into())),
        Err(SessionError::Invalid) => {
            return Err(AppError::Unauthorized("invalid session cookie".into()));
        }
    };
    match evaluate_connect_gate(&state, &ext, &session, &flow, allow_remint(&ext)).await? {
        ConnectGateOutcome::Deny => Ok(mismatch_html()),
        // Owner/auto-switch, or a consented admin/actor — both proceed.
        ConnectGateOutcome::Allow { set_cookie }
        | ConnectGateOutcome::NeedsConsent { set_cookie, .. } => {
            consume_and_redirect(&state, &ext, &flow.id, set_cookie).await
        }
    }
}

/// Whether the connect gate may transparently re-mint the session cookie to the
/// flow's org. On an explicit org subdomain the dashboard already aligns the
/// cookie via `/auth/switch-org`, so we never silently re-scope there; on
/// `Root` (local dev with no subdomains, or the apex) the auto-switch is the
/// fix for multi-org / multi-IdP users.
fn allow_remint(ext: &axum::http::Extensions) -> bool {
    !matches!(
        ext.get::<crate::middleware::subdomain::RequestOrgContext>(),
        Some(crate::middleware::subdomain::RequestOrgContext::Org { .. })
    )
}

/// Atomically claim the flow for redirect and 303 to the upstream provider,
/// attaching `set_cookie` only on the winning consume (so we never re-scope a
/// session for a flow we didn't actually start). `consume` is the gate's
/// single-use UX flag — a concurrent click that already marked the row returns
/// `None`, in which case we render the "already been used" page instead of
/// letting two browser tabs race into the upstream provider. The
/// `/v1/oauth/callback` security boundary still re-validates everything from the
/// OAuth `state` parameter regardless.
async fn consume_and_redirect(
    state: &AppState,
    ext: &axum::http::Extensions,
    flow_id: &str,
    set_cookie: Option<axum::http::HeaderValue>,
) -> Result<Response> {
    match oauth_connection_flow::consume(state.db(ext), flow_id).await? {
        Some(row) => {
            let mut resp = Redirect::to(&row.upstream_authorize_url).into_response();
            if let Some(cookie) = set_cookie {
                resp.headers_mut().insert(header::SET_COOKIE, cookie);
            }
            Ok(resp)
        }
        None => Ok(gone_html(
            "This OAuth link has already been used. Initiate the connection again to retry.",
        )),
    }
}
