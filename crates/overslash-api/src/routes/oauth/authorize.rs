//! Authorization endpoint (`GET /oauth/authorize`), IdP bounce and code issuance.

use super::*;

// ---------------------------------------------------------------------------
// Authorize (OAuth 2.1 §4.1 + PKCE)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct AuthorizeQuery {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    code_challenge: String,
    code_challenge_method: String,
    scope: Option<String>,
    state: Option<String>,
}

pub(super) async fn authorize(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    ctx: Option<Extension<RequestOrgContext>>,
    Query(params): Query<AuthorizeQuery>,
    headers: HeaderMap,
) -> Response {
    // Older test harnesses mount the OAuth router without the subdomain
    // middleware; treat the missing extension as Root so the existing
    // env-var IdP path still works.
    let ctx = ctx.map(|Extension(c)| c).unwrap_or(RequestOrgContext::Root);
    // Reject bad params BEFORE checking auth so every failure is diagnosable.
    if params.response_type != "code" {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            "response_type must be \"code\"",
        );
    }
    if params.code_challenge_method != "S256" {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_challenge_method must be S256",
        );
    }
    if params.code_challenge.is_empty() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_challenge required",
        );
    }
    if !params
        .scope
        .as_deref()
        .map(|s| s.split_whitespace().any(|t| t == "mcp"))
        .unwrap_or(false)
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "scope must include \"mcp\"",
        );
    }

    let client = match oauth_mcp_client::get_by_client_id(state.db(&ext), &params.client_id).await {
        Ok(Some(c)) if !c.is_revoked => c,
        Ok(_) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "unknown or revoked client",
            );
        }
        Err(e) => {
            tracing::error!("DCR lookup failed: {e}");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "failed to look up client",
            );
        }
    };
    if !client
        .redirect_uris
        .iter()
        .any(|r| r == &params.redirect_uri)
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "redirect_uri does not match any registered URI",
        );
    }

    // Client org gate (hardening): on a corp subdomain, a client stamped for a
    // *different* org can't authorize here — blocks cross-subdomain replay of a
    // `client_id`. A NULL (root/multi-org) client is accepted; the
    // org-derivation below forces the agent into ctx.org regardless of the
    // client. See docs/design/mcp-enrollment-org-scoping.md.
    if let RequestOrgContext::Org { org_id, .. } = &ctx {
        if let Some(client_org) = client.org_id {
            if client_org != *org_id {
                return oauth_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "client is registered to a different org",
                );
            }
        }
    }

    // Bounce through IdP login if not signed in.
    let session_claims = match session::extract_session(&state, &headers) {
        Some(c) => c,
        None => return idp_bounce(&state, &ext, &ctx, &params).await,
    };

    // Reconcile the session against the subdomain. On a corp subdomain a
    // session for a *different* org must not divert the enrollment: force a
    // re-auth through the org's IdP (next= preserved) so the agent lands in
    // ctx.org, never in the stale session's org. Root has no subdomain to
    // mismatch against, so a valid session (corp or personal) is untouched.
    // See docs/design/mcp-enrollment-org-scoping.md.
    if let RequestOrgContext::Org { org_id, .. } = &ctx {
        if session_claims.org != *org_id {
            return idp_bounce(&state, &ext, &ctx, &params).await;
        }
    }

    // The org the enrolled agent lands in: the subdomain org on a corp
    // subdomain, the session org at root (today's behavior). After the
    // reconcile above these are equal on a corp subdomain.
    let resolved_org = match &ctx {
        RequestOrgContext::Org { org_id, .. } => *org_id,
        RequestOrgContext::Root => session_claims.org,
    };

    // Fast path: if this (user, client_id) already has an enrolled agent in
    // the resolved org, skip the consent screen and issue a code bound to that
    // agent. The lookup failure-mode is "fall through to consent" rather than
    // 500 so a transient DB blip doesn't lock the user out of authentication.
    if let Ok(Some(binding)) = mcp_client_agent_binding::get_for(
        state.db(&ext),
        session_claims.sub,
        &client.client_id,
        resolved_org,
    )
    .await
    {
        if let Ok(Some(agent)) =
            identity::get_by_id(state.db(&ext), resolved_org, binding.agent_identity_id).await
        {
            if agent.archived_at.is_none() && agent.kind == "agent" {
                let email = agent.email.as_deref().unwrap_or(&session_claims.email);
                return issue_authorization_code(
                    &state,
                    &ext,
                    &client.client_id,
                    agent.id,
                    resolved_org,
                    email,
                    &params.redirect_uri,
                    &params.code_challenge,
                    params.state.as_deref(),
                );
            }
        }
        // Binding points at an archived / missing / wrong-kind agent —
        // stale row. Fall through to consent so the user re-enrolls.
    }

    // No binding (or stale): park the authorize request and redirect to the
    // consent screen. The `request_id` lives only in memory (60s TTL) so a
    // consent submission against a stale or forged id fails closed.
    let request_id = oauth_as::generate_auth_code();
    state.pending_authorize_store(&ext).insert(
        request_id.clone(),
        oauth_as::PendingAuthorize {
            client_id: client.client_id.clone(),
            redirect_uri: params.redirect_uri.clone(),
            code_challenge: params.code_challenge.clone(),
            state_param: params.state.clone(),
            user_identity_id: session_claims.sub,
            org_id: resolved_org,
            email: session_claims.email.clone(),
            issued_at: Instant::now(),
        },
    );
    Redirect::to(&state.config.dashboard_url_for(&format!(
        "/oauth/consent?request_id={}",
        urlencoding::encode(&request_id)
    )))
    .into_response()
}

fn rebuild_authorize_path(p: &AuthorizeQuery) -> String {
    let mut qs = format!(
        "/oauth/authorize?response_type={}&client_id={}&redirect_uri={}\
         &code_challenge={}&code_challenge_method={}",
        urlencoding::encode(&p.response_type),
        urlencoding::encode(&p.client_id),
        urlencoding::encode(&p.redirect_uri),
        urlencoding::encode(&p.code_challenge),
        urlencoding::encode(&p.code_challenge_method),
    );
    if let Some(s) = p.scope.as_deref() {
        qs.push_str(&format!("&scope={}", urlencoding::encode(s)));
    }
    if let Some(s) = p.state.as_deref() {
        qs.push_str(&format!("&state={}", urlencoding::encode(s)));
    }
    qs
}

/// Redirect an `/oauth/authorize` caller through IdP login, preserving the
/// authorize request as `next=`. Used both when no session is present (cold
/// login) and when a warm session belongs to a different org than the corp
/// subdomain demands (reconcile) — in both cases the user must sign into the
/// org the subdomain names before the agent can be enrolled.
async fn idp_bounce(
    state: &AppState,
    ext: &axum::http::Extensions,
    ctx: &RequestOrgContext,
    params: &AuthorizeQuery,
) -> Response {
    let authorize_path = rebuild_authorize_path(params);
    let next = urlencoding::encode(&authorize_path);
    match default_idp_provider_for_request(state, ext, ctx).await {
        IdpBounce::Provider(provider) => {
            // Dev login is a separate endpoint, not the generic
            // /auth/login/{provider_key} path (which requires an
            // oauth_providers DB row).
            let login = if provider == "dev" {
                format!("/auth/dev/token?next={next}")
            } else {
                format!("/auth/login/{provider}?next={next}")
            };
            Redirect::to(&login).into_response()
        }
        IdpBounce::Picker => {
            // Corp subdomain with multiple enabled IdPs and no designated
            // default — let the user pick. The dashboard login page calls
            // /auth/providers and renders the list.
            Redirect::to(&format!("/login?next={next}")).into_response()
        }
        IdpBounce::None => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "login_required",
            "no IdP is configured for this org",
        ),
    }
}

/// Build the final authorize-code redirect back to the MCP client. Shared
/// between the fast-path in `authorize` (existing binding) and
/// `consent_finish` (newly-enrolled agent) so there's a single canonical
/// code-issuance site.
#[allow(clippy::too_many_arguments)]
fn issue_authorization_code(
    state: &AppState,
    ext: &axum::http::Extensions,
    client_id: &str,
    identity_id: Uuid,
    org_id: Uuid,
    email: &str,
    redirect_uri: &str,
    code_challenge: &str,
    state_param: Option<&str>,
) -> Response {
    let code = oauth_as::generate_auth_code();
    state.auth_code_store(ext).insert(
        code.clone(),
        oauth_as::AuthCodeRecord {
            client_id: client_id.to_string(),
            identity_id,
            org_id,
            email: email.to_string(),
            redirect_uri: redirect_uri.to_string(),
            code_challenge: code_challenge.to_string(),
            issued_at: Instant::now(),
        },
    );
    let mut redirect = format!("{}?code={}", redirect_uri, urlencoding::encode(&code));
    if let Some(s) = state_param {
        redirect.push_str(&format!("&state={}", urlencoding::encode(s)));
    }
    Redirect::to(&redirect).into_response()
}

/// Outcome of picking an IdP to bounce an unauthenticated `/oauth/authorize`
/// caller through.
enum IdpBounce {
    /// One specific provider key — redirect straight to its login.
    Provider(String),
    /// Multiple IdPs configured for the org and none marked default — the
    /// dashboard `/login` page should render a picker.
    Picker,
    /// No IdP available at all → service-unavailable.
    None,
}

/// Pick how to bounce an unauthenticated `/oauth/authorize` caller through
/// IdP login.
///
/// On a corp subdomain (`RequestOrgContext::Org`) we honor the org's
/// designated default IdP, then fall back to the picker if any IdPs are
/// enabled. We **never** fall through to env-var (Overslash-managed) login
/// on a corp subdomain — corp subdomains are strict trust domains
/// (DECISIONS.md D12).
///
/// On the apex (`RequestOrgContext::Root`) we keep the existing env-var
/// behavior so personal-org sign-up keeps working without any DB IdP rows.
async fn default_idp_provider_for_request(
    state: &AppState,
    ext: &axum::http::Extensions,
    ctx: &RequestOrgContext,
) -> IdpBounce {
    match ctx {
        RequestOrgContext::Org { org_id, .. } => {
            // Designated default first.
            if let Ok(Some(row)) = org_idp_config::get_default_by_org(state.db(ext), *org_id).await
            {
                return IdpBounce::Provider(row.provider_key);
            }
            // No default but at least one enabled IdP → picker.
            match org_idp_config::list_enabled_by_org(state.db(ext), *org_id).await {
                Ok(rows) if !rows.is_empty() => IdpBounce::Picker,
                _ => IdpBounce::None,
            }
        }
        RequestOrgContext::Root => {
            if state.config.google_auth_client_id.is_some()
                && state.config.google_auth_client_secret.is_some()
            {
                return IdpBounce::Provider("google".into());
            }
            if state.config.github_auth_client_id.is_some()
                && state.config.github_auth_client_secret.is_some()
            {
                return IdpBounce::Provider("github".into());
            }
            if state.config.dev_auth_enabled {
                return IdpBounce::Provider("dev".into());
            }
            IdpBounce::None
        }
    }
}
