//! OAuth / credential resolution, scope checks, and re-auth envelopes.

use uuid::Uuid;

use overslash_db::scopes::OrgScope;

use crate::{
    AppState,
    error::AppError,
    services::{oauth::OAuthError, platform_connections},
};
use overslash_core::types::{AuthHeader, InjectAs, SecretRef};

use super::*;

/// Outcome of service/instance auth resolution.
///
/// The live OAuth credential rides in `auth_header` — a non-`Serialize`
/// type merged into the outgoing header map only at send time — instead of
/// being baked into the request's header map, so approval/audit/replay
/// persistence can never capture it.
pub(crate) struct ResolvedAuth {
    pub secrets: Vec<SecretRef>,
    pub auth_header: Option<AuthHeader>,
    /// Whether OAuth resolution succeeded. Distinct from
    /// `auth_header.is_some()` only for templates that declare a query-param
    /// token injection (no header to build); kept so the
    /// `needs_authentication` gate behaves identically for those.
    pub oauth_injected: bool,
}

impl ResolvedAuth {
    fn secrets_only(secrets: Vec<SecretRef>) -> Self {
        Self {
            secrets,
            auth_header: None,
            oauth_injected: false,
        }
    }

    fn oauth(auth_header: Option<AuthHeader>) -> Self {
        Self {
            secrets: Vec::new(),
            auth_header,
            oauth_injected: true,
        }
    }

    fn none() -> Self {
        Self::secrets_only(Vec::new())
    }
}

pub(super) fn classify_oauth(err: &OAuthError) -> OAuthOutcome {
    match err {
        OAuthError::RefreshFailed(_) => OAuthOutcome::Reauth("refresh_token_failed"),
        OAuthError::NoRefreshToken => OAuthOutcome::Reauth("no_refresh_token"),
        OAuthError::ReauthRequired(_) => OAuthOutcome::Reauth("credential_replaced"),
        OAuthError::CryptoError(_)
        | OAuthError::DbError(_)
        | OAuthError::ParseError(_)
        | OAuthError::ProviderNotFound(_) => OAuthOutcome::Internal,
        OAuthError::HttpError(_) | OAuthError::TokenExchangeFailed(_) => OAuthOutcome::Upstream,
    }
}

/// Whether `org_id` is a headless (white-label) org: auth-recovery returns
/// URL-less typed envelopes instead of minting gated `/connect-authorize`
/// links (and no `oauth_connection_flows` row). A read failure or missing org
/// defaults to `false` — the safe, gated path for normal dashboard customers.
///
/// Pass the request's pool (`state.db(ext)` or `scope.db()`) so the lookup hits
/// the right database under the shared-router test harness (in production /
/// per-test routers that is `&state.db`).
async fn org_is_headless(db: &sqlx::PgPool, org_id: Uuid) -> bool {
    overslash_db::repos::org::get_headless(db, org_id)
        .await
        .ok()
        .flatten()
        .unwrap_or(false)
}

/// Map an `OAuthError` to the right `AppError` response shape, given a
/// connection that the user could potentially reauth against. Centralises
/// the Reauth-vs-Internal-vs-Upstream split so both auth resolvers
/// (instance- and service-level) make the same call.
///
/// The instance-bound branch of the action shape calls this directly:
/// it targets a *specific* connection, so an upstream blip can't
/// recover by trying another provider — we surface BadGateway. The
/// per-provider auth loop (when no instance is bound) calls a
/// non-bailing variant: see [`oauth_error_to_app_error_or_continue`].
pub(super) async fn oauth_error_to_app_error(
    state: &AppState,
    ext: &axum::http::Extensions,
    org_id: Uuid,
    owner_identity_id: Uuid,
    conn: &overslash_db::repos::connection::ConnectionRow,
    err: OAuthError,
    return_url_hint: Option<&str>,
) -> AppError {
    match classify_oauth(&err) {
        OAuthOutcome::Reauth(reason) => {
            reauth_required_envelope(
                state,
                ext,
                org_id,
                owner_identity_id,
                conn,
                reason,
                &err,
                return_url_hint,
            )
            .await
        }
        OAuthOutcome::Internal => {
            tracing::error!("OAuth internal error on connection {}: {err}", conn.id);
            AppError::Internal(format!("OAuth token resolution failed: {err}"))
        }
        OAuthOutcome::Upstream => {
            AppError::BadGateway(format!("OAuth provider returned an error: {err}"))
        }
    }
}

/// Variant used inside the multi-provider loop in `resolve_service_auth`:
/// returns `Some(err)` for outcomes that should bail the whole loop
/// (Reauth — actionable for the user; Internal — won't recover by
/// trying another provider), and `None` for Upstream errors — those
/// log + `continue` so a transient blip on provider A doesn't break
/// authentication via provider B.
pub(super) async fn oauth_error_to_app_error_or_continue(
    state: &AppState,
    ext: &axum::http::Extensions,
    org_id: Uuid,
    owner_identity_id: Uuid,
    conn: &overslash_db::repos::connection::ConnectionRow,
    err: OAuthError,
    return_url_hint: Option<&str>,
) -> Option<AppError> {
    match classify_oauth(&err) {
        OAuthOutcome::Reauth(reason) => Some(
            reauth_required_envelope(
                state,
                ext,
                org_id,
                owner_identity_id,
                conn,
                reason,
                &err,
                return_url_hint,
            )
            .await,
        ),
        OAuthOutcome::Internal => {
            tracing::error!("OAuth internal error on connection {}: {err}", conn.id);
            Some(AppError::Internal(format!(
                "OAuth token resolution failed: {err}"
            )))
        }
        OAuthOutcome::Upstream => {
            tracing::warn!(
                "upstream OAuth error on provider '{}'; trying next provider: {err}",
                conn.provider_key
            );
            None
        }
    }
}

/// Build the structured `ReauthRequired` envelope: mint a gated upgrade URL
/// pointing at the existing connection (so the OAuth callback updates the
/// row in place), pack it together with the caller-supplied `reason` tag,
/// and fall back to `Internal` if the URL mint itself fails — at that
/// point we genuinely can't help the user from this response and the
/// operator needs to investigate.
#[allow(clippy::too_many_arguments)]
pub(super) async fn reauth_required_envelope(
    state: &AppState,
    ext: &axum::http::Extensions,
    org_id: Uuid,
    // The connection lives at the owner identity (D22), so mint the gated
    // upgrade flow against the owner — the human owner is who can heal the
    // shared credential, and the minted flow/connection must key to the same
    // identity the resolver read from.
    owner_identity_id: Uuid,
    conn: &overslash_db::repos::connection::ConnectionRow,
    reason: &'static str,
    underlying: &OAuthError,
    return_url_hint: Option<&str>,
) -> AppError {
    // Headless (white-label) org: the connection's end users have no Overslash
    // session, so mint no gated link and no flow row. Return a URL-less
    // envelope keyed by provider/scopes/email; the integration re-runs its own
    // dance and re-imports. This is the single choke point for reauth, so it
    // covers both the bailing and the non-bailing callers.
    if org_is_headless(state.db(ext), org_id).await {
        return AppError::ReauthRequired {
            connection_id: conn.id,
            provider: conn.provider_key.clone(),
            auth_url: None,
            short: None,
            reason: reason.to_string(),
            required_scopes: conn.scopes.clone().unwrap_or_default(),
            account_email: conn.account_email.clone(),
            headless: true,
        };
    }
    match platform_connections::mint_upgrade_auth_url(
        state,
        org_id,
        owner_identity_id,
        conn,
        &[],
        return_url_hint,
    )
    .await
    {
        Ok(urls) => AppError::ReauthRequired {
            connection_id: conn.id,
            provider: conn.provider_key.clone(),
            auth_url: Some(urls.auth_url),
            short: urls.short,
            reason: reason.to_string(),
            required_scopes: Vec::new(),
            account_email: conn.account_email.clone(),
            headless: false,
        },
        Err(mint_err) => {
            // Pass the kernel's typed error through verbatim — wrapping
            // it as Internal would lose the right status (e.g. a
            // `Forbidden` from `validate_on_behalf_of` cross-identity
            // check, or a `NotFound` for a missing OAuth provider row)
            // and tell the caller "OAuth token resolution failed" when
            // the real cause is a permission or config problem.
            tracing::warn!(
                "reauth flow on connection {}: underlying OAuth error was {underlying}; mint of gated URL failed: {mint_err}",
                conn.id
            );
            mint_err
        }
    }
}

/// Mode C: when auth resolution returned no header / no secret on a service
/// whose template requires auth, the upstream call is going to fail with
/// whatever shape the provider returns to an empty Authorization header.
/// Detect that *here* and hand the agent a structured `NeedsAuthentication`
/// envelope with a freshly-minted gated URL, so they can forward it to the
/// user instead of forwarding an opaque 401-from-Google.
///
/// Returns:
/// - `Ok(Some(err))` — the template declares OAuth and the URL mint
///   succeeded; caller should `Err(err)` out of `resolve_request`.
/// - `Ok(None)` — the template has no OAuth provider declared (the
///   no-op happy path for free templates and ApiKey-only templates).
/// - `Err(_)` — an internal failure during URL mint (DB, crypto).
///   Surfaced so the caller can decide whether to wrap or bail.
#[allow(clippy::too_many_arguments)]
pub(super) async fn needs_authentication_for_service(
    state: &AppState,
    ext: &axum::http::Extensions,
    org_id: Uuid,
    // Mint the initial connect flow at the owner (D22) so the connection the
    // user creates lands on the owner identity and is shared by every agent.
    owner_identity_id: Uuid,
    svc: &overslash_core::types::ServiceDefinition,
    action: &overslash_core::types::ServiceAction,
    instance: Option<&overslash_db::repos::service_instance::ServiceInstanceRow>,
    service_key: &str,
    return_url_hint: Option<&str>,
) -> Result<Option<AppError>, AppError> {
    // First OAuth provider declared by the template. If the template has
    // multiple OAuth providers (rare), we pick the first — that mirrors
    // what `resolve_service_auth` already does.
    let provider = svc.auth.iter().find_map(|a| match a {
        overslash_core::types::ServiceAuth::OAuth { provider, .. } => Some(provider.clone()),
        _ => None,
    });

    // Templates that don't declare OAuth: nothing to mint a URL for. The
    // template might require an API key, but we don't have a click-to-fix
    // recovery shape for that today — the existing
    // `secret-not-found`-style errors handle it. Future: emit a different
    // typed envelope with a "go to dashboard / set this secret" hint.
    let Some(provider) = provider else {
        return Ok(None);
    };

    // Headless (white-label) org: no gated URL, no flow row. Hand back a
    // URL-less envelope naming the provider + required scopes so the
    // integration runs its own dance and imports a connection.
    if org_is_headless(state.db(ext), org_id).await {
        return Ok(Some(AppError::NeedsAuthentication {
            service: Some(service_key.to_string()),
            service_instance_id: instance.map(|i| i.id),
            connection_id: None,
            auth_url: None,
            short: None,
            provider: Some(provider),
            required_scopes: action.required_scopes.clone(),
            account_email: None,
            headless: true,
        }));
    }

    // Request the action's declared `required_scopes` up-front so the user
    // only sees one consent screen instead of two (consenting to nothing,
    // then being bounced through `missing_scopes` for the real set). When
    // the action declares no scopes, the empty vec is what we want anyway.
    //
    // If the URL mint fails, distinguish the *caller-actionable* failure
    // from server-side misconfig. No OAuth client at all (no managed
    // client, no org creds, no BYOC) surfaces from the credential cascade
    // as `BadRequest("no OAuth client credentials configured…")` — that
    // should reach the agent verbatim so it gets the same "configure org
    // OAuth / create a BYOC credential" guidance the documented
    // `create_connection` path already returns; wrapping it as `Internal`
    // would bury the fix behind an opaque 500 and make the same root cause
    // read differently depending on whether the agent went through
    // `create_connection` or straight to the action. A missing provider
    // row (`NotFound`) or crypto/DB hiccups are operator-side problems the
    // agent can't act on — those stay wrapped as `Internal` so a raw 404
    // doesn't read as "the action doesn't exist". See the match below.
    let urls = match platform_connections::mint_initial_auth_url(
        state,
        org_id,
        owner_identity_id,
        &provider,
        &action.required_scopes,
        None,
        return_url_hint,
    )
    .await
    {
        Ok(urls) => urls,
        Err(mint_err) => {
            tracing::error!(
                "needs_authentication: failed to mint initial auth url for provider '{provider}': {mint_err}"
            );
            return Err(match mint_err {
                // Caller-actionable: the credential cascade exhausted with no
                // OAuth client (no managed client, no org creds, no BYOC) or a
                // deleted pinned BYOC — both `BadRequest`. Surface verbatim so
                // the agent gets the same "configure org OAuth / create a BYOC
                // credential" guidance the `create_connection` path returns.
                err @ AppError::BadRequest(_) => err,
                // Everything else (a missing `oauth_provider` row → `NotFound`,
                // crypto/DB hiccups) is a server-side misconfig the agent can't
                // fix. Keep the `Internal` wrap: a raw 404 here would read as
                // "the action doesn't exist" rather than "provider not set up".
                other => AppError::Internal(format!(
                    "OAuth provider '{provider}' is not configured for this org: {other}"
                )),
            });
        }
    };

    Ok(Some(AppError::NeedsAuthentication {
        service: Some(service_key.to_string()),
        service_instance_id: instance.map(|i| i.id),
        connection_id: None,
        auth_url: Some(urls.auth_url),
        short: urls.short,
        provider: Some(provider),
        required_scopes: action.required_scopes.clone(),
        account_email: None,
        headless: false,
    }))
}

/// Auto-resolve auth for a service. Uses the identity's OAuth connection when the
/// template declares OAuth auth. A resolved OAuth token is returned as
/// [`ResolvedAuth::auth_header`] (never written into the request's header
/// map — see [`ResolvedAuth`]).
///
/// `RefreshFailed` / `NoRefreshToken` from the OAuth resolver bubble up as
/// `AppError::ReauthRequired` (with a freshly-minted gated URL) so the
/// caller doesn't see the upstream call fail with an opaque 5xx. Other
/// resolver errors (crypto/db/provider lookup) keep the legacy
/// fall-through behavior — they don't have a clean "click here to fix"
/// recovery shape.
pub(crate) async fn resolve_service_auth(
    state: &AppState,
    ext: &axum::http::Extensions,
    scope: &OrgScope,
    // The connection (and its client credentials / reauth recovery) resolves
    // at the OWNER identity, not the calling agent (D22): connections are
    // identity-scoped but shared at the owner, so a child agent inherits the
    // owner user's connection and one reauth heals every agent. Callers pass
    // the ceiling user id (`group_ceiling::ceiling_user_id_from_identity`).
    owner_identity_id: Uuid,
    svc: &overslash_core::types::ServiceDefinition,
    explicit_secrets: &[SecretRef],
    return_url_hint: Option<&str>,
) -> Result<ResolvedAuth, AppError> {
    if !explicit_secrets.is_empty() {
        return Ok(ResolvedAuth::secrets_only(explicit_secrets.to_vec()));
    }

    let org_id = scope.org_id();
    // Resolve the connection at the owner identity. `UserScope` here is really
    // an identity scope (its `user_id` field holds any identity_id), so a
    // UserScope built from the owner selects the owner's connections.
    let user_scope =
        overslash_db::scopes::UserScope::new(org_id, owner_identity_id, scope.db().clone());

    // Try OAuth first: check if identity has a connection for this service's OAuth provider
    // The encryption key is process-global, so a parse error here can't be
    // recovered by trying the next provider — propagate Internal once,
    // outside the loop.
    let enc_key = state
        .config
        .keyring()
        .map_err(|e| AppError::Internal(format!("encryption key invalid: {e}")))?;

    // Track the first transient upstream error we hit while iterating
    // providers. If no provider succeeds AND at least one had a
    // connection that failed transiently, return BadGateway instead of
    // falling through to `needs_authentication` — otherwise the caller
    // would prompt the user to create a *duplicate* connection on a
    // template they're already authenticated against, just because the
    // provider had a hiccup.
    let mut first_upstream_blip: Option<String> = None;

    for service_auth in &svc.auth {
        if let overslash_core::types::ServiceAuth::OAuth {
            provider,
            token_injection,
            ..
        } = service_auth
        {
            // Per-provider lookup. `Ok(None)` is the legitimate "no
            // connection yet" case — try the next provider. An `Err` is
            // a DB problem; propagate immediately as Internal so a
            // transient DB failure on a single-provider template doesn't
            // silently degrade to a `needs_authentication` 401 prompting
            // the user to "fix" something that isn't their fault.
            let conn = match user_scope.find_my_connection_by_provider(provider).await {
                Ok(Some(conn)) => conn,
                Ok(None) => continue,
                Err(e) => {
                    return Err(AppError::Internal(format!(
                        "connection lookup for provider '{provider}' failed: {e}"
                    )));
                }
            };
            // Per-provider credentials resolution. Failures here are
            // typically "no BYOC for provider X and no env fallback" — a
            // legitimate "try the next provider" signal. Log and continue
            // instead of bailing the whole loop.
            let creds = match crate::services::client_credentials::resolve(
                state.db(ext),
                &enc_key,
                org_id,
                Some(owner_identity_id),
                provider,
                Some(&conn),
                None,
            )
            .await
            {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(
                        "OAuth client credentials resolution for '{provider}' failed; trying next provider: {e}"
                    );
                    continue;
                }
            };

            match crate::services::oauth::resolve_access_token(
                scope,
                &state.http_client,
                &enc_key,
                &conn,
                &creds.client_id,
                &creds.client_secret,
            )
            .await
            {
                Ok(access_token) => {
                    // Carry the live token out-of-band; it is merged into the
                    // outgoing header map only at send time.
                    let value = match &token_injection.prefix {
                        Some(p) => format!("{p}{access_token}"),
                        None => access_token,
                    };
                    let auth_header =
                        token_injection
                            .header_name
                            .as_ref()
                            .map(|header_name| AuthHeader {
                                name: header_name.clone(),
                                value,
                            });
                    return Ok(ResolvedAuth::oauth(auth_header));
                }
                Err(e) => {
                    let err_str = e.to_string();
                    if let Some(err) = oauth_error_to_app_error_or_continue(
                        state,
                        ext,
                        org_id,
                        owner_identity_id,
                        &conn,
                        e,
                        return_url_hint,
                    )
                    .await
                    {
                        return Err(err);
                    }
                    // Upstream blip — keep trying the next OAuth provider
                    // in the template, but remember it so we can surface
                    // BadGateway after the loop instead of misleading the
                    // user into a duplicate-connection prompt.
                    if first_upstream_blip.is_none() {
                        first_upstream_blip =
                            Some(format!("provider '{}': {err_str}", conn.provider_key));
                    }
                    continue;
                }
            }
        }
    }

    if let Some(detail) = first_upstream_blip {
        return Err(AppError::BadGateway(format!(
            "OAuth provider returned an error: {detail}"
        )));
    }
    Ok(ResolvedAuth::none())
}

/// Resolve a live OAuth bearer for an MCP-runtime service whose `mcp.auth`
/// declares `{ kind: oauth, provider }`. Mirrors the OAuth arm of
/// [`resolve_service_auth`] but for the single provider named in the MCP
/// block and always as `Authorization: Bearer <token>` (MCP servers take the
/// token in that header). Returns:
/// - `Ok(Some(header))` — a connection exists and a token resolved (refreshed
///   via the org/BYOC client if the access token had expired).
/// - `Ok(None)` — no connection for `provider` yet. The caller decides: the
///   inline resolver mints an auth URL and gates; replay fails the execution.
/// - `Err(_)` — reauth required (refresh failed / no refresh token) mapped to
///   the same recovery envelope the HTTP path uses, or a credential/upstream
///   error.
pub(crate) async fn resolve_mcp_oauth_bearer(
    state: &AppState,
    ext: &axum::http::Extensions,
    scope: &OrgScope,
    // Owner identity (D22): connections resolve at the owner, shared by every
    // child agent, so one reauth heals all.
    owner_identity_id: Uuid,
    provider: &str,
    return_url_hint: Option<&str>,
) -> Result<Option<AuthHeader>, AppError> {
    let org_id = scope.org_id();
    let user_scope =
        overslash_db::scopes::UserScope::new(org_id, owner_identity_id, scope.db().clone());
    let enc_key = state
        .config
        .keyring()
        .map_err(|e| AppError::Internal(format!("encryption key invalid: {e}")))?;

    let conn = match user_scope.find_my_connection_by_provider(provider).await {
        Ok(Some(conn)) => conn,
        Ok(None) => return Ok(None),
        Err(e) => {
            return Err(AppError::Internal(format!(
                "connection lookup for provider '{provider}' failed: {e}"
            )));
        }
    };

    // Client credentials for refresh — resolves the connection's pinned BYOC,
    // then the identity/org/env cascade. HubSpot's remote MCP requires a
    // custom BYOC app, so this is where that client_id/secret is picked up.
    let creds = crate::services::client_credentials::resolve(
        state.db(ext),
        &enc_key,
        org_id,
        Some(owner_identity_id),
        provider,
        Some(&conn),
        None,
    )
    .await?;

    match crate::services::oauth::resolve_access_token(
        scope,
        &state.http_client,
        &enc_key,
        &conn,
        &creds.client_id,
        &creds.client_secret,
    )
    .await
    {
        Ok(access_token) => Ok(Some(AuthHeader {
            name: "Authorization".to_string(),
            value: format!("Bearer {access_token}"),
        })),
        Err(e) => {
            // RefreshFailed / NoRefreshToken → `ReauthRequired` (gated URL);
            // other resolver errors have no click-to-fix shape → BadGateway.
            if let Some(err) = oauth_error_to_app_error_or_continue(
                state,
                ext,
                org_id,
                owner_identity_id,
                &conn,
                e,
                return_url_hint,
            )
            .await
            {
                Err(err)
            } else {
                Err(AppError::BadGateway(
                    "OAuth provider returned an error resolving the MCP access token".into(),
                ))
            }
        }
    }
}

/// Fail-fast scope gate: before the outgoing request is built, compare the
/// connection's granted scopes against what this action declares. When a
/// template doesn't declare `required_scopes`, returns `Ok(())` — preserves
/// today's behavior for templates that haven't adopted the field.
///
/// Returns `AppError::MissingScopes`, rendered as 403 with the typed
/// `missing_scopes` envelope (`{ error, missing, connection_id, upgrade_url,
/// auth_url? }`). The `upgrade_url` is the raw REST endpoint white-label
/// callers can POST to; `auth_url` is the chat-deliverable gated link agents
/// should hand to the user.
pub(super) async fn check_required_scopes(
    state: &AppState,
    scope: &OrgScope,
    // Auto-resolved connections are read at the owner identity (D22), matching
    // what `resolve_service_auth` will actually use. Explicit instance→
    // connection bindings still resolve org-scoped via `scope.get_connection`.
    owner_identity_id: Uuid,
    instance: Option<&overslash_db::repos::service_instance::ServiceInstanceRow>,
    svc: &overslash_core::types::ServiceDefinition,
    action: &overslash_core::types::ServiceAction,
    return_url_hint: Option<&str>,
) -> Result<(), AppError> {
    if action.required_scopes.is_empty() {
        return Ok(());
    }

    // Find the OAuth service-auth entry; a template without OAuth can't have
    // its scopes checked here.
    let provider = svc.auth.iter().find_map(|a| match a {
        overslash_core::types::ServiceAuth::OAuth { provider, .. } => Some(provider.clone()),
        _ => None,
    });
    let Some(provider) = provider else {
        return Ok(());
    };

    let org_id = scope.org_id();
    let user_scope =
        overslash_db::scopes::UserScope::new(org_id, owner_identity_id, scope.db().clone());

    // Resolve the connection the exec path would actually use — instance's
    // explicit binding takes precedence, else `find_my_connection_by_provider`.
    let connection = if let Some(inst) = instance {
        if let Some(conn_id) = inst.connection_id {
            scope.get_connection(conn_id).await?
        } else if inst.use_default_connection {
            user_scope.find_my_connection_by_provider(&provider).await?
        } else {
            // Opted out of the default-connection fallback: the exec path
            // resolves no connection (yields `needs_authentication`), so there
            // is nothing to gate here. Mirror `resolve_instance_auth`.
            None
        }
    } else {
        user_scope.find_my_connection_by_provider(&provider).await?
    };

    let Some(connection) = connection else {
        // Fall through — auth resolution will report the missing connection
        // in its own way. The scope gate is only meaningful when a
        // connection exists.
        return Ok(());
    };

    // Unknown granted scopes (a token import that didn't declare them) get the
    // benefit of the doubt — Overslash can't know what the token covers, so it
    // doesn't pre-emptively 403; a genuine scope shortfall still surfaces as the
    // upstream's own error. A known set (orchestrated connections always record
    // one) is gated precisely.
    let Some(granted_scopes) = connection.scopes.as_deref() else {
        return Ok(());
    };
    let granted: std::collections::HashSet<&str> =
        granted_scopes.iter().map(String::as_str).collect();
    let missing: Vec<String> = action
        .required_scopes
        .iter()
        .filter(|s| !granted.contains(s.as_str()))
        .cloned()
        .collect();

    if missing.is_empty() {
        return Ok(());
    }

    // Headless (white-label) org: omit both the gated `auth_url` and the
    // `upgrade_url` — the org's end users can't open either, and minting an
    // upgrade flow would leave a stray flow row. The integration broadens the
    // grant against its own client and re-imports the connection.
    if org_is_headless(scope.db(), org_id).await {
        return Err(AppError::MissingScopes {
            connection_id: connection.id,
            required: action.required_scopes.clone(),
            missing,
            upgrade_url: None,
            auth_url: None,
            short: None,
            provider: Some(connection.provider_key.clone()),
            account_email: connection.account_email.clone(),
            headless: true,
        });
    }

    // Mint a chat-deliverable gated `/connect-authorize` URL that, when
    // consumed, runs an incremental-scope OAuth flow against the existing
    // connection (the minted flow row's `upgrade_connection_id` points at
    // `connection.id`; the callback reads it back from the row). The legacy
    // `upgrade_url` field — pointing at the raw REST endpoint
    // `/v1/connections/{id}/upgrade_scopes` — is preserved alongside for
    // white-label callers that drive the API directly. Agents should use
    // `auth_url`.
    //
    // If the mint fails (DB hiccup, provider-key lookup), don't break the
    // missing_scopes contract by surfacing the mint error: log it and omit
    // `auth_url` from the body. The dashboard / REST clients will fall
    // back to `upgrade_url`, and the client still gets the correct 403
    // missing_scopes shape.
    let (auth_url, short) = match platform_connections::mint_upgrade_auth_url(
        state,
        scope.org_id(),
        owner_identity_id,
        &connection,
        &missing,
        return_url_hint,
    )
    .await
    {
        Ok(urls) => (Some(urls.auth_url), urls.short),
        Err(e) => {
            tracing::error!(
                "missing_scopes: failed to mint upgrade auth url for connection {}: {e}",
                connection.id
            );
            (None, None)
        }
    };
    let upgrade_url = format!(
        "{}/v1/connections/{}/upgrade_scopes",
        state.config.public_url.trim_end_matches('/'),
        connection.id
    );
    Err(AppError::MissingScopes {
        connection_id: connection.id,
        required: action.required_scopes.clone(),
        missing,
        upgrade_url: Some(upgrade_url),
        auth_url,
        short,
        provider: Some(connection.provider_key.clone()),
        account_email: connection.account_email.clone(),
        headless: false,
    })
}

/// Whether an upstream response body is Google's "metadata scope" denial:
/// a `PERMISSION_DENIED` (HTTP 403) whose message is
/// `"Metadata scope does not support 'q' parameter"` (or any other metadata
/// message). This means the *injected access token was metadata-only* even
/// though the connection's recorded scopes claimed a broader grant like
/// `gmail.readonly` — the exact divergence from connection `85844f1a`.
///
/// We match on the stable substring `"Metadata scope does not support"` rather
/// than the full message so a change to the offending parameter name (`'q'` vs
/// something else) doesn't slip past. Only inspects 403 responses.
pub(super) fn is_metadata_scope_denial(status_code: u16, body: &str) -> bool {
    status_code == 403 && body.contains("Metadata scope does not support")
}

/// Surface a metadata-scope denial (see [`is_metadata_scope_denial`]) as a
/// typed `reauth_required` envelope instead of a 200 with the upstream 403
/// buried in the body.
///
/// The recorded scopes lie (they say `gmail.readonly` but the token is
/// metadata-only), and the self-refresh path can't heal it — the stored refresh
/// token is itself metadata-scoped. The only fix is a fresh consent, so a
/// reauth envelope is the right shape: for a headless (white-label) org it's a
/// URL-less signal the partner acts on by re-running its own OAuth dance and
/// re-importing with a fresh refresh token; for an orchestrated org it mints a
/// gated reconnect link.
///
/// Returns `None` when the service has no OAuth provider or no resolvable
/// connection — in that unexpected case the caller falls back to returning the
/// upstream 403 unchanged rather than fabricating a reauth for a connection we
/// can't name.
pub(super) async fn metadata_scope_reauth_envelope(
    state: &AppState,
    ext: &axum::http::Extensions,
    scope: &OrgScope,
    ceiling_user_id: Uuid,
    service_key: &str,
) -> Option<AppError> {
    // Resolve the service definition to find its OAuth provider. `None` for a
    // raw-HTTP shape or a template without OAuth — nothing to reauth.
    let svc = crate::routes::templates::resolve_template_definition(
        state,
        ext,
        scope.org_id(),
        Some(ceiling_user_id),
        service_key,
    )
    .await
    .ok()?;

    let provider = svc.auth.iter().find_map(|a| match a {
        overslash_core::types::ServiceAuth::OAuth { provider, .. } => Some(provider.clone()),
        _ => None,
    })?;

    // Connections resolve at the owner identity (D22).
    let owner_identity_id =
        crate::services::group_ceiling::resolve_ceiling_user_id(scope, ceiling_user_id)
            .await
            .ok()?;
    let user_scope =
        overslash_db::scopes::UserScope::new(scope.org_id(), owner_identity_id, scope.db().clone());
    let connection = user_scope
        .find_my_connection_by_provider(&provider)
        .await
        .ok()
        .flatten()?;

    Some(
        reauth_required_envelope(
            state,
            ext,
            scope.org_id(),
            owner_identity_id,
            &connection,
            "metadata_scope_token",
            &OAuthError::RefreshFailed(
                "injected access token is metadata-only despite recorded scopes; \
                 the stored refresh token cannot self-heal — fresh consent required"
                    .into(),
            ),
            None,
        )
        .await,
    )
}

/// Re-resolve the live OAuth header for an approval replay.
///
/// Replay payloads are credential-free: when the original call resolved an
/// OAuth header, `StoredCallRequest` records the `service_key` (and
/// `instance_id` binding, when there was one) instead of the token. This
/// re-runs the same resolution against the requester's identity to mint a
/// fresh token at replay time — which also keeps approvals replayable after
/// the original token would have expired.
///
/// Fails with `Conflict` when the service/template was deleted since the
/// approval was created, or when auth no longer resolves to a header — a
/// tokenless replay of a call that originally carried OAuth would surface
/// as a confusing upstream 401 otherwise. Typed OAuth errors
/// (`ReauthRequired` etc.) propagate as-is.
pub(crate) async fn resolve_replay_auth_header(
    state: &AppState,
    ext: &axum::http::Extensions,
    scope: &OrgScope,
    identity_id: Uuid,
    service_key: &str,
    instance_id: Option<Uuid>,
) -> Result<AuthHeader, AppError> {
    // Instance deleted since approval-create falls through to the
    // service-level resolve below — same recovery the live call path has
    // for a connection deleted out from under an instance.
    let instance = match instance_id {
        Some(id) => scope.get_service_instance(id).await?,
        None => None,
    };

    // `resolve_template_definition` walks user tier → org tier → global
    // registry, same as the live call path.
    let template_key = instance
        .as_ref()
        .map(|i| i.template_key.as_str())
        .unwrap_or(service_key);
    let svc = crate::routes::templates::resolve_template_definition(
        state,
        ext,
        scope.org_id(),
        Some(identity_id),
        template_key,
    )
    .await
    .map_err(|e| {
        AppError::Conflict(format!(
            "cannot replay: service '{service_key}' is no longer resolvable: {e}"
        ))
    })?;

    // Connections resolve at the owner identity (D22). The replay path only
    // carries the requester's identity, so derive the owner here (template
    // tier resolution above stays per-caller).
    let owner_identity_id =
        crate::services::group_ceiling::resolve_ceiling_user_id(scope, identity_id).await?;

    let resolved = if let Some(ref inst) = instance {
        resolve_instance_auth(state, ext, scope, owner_identity_id, inst, &svc, &[], None).await?
    } else {
        resolve_service_auth(state, ext, scope, owner_identity_id, &svc, &[], None).await?
    };

    resolved.auth_header.ok_or_else(|| {
        AppError::Conflict(format!(
            "cannot replay: authentication for service '{service_key}' no longer resolves \
             (the original call carried an OAuth credential)"
        ))
    })
}

/// Resolve auth for a service instance. If the instance has a bound connection_id or secret_name,
/// use that directly. Otherwise fall back to auto-resolve from the template's auth config.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn resolve_instance_auth(
    state: &AppState,
    ext: &axum::http::Extensions,
    scope: &OrgScope,
    // Owner identity (D22). Used for client-credential resolution, reauth
    // recovery, and the template auto-resolve fall-through. The explicit
    // instance→connection binding below stays org-scoped (`scope.get_connection`).
    owner_identity_id: Uuid,
    instance: &overslash_db::repos::service_instance::ServiceInstanceRow,
    svc: &overslash_core::types::ServiceDefinition,
    explicit_secrets: &[SecretRef],
    return_url_hint: Option<&str>,
) -> Result<ResolvedAuth, AppError> {
    if !explicit_secrets.is_empty() {
        return Ok(ResolvedAuth::secrets_only(explicit_secrets.to_vec()));
    }

    let org_id = scope.org_id();
    // If instance has a bound connection, use it directly. Errors here
    // (encryption-key parse, client-credentials resolve) are server-side
    // problems on the *specific* connection the instance is bound to —
    // falling back to template-level resolve_service_auth would either
    // re-trigger the same crypto error or pick an unrelated connection
    // that the operator never asked us to use. Propagate Internal so the
    // operator can see the real cause; mirror what resolve_service_auth
    // does for its access_token errors.
    if let Some(conn_id) = instance.connection_id {
        // Explicit `match` (rather than `if let Ok(Some(...))`) so a DB
        // error doesn't get silently treated as "no connection bound" and
        // misrouted to a `needs_authentication` 401. Ok(None) — the
        // connection was deleted out from under the instance — *does*
        // fall through to the template-auto-resolve / API-key path, which
        // will pick up any newly-minted connection on the calling
        // identity (e.g. one the user just created via the gated link
        // returned by `needs_authentication_for_service`). So a
        // disconnected instance recovers on the next call after reauth
        // without us needing to touch the binding here.
        let conn = match scope.get_connection(conn_id).await {
            Ok(Some(c)) => Some(c),
            Ok(None) => None,
            Err(e) => {
                return Err(AppError::Internal(format!(
                    "lookup of instance-bound connection {conn_id} failed: {e}"
                )));
            }
        };
        if let Some(conn) = conn {
            let enc_key = state
                .config
                .keyring()
                .map_err(|e| AppError::Internal(format!("encryption key invalid: {e}")))?;
            let creds = crate::services::client_credentials::resolve(
                state.db(ext),
                &enc_key,
                org_id,
                Some(owner_identity_id),
                &conn.provider_key,
                Some(&conn),
                None,
            )
            .await
            .map_err(|e| {
                AppError::Internal(format!(
                    "OAuth client credentials resolution for instance-bound connection {} failed: {e}",
                    conn.id
                ))
            })?;

            match crate::services::oauth::resolve_access_token(
                scope,
                &state.http_client,
                &enc_key,
                &conn,
                &creds.client_id,
                &creds.client_secret,
            )
            .await
            {
                Ok(access_token) => {
                    // Find the matching token_injection from the template's auth config
                    for service_auth in &svc.auth {
                        if let overslash_core::types::ServiceAuth::OAuth {
                            provider,
                            token_injection,
                            ..
                        } = service_auth
                        {
                            if *provider == conn.provider_key {
                                let value = match &token_injection.prefix {
                                    Some(p) => format!("{p}{access_token}"),
                                    None => access_token,
                                };
                                let auth_header =
                                    token_injection.header_name.as_ref().map(|header_name| {
                                        AuthHeader {
                                            name: header_name.clone(),
                                            value,
                                        }
                                    });
                                return Ok(ResolvedAuth::oauth(auth_header));
                            }
                        }
                    }
                    // No matching auth config found, carry as Bearer by default
                    return Ok(ResolvedAuth::oauth(Some(AuthHeader {
                        name: "Authorization".into(),
                        value: format!("Bearer {access_token}"),
                    })));
                }
                Err(e) => {
                    // Surface the typed AppError up the call stack — the
                    // caller (resolve_request) maps each variant to the
                    // right HTTP status. Falling back to API-key /
                    // resolve_service_auth on a transient OAuth error
                    // would hide the real failure behind a misleading
                    // `needs_authentication` 401.
                    return Err(oauth_error_to_app_error(
                        state,
                        ext,
                        org_id,
                        owner_identity_id,
                        &conn,
                        e,
                        return_url_hint,
                    )
                    .await);
                }
            }
        }
    }

    // If instance has a bound secret_name AND the template declares ApiKey auth, use it.
    // OAuth-only templates never reach the ApiKey branch; `secret_name` would be either
    // already NULL (migration 037) or blocked at create/update by the services API.
    if let Some(ref secret_name) = instance.secret_name {
        for service_auth in &svc.auth {
            if let overslash_core::types::ServiceAuth::ApiKey { injection, .. } = service_auth {
                return Ok(ResolvedAuth::secrets_only(vec![SecretRef {
                    name: secret_name.clone(),
                    inject_as: if injection.inject_as == "query" {
                        InjectAs::Query
                    } else {
                        InjectAs::Header
                    },
                    header_name: injection.header_name.clone(),
                    query_param: injection.query_param.clone(),
                    prefix: injection.prefix.clone(),
                }]));
            }
        }
    }

    // No bound credentials on instance. Before falling back to auto-resolve
    // (which would grab the identity's *default* connection for the provider
    // via `find_my_connection_by_provider`), honor the instance's opt-out: with
    // `use_default_connection = false`, an unbound OAuth instance must NOT
    // silently borrow the default. Return `none()` — the caller renders this as
    // `needs_authentication`, prompting a connect-and-pin. Only short-circuits
    // OAuth-backed templates (the only ones that resolve a default connection);
    // ApiKey/env resolution below is unaffected because such templates declare
    // no OAuth provider.
    if !instance.use_default_connection
        && svc
            .auth
            .iter()
            .any(|a| matches!(a, overslash_core::types::ServiceAuth::OAuth { .. }))
    {
        return Ok(ResolvedAuth::none());
    }

    resolve_service_auth(
        state,
        ext,
        scope,
        owner_identity_id,
        svc,
        explicit_secrets,
        return_url_hint,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_scope_denial_detected_only_on_403() {
        let body = r#"{"error":{"code":403,"status":"PERMISSION_DENIED","message":"Metadata scope does not support 'q' parameter"}}"#;
        assert!(is_metadata_scope_denial(403, body));
        // Same body on a non-403 status is not the metadata-scope signal.
        assert!(!is_metadata_scope_denial(200, body));
        assert!(!is_metadata_scope_denial(500, body));
    }

    #[test]
    fn metadata_scope_denial_ignores_unrelated_403() {
        let body = r#"{"error":{"code":403,"status":"PERMISSION_DENIED","message":"Request had insufficient authentication scopes."}}"#;
        assert!(!is_metadata_scope_denial(403, body));
    }

    #[test]
    fn classify_oauth_reauth_signals() {
        match classify_oauth(&OAuthError::RefreshFailed("provider said no".into())) {
            OAuthOutcome::Reauth(reason) => assert_eq!(reason, "refresh_token_failed"),
            other => panic!("expected Reauth, got {other:?}"),
        }
        match classify_oauth(&OAuthError::NoRefreshToken) {
            OAuthOutcome::Reauth(reason) => assert_eq!(reason, "no_refresh_token"),
            other => panic!("expected Reauth, got {other:?}"),
        }
        // A connection flagged `reauth_required` (its BYOC client was replaced)
        // maps to the distinct `credential_replaced` reason.
        match classify_oauth(&OAuthError::ReauthRequired("byoc_client_replaced".into())) {
            OAuthOutcome::Reauth(reason) => assert_eq!(reason, "credential_replaced"),
            other => panic!("expected Reauth, got {other:?}"),
        }
    }

    #[test]
    fn classify_oauth_internal_signals() {
        for err in [
            OAuthError::CryptoError("bad key".into()),
            OAuthError::DbError("conn refused".into()),
            OAuthError::ParseError("bad json".into()),
            OAuthError::ProviderNotFound("x".into()),
        ] {
            assert!(
                matches!(classify_oauth(&err), OAuthOutcome::Internal),
                "{err:?} should be Internal"
            );
        }
    }

    #[test]
    fn classify_oauth_upstream_signals() {
        for err in [
            OAuthError::HttpError("timeout".into()),
            OAuthError::TokenExchangeFailed("provider 500".into()),
        ] {
            assert!(
                matches!(classify_oauth(&err), OAuthOutcome::Upstream),
                "{err:?} should be Upstream"
            );
        }
    }
}
