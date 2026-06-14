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
        // Integration-managed staleness is handled before token resolution
        // (it never reaches the normal reauth path), but classify it here for
        // completeness: it is a caller-actionable reauth, not a server fault.
        OAuthError::IntegrationManagedStale => OAuthOutcome::Reauth("integration_token_expired"),
        OAuthError::CryptoError(_)
        | OAuthError::DbError(_)
        | OAuthError::ParseError(_)
        | OAuthError::ProviderNotFound(_) => OAuthOutcome::Internal,
        OAuthError::HttpError(_) | OAuthError::TokenExchangeFailed(_) => OAuthOutcome::Upstream,
    }
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
    org_id: Uuid,
    caller_identity_id: Uuid,
    conn: &overslash_db::repos::connection::ConnectionRow,
    err: OAuthError,
    return_url_hint: Option<&str>,
) -> AppError {
    match classify_oauth(&err) {
        OAuthOutcome::Reauth(reason) => {
            reauth_required_envelope(
                state,
                org_id,
                caller_identity_id,
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
    org_id: Uuid,
    caller_identity_id: Uuid,
    conn: &overslash_db::repos::connection::ConnectionRow,
    err: OAuthError,
    return_url_hint: Option<&str>,
) -> Option<AppError> {
    match classify_oauth(&err) {
        OAuthOutcome::Reauth(reason) => Some(
            reauth_required_envelope(
                state,
                org_id,
                caller_identity_id,
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
pub(super) async fn reauth_required_envelope(
    state: &AppState,
    org_id: Uuid,
    caller_identity_id: Uuid,
    conn: &overslash_db::repos::connection::ConnectionRow,
    reason: &'static str,
    underlying: &OAuthError,
    return_url_hint: Option<&str>,
) -> AppError {
    match platform_connections::mint_upgrade_auth_url(
        state,
        org_id,
        caller_identity_id,
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
            integration_managed: false,
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

/// Reauth envelope for an integration-managed (imported, no-client)
/// connection. Overslash holds no OAuth client for it, so there is no
/// reconnect URL to mint — the integration must refresh and re-import. The
/// envelope carries `integration_managed: true` and omits `auth_url`/`short`.
/// A `connection.refresh_required` webhook fires alongside so the partner can
/// refresh proactively before the next call fails.
pub(super) fn integration_managed_reauth_envelope(
    state: &AppState,
    org_id: Uuid,
    conn: &overslash_db::repos::connection::ConnectionRow,
) -> AppError {
    {
        let db = state.db.clone();
        let client = state.http_client.clone();
        let connection_id = conn.id;
        let provider = conn.provider_key.clone();
        let identity_id = conn.identity_id;
        let account_email = conn.account_email.clone();
        tokio::spawn(async move {
            let payload = serde_json::json!({
                "connection_id": connection_id,
                "provider": provider,
                "identity_id": identity_id,
                "account_email": account_email,
            });
            crate::services::webhook_dispatcher::dispatch(
                &db,
                &client,
                org_id,
                "connection.refresh_required",
                payload,
            )
            .await;
        });
    }
    AppError::ReauthRequired {
        connection_id: conn.id,
        provider: conn.provider_key.clone(),
        auth_url: None,
        short: None,
        reason: "integration_token_expired".to_string(),
        integration_managed: true,
    }
}

/// Resolve the injected auth value for an integration-managed connection, or
/// the appropriate error: the integration-managed reauth envelope when the
/// stored token has expired, or `Internal` on a crypto failure (wrong key —
/// not caller-actionable). Shared by the service- and instance-bound paths.
fn resolve_integration_managed_header_value(
    state: &AppState,
    enc_key: &overslash_core::crypto::Keyring,
    org_id: Uuid,
    conn: &overslash_db::repos::connection::ConnectionRow,
) -> Result<String, AppError> {
    match crate::services::oauth::resolve_integration_managed_token(enc_key, conn) {
        Ok(token) => Ok(token),
        Err(OAuthError::IntegrationManagedStale) => {
            Err(integration_managed_reauth_envelope(state, org_id, conn))
        }
        Err(e) => Err(AppError::Internal(format!(
            "integration-managed token resolution failed for connection {}: {e}",
            conn.id
        ))),
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
    org_id: Uuid,
    caller_identity_id: Uuid,
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
        caller_identity_id,
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
        auth_url: urls.auth_url,
        short: urls.short,
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
    identity_id: Uuid,
    svc: &overslash_core::types::ServiceDefinition,
    explicit_secrets: &[SecretRef],
    return_url_hint: Option<&str>,
) -> Result<ResolvedAuth, AppError> {
    if !explicit_secrets.is_empty() {
        return Ok(ResolvedAuth::secrets_only(explicit_secrets.to_vec()));
    }

    let org_id = scope.org_id();
    // The auto-resolve path is per-identity: build a UserScope so the
    // connection lookup is bounded by `(org_id, user_id)`.
    let user_scope = overslash_db::scopes::UserScope::new(org_id, identity_id, scope.db().clone());

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
            // Integration-managed (imported, no shared client) connections
            // never resolve a client or refresh: inject the stored token until
            // it expires, then signal the integration to refresh and re-import.
            // This is the explicit exception to the credential cascade — an
            // imported connection must never borrow the org/env OAuth client.
            if conn.integration_managed {
                let value =
                    resolve_integration_managed_header_value(state, &enc_key, org_id, &conn)?;
                let value = match &token_injection.prefix {
                    Some(p) => format!("{p}{value}"),
                    None => value,
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
            // Per-provider credentials resolution. Failures here are
            // typically "no BYOC for provider X and no env fallback" — a
            // legitimate "try the next provider" signal. Log and continue
            // instead of bailing the whole loop.
            let creds = match crate::services::client_credentials::resolve(
                state.db(ext),
                &enc_key,
                org_id,
                Some(identity_id),
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
                        org_id,
                        identity_id,
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
    identity_id: Uuid,
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
    let user_scope = overslash_db::scopes::UserScope::new(org_id, identity_id, scope.db().clone());

    // Resolve the connection the exec path would actually use — instance's
    // explicit binding takes precedence, else `find_my_connection_by_provider`.
    let connection = if let Some(inst) = instance {
        if let Some(conn_id) = inst.connection_id {
            scope.get_connection(conn_id).await?
        } else {
            user_scope.find_my_connection_by_provider(&provider).await?
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

    // Integration-managed connections can't use the orchestrated upgrade flow —
    // Overslash holds no client to mint an authorize URL against, and minting
    // one would do wasted work and leave a stray flow row. Skip the mint and
    // return the missing_scopes envelope with no `auth_url`/`short`; the
    // integration broadens the grant and re-imports the connection.
    if connection.integration_managed {
        let upgrade_url = format!(
            "{}/v1/connections/{}/upgrade_scopes",
            state.config.public_url.trim_end_matches('/'),
            connection.id
        );
        return Err(AppError::MissingScopes {
            connection_id: connection.id,
            required: action.required_scopes.clone(),
            missing,
            upgrade_url,
            auth_url: None,
            short: None,
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
        identity_id,
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
        upgrade_url,
        auth_url,
        short,
    })
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

    let resolved = if let Some(ref inst) = instance {
        resolve_instance_auth(state, ext, scope, identity_id, inst, &svc, &[], None).await?
    } else {
        resolve_service_auth(state, ext, scope, identity_id, &svc, &[], None).await?
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
    identity_id: Uuid,
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
            // Integration-managed connections never resolve a client or
            // refresh — inject the stored token until expiry, then signal the
            // integration. See `resolve_service_auth` for the rationale.
            if conn.integration_managed {
                let access_token =
                    resolve_integration_managed_header_value(state, &enc_key, org_id, &conn)?;
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
                return Ok(ResolvedAuth::oauth(Some(AuthHeader {
                    name: "Authorization".into(),
                    value: format!("Bearer {access_token}"),
                })));
            }
            let creds = crate::services::client_credentials::resolve(
                state.db(ext),
                &enc_key,
                org_id,
                Some(identity_id),
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
                        org_id,
                        identity_id,
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

    // No bound credentials on instance — fall back to auto-resolve
    resolve_service_auth(
        state,
        ext,
        scope,
        identity_id,
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
    fn classify_oauth_reauth_signals() {
        match classify_oauth(&OAuthError::RefreshFailed("provider said no".into())) {
            OAuthOutcome::Reauth(reason) => assert_eq!(reason, "refresh_token_failed"),
            other => panic!("expected Reauth, got {other:?}"),
        }
        match classify_oauth(&OAuthError::NoRefreshToken) {
            OAuthOutcome::Reauth(reason) => assert_eq!(reason, "no_refresh_token"),
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
