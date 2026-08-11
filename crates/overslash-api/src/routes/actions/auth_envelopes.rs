//! Re-auth / needs-authentication envelope builders.
//!
//! Split out of `auth.rs`; the core `ResolvedAuth` type and the
//! `OAuthError` classifier live there, the resolvers in `auth_resolve.rs`.

use uuid::Uuid;

use overslash_db::scopes::OrgScope;

use crate::{
    AppState,
    error::AppError,
    services::{oauth::OAuthError, platform_connections},
};

use super::auth::{MissingCredentials, classify_oauth, org_is_headless};
use super::*;

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

    // Templates that don't declare OAuth: nothing to mint a URL for. Their
    // recovery shape is [`needs_credentials_for_service`] below, which the
    // caller runs straight after this one.
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
            missing_credentials: Vec::new(),
            hint_url: None,
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
        missing_credentials: Vec::new(),
        hint_url: None,
    }))
}

/// Mode B/C: the secret-backed twin of [`needs_authentication_for_service`].
///
/// A template that authenticates with vault secrets has no OAuth provider, so
/// there is no consent page to mint a URL for and the OAuth builder above
/// declines. Historically that meant resolution simply ended with no
/// credentials and the request went upstream unauthenticated — the caller got
/// the provider's opaque 401 instead of "go set this field". This builds the
/// envelope that says which field.
///
/// Reuses the `needs_authentication` code rather than minting a new one: the
/// MCP relay whitelist, `?wrap=true`, and every agent already branch on it.
/// The recovery affordance differs (`hint_url` + `missing_credentials` instead
/// of `auth_url`), which the variant's doc comment spells out.
///
/// Returns `None` — meaning "let the call proceed unauthenticated, as before" —
/// when the template declares OAuth (the other builder owns that case), or when
/// it requires no credential the instance is missing. That second case is what
/// keeps genuinely credential-free templates (`deepwiki`, the `platform`
/// runtime) and optional-only credentials (an `email` instance that needs no
/// gateway key) working exactly as they did.
pub(super) async fn needs_credentials_for_service(
    state: &AppState,
    ext: &axum::http::Extensions,
    org_id: Uuid,
    svc: &overslash_core::types::ServiceDefinition,
    instance: Option<&overslash_db::repos::service_instance::ServiceInstanceRow>,
    service_key: &str,
    missing: Option<&MissingCredentials>,
) -> Option<AppError> {
    // An OAuth template's empty resolution is a missing *connection*, not
    // missing configuration; `needs_authentication_for_service` mints the
    // consent link for it. Callers run that one first, so this is belt and
    // braces — but cheap, and it keeps the two builders' domains disjoint no
    // matter the call order.
    if svc
        .auth
        .iter()
        .any(|a| matches!(a, overslash_core::types::ServiceAuth::OAuth { .. }))
    {
        return None;
    }

    // Prefer the resolver's own diagnosis: it walked the full chain (per-slot
    // binding → legacy scalar → org default → platform credential, plus the
    // D38 config pass) and knows exactly which rung came up empty. Fall back to
    // deriving it from the template when there is none — the no-instance path,
    // where a global template is called by key and `resolve_service_auth` ran
    // alone.
    let keys = match missing.filter(|m| !m.is_empty()) {
        Some(m) => m.keys(),
        None => derive_missing_keys(svc, instance),
    };
    if keys.is_empty() {
        return None;
    }

    // Headless (white-label) org: no Overslash dashboard to point at, so no
    // `hint_url` — but the field list still ships, since the integration is the
    // one that has to collect those values. Mirrors the OAuth builder's split.
    let headless = org_is_headless(state.db(ext), org_id).await;
    let hint_url = (!headless).then(|| {
        state.config.dashboard_url_for(&match instance {
            // The instance exists but isn't configured: land on its
            // credentials form.
            Some(i) => format!("/services/{}?tab=credentials", i.id),
            // No instance at all: the fix is to create one from the template.
            None => format!(
                "/services/new?template={}",
                urlencoding::encode(service_key)
            ),
        })
    });

    Some(AppError::NeedsAuthentication {
        service: Some(service_key.to_string()),
        service_instance_id: instance.map(|i| i.id),
        connection_id: None,
        // No consent page exists for a secret-backed template.
        auth_url: None,
        short: None,
        provider: None,
        required_scopes: Vec::new(),
        account_email: None,
        headless,
        missing_credentials: keys,
        hint_url,
    })
}

/// Which template-declared fields an instance has not supplied, derived from
/// the template + stored instance rather than from a resolution attempt.
///
/// Only used when the resolver handed back no diagnosis — chiefly the
/// no-instance path, where every required field is by definition missing.
/// Mirrors the resolution chain in `resolve_instance_auth` and the classifier
/// behind the dashboard's credentials badge
/// (`platform_services::status::derive_credentials_status`); whether the named
/// secret actually exists in the vault is a send-time concern, reported
/// separately as `credential_missing`.
fn derive_missing_keys(
    svc: &overslash_core::types::ServiceDefinition,
    instance: Option<&overslash_db::repos::service_instance::ServiceInstanceRow>,
) -> Vec<String> {
    use overslash_core::types::SecretSource;

    let mut keys: Vec<String> = Vec::new();

    // Config first: the human-recognisable half (a username before its
    // password). Only vars wired to a secret scheme count — the same set
    // `resolve_instance_auth` checks.
    for auth in &svc.auth {
        for var in svc.config_for(auth) {
            if !var.required || keys.contains(&var.key) {
                continue;
            }
            let present = instance
                .and_then(|i| i.config.0.get(&var.key))
                .or_else(|| {
                    svc.instance_defaults
                        .as_ref()
                        .and_then(|d| d.config.get(&var.key))
                })
                .is_some();
            if !present {
                keys.push(var.key.clone());
            }
        }
    }

    // The legacy scalar `secret_name` only ever stood for a single credential,
    // so it cannot vouch for one half of a composed one.
    let single_instance_slot = svc
        .all_slots()
        .iter()
        .filter(|s| s.source == SecretSource::Instance)
        .count()
        <= 1;
    for slot in svc.all_slots() {
        if slot.optional || keys.contains(&slot.key) {
            continue;
        }
        let bound = instance
            .and_then(|i| i.credentials.get(&slot.key))
            .is_some_and(|n| !n.is_empty());
        if bound {
            continue;
        }
        let resolvable = match slot.source {
            SecretSource::Instance => {
                single_instance_slot
                    && instance
                        .and_then(|i| i.secret_name.as_deref())
                        .is_some_and(|n| !n.is_empty())
            }
            SecretSource::Org => !slot.default_secret_name.is_empty(),
        };
        if !resolvable {
            keys.push(slot.key.clone());
        }
    }

    keys
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
pub(crate) async fn metadata_scope_reauth_envelope(
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
