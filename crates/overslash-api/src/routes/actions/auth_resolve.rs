//! Service / instance / MCP / replay credential resolvers.
//!
//! Split out of `auth.rs`; the `ResolvedAuth` type lives there and the
//! recovery envelopes in `auth_envelopes.rs`.

use uuid::Uuid;

use overslash_db::scopes::OrgScope;

use crate::{AppState, error::AppError};
use overslash_core::types::{AuthHeader, InjectAs, SecretRef};

use super::auth::ResolvedAuth;
use super::auth_envelopes::{oauth_error_to_app_error, oauth_error_to_app_error_or_continue};

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
    // Instance whose OAuth actions we're minting for. Drives connection
    // precedence (explicit binding → default → opt-out); `None` (e.g. the
    // replay path) always uses the owner's default connection.
    instance: Option<&overslash_db::repos::service_instance::ServiceInstanceRow>,
    provider: &str,
    return_url_hint: Option<&str>,
) -> Result<Option<AuthHeader>, AppError> {
    let org_id = scope.org_id();
    let enc_key = state
        .config
        .keyring()
        .map_err(|e| AppError::Internal(format!("encryption key invalid: {e}")))?;

    let conn = match super::mcp_resolve::resolve_instance_connection(
        scope,
        owner_identity_id,
        instance,
        provider,
    )
    .await?
    {
        Some(conn) => conn,
        None => return Ok(None),
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

    // Build a SecretRef per secret-backed scheme the template declares. Each
    // scheme reads one or more credential *slots*, and each slot resolves its
    // vault secret name independently:
    //   1. the instance's explicit per-slot binding (`credentials[slot]`),
    //   2. else the legacy scalar `secret_name` (instance-source, and only for
    //      a scheme that reads a single slot — with several the alias would be
    //      ambiguous, which is what `reconcile_credentials` refuses to store),
    //   3. else the slot's fixed `default_secret_name` from the org vault
    //      (org-source slots only — a shared org-wide default).
    // That is what lets one overfwd instance carry both the per-mailbox
    // `X-Mailbox-Auth: Basic base64(user:pass)` — itself joined from two
    // separate secrets — and its own gateway `Authorization: Bearer …` on the
    // same request. OAuth-only templates declare no secret scheme and fall
    // through; instances with empty `credentials` keep the historical
    // behaviour exactly (steps 2 and 3).
    let mut secret_refs: Vec<SecretRef> = Vec::new();
    let mut instance_secret_missing = false;
    // Where this instance's traffic lands — the same derivation the executor
    // uses, so the platform-credential host check below can't disagree with the
    // URL actually dialled. Only consulted for the platform rung.
    let platform_base =
        crate::routes::actions::service_resolve::effective_base(Some(instance), svc);
    for service_auth in &svc.auth {
        let overslash_core::types::ServiceAuth::Secret {
            scheme,
            injection,
            template,
            ..
        } = service_auth
        else {
            continue;
        };

        let slots = svc.slots_for(service_auth);
        let single_slot = slots.len() == 1;
        let mut bindings = std::collections::BTreeMap::new();
        let mut config = std::collections::BTreeMap::new();
        // A scheme is emitted only when every slot it reads resolved; a
        // half-composed header would authenticate as nobody.
        let mut scheme_unresolved = false;

        for slot in &slots {
            let name = if let Some(bound) = instance.credentials.get(&slot.key) {
                // Explicitly bound per instance. An explicit binding on an
                // `optional` slot makes it required: the user asked for this
                // credential, so a missing secret surfaces as a send-time
                // error instead of being silently skipped.
                bound.clone()
            } else {
                match slot.source {
                    overslash_core::types::SecretSource::Org => {
                        // An optional org credential (e.g. an overfwd gateway key
                        // when the gateway runs with OVERFWD_REQUIRE_API_KEY=false)
                        // is injected only if the org has configured it — a keyless
                        // deployment simply omits it rather than failing on a
                        // missing secret. Required org slots fall through to the
                        // send-time `secret not found` error as before.
                        //
                        // …unless the platform itself holds a credential for
                        // this slot on the host this request is bound for
                        // (D39): the shared Mailbox Gateway requires a key, and
                        // asking every org to store the same platform key would
                        // be absurd. The org vault still wins — this only
                        // decides whether an *absent* org secret means "skip
                        // the header" or "the platform will supply it at send
                        // time"; the value itself is resolved (and host-checked
                        // again) in `resolve_credential_values`.
                        if slot.optional
                            && scope
                                .get_current_secret_value(&slot.default_secret_name)
                                .await?
                                .is_none()
                            && platform_base
                                .as_deref()
                                .and_then(|base| {
                                    state
                                        .config
                                        .platform_credential_for(&slot.default_secret_name, base)
                                })
                                .is_none()
                        {
                            scheme_unresolved = true;
                            break;
                        }
                        slot.default_secret_name.clone()
                    }
                    overslash_core::types::SecretSource::Instance => {
                        match instance.secret_name.as_ref().filter(|_| single_slot) {
                            Some(n) => n.clone(),
                            // The template requires a per-instance credential but
                            // the instance has none bound. Record it so we DON'T
                            // return the org-source keys alone — a partial
                            // injection would send an incomplete request (e.g.
                            // gateway Bearer without the mailbox `X-Mailbox-Auth`)
                            // that fails downstream instead of cleanly prompting
                            // the caller to bind the credential.
                            None => {
                                if !slot.optional {
                                    instance_secret_missing = true;
                                }
                                scheme_unresolved = true;
                                break;
                            }
                        }
                    }
                }
            };
            // A blank resolved name can only come from corrupted stored data
            // (API validation rejects blank bindings and blank org defaults).
            // For a required slot treat it like an unbound credential —
            // silently skipping would inject the OTHER schemes and send a
            // partially-authenticated request downstream.
            if name.is_empty() {
                if !slot.optional {
                    instance_secret_missing = true;
                }
                scheme_unresolved = true;
                break;
            }
            bindings.insert(slot.key.clone(), name);
        }

        // The non-secret half of the same credential. Same two sources, same
        // precedence, as any other key of the instance's `config` map: the
        // instance's own value, else the org layer's `instance_defaults.config`
        // (see `apply_instance_config`). Unlike a slot there is no vault
        // fallback — a config var is never in the vault.
        for var in svc.config_for(service_auth) {
            let value = instance
                .config
                .0
                .get(&var.key)
                .or_else(|| {
                    svc.instance_defaults
                        .as_ref()
                        .and_then(|d| d.config.get(&var.key))
                })
                .cloned();
            match value {
                Some(v) => {
                    config.insert(var.key.clone(), v);
                }
                // Required and unset is the same failure as an unbound slot,
                // and must be treated the same: emitting the scheme anyway
                // would render a truncated credential (`Basic base64(":pass")`)
                // that reads downstream as a wrong password rather than as
                // missing configuration.
                None if var.required => {
                    instance_secret_missing = true;
                    scheme_unresolved = true;
                    break;
                }
                // Optional and unset: the expression must tolerate it (jq's
                // `// ""`), so leave the key out and let the template decide.
                None => {}
            }
        }

        if scheme_unresolved || bindings.is_empty() {
            continue;
        }

        secret_refs.push(SecretRef {
            name: scheme.clone(),
            inject_as: if injection.inject_as == "query" {
                InjectAs::Query
            } else {
                InjectAs::Header
            },
            header_name: injection.header_name.clone(),
            query_param: injection.query_param.clone(),
            template: template.clone(),
            bindings,
            config,
            ..Default::default()
        });
    }
    // Only return credentials when the full set the template requires is
    // available. A missing instance-source secret falls through to the
    // auto-resolve / `needs_authentication` path below (matching the historical
    // single-apiKey behaviour: an unbound instance was never partially injected).
    if !instance_secret_missing && !secret_refs.is_empty() {
        return Ok(ResolvedAuth::secrets_only(secret_refs));
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
