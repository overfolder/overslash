//! Auth-recovery URL minters used by the action handler's
//! `needs_authentication` / `reauth_required` / `missing_scopes` arms.

use super::create::*;
use super::scopes::*;
use super::*;

/// Build a `PlatformCallContext` from `AppState` + caller identity, suitable
/// for dispatching `kernel_create_connection` from inside a non-platform
/// route handler (e.g. `routes/actions.rs`). Centralised so the
/// auth-recovery arms in the action handler don't each re-derive the same
/// shape.
fn ctx_from_state(
    state: &AppState,
    org_id: Uuid,
    identity_id: Option<Uuid>,
) -> PlatformCallContext {
    PlatformCallContext {
        org_id,
        identity_id,
        // Auth-recovery URL minting doesn't itself trip the access-level
        // gate — the action handler's normal Layer 1/2 path has already
        // run by the time we mint a reauth URL. `Read` is the lowest
        // ceiling and matches the read-only nature of "give me a URL".
        access_level: overslash_core::permissions::AccessLevel::Read,
        db: state.db.clone(),
        registry: state.registry.clone(),
        config: state.config.clone(),
        http_client: state.http_client.clone(),
    }
}

/// Mint a fresh-create gated `/connect-authorize` URL for an action call
/// that hit a service with no live credentials yet. The caller supplies
/// the template's OAuth provider plus any required scopes. The returned
/// URL is what the agent should hand the user — clicking it walks the
/// gated flow and creates a new connection on the calling identity (or
/// `on_behalf_of` if set).
pub async fn mint_initial_auth_url(
    state: &AppState,
    org_id: Uuid,
    caller_identity_id: Uuid,
    provider: &str,
    scopes: &[String],
    on_behalf_of: Option<Uuid>,
    return_url: Option<&str>,
) -> Result<AuthRecoveryUrls, AppError> {
    let ctx = ctx_from_state(state, org_id, Some(caller_identity_id));
    let response = kernel_create_connection(
        ctx,
        CreateConnectionInput {
            provider: provider.to_string(),
            scopes: scopes.to_vec(),
            byoc_credential_id: None,
            on_behalf_of,
            upgrade_connection_id: None,
            // Carries the caller's `CallRequest.return_url` hint when the
            // reactive first-connect flow is minted during a failed action
            // call, so the OAuth callback 303s the user back to the partner
            // instead of landing on the default JSON response. The host is
            // re-validated against the allow-list at callback time.
            return_url: return_url.map(str::to_string),
            service_instance_id: None,
            pin_service_ids: vec![],
            // First connect — there is no prior connection to inherit an
            // account from, and the action handler has no account context of
            // its own to offer.
            login_hint: None,
        },
        RequestMeta::default(),
    )
    .await?;
    Ok(AuthRecoveryUrls {
        auth_url: response.auth_url,
        short: response.short,
    })
}

/// Mint a gated `/connect-authorize` URL that, when consumed, refreshes
/// the *existing* connection in place (the minted flow row carries
/// `upgrade_connection_id` so the callback updates that row instead of
/// creating a new one). Used by the action handler's `reauth_required`
/// arm (refresh-token failed) and the `missing_scopes` arm (incremental
/// scope upgrade).
///
/// Scopes default to the connection's existing set unioned with
/// `extra_scopes` — Google with `include_granted_scopes=true` would
/// preserve the old ones anyway, but sending the full union makes
/// non-Google providers work too. Mirrors `merge_scopes` in
/// `routes/connections.rs::upgrade_connection_scopes`.
///
/// `return_url` carries the caller's `CallRequest.return_url` hint (already
/// format-validated at the request boundary). It's stamped onto the minted
/// flow row so the OAuth callback can 303 the user back to the partner app
/// once consent completes — the same redirect the first-connect path gets.
/// The host is re-checked against the allow-list at callback time; an
/// off-list host silently falls back to the JSON response.
pub async fn mint_upgrade_auth_url(
    state: &AppState,
    org_id: Uuid,
    caller_identity_id: Uuid,
    conn: &ConnectionRow,
    extra_scopes: &[String],
    return_url: Option<&str>,
) -> Result<AuthRecoveryUrls, AppError> {
    let scopes = merge_scopes(conn.scopes.as_deref().unwrap_or(&[]), extra_scopes);
    let scope = OrgScope::new(org_id, state.db.clone());

    // The OAuth callback (`routes/connections.rs::oauth_callback`) updates
    // the existing row in place when the flow row's `upgrade_connection_id`
    // is set — it preserves `existing.identity_id` and just swaps
    // tokens/scopes. So whichever identity owns the flow row, the
    // connection's owner is unchanged after the dance. Two cases to handle:
    //
    // (1) Same-identity caller. Bind the flow to the connection's own identity
    //     directly — an upgrade MUST mint at `existing.identity_id` (the
    //     callback rejects a flow whose identity differs). We can't route this
    //     through `kernel_create_connection`, which re-homes fresh connections
    //     to the caller's ceiling owner (D23): for a legacy agent-owned row
    //     that would mint at the owner and trip the callback's state-mismatch
    //     guard.
    //
    // (2) Cross-identity caller. Either an agent acting for its owner user
    //     (handled by `on_behalf_of` + `validate_on_behalf_of`), or user A
    //     reaching user B's connection via a group grant on a service
    //     instance bound to it. The group-granted branch bypasses
    //     `validate_on_behalf_of` because the group grant is itself the
    //     caller's authorisation to touch the connection; running the
    //     ceiling check on top would refuse a flow the resolver already
    //     accepts at call time.
    if conn.identity_id == caller_identity_id {
        let ctx = ctx_from_state(state, org_id, Some(caller_identity_id));
        let response = kernel_create_connection_for_identity(
            ctx,
            conn.identity_id,
            caller_identity_id,
            CreateConnectionInput {
                provider: conn.provider_key.clone(),
                scopes,
                byoc_credential_id: conn.byoc_credential_id,
                on_behalf_of: None,
                upgrade_connection_id: Some(conn.id),
                return_url: return_url.map(str::to_string),
                service_instance_id: None,
                pin_service_ids: vec![],
                // Derived by the kernel from the connection's
                // `account_email` — see `CreateConnectionInput::login_hint`.
                login_hint: None,
            },
            RequestMeta::default(),
        )
        .await?;
        return Ok(AuthRecoveryUrls {
            auth_url: response.auth_url,
            short: response.short,
        });
    }

    // Cross-identity. Try the group-granted path first.
    let ceiling_user_id =
        group_ceiling::resolve_ceiling_user_id(&scope, caller_identity_id).await?;
    let group_granted = scope
        .caller_has_group_access_to_connection(ceiling_user_id, conn.id)
        .await?;
    if group_granted && ceiling_user_id != conn.identity_id {
        let ctx = ctx_from_state(state, org_id, Some(caller_identity_id));
        let response = kernel_create_connection_for_identity(
            ctx,
            conn.identity_id,
            caller_identity_id,
            CreateConnectionInput {
                provider: conn.provider_key.clone(),
                scopes,
                byoc_credential_id: conn.byoc_credential_id,
                on_behalf_of: None,
                upgrade_connection_id: Some(conn.id),
                return_url: return_url.map(str::to_string),
                service_instance_id: None,
                pin_service_ids: vec![],
                // Derived by the kernel from the connection's
                // `account_email` — see `CreateConnectionInput::login_hint`.
                login_hint: None,
            },
            RequestMeta::default(),
        )
        .await?;
        return Ok(AuthRecoveryUrls {
            auth_url: response.auth_url,
            short: response.short,
        });
    }

    // No group grant — fall through to the existing agent-on-behalf-of-owner
    // path. `validate_on_behalf_of` will accept when the caller's ceiling
    // user equals the connection owner (i.e. an agent calling its own
    // owner user's connection) and reject otherwise. This preserves the
    // original boundary for callers with neither relationship.
    let ctx = ctx_from_state(state, org_id, Some(caller_identity_id));
    let response = kernel_create_connection(
        ctx,
        CreateConnectionInput {
            provider: conn.provider_key.clone(),
            scopes,
            byoc_credential_id: conn.byoc_credential_id,
            on_behalf_of: Some(conn.identity_id),
            upgrade_connection_id: Some(conn.id),
            return_url: return_url.map(str::to_string),
            service_instance_id: None,
            pin_service_ids: vec![],
            // Derived by the kernel from the connection's `account_email`.
            login_hint: None,
        },
        RequestMeta::default(),
    )
    .await?;
    Ok(AuthRecoveryUrls {
        auth_url: response.auth_url,
        short: response.short,
    })
}
