//! Connection creation: `POST /v1/connections` (orchestrated OAuth) and
//! `POST /v1/connections/import` (white-label token vault).

use super::*;

#[derive(Deserialize)]
pub(super) struct InitiateConnectionRequest {
    provider: String,
    #[serde(default)]
    scopes: Vec<String>,
    /// Pin a specific BYOC credential for this connection. If omitted, the
    /// cascade resolver picks identity-level → org-level → env fallback.
    #[serde(default)]
    byoc_credential_id: Option<Uuid>,
    /// Bind the resulting connection to this user identity instead of the
    /// calling agent. Caller must be an agent whose owner is this user (or the
    /// user itself). Lets all agents under the user share the connection.
    #[serde(default)]
    on_behalf_of: Option<Uuid>,
    /// Optional tenant-supplied URL the callback redirects to after the
    /// OAuth dance finishes. See [`CreateConnectionInput::return_url`].
    #[serde(default)]
    return_url: Option<String>,
    /// Service instances to atomically bind the resulting connection to when
    /// the callback fires. Plural; the singular `service_instance_id` alias is
    /// merged in. See [`CreateConnectionInput::pin_service_ids`].
    #[serde(default)]
    pin_service_ids: Vec<Uuid>,
    /// Singular back-compat alias for `pin_service_ids`, merged into the list.
    #[serde(default)]
    service_instance_id: Option<Uuid>,
    /// Account to pre-select at the provider (typically an email). Only sent
    /// to providers that accept an account hint. See
    /// [`CreateConnectionInput::login_hint`].
    #[serde(default)]
    login_hint: Option<String>,
}

/// Wire shape for `POST /v1/connections`.
///
/// Field name `auth_url` is unchanged from the pre-PR shape — the *value*
/// upgrades to the Overslash-gated URL (`/connect-authorize?id=…`) which
/// fail-fasts on session mismatch before redirecting to the provider, so
/// existing callers transparently inherit the chat-delivery hardening
/// described in the kernel doc-comment in
/// `services/platform_connections.rs`. The raw provider authorize URL is
/// never surfaced — white-label partners import tokens instead of wrapping an
/// Overslash-built authorize URL.
#[derive(Serialize)]
pub(super) struct InitiateConnectionResponse {
    auth_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    short: Option<String>,
    state: String,
    provider: String,
    expires_at: OffsetDateTime,
    flow_id: String,
}

pub(super) async fn initiate_connection(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    headers: HeaderMap,
    Json(req): Json<InitiateConnectionRequest>,
) -> Result<Json<InitiateConnectionResponse>> {
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok());
    let ctx = PlatformCallContext {
        org_id: acl.org_id,
        identity_id: acl.identity_id,
        access_level: acl.access_level,
        db: state.db_pool(&ext),
        registry: state.registry.clone(),
        config: state.config.clone(),
        http_client: state.http_client.clone(),
    };
    // Merge the singular alias into the plural list (dedup preserves order).
    let mut pin_service_ids = req.pin_service_ids;
    if let Some(sid) = req.service_instance_id
        && !pin_service_ids.contains(&sid)
    {
        pin_service_ids.push(sid);
    }
    let input = CreateConnectionInput {
        provider: req.provider,
        scopes: req.scopes,
        byoc_credential_id: req.byoc_credential_id,
        on_behalf_of: req.on_behalf_of,
        // REST `POST /v1/connections` is the create-from-scratch entry
        // point. The reauth/upgrade flows go through the action handler's
        // recovery arms (or the dedicated `/upgrade_scopes` route).
        upgrade_connection_id: None,
        return_url: req.return_url,
        service_instance_id: None,
        pin_service_ids,
        login_hint: req.login_hint,
    };
    let kernel_response: CreateConnectionResponse = kernel_create_connection(
        ctx,
        input,
        RequestMeta {
            ip: ip.0.as_deref(),
            user_agent,
        },
    )
    .await?;

    Ok(Json(InitiateConnectionResponse {
        auth_url: kernel_response.auth_url,
        short: kernel_response.short,
        state: kernel_response.state,
        provider: kernel_response.provider,
        expires_at: kernel_response.expires_at,
        flow_id: kernel_response.flow_id,
    }))
}

// ---------------------------------------------------------------------------
// POST /v1/connections/import — white-label token vault
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct ImportConnectionRequest {
    provider: String,
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    scopes: Option<Vec<String>>,
    #[serde(default)]
    account_email: Option<String>,
    #[serde(default)]
    byoc_credential_id: Option<Uuid>,
    #[serde(default)]
    on_behalf_of: Option<Uuid>,
    /// Service instances to atomically bind to the imported connection. The
    /// plural form; the singular `service_instance_id` is accepted as an alias
    /// and merged in.
    #[serde(default)]
    pin_service_ids: Vec<Uuid>,
    /// Singular back-compat alias for `pin_service_ids`. Merged into the list.
    #[serde(default)]
    service_instance_id: Option<Uuid>,
}

#[derive(Serialize)]
pub(super) struct ImportConnectionResponse {
    connection_id: Uuid,
    provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    account_email: Option<String>,
    /// `null` when the import didn't declare scopes (unknown — the scope-gate
    /// gives the connection the benefit of the doubt).
    scopes: Option<Vec<String>>,
    is_default: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pinned_service_ids: Vec<Uuid>,
}

/// `POST /v1/connections/import` — vault OAuth tokens a white-label partner
/// minted itself. The partner runs the full OAuth dance against its own client
/// and POSTs the resulting tokens here with an org API key, pinning a
/// **required** `byoc_credential_id`; Overslash stores, self-refreshes via that
/// pinned client, and injects them, and never issues a `redirect_uri`.
/// See `docs/design/white-label-token-vault.md`.
pub(super) async fn import_connection(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    headers: HeaderMap,
    Json(req): Json<ImportConnectionRequest>,
) -> Result<Json<ImportConnectionResponse>> {
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok());
    let ctx = PlatformCallContext {
        org_id: acl.org_id,
        identity_id: acl.identity_id,
        access_level: acl.access_level,
        db: state.db_pool(&ext),
        registry: state.registry.clone(),
        config: state.config.clone(),
        http_client: state.http_client.clone(),
    };
    // Merge the singular alias into the plural list (dedup preserves order).
    let mut pin_service_ids = req.pin_service_ids;
    if let Some(sid) = req.service_instance_id
        && !pin_service_ids.contains(&sid)
    {
        pin_service_ids.push(sid);
    }
    let input = crate::services::platform_connections::ImportConnectionInput {
        provider: req.provider,
        access_token: req.access_token,
        refresh_token: req.refresh_token,
        expires_at: req.expires_at,
        expires_in: req.expires_in,
        scopes: req.scopes,
        account_email: req.account_email,
        byoc_credential_id: req.byoc_credential_id,
        on_behalf_of: req.on_behalf_of,
        pin_service_ids,
    };
    let resp = crate::services::platform_connections::kernel_import_connection(
        ctx,
        input,
        RequestMeta {
            ip: ip.0.as_deref(),
            user_agent,
        },
    )
    .await?;

    Ok(Json(ImportConnectionResponse {
        connection_id: resp.connection_id,
        provider: resp.provider,
        account_email: resp.account_email,
        scopes: resp.scopes,
        is_default: resp.is_default,
        pinned_service_ids: resp.pinned_service_ids,
    }))
}
