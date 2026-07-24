//! Connection-create kernel: typed input/response, the identity-resolving
//! entry points, and the platform-registry dispatch adapter.

use super::scopes::*;
use super::url::*;
use super::*;

#[derive(Debug, Default, Deserialize)]
pub struct CreateConnectionInput {
    pub provider: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Pin a specific BYOC credential. If omitted, the cascade resolver
    /// picks identity-level → org-level → env fallback (matches the REST
    /// behavior).
    #[serde(default)]
    pub byoc_credential_id: Option<Uuid>,
    /// Bind the resulting connection to this user identity instead of the
    /// calling agent. Caller must be an agent whose owner is this user (or
    /// the user itself).
    #[serde(default)]
    pub on_behalf_of: Option<Uuid>,
    /// When set, the OAuth callback updates the named connection in place
    /// instead of minting a new row. Used by the action handler's
    /// `reauth_required` and `missing_scopes` arms — without this, a
    /// reauth would orphan the broken connection alongside a brand-new
    /// row, leaving `service_instances.connection_id` pointing at the
    /// dead one. Persisted on the flow row; the callback reads it back
    /// when resolving the state.
    #[serde(default)]
    pub upgrade_connection_id: Option<Uuid>,
    /// Optional URL the callback redirects the user to after the flow
    /// completes — e.g. `https://cloud.overfolder.com/oauth/overslash/callback`.
    /// Format is validated at create time (https, no fragment/userinfo,
    /// ≤2048 chars; `http://localhost` allowed for dev). The host must
    /// additionally appear in the operator allow-list
    /// (`OVERSLASH_CONNECTION_RETURN_URL_HOSTS`) at callback time —
    /// otherwise the callback silently falls back to the default JSON
    /// response, preserving today's behavior.
    #[serde(default)]
    pub return_url: Option<String>,
    /// When `POST /v1/services` orchestrates an OAuth flow as part of
    /// setting up a new service, this carries the just-created instance's
    /// id so the callback can bind the resulting connection back onto the
    /// service. Plumbed onto the flow row; `None` is the low-level path
    /// where the caller is not orchestrating a service alongside.
    #[serde(default)]
    pub service_instance_id: Option<Uuid>,
    /// Service instances to atomically bind the resulting connection to when
    /// the OAuth callback fires — the plural successor to
    /// `service_instance_id`. Persisted on the flow row; the callback binds
    /// every id in one transaction alongside the connection insert. Empty ⇒
    /// no multi-pin.
    #[serde(default)]
    pub pin_service_ids: Vec<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct CreateConnectionResponse {
    /// The Overslash-gated URL (`{public_url}/connect-authorize?id=…`).
    /// Hand this to the user — the gate fail-fasts on session mismatch
    /// before redirecting to the provider. Field name kept as
    /// `auth_url` so existing REST callers keep working transparently;
    /// the *value* is the gated URL (never the raw provider URL).
    pub auth_url: String,
    /// Optional shortened form (only present if the shortener is configured).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short: Option<String>,
    /// OAuth state parameter. Already bound to org/identity/provider/PKCE
    /// server-side; surfaced here so REST callers can correlate the
    /// callback if they want to.
    pub state: String,
    pub provider: String,
    pub expires_at: OffsetDateTime,
    pub flow_id: String,
}

/// Bundle of authorize-URL flavors returned by the action-handler
/// minters ([`mint_initial_auth_url`] and [`mint_upgrade_auth_url`]).
/// Mirrors the same triplet on [`CreateConnectionResponse`] minus the
/// kernel-only fields (state/flow_id/expires_at) the error envelopes
/// don't need.
#[derive(Debug)]
pub struct AuthRecoveryUrls {
    pub auth_url: String,
    pub short: Option<String>,
}

pub async fn kernel_create_connection(
    ctx: PlatformCallContext,
    input: CreateConnectionInput,
    request_meta: RequestMeta<'_>,
) -> Result<CreateConnectionResponse, AppError> {
    // OAuth is identity-bound by construction (the resulting connection row
    // pins to an identity). Org-level keys cannot initiate.
    let caller_identity_id = ctx
        .identity_id
        .ok_or_else(|| AppError::BadRequest("OAuth requires an identity-bound API key".into()))?;

    let scope = OrgScope::new(ctx.org_id, ctx.db.clone());

    // OAuth connections bind to the OWNER identity (ceiling root) so every agent
    // under a user shares one connection and a single reauth heals them all (D22).
    // on_behalf_of, when given, must still name that owner — validate it for a
    // precise 403 — but the binding is the owner either way. Audit stays on the
    // caller (passed separately into kernel_create_connection_for_identity below).
    if let Some(target) = input.on_behalf_of {
        group_ceiling::validate_on_behalf_of(&scope, caller_identity_id, target).await?;
    }
    let identity_id = group_ceiling::resolve_ceiling_user_id(&scope, caller_identity_id).await?;

    kernel_create_connection_for_identity(ctx, identity_id, caller_identity_id, input, request_meta)
        .await
}

/// Build the OAuth flow row + authorize URLs binding the eventual connection
/// to `identity_id`, attributed to `caller_identity_id` for audit. No caller
/// validation — the caller has already decided which identity the
/// connection (or upgrade) belongs to.
///
/// Reachable from inside this module only. Two callers:
///   - `kernel_create_connection` after `validate_on_behalf_of` has run.
///   - `mint_upgrade_auth_url`'s group-granted cross-user branch, which
///     authorises the call via `caller_has_group_access_to_connection`
///     instead of the on_behalf_of ceiling check.
pub(crate) async fn kernel_create_connection_for_identity(
    ctx: PlatformCallContext,
    identity_id: Uuid,
    caller_identity_id: Uuid,
    input: CreateConnectionInput,
    request_meta: RequestMeta<'_>,
) -> Result<CreateConnectionResponse, AppError> {
    let provider = overslash_db::repos::oauth_provider::get_by_key(&ctx.db, &input.provider)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("provider '{}' not found", input.provider)))?;

    let enc_key = ctx.config.keyring()?;
    let creds = crate::services::client_credentials::resolve(
        &ctx.db,
        &enc_key,
        ctx.org_id,
        Some(identity_id),
        &input.provider,
        None,
        input.byoc_credential_id,
    )
    .await?;

    // Every orchestrated flow uses the single default callback at both
    // authorize build and token exchange. White-label partners no longer
    // orchestrate through Overslash, so there is no per-flow redirect override.
    let redirect_uri = default_callback_redirect_uri(&ctx.config.public_url);

    let byoc_id = creds.byoc_credential_id;

    let pkce = if provider.supports_pkce {
        Some(oauth::generate_pkce())
    } else {
        None
    };

    // Validate the caller-supplied return URL up front. The kernel mints
    // the flow row below; we need a parsed value to persist and a
    // 400-on-failure shape that flows out of `initiate_connection`.
    let return_url = parse_return_url(input.return_url.as_deref())?;

    // Always include the provider's identity scopes. Without them the
    // callback's `fetch_account_email` call against `userinfo_endpoint`
    // returns 401 and the connection lands with a NULL `account_email`,
    // so the dashboard can't show which account is connected. Declared
    // per-provider in the `oauth_providers` row so this fix covers every
    // initiate path: REST, MCP, the Create-Service wizard, and the
    // action-handler's `needs_authentication` minter.
    let scopes = merge_scopes(&input.scopes, &provider.default_identity_scopes);

    // The OAuth `state` parameter is the opaque base62 flow id. The
    // callback resolves it back to this row and reads every other field
    // (org, identity, provider, byoc, PKCE verifier, actor, upgrade
    // target) directly from the row — no segments to forge.
    let flow_id = svc::mint_flow_id();
    let oauth_state = flow_id.clone();

    let raw_authorize_url = oauth::build_auth_url(
        &provider,
        &creds.client_id,
        &redirect_uri,
        &scopes,
        &oauth_state,
        pkce.as_ref().map(|p| p.challenge.as_str()),
    );

    // Persist the gate-flow row. `flow_id` is the OAuth `state` parameter
    // we just emitted, so the callback can look this row up directly and
    // read identity, PKCE, byoc, return_url, and upgrade target off it.
    let now = OffsetDateTime::now_utc();
    let expires_at = now + FLOW_TTL;
    let pkce_verifier = pkce.as_ref().map(|p| p.verifier.as_str());

    oauth_connection_flow::create(
        &ctx.db,
        &CreateOauthConnectionFlow {
            id: &flow_id,
            org_id: ctx.org_id,
            identity_id,
            actor_identity_id: caller_identity_id,
            provider_key: &input.provider,
            byoc_credential_id: byoc_id,
            scopes: &scopes,
            pkce_code_verifier: pkce_verifier,
            upstream_authorize_url: &raw_authorize_url,
            expires_at,
            created_ip: request_meta.ip,
            created_user_agent: request_meta.user_agent,
            return_url: return_url.as_deref(),
            upgrade_connection_id: input.upgrade_connection_id,
            service_instance_id: input.service_instance_id,
            pin_service_instance_ids: &input.pin_service_ids,
        },
    )
    .await?;

    let auth_url = format!(
        "{}/connect-authorize?id={}",
        ctx.config.public_url.trim_end_matches('/'),
        flow_id
    );
    let short = match (
        ctx.config.oversla_sh_base_url.as_deref(),
        ctx.config.oversla_sh_api_key.as_deref(),
    ) {
        (Some(base), Some(key)) => {
            short_url::mint_with_client(&ctx.http_client, base, key, &auth_url, expires_at).await
        }
        _ => None,
    };

    Ok(CreateConnectionResponse {
        auth_url,
        short,
        state: oauth_state,
        provider: input.provider,
        expires_at,
        flow_id,
    })
}

/// Network metadata captured at request time. Kernel-shaped so the REST
/// adapter and the MCP platform dispatcher can both feed in whatever they
/// have (the MCP path has neither — both fields are `None` there).
#[derive(Default, Clone, Copy)]
pub struct RequestMeta<'a> {
    pub ip: Option<&'a str>,
    pub user_agent: Option<&'a str>,
}

/// Adapter used by the platform_registry handler — accepts a JSON params
/// map and dispatches into [`kernel_create_connection`] with no network
/// metadata.
pub async fn dispatch_create_connection(
    ctx: PlatformCallContext,
    params: HashMap<String, serde_json::Value>,
) -> Result<serde_json::Value, AppError> {
    let value = serde_json::Value::Object(params.into_iter().collect());
    let mut input: CreateConnectionInput = serde_json::from_value(value)
        .map_err(|e| AppError::BadRequest(format!("invalid params: {e}")))?;
    if input.provider.is_empty() {
        return Err(AppError::BadRequest("'provider' is required".into()));
    }
    // `service_instance_id` is an internal handshake field set by
    // `kernel_create_service` when it orchestrates an OAuth flow on behalf
    // of `POST /v1/services`. Letting an MCP-using agent pass it directly
    // through `overslash.create_connection` would let them target another
    // user's service instance — the callback's bind step would refuse on
    // the ownership check, but stripping here is the defense-in-depth.
    input.service_instance_id = None;
    let response = kernel_create_connection(ctx, input, RequestMeta::default()).await?;
    Ok(serde_json::to_value(response).unwrap_or(serde_json::Value::Null))
}
