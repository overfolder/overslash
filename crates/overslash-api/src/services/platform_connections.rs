//! Platform kernel for HTTP-OAuth connection initiation.
//!
//! Mirrors `platform_services.rs` and `platform_templates.rs`: a pure async
//! function that takes a [`PlatformCallContext`] plus typed input and returns
//! a typed response. Both the REST handler in `routes/connections.rs` and the
//! MCP platform dispatcher (via `platform_registry`) call into the same
//! kernel.
//!
//! ## Why this kernel does not return the raw provider authorize URL
//!
//! The Obsidian Security writeup *"When MCP Meets OAuth: Common Pitfalls
//! Leading to One-Click Account Takeover"* (2025) catalogues attack patterns
//! that get worse when an agent delivers a raw provider authorize URL to the
//! user over chat — the user sees `https://github.com/...` and has no
//! Overslash-branded checkpoint that says *which* agent triggered *which*
//! identity's flow on *which* org. The mitigations baked into
//! `crates/overslash-api/src/routes/oauth.rs` (PKCE-S256 mandatory, state
//! bound to session/org at the consent step, DCR-validated `redirect_uri`,
//! single-use refresh-token rotation) all hold per the table in
//! `docs/design/agent-mcp-bootstrap-story.md` §3 — those mechanisms are
//! untouched by this kernel.
//!
//! What this kernel adds on top of those is the chat-delivery hardening
//! that the upstream-MCP path already has via `mcp_upstream_flows` /
//! `/gated-authorize` (`routes/oauth_upstream.rs`). The kernel persists an
//! `oauth_connection_flows` row holding the raw authorize URL and returns
//! `auth_url` set to `{public_url}/connect-authorize?id=<flow>` instead
//! of the raw provider URL. The wire-level field name is unchanged so
//! existing REST clients keep working — only the *value* upgrades to the
//! gated URL, which fail-fasts on missing/expired/consumed/session-
//! mismatch before 302ing to the provider. White-label REST callers that
//! still need the raw provider URL can opt in via `include_raw: true`.

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use time::{Duration as TimeDuration, OffsetDateTime};
use uuid::Uuid;

use overslash_core::crypto;
use overslash_db::repos::connection::ConnectionRow;
use overslash_db::repos::oauth_connection_flow::{self, CreateOauthConnectionFlow};
use overslash_db::scopes::OrgScope;

use super::group_ceiling;
use super::oauth;
use super::oauth_upstream as svc;
use super::platform_caller::PlatformCallContext;
use super::short_url;
use crate::AppState;
use crate::error::AppError;

/// Gate-flow TTL. Matches `mcp_upstream_flow` (10 min) — long enough to
/// survive a chat delivery + email round-trip, short enough that an
/// abandoned link doesn't sit forever.
const FLOW_TTL: TimeDuration = TimeDuration::minutes(10);

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
    /// dead one. See `routes/connections.rs::oauth_callback` for the
    /// state-segment parser.
    #[serde(default)]
    pub upgrade_connection_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct CreateConnectionResponse {
    /// The Overslash-gated URL (`{public_url}/connect-authorize?id=…`).
    /// Hand this to the user — the gate fail-fasts on session mismatch
    /// before redirecting to the provider. Field name kept as
    /// `auth_url` so existing REST callers keep working transparently;
    /// the *value* changed (gated URL instead of raw provider URL),
    /// which is the security upgrade. White-label callers that need the
    /// raw provider URL must opt in via `include_raw: true`.
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

    let provider = overslash_db::repos::oauth_provider::get_by_key(&ctx.db, &input.provider)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("provider '{}' not found", input.provider)))?;

    // If on_behalf_of is set, validate it walks the agent's owner chain and
    // bind the resulting connection to the user instead of the calling agent.
    let identity_id = if let Some(target) = input.on_behalf_of {
        group_ceiling::validate_on_behalf_of(&scope, caller_identity_id, target).await?
    } else {
        caller_identity_id
    };

    let enc_key = crypto::parse_hex_key(&ctx.config.secrets_encryption_key)?;
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

    let redirect_uri = format!(
        "{}/v1/oauth/callback",
        ctx.config.public_url.trim_end_matches('/')
    );

    let byoc_id = creds.byoc_credential_id;
    let byoc_segment = byoc_id.map_or_else(|| "_".to_string(), |id| id.to_string());

    let pkce = if provider.supports_pkce {
        Some(oauth::generate_pkce())
    } else {
        None
    };
    let verifier_segment = pkce.as_ref().map(|p| p.verifier.as_str()).unwrap_or("_");

    // The actor (caller agent) is preserved separately from `identity_id` so
    // the callback can audit the agent that initiated the OAuth flow even
    // when the resulting connection is bound to the owner user via
    // on_behalf_of. State format unchanged — see routes/connections.rs
    // `oauth_callback` for the parser.
    let actor_segment = if caller_identity_id == identity_id {
        "_".to_string()
    } else {
        caller_identity_id.to_string()
    };

    let upgrade_segment = input
        .upgrade_connection_id
        .map_or_else(|| "_".to_string(), |id| id.to_string());

    let oauth_state = format!(
        "{}:{}:{}:{}:{}:{}:{}",
        ctx.org_id,
        identity_id,
        input.provider,
        byoc_segment,
        verifier_segment,
        actor_segment,
        upgrade_segment
    );

    let raw_authorize_url = oauth::build_auth_url(
        &provider,
        &creds.client_id,
        &redirect_uri,
        &input.scopes,
        &oauth_state,
        pkce.as_ref().map(|p| p.challenge.as_str()),
    );

    // Persist the gate-flow row. The flow id is the URL short-id (`?id=`)
    // and is independent of the OAuth `state` — `state` is the security-
    // critical parameter at the callback boundary; the flow id is just the
    // gate's lookup key. We could collapse the two but keeping them
    // separate matches `mcp_upstream_flow` and means rotating one doesn't
    // affect the other.
    let flow_id = svc::mint_flow_id();
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
            scopes: &input.scopes,
            pkce_code_verifier: pkce_verifier,
            upstream_authorize_url: &raw_authorize_url,
            expires_at,
            created_ip: request_meta.ip,
            created_user_agent: request_meta.user_agent,
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

/// Return the union of `existing` and `incoming`, preserving an order
/// that's deterministic for downstream comparison (lexicographic via
/// `BTreeSet`). Used by both the REST upgrade-scopes route and the
/// action handler's reauth/missing-scopes URL minters so they can't
/// drift on dedup or ordering.
pub fn merge_scopes(existing: &[String], incoming: &[String]) -> Vec<String> {
    let mut set: BTreeSet<String> = existing.iter().cloned().collect();
    for s in incoming {
        set.insert(s.clone());
    }
    set.into_iter().collect()
}

/// Adapter used by the platform_registry handler — accepts a JSON params
/// map and dispatches into [`kernel_create_connection`] with no network
/// metadata.
pub async fn dispatch_create_connection(
    ctx: PlatformCallContext,
    params: HashMap<String, serde_json::Value>,
) -> Result<serde_json::Value, AppError> {
    let value = serde_json::Value::Object(params.into_iter().collect());
    let input: CreateConnectionInput = serde_json::from_value(value)
        .map_err(|e| AppError::BadRequest(format!("invalid params: {e}")))?;
    if input.provider.is_empty() {
        return Err(AppError::BadRequest("'provider' is required".into()));
    }
    let response = kernel_create_connection(ctx, input, RequestMeta::default()).await?;
    Ok(serde_json::to_value(response).unwrap_or(serde_json::Value::Null))
}

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
) -> Result<String, AppError> {
    let ctx = ctx_from_state(state, org_id, Some(caller_identity_id));
    let response = kernel_create_connection(
        ctx,
        CreateConnectionInput {
            provider: provider.to_string(),
            scopes: scopes.to_vec(),
            byoc_credential_id: None,
            on_behalf_of,
            upgrade_connection_id: None,
        },
        RequestMeta::default(),
    )
    .await?;
    Ok(response.auth_url)
}

/// Mint a gated `/connect-authorize` URL that, when consumed, refreshes
/// the *existing* connection in place (sets segment 7 of the OAuth state
/// so the callback updates the row instead of creating a new one). Used
/// by the action handler's `reauth_required` arm (refresh-token failed)
/// and the `missing_scopes` arm (incremental scope upgrade).
///
/// Scopes default to the connection's existing set unioned with
/// `extra_scopes` — Google with `include_granted_scopes=true` would
/// preserve the old ones anyway, but sending the full union makes
/// non-Google providers work too. Mirrors `merge_scopes` in
/// `routes/connections.rs::upgrade_connection_scopes`.
pub async fn mint_upgrade_auth_url(
    state: &AppState,
    org_id: Uuid,
    caller_identity_id: Uuid,
    conn: &ConnectionRow,
    extra_scopes: &[String],
) -> Result<String, AppError> {
    let scopes = merge_scopes(&conn.scopes, extra_scopes);

    // If the connection belongs to a different identity than the caller
    // (agent-on-behalf-of-user case), thread `on_behalf_of` so the kernel's
    // ceiling-validation runs and the resulting flow updates the
    // user-bound row rather than failing cross-identity.
    let on_behalf_of = (conn.identity_id != caller_identity_id).then_some(conn.identity_id);

    let ctx = ctx_from_state(state, org_id, Some(caller_identity_id));
    let response = kernel_create_connection(
        ctx,
        CreateConnectionInput {
            provider: conn.provider_key.clone(),
            scopes,
            byoc_credential_id: conn.byoc_credential_id,
            on_behalf_of,
            upgrade_connection_id: Some(conn.id),
        },
        RequestMeta::default(),
    )
    .await?;
    Ok(response.auth_url)
}
