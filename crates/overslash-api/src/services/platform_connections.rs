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

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use time::{Duration as TimeDuration, OffsetDateTime};
use uuid::Uuid;

use overslash_core::crypto;
use overslash_db::repos::oauth_connection_flow::{self, CreateOauthConnectionFlow};
use overslash_db::scopes::OrgScope;

use super::group_ceiling;
use super::oauth;
use super::oauth_upstream as svc;
use super::platform_caller::PlatformCallContext;
use super::short_url;
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

    let oauth_state = format!(
        "{}:{}:{}:{}:{}:{}:_",
        ctx.org_id, identity_id, input.provider, byoc_segment, verifier_segment, actor_segment
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
    let short = short_url::mint_short_url(
        &ctx.http_client,
        ctx.config.oversla_sh_base_url.as_deref(),
        ctx.config.oversla_sh_api_key.as_deref(),
        &auth_url,
        expires_at,
    )
    .await;

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
    let input: CreateConnectionInput = serde_json::from_value(value)
        .map_err(|e| AppError::BadRequest(format!("invalid params: {e}")))?;
    if input.provider.is_empty() {
        return Err(AppError::BadRequest("'provider' is required".into()));
    }
    let response = kernel_create_connection(ctx, input, RequestMeta::default()).await?;
    Ok(serde_json::to_value(response).unwrap_or(serde_json::Value::Null))
}
