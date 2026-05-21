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
//!
//! ## Three-URL bundle
//!
//! The kernel returns three flavors of the same authorize handle:
//!
//! - `auth_url`: the Overslash-gated URL — the default deliverable.
//! - `short`: best-effort `oversla.sh/<slug>` redirect to `auth_url`,
//!   present only when the shortener is configured. Friendlier for chat
//!   delivery where long base62 ids get mangled by line-wrapping.
//! - `raw`: the upstream provider authorize URL. White-label REST
//!   integrators wrap this in their own consent UI. The MCP forwarder
//!   strips this field before handing the envelope to the agent — see
//!   `routes/mcp.rs::forward` and the Obsidian threat-model notes above.
//!
//! The same triplet flows through the action-handler error envelopes
//! (`reauth_required`, `needs_authentication`, `missing_scopes`) via
//! [`mint_initial_auth_url`] and [`mint_upgrade_auth_url`].

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use time::{Duration as TimeDuration, OffsetDateTime};
use uuid::Uuid;

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
}

/// Maximum byte length for caller-supplied `return_url`. Cap is generous
/// (we don't expect tenants to pack significant data into the URL) but
/// finite — keeps the DB column honest and the redirect header sane.
const RETURN_URL_MAX_LEN: usize = 2048;

/// Parse and validate a caller-supplied `return_url`. Allow-list membership
/// is intentionally **not** checked here — that gate lives at the callback
/// so an allow-list misconfiguration falls back to JSON instead of
/// breaking flow creation. See [`oauth_callback`].
pub(crate) fn parse_return_url(raw: Option<&str>) -> Result<Option<String>, AppError> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    if raw.len() > RETURN_URL_MAX_LEN {
        return Err(AppError::BadRequest(format!(
            "return_url exceeds {RETURN_URL_MAX_LEN}-byte limit"
        )));
    }
    let parsed = url::Url::parse(raw)
        .map_err(|e| AppError::BadRequest(format!("return_url is not a valid URL: {e}")))?;
    // `url::Url::parse` accepts relative-looking inputs like `foo:bar` as
    // opaque-data URLs; require a real authority with a host instead.
    let host = parsed
        .host_str()
        .ok_or_else(|| AppError::BadRequest("return_url must include a host".into()))?
        .to_ascii_lowercase();
    let scheme = parsed.scheme();
    let scheme_ok = scheme == "https"
        || (scheme == "http" && matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1"));
    if !scheme_ok {
        return Err(AppError::BadRequest(
            "return_url must use https (http allowed only for localhost)".into(),
        ));
    }
    if parsed.fragment().is_some() {
        return Err(AppError::BadRequest(
            "return_url must not contain a fragment".into(),
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(AppError::BadRequest(
            "return_url must not contain userinfo".into(),
        ));
    }
    Ok(Some(parsed.into()))
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
    /// Raw upstream provider authorize URL (e.g. `https://accounts.google.com/...`).
    /// Marked `#[serde(skip)]` so the platform-registry MCP path
    /// (`dispatch_create_connection`) cannot accidentally surface it via a
    /// blanket `serde_json::to_value(response)` call. The REST
    /// `initiate_connection` wrapper still gates exposure on
    /// `include_raw`; the action-handler error envelopes always expose it
    /// on REST and the MCP forwarder strips it.
    #[serde(skip)]
    pub raw: String,
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
    pub raw: String,
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

    // If on_behalf_of is set, validate it walks the agent's owner chain and
    // bind the resulting connection to the user instead of the calling agent.
    let identity_id = if let Some(target) = input.on_behalf_of {
        group_ceiling::validate_on_behalf_of(&scope, caller_identity_id, target).await?
    } else {
        caller_identity_id
    };

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
async fn kernel_create_connection_for_identity(
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

    let redirect_uri = format!(
        "{}/v1/oauth/callback",
        ctx.config.public_url.trim_end_matches('/')
    );

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
        &input.scopes,
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
            scopes: &input.scopes,
            pkce_code_verifier: pkce_verifier,
            upstream_authorize_url: &raw_authorize_url,
            expires_at,
            created_ip: request_meta.ip,
            created_user_agent: request_meta.user_agent,
            return_url: return_url.as_deref(),
            upgrade_connection_id: input.upgrade_connection_id,
            service_instance_id: input.service_instance_id,
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
        raw: raw_authorize_url,
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
            // Action-handler auth-recovery doesn't surface a tenant
            // return_url today; the URL the agent hands the user lands
            // back on the default JSON response.
            return_url: None,
            service_instance_id: None,
        },
        RequestMeta::default(),
    )
    .await?;
    Ok(AuthRecoveryUrls {
        auth_url: response.auth_url,
        short: response.short,
        raw: response.raw,
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
pub async fn mint_upgrade_auth_url(
    state: &AppState,
    org_id: Uuid,
    caller_identity_id: Uuid,
    conn: &ConnectionRow,
    extra_scopes: &[String],
) -> Result<AuthRecoveryUrls, AppError> {
    let scopes = merge_scopes(&conn.scopes, extra_scopes);
    let scope = OrgScope::new(org_id, state.db.clone());

    // The OAuth callback (`routes/connections.rs::oauth_callback`) updates
    // the existing row in place when the flow row's `upgrade_connection_id`
    // is set — it preserves `existing.identity_id` and just swaps
    // tokens/scopes. So whichever identity owns the flow row, the
    // connection's owner is unchanged after the dance. Two cases to handle:
    //
    // (1) Same-identity caller. Nothing to validate; the existing kernel
    //     handles it directly.
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
        let response = kernel_create_connection(
            ctx,
            CreateConnectionInput {
                provider: conn.provider_key.clone(),
                scopes,
                byoc_credential_id: conn.byoc_credential_id,
                on_behalf_of: None,
                upgrade_connection_id: Some(conn.id),
                return_url: None,
                service_instance_id: None,
            },
            RequestMeta::default(),
        )
        .await?;
        return Ok(AuthRecoveryUrls {
            auth_url: response.auth_url,
            short: response.short,
            raw: response.raw,
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
                return_url: None,
                service_instance_id: None,
            },
            RequestMeta::default(),
        )
        .await?;
        return Ok(AuthRecoveryUrls {
            auth_url: response.auth_url,
            short: response.short,
            raw: response.raw,
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
            return_url: None,
            service_instance_id: None,
        },
        RequestMeta::default(),
    )
    .await?;
    Ok(AuthRecoveryUrls {
        auth_url: response.auth_url,
        short: response.short,
        raw: response.raw,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_scopes_dedupes_and_sorts() {
        let existing = vec!["b".into(), "a".into()];
        let incoming = vec!["a".into(), "c".into()];
        assert_eq!(
            merge_scopes(&existing, &incoming),
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
    }

    #[test]
    fn merge_scopes_handles_empty_inputs() {
        assert!(merge_scopes(&[], &[]).is_empty());
        assert_eq!(merge_scopes(&["x".into()], &[]), vec!["x".to_string()]);
        assert_eq!(merge_scopes(&[], &["x".into()]), vec!["x".to_string()]);
    }

    #[test]
    fn parse_return_url_accepts_https() {
        let parsed = parse_return_url(Some("https://cloud.overfolder.com/cb"))
            .expect("valid")
            .expect("present");
        assert_eq!(parsed, "https://cloud.overfolder.com/cb");
    }

    #[test]
    fn parse_return_url_accepts_http_localhost() {
        let parsed = parse_return_url(Some("http://localhost:5173/cb?ref=x"))
            .expect("valid")
            .expect("present");
        assert_eq!(parsed, "http://localhost:5173/cb?ref=x");
    }

    #[test]
    fn parse_return_url_none_and_blank_pass_through_as_none() {
        assert!(parse_return_url(None).unwrap().is_none());
        assert!(parse_return_url(Some("")).unwrap().is_none());
        assert!(parse_return_url(Some("   ")).unwrap().is_none());
    }

    #[test]
    fn parse_return_url_rejects_plain_http_non_localhost() {
        assert!(parse_return_url(Some("http://evil.example.com/cb")).is_err());
    }

    #[test]
    fn parse_return_url_rejects_fragment() {
        assert!(parse_return_url(Some("https://cloud.overfolder.com/cb#frag")).is_err());
    }

    #[test]
    fn parse_return_url_rejects_userinfo() {
        assert!(parse_return_url(Some("https://attacker@cloud.overfolder.com/cb")).is_err());
        assert!(parse_return_url(Some("https://u:p@cloud.overfolder.com/cb")).is_err());
    }

    #[test]
    fn parse_return_url_rejects_overlong() {
        let mut s = String::from("https://cloud.overfolder.com/");
        s.extend(std::iter::repeat_n('a', RETURN_URL_MAX_LEN));
        assert!(parse_return_url(Some(&s)).is_err());
    }

    #[test]
    fn parse_return_url_rejects_relative_and_unparseable() {
        assert!(parse_return_url(Some("/just/a/path")).is_err());
        assert!(parse_return_url(Some("not a url")).is_err());
        // Schemes without an authority (no host) — e.g. `mailto:`,
        // `javascript:` — must be rejected so the redirect can't escape
        // to a non-HTTP target.
        assert!(parse_return_url(Some("javascript:alert(1)")).is_err());
        assert!(parse_return_url(Some("mailto:foo@example.com")).is_err());
    }
}
