//! Platform kernels for the secret-request handshake.
//!
//! The agent calls `overslash.request_secret` over MCP; this kernel mints a
//! signed, single-use URL the user can open to paste the value. The secret
//! value never traverses the agent — only the URL does. Mirrors the REST
//! endpoint at `routes/secret_requests.rs::create_secret_request`; both call
//! the same primitives (JWT mint, `secret_request::create`, audit log) so
//! the handshake is identical regardless of surface.
//!
//! Permission split (mirroring `manage_services_own / _share` from
//! `routes/groups.rs`): targeting the caller's own identity, or a descendant
//! of the caller, satisfies `request_secrets_own` (the YAML anchor on the
//! action). Targeting any other identity additionally requires admin-level
//! overslash access — i.e. `request_secrets_share`, which is dashboard-only
//! and never auto-grantable to agents.

use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use overslash_core::permissions::AccessLevel;
use overslash_db::scopes::OrgScope;

use super::permission_chain;
use super::platform_caller::PlatformCallContext;
use super::service_setup;
use crate::error::AppError;
use crate::routes::util::fmt_time;

/// Default TTL for the signed provide URL. Kept short so a request the user
/// never opens drops off the table within the hour. Use the REST endpoint
/// (`POST /v1/secrets/requests`) when an override is needed.
const DEFAULT_TTL_SECS: i64 = 3600;

#[derive(Debug, Default, Deserialize)]
pub struct RequestSecretInput {
    pub secret_name: String,
    /// Identity that the secret will be persisted under. Defaults to the
    /// caller's own identity when omitted.
    #[serde(default)]
    pub identity_id: Option<Uuid>,
    /// Free-form rationale shown on the provide page so the human knows
    /// what they're being asked to paste.
    #[serde(default)]
    pub purpose: Option<String>,
    /// Service instance this value is for. When set, fulfilling the request
    /// also binds the instance's credential slot and the minted URL is the
    /// setup page rather than the bare provide page — the agent hands over
    /// one link that finishes the whole setup.
    ///
    /// Rarely needed by hand: `create_service` already mints these itself and
    /// returns them as `setup.setup_url`. This is the path for binding a
    /// credential to an instance that already exists.
    #[serde(default)]
    pub service_id: Option<Uuid>,
    /// Which credential slot to bind. Optional when the template declares a
    /// single per-instance slot, which is every shipped template.
    #[serde(default)]
    pub credential_key: Option<String>,
    /// Mint even though `secret_name` already exists, accepting that whoever
    /// opens the link stores a new version over the current value. Without it
    /// such a request is refused with `secret_name_conflict` (409).
    ///
    /// The refusal is the point: an agent picking a name by convention has no
    /// way to know the org already uses it, and the person opening the link
    /// is shown a name, not a history.
    #[serde(default)]
    pub force: bool,
}

pub async fn kernel_request_secret(
    ctx: PlatformCallContext,
    input: RequestSecretInput,
) -> Result<Value, AppError> {
    if input.secret_name.trim().is_empty() {
        return Err(AppError::BadRequest("secret_name is required".into()));
    }

    // Org-level API keys (no identity binding) cannot mint a request — the
    // row's `identity_id` and `requested_by` are NOT NULL, and there's no
    // sensible default that wouldn't drop us straight into the share path
    // without an admin gate.
    let caller_identity = ctx
        .identity_id
        .ok_or_else(|| AppError::BadRequest("identity required to request a secret".into()))?;
    let target = input.identity_id.unwrap_or(caller_identity);
    let scope = OrgScope::new(ctx.org_id, ctx.db.clone());
    let _target_row = scope
        .get_identity(target)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;

    // _own / _share split. The YAML anchor `request_secrets_own` already
    // gated the call at the action layer. Anything beyond self-or-descendant
    // additionally requires admin-level overslash access (i.e. the holder
    // of `request_secrets_share`). Mirrors the pattern in
    // routes/groups.rs:333-342.
    if target != caller_identity
        && !permission_chain::is_self_or_ancestor(&scope, caller_identity, target).await?
        && ctx.access_level < AccessLevel::Admin
    {
        return Err(AppError::Forbidden(
            "request_secrets_share required to mint a request for another identity".into(),
        ));
    }

    // Resolve the service binding before anything is written — fulfilment
    // runs from a public route holding only a capability token, so this is
    // the only place the pair is checked.
    let binding = match input.service_id {
        Some(service_id) => Some(
            service_setup::validate_binding(
                &scope,
                &ctx.registry,
                Some(caller_identity),
                ctx.access_level,
                service_id,
                input.credential_key.as_deref(),
            )
            .await?,
        ),
        None => None,
    };

    // Capture the org's User-Signed-Mode policy at mint time so flipping the
    // toggle later never retroactively breaks in-flight URLs.
    let allow_unsigned =
        overslash_db::repos::org::get_allow_unsigned_secret_provide(&ctx.db, ctx.org_id)
            .await?
            .unwrap_or(true);
    let require_user_session = !allow_unsigned;

    // Read the version being superseded before minting, so a forced request
    // reports what was actually there when the agent asked.
    let warning = if input.force {
        service_setup::conflicting_secret_names(
            &scope,
            &[(None, input.secret_name.trim().to_string())],
        )
        .await?
        .first()
        .map(|c| {
            format!(
                "secret '{}' already exists; fulfilling this request replaces \
                 its current value (v{}). The old version stays restorable.",
                c.secret_name, c.current_version
            )
        })
    } else {
        None
    };

    let minted = service_setup::mint(
        &ctx.db,
        &ctx.http_client,
        &ctx.config,
        service_setup::MintRequest {
            org_id: ctx.org_id,
            target_identity: target,
            requested_by: caller_identity,
            secret_name: input.secret_name.trim(),
            reason: input.purpose.as_deref(),
            ttl_seconds: DEFAULT_TTL_SECS,
            require_user_session,
            service_instance_id: binding.as_ref().map(|(row, _)| row.id),
            credential_key: binding.as_ref().map(|(_, key)| key.as_str()),
            force: input.force,
            via: "mcp",
            // The platform runtime is transport-agnostic and carries no
            // client IP down to the kernel.
            ip_address: None,
        },
    )
    .await?;
    crate::services::events::emit(ctx.db.clone(), ctx.http_client.clone(), minted.event);
    let (req_id, url, short_url, expires_at) = (
        minted.request_id,
        minted.url,
        minted.short_url,
        minted.expires_at,
    );

    let mut out = serde_json::json!({
        "request_id": req_id,
        // Named `provide_url` on both shapes: an agent that learned the key
        // before setup links existed keeps working, and the URL is still the
        // thing you hand your user either way.
        "provide_url": url,
        "short_url": short_url,
        "expires_at": fmt_time(expires_at),
    });
    // Inserted only when there is a binding, matching the REST shape's
    // `skip_serializing_if`. Emitting them as `null` otherwise would give an
    // agent branching on key presence a different answer per transport.
    if let Some((row, key)) = binding
        && let Some(obj) = out.as_object_mut()
    {
        obj.insert("service_id".into(), serde_json::json!(row.id));
        obj.insert("credential_key".into(), serde_json::json!(key));
    }
    // Same key-presence rule as the binding fields above: absent rather than
    // null, so an agent branching on presence gets one answer per transport.
    if let Some(warning) = warning
        && let Some(obj) = out.as_object_mut()
    {
        obj.insert("warning".into(), serde_json::json!(warning));
    }
    Ok(out)
}
