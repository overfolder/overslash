//! Token import kernel (white-label token vault): typed input/response,
//! the idempotent re-import path, and the pin-error mapping.

use super::create::*;
use super::scopes::*;
use super::*;

// ---------------------------------------------------------------------------
// Token import (white-label token vault)
// ---------------------------------------------------------------------------

/// Tokens a white-label partner imports after running the OAuth dance itself.
/// Overslash stores, refreshes (when a client is shared), and injects them; it
/// never issues a `redirect_uri`. See `docs/design/white-label-token-vault.md`.
#[derive(Debug, Default, Deserialize)]
pub struct ImportConnectionInput {
    pub provider: String,
    /// The bearer access token to vault and inject.
    pub access_token: String,
    /// Enables Overslash-managed refresh (only used together with a
    /// `byoc_credential_id`). Omitted ⇒ the connection lives until the access
    /// token expires and the partner re-imports.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Absolute expiry as a Unix timestamp (seconds). Takes precedence over
    /// `expires_in`. Omitted (with no `expires_in`) ⇒ treated as long-lived.
    #[serde(default)]
    pub expires_at: Option<i64>,
    /// Lifetime in seconds from now (the raw OAuth `expires_in`). Used when
    /// `expires_at` is absent.
    #[serde(default)]
    pub expires_in: Option<i64>,
    /// Granted scopes — labeling + the action scope-gate. Omitted ⇒ `null`
    /// (unknown): Overslash records no scope set and the action scope-gate gives
    /// the connection the benefit of the doubt rather than 403ing scope-gated
    /// calls. Pass the granted set to opt into precise scope checking.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    /// Account label. Omitted ⇒ best-effort fetch via the provider userinfo
    /// endpoint. Also the multi-account key for idempotent re-import.
    #[serde(default)]
    pub account_email: Option<String>,
    /// The partner's registered BYOC client. **Required**: every imported
    /// connection is hard-pinned to a BYOC client and self-refreshes via it
    /// (never the org/env cascade — a refresh token is valid only against the
    /// client that issued it). A null value is rejected with 400. No inline
    /// client_id/secret — refresh creds always come from a stored BYOC row.
    #[serde(default)]
    pub byoc_credential_id: Option<Uuid>,
    /// Owner-user binding, same semantics as `POST /v1/connections`.
    #[serde(default)]
    pub on_behalf_of: Option<Uuid>,
    /// Service instances to atomically bind to the imported connection, in the
    /// same transaction as the connection write. Each instance must be owned by
    /// the connection's owner identity; a bad id rolls the whole import back so
    /// no connection is created. Lets a white-label partner mint a service
    /// (with `use_default_connection = false`) and its connection in one
    /// coherent step. Empty ⇒ no pinning.
    #[serde(default)]
    pub pin_service_ids: Vec<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct ImportConnectionResponse {
    pub connection_id: Uuid,
    pub provider: String,
    pub account_email: Option<String>,
    /// The recorded granted scopes, or `null` when unknown (an import that
    /// didn't declare them — the scope-gate gives such a connection the benefit
    /// of the doubt).
    pub scopes: Option<Vec<String>>,
    pub is_default: bool,
    /// Instances that were bound to this connection by `pin_service_ids`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pinned_service_ids: Vec<Uuid>,
}

/// Import partner-minted OAuth tokens as a connection. The partner ran the
/// OAuth dance against its own client; Overslash vaults the tokens and treats
/// the resulting row exactly like an orchestrated connection for execution,
/// permissions, and approvals.
///
/// A `byoc_credential_id` is **required**: the import is hard-pinned to that
/// client and self-refreshes via it (validated now, never cascades). Re-import
/// for the same (identity, provider[, account_email]) updates the existing
/// row's tokens in place — the partner's refresh path. Auth-recovery on a
/// headless org returns a URL-less envelope so the partner re-runs its own
/// dance and re-imports (see `error.rs` and `routes/actions/auth.rs`).
pub async fn kernel_import_connection(
    ctx: PlatformCallContext,
    input: ImportConnectionInput,
    request_meta: RequestMeta<'_>,
) -> Result<ImportConnectionResponse, AppError> {
    let caller_identity_id = ctx.identity_id.ok_or_else(|| {
        AppError::BadRequest("connection import requires an identity-bound API key".into())
    })?;
    if input.access_token.trim().is_empty() {
        return Err(AppError::BadRequest("access_token is required".into()));
    }

    let scope = OrgScope::new(ctx.org_id, ctx.db.clone());
    // Bind imported connections to the OWNER identity (ceiling root), same as the
    // orchestrated create path, so every agent under a user shares one connection
    // (D22). on_behalf_of, when given, must still name that owner; audit below is
    // attributed to caller_identity_id.
    if let Some(target) = input.on_behalf_of {
        group_ceiling::validate_on_behalf_of(&scope, caller_identity_id, target).await?;
    }
    let identity_id = group_ceiling::resolve_ceiling_user_id(&scope, caller_identity_id).await?;

    let provider = overslash_db::repos::oauth_provider::get_by_key(&ctx.db, &input.provider)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("provider '{}' not found", input.provider)))?;

    let enc_key = ctx.config.keyring()?;

    // Imported connections must pin a BYOC client: Overslash self-refreshes the
    // token via that client, hard-pinned (never the org/env cascade — a refresh
    // token is valid only against the client that issued it). Validate the pin
    // resolves for this org/provider now (Tier-1 hard pin — `resolve` errors if
    // the row is missing) so a bad id fails loudly here, not at first refresh.
    let pinned_byoc_id = input.byoc_credential_id.ok_or_else(|| {
        AppError::BadRequest(
            "byoc_credential_id is required: imported connections self-refresh via a pinned \
             client. Register the client as a BYOC credential and import against it."
                .into(),
        )
    })?;
    let creds = crate::services::client_credentials::resolve(
        &ctx.db,
        &enc_key,
        ctx.org_id,
        Some(identity_id),
        &input.provider,
        None,
        Some(pinned_byoc_id),
    )
    .await?;
    let byoc_id = creds.byoc_credential_id;

    let expires_at = match input.expires_at {
        Some(ts) => Some(OffsetDateTime::from_unix_timestamp(ts).map_err(|_| {
            AppError::BadRequest("expires_at is not a valid Unix timestamp".into())
        })?),
        None => input
            .expires_in
            .map(|secs| OffsetDateTime::now_utc() + TimeDuration::seconds(secs)),
    };

    // Caller-supplied label wins; otherwise best-effort userinfo fetch (never
    // fails the import — an unlabeled connection is fine).
    //
    // That same round-trip is the only place an avatar could come from, so a
    // caller that names the account gets no picture: paying for a request the
    // label does not need would change who this path dials, and the UI falls
    // back to initials either way.
    let caller_label = input
        .account_email
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let fetched = match caller_label {
        Some(_) => oauth::AccountProfile::default(),
        None => oauth::fetch_account_profile(&ctx.http_client, &provider, &input.access_token)
            .await
            .unwrap_or_default(),
    };
    let account_email = caller_label.map(str::to_string).or(fetched.email);
    let account_picture = fetched.picture;

    let encrypted_access = crypto::encrypt(&enc_key, input.access_token.as_bytes())?;
    let encrypted_refresh = input
        .refresh_token
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|rt| crypto::encrypt(&enc_key, rt.as_bytes()))
        .transpose()?;

    // Idempotent re-import: update the existing row in place so the partner's
    // refresh/re-auth loop doesn't accrete duplicates.
    let candidate = scope
        .find_connection_for_import(identity_id, &input.provider, account_email.as_deref())
        .await?;

    // Whether the import's pinned client matches an existing row's. The pinned
    // client is fixed at first import.
    let mode_matches = |existing: &ConnectionRow| existing.byoc_credential_id == byoc_id;

    // Decide whether `candidate` is genuinely *this* vault connection or an
    // accidental match we must not overwrite (notably an orchestrated
    // connection grabbed by the emailless `(identity, provider)` fallback).
    let existing = match candidate {
        Some(c) if account_email.is_some() => {
            // Email-keyed match: the caller named this account, so an in-place
            // update is intended. The pinned client is fixed — reject an
            // explicit change rather than silently validating-and-discarding a
            // `byoc_credential_id` (which would leave a misconfigured row).
            if !mode_matches(&c) {
                return Err(AppError::BadRequest(
                    "a connection for this account already exists with a different pinned \
                     client; the pinned client is fixed at import — delete it and re-import \
                     to change it"
                        .into(),
                ));
            }
            Some(c)
        }
        Some(c) if mode_matches(&c) => {
            // Emailless heuristic match (the identity's default connection for
            // the provider). Only reuse it when it pins the *same* client. This
            // is what stops an emailless import from overwriting an orchestrated
            // connection (or a differently-pinned one): on a mismatch we fall
            // through to creating a fresh row.
            Some(c)
        }
        _ => None,
    };

    let (connection_id, is_default, effective_scopes, event_type) = if let Some(existing) = existing
    {
        // Preserve the existing expiry on a token-only re-import that carries
        // no fresh one — otherwise we'd null `token_expires_at` and the
        // connection would look perpetually valid, so a connection with a
        // dead refresh token would never surface `reauth_required` (and would
        // keep injecting a token that has actually expired upstream). A
        // re-import that *does* supply `expires_at`/`expires_in` overrides it.
        let next_expires_at = expires_at.or(existing.token_expires_at);
        // Likewise preserve the recorded scopes when the re-import omits them
        // (`scopes` is now `null`/`None` ⇒ "unknown", not `[]`). Overwriting
        // with NULL would discard a known granted set; a re-import that
        // supplies `scopes` overrides it.
        let next_scopes = input.scopes.clone().or_else(|| existing.scopes.clone());

        // Guard the metadata-refresh-token-behind-readonly-scopes divergence
        // (connection `85844f1a`). A re-import that BROADENS the recorded
        // scopes while carrying NO fresh refresh token would COALESCE-preserve
        // the *old* refresh token (below) — but that token was minted for the
        // narrower grant and, on the next self-refresh, echoes only the
        // narrower scopes. The scopes advance to (say) gmail.readonly while the
        // stored refresh token is metadata-only, so calls 403 forever and the
        // refresh path can't heal it. Google reuses one refresh token per
        // client+user and returns `None` on re-consent, so the partner's
        // re-import legitimately can carry no refresh token — but then it must
        // NOT also broaden scopes against a preserved token we can't trust.
        // Reject loudly so the partner re-runs consent with `prompt=consent`
        // (or `access_type=offline` + revoke) to force a fresh refresh token
        // that actually backs the wider grant.
        let import_has_fresh_refresh = encrypted_refresh.is_some();
        let existing_has_refresh = existing.encrypted_refresh_token.is_some();
        if !import_has_fresh_refresh
            && existing_has_refresh
            && let Some(broadened) =
                scopes_broadened(existing.scopes.as_deref(), input.scopes.as_deref())
        {
            return Err(AppError::BadRequest(format!(
                "re-import broadens granted scopes ({broadened}) but carries no fresh \
                         refresh_token: the preserved refresh token was minted for the narrower \
                         grant and cannot self-refresh the wider scopes (it would silently \
                         downgrade the connection to metadata-only). Re-run the OAuth consent \
                         with prompt=consent so the provider issues a fresh refresh token for the \
                         wider grant, then re-import with it."
            )));
        }

        let updated = scope
            .update_connection_tokens_and_scopes(
                existing.id,
                &encrypted_access,
                encrypted_refresh.as_deref(),
                next_expires_at,
                next_scopes.as_deref(),
                account_email.as_deref(),
                account_picture.as_deref(),
            )
            .await?;
        if !updated {
            return Err(AppError::NotFound(
                "connection was deleted during import".into(),
            ));
        }
        // Re-import reuses the existing row; bind any requested pins in their
        // own transaction (the connection already exists, so there's nothing
        // to roll back on the connection itself — but the binds are still
        // all-or-nothing and ownership-gated).
        scope
            .pin_service_instances(existing.id, existing.identity_id, &input.pin_service_ids)
            .await
            .map_err(pin_error_to_app_error)?;
        (
            existing.id,
            existing.is_default,
            next_scopes,
            crate::services::events::EventType::ConnectionUpdated,
        )
    } else {
        let conn = scope
            .create_connection_and_pin(
                CreateConnection {
                    org_id: ctx.org_id,
                    identity_id,
                    provider_key: &input.provider,
                    encrypted_access_token: &encrypted_access,
                    encrypted_refresh_token: encrypted_refresh.as_deref(),
                    token_expires_at: expires_at,
                    scopes: input.scopes.as_deref(),
                    account_email: account_email.as_deref(),
                    account_picture: account_picture.as_deref(),
                    byoc_credential_id: byoc_id,
                },
                &input.pin_service_ids,
            )
            .await
            .map_err(pin_error_to_app_error)?;
        (
            conn.id,
            conn.is_default,
            input.scopes.clone(),
            crate::services::events::EventType::ConnectionCreated,
        )
    };

    let _ = scope
        .log_audit(overslash_db::repos::audit::AuditEntry {
            org_id: ctx.org_id,
            identity_id: Some(caller_identity_id),
            action: event_type.as_str(),
            resource_type: Some("connection"),
            resource_id: Some(connection_id),
            detail: serde_json::json!({
                "provider": input.provider,
                "account_email": account_email,
                "scopes": effective_scopes,
                "imported": true,
            }),
            description: None,
            ip_address: request_meta.ip,
        })
        .await;

    {
        let payload = serde_json::json!({
            "connection_id": connection_id,
            "provider": input.provider,
            "account_email": account_email,
            "scopes": effective_scopes,
            "identity_id": identity_id,
            "imported": true,
        });
        let audience = crate::services::events::audience::for_connection(
            &scope,
            Some(identity_id),
            Some(caller_identity_id),
        )
        .await;
        crate::services::events::emit(
            ctx.db.clone(),
            ctx.http_client.clone(),
            crate::services::events::EventDraft {
                org_id: ctx.org_id,
                event_type,
                payload,
                audience,
            },
        );
    }

    Ok(ImportConnectionResponse {
        connection_id,
        provider: input.provider,
        account_email,
        scopes: effective_scopes,
        is_default,
        pinned_service_ids: input.pin_service_ids,
    })
}

/// Map the atomic-pin failure onto the API error surface. A `Bind` error is the
/// caller's fault (unknown / foreign-owned / org-level instance id) → 400 with
/// the coarse code; a DB error propagates as-is.
pub(crate) fn pin_error_to_app_error(e: overslash_db::scopes::CreateAndPinError) -> AppError {
    use overslash_db::scopes::CreateAndPinError;
    match e {
        CreateAndPinError::Db(e) => AppError::Database(e),
        CreateAndPinError::Bind {
            service_instance_id,
            code,
        } => AppError::BadRequest(format!(
            "{code}: service instance {service_instance_id} cannot be pinned to this connection"
        )),
    }
}
