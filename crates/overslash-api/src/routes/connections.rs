use std::collections::{BTreeSet, HashMap};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::repos::audit::AuditEntry;
use overslash_db::scopes::{OrgScope, UserScope};

use super::util::fmt_time;
use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{ClientIp, WriteAcl},
    services::{client_credentials, oauth},
};
use overslash_core::crypto;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/connections",
            post(initiate_connection).get(list_connections),
        )
        .route("/v1/connections/{id}", delete(delete_connection))
        .route(
            "/v1/connections/{id}/upgrade_scopes",
            post(upgrade_connection_scopes),
        )
        .route("/v1/oauth/callback", get(oauth_callback))
}

#[derive(Deserialize)]
struct InitiateConnectionRequest {
    provider: String,
    #[serde(default)]
    scopes: Vec<String>,
    /// Pin a specific BYOC credential for this connection. If omitted, the
    /// cascade resolver picks identity-level → org-level → env fallback.
    byoc_credential_id: Option<Uuid>,
    /// Bind the resulting connection to this user identity instead of the
    /// calling agent. Caller must be an agent whose owner is this user (or the
    /// user itself). Lets all agents under the user share the connection.
    #[serde(default)]
    on_behalf_of: Option<Uuid>,
}

#[derive(Serialize)]
struct InitiateConnectionResponse {
    auth_url: String,
    state: String,
    provider: String,
}

async fn initiate_connection(
    State(state): State<AppState>,
    WriteAcl(acl): WriteAcl,
    scope: OrgScope,
    Json(req): Json<InitiateConnectionRequest>,
) -> Result<Json<InitiateConnectionResponse>> {
    let auth = acl;
    let provider = overslash_db::repos::oauth_provider::get_by_key(&state.db, &req.provider)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("provider '{}' not found", req.provider)))?;

    // OAuth connections require an identity-bound API key
    let caller_identity_id = auth
        .identity_id
        .ok_or_else(|| AppError::BadRequest("OAuth requires an identity-bound API key".into()))?;

    // If on_behalf_of is set, validate it walks the agent's owner chain and
    // bind the resulting connection to the user instead of the calling agent.
    let identity_id = if let Some(target) = req.on_behalf_of {
        crate::services::group_ceiling::validate_on_behalf_of(&scope, caller_identity_id, target)
            .await?
    } else {
        caller_identity_id
    };

    let enc_key = crypto::parse_hex_key(&state.config.secrets_encryption_key)?;
    let creds = client_credentials::resolve(
        &state.db,
        &enc_key,
        auth.org_id,
        Some(identity_id),
        &req.provider,
        None,
        req.byoc_credential_id,
    )
    .await?;

    let redirect_uri = format!(
        "{}/v1/oauth/callback",
        state.config.public_url.trim_end_matches('/')
    );

    let byoc_id = creds.byoc_credential_id;
    let byoc_segment = byoc_id.map_or_else(|| "_".to_string(), |id| id.to_string());

    // Generate PKCE pair if the provider requires it
    let pkce = if provider.supports_pkce {
        Some(oauth::generate_pkce())
    } else {
        None
    };

    let verifier_segment = pkce.as_ref().map(|p| p.verifier.as_str()).unwrap_or("_");

    // The actor (caller agent) is preserved separately from `identity_id` so the
    // callback can audit the agent that initiated the OAuth flow even when the
    // resulting connection is bound to the owner user via on_behalf_of.
    let actor_segment = if caller_identity_id == identity_id {
        "_".to_string()
    } else {
        caller_identity_id.to_string()
    };

    // State encodes: org_id:identity_id:provider_key:byoc_credential_id:code_verifier:actor_identity_id:upgrade_connection_id
    // Initiate path never carries an upgrade id — the callback treats a bare
    // trailing `_` (or absence) as "create a new connection".
    let oauth_state = format!(
        "{}:{}:{}:{}:{}:{}:_",
        auth.org_id, identity_id, req.provider, byoc_segment, verifier_segment, actor_segment
    );

    let auth_url = oauth::build_auth_url(
        &provider,
        &creds.client_id,
        &redirect_uri,
        &req.scopes,
        &oauth_state,
        pkce.as_ref().map(|p| p.challenge.as_str()),
    );

    Ok(Json(InitiateConnectionResponse {
        auth_url,
        state: oauth_state,
        provider: req.provider,
    }))
}

#[derive(Deserialize)]
struct OAuthCallbackParams {
    code: String,
    state: String,
}

async fn oauth_callback(
    State(state): State<AppState>,
    ip: ClientIp,
    Query(params): Query<OAuthCallbackParams>,
) -> Result<Json<serde_json::Value>> {
    // Parse state: org_id:identity_id:provider_key:byoc_credential_id[:code_verifier[:actor_identity_id[:upgrade_connection_id]]]
    let parts: Vec<&str> = params.state.splitn(7, ':').collect();
    if parts.len() < 3 {
        return Err(AppError::BadRequest("invalid state parameter".into()));
    }
    let org_id: Uuid = parts[0]
        .parse()
        .map_err(|_| AppError::BadRequest("invalid org_id in state".into()))?;
    let identity_id: Uuid = parts[1]
        .parse()
        .map_err(|_| AppError::BadRequest("invalid identity_id in state".into()))?;
    let provider_key = parts[2];
    let byoc_credential_id: Option<Uuid> = parts
        .get(3)
        .and_then(|s| if *s == "_" { None } else { s.parse().ok() });
    let code_verifier: Option<&str> = parts
        .get(4)
        .and_then(|s| if *s == "_" { None } else { Some(*s) });
    // Actor (agent) for audit attribution. Falls back to identity_id when the
    // connection wasn't on_behalf_of (i.e. caller == owner).
    let actor_identity_id: Uuid = parts
        .get(5)
        .and_then(|s| if *s == "_" { None } else { s.parse().ok() })
        .unwrap_or(identity_id);
    // When present, the callback updates this existing connection in place
    // (incremental scope upgrade) instead of minting a new one.
    let upgrade_connection_id: Option<Uuid> = parts
        .get(6)
        .and_then(|s| if *s == "_" { None } else { s.parse().ok() });

    let provider = overslash_db::repos::oauth_provider::get_by_key(&state.db, provider_key)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("provider '{provider_key}' not found")))?;

    let enc_key = crypto::parse_hex_key(&state.config.secrets_encryption_key)?;
    let creds = client_credentials::resolve(
        &state.db,
        &enc_key,
        org_id,
        Some(identity_id),
        provider_key,
        None,
        byoc_credential_id,
    )
    .await?;

    let effective_byoc_id = creds.byoc_credential_id;

    let redirect_uri = format!(
        "{}/v1/oauth/callback",
        state.config.public_url.trim_end_matches('/')
    );

    // Exchange code for tokens
    let tokens = oauth::exchange_code(
        &state.http_client,
        &provider,
        &creds.client_id,
        &creds.client_secret,
        &params.code,
        &redirect_uri,
        code_verifier,
    )
    .await
    .map_err(|e| AppError::BadRequest(format!("token exchange failed: {e}")))?;

    // Fetch account identity (email / login) from the provider — best-effort;
    // a failure leaves the label blank but still lands the connection.
    let account_email =
        oauth::fetch_account_email(&state.http_client, &provider, &tokens.access_token)
            .await
            .unwrap_or(None);
    let granted_scopes = tokens.granted_scopes();

    // Encrypt tokens
    let encrypted_access = crypto::encrypt(&enc_key, tokens.access_token.as_bytes())?;
    let encrypted_refresh = tokens
        .refresh_token
        .as_ref()
        .map(|rt| crypto::encrypt(&enc_key, rt.as_bytes()))
        .transpose()?;
    let expires_at = tokens
        .expires_in
        .map(|secs| time::OffsetDateTime::now_utc() + time::Duration::seconds(secs));

    // The org_id from state is the source of truth for scope construction.
    // The OAuth callback is unauthenticated by design (the redirect_uri is
    // public), so all tenancy invariants come from the state we issued at
    // initiate time — which we already validated above by decoding into Uuids.
    let scope = OrgScope::new(org_id, state.db.clone());

    let (connection_id, audit_action) = if let Some(existing_id) = upgrade_connection_id {
        // Incremental upgrade: union the granted scope set with what was on
        // the connection, update tokens, keep the same row id so every
        // service pointing at it stays bound.
        let existing = scope
            .get_connection(existing_id)
            .await?
            .ok_or_else(|| AppError::NotFound("connection not found".into()))?;
        if existing.identity_id != identity_id || existing.provider_key != provider_key {
            return Err(AppError::BadRequest(
                "state mismatch: upgrade connection does not match identity/provider".into(),
            ));
        }
        let merged: Vec<String> = merge_scopes(&existing.scopes, &granted_scopes);
        let updated = scope
            .update_connection_tokens_and_scopes(
                existing_id,
                &encrypted_access,
                encrypted_refresh.as_deref(),
                expires_at,
                &merged,
                // Refresh the label too — the provider may have renamed the
                // account between the original connect and the upgrade.
                // `COALESCE` on the repo side leaves the existing value
                // intact when we pass `None` (userinfo fetch failed).
                account_email.as_deref(),
            )
            .await?;
        if !updated {
            // Concurrent deletion between the initial get_connection() read
            // and this update. Surface a specific error instead of telling
            // the caller the upgrade succeeded against a row that's gone.
            return Err(AppError::NotFound(
                "connection was deleted during upgrade".into(),
            ));
        }
        (existing_id, "connection.scopes_upgraded")
    } else {
        let conn = scope
            .create_connection(overslash_db::repos::connection::CreateConnection {
                org_id,
                identity_id,
                provider_key,
                encrypted_access_token: &encrypted_access,
                encrypted_refresh_token: encrypted_refresh.as_deref(),
                token_expires_at: expires_at,
                scopes: &granted_scopes,
                account_email: account_email.as_deref(),
                byoc_credential_id: effective_byoc_id,
            })
            .await?;
        (conn.id, "connection.created")
    };

    let _ = scope
        .log_audit(AuditEntry {
            org_id,
            identity_id: Some(actor_identity_id),
            action: audit_action,
            resource_type: Some("connection"),
            resource_id: Some(connection_id),
            detail: serde_json::json!({
                "provider": provider_key,
                "account_email": account_email,
                "scopes": granted_scopes,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(serde_json::json!({
        "status": "connected",
        "connection_id": connection_id,
        "provider": provider_key,
        "account_email": account_email,
        "scopes": granted_scopes,
    })))
}

/// Return the union of `existing` and `incoming`, preserving an order that's
/// deterministic for downstream comparison (lexicographic via BTreeSet).
fn merge_scopes(existing: &[String], incoming: &[String]) -> Vec<String> {
    let mut set: BTreeSet<String> = existing.iter().cloned().collect();
    for s in incoming {
        set.insert(s.clone());
    }
    set.into_iter().collect()
}

#[derive(Serialize)]
struct ConnectionSummary {
    id: Uuid,
    provider_key: String,
    account_email: Option<String>,
    /// Scopes the provider actually granted at the last OAuth flow. The
    /// dashboard renders these as chips and compares them to a template's
    /// required scopes when deciding whether to offer the "upgrade" prompt.
    scopes: Vec<String>,
    /// Template keys of active service instances currently bound to this
    /// connection. The dashboard's new-service wizard uses this to prefer a
    /// connection that *isn't* already in use for the template being created.
    used_by_service_templates: Vec<String>,
    is_default: bool,
    created_at: String,
}

async fn list_connections(scope: UserScope) -> Result<Json<Vec<ConnectionSummary>>> {
    let rows = scope.list_my_connections().await?;
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    // Usage lookup is org-scoped; downgrade the UserScope to an OrgScope so
    // the service_instances query doesn't need a user bound.
    let usage_rows = scope.org().connection_usage_by_template(&ids).await?;
    let mut usage: HashMap<Uuid, Vec<String>> = HashMap::new();
    for (conn_id, tpl) in usage_rows {
        usage.entry(conn_id).or_default().push(tpl);
    }

    Ok(Json(
        rows.into_iter()
            .map(|r| ConnectionSummary {
                used_by_service_templates: usage.remove(&r.id).unwrap_or_default(),
                id: r.id,
                provider_key: r.provider_key,
                account_email: r.account_email,
                scopes: r.scopes,
                is_default: r.is_default,
                created_at: fmt_time(r.created_at),
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
struct UpgradeScopesRequest {
    /// Additional scopes to request on top of the connection's current set.
    /// May overlap the current set — duplicates are deduped.
    scopes: Vec<String>,
}

#[derive(Serialize)]
struct UpgradeScopesResponse {
    auth_url: String,
    state: String,
    connection_id: Uuid,
    /// The union of existing + requested scopes the provider will be asked
    /// for. Useful for the UI to show the user what consent they're about
    /// to give.
    requested_scopes: Vec<String>,
}

/// Start an incremental-scope OAuth flow for an existing connection. Returns
/// an auth URL whose state encodes the connection id — the callback will
/// update the row in place instead of minting a new one.
async fn upgrade_connection_scopes(
    State(state): State<AppState>,
    WriteAcl(acl): WriteAcl,
    Path(id): Path<Uuid>,
    Json(req): Json<UpgradeScopesRequest>,
) -> Result<Json<UpgradeScopesResponse>> {
    let caller_identity_id = acl
        .identity_id
        .ok_or_else(|| AppError::BadRequest("OAuth requires an identity-bound API key".into()))?;

    let org_scope = OrgScope::new(acl.org_id, state.db.clone());
    let existing = org_scope
        .get_connection(id)
        .await?
        .ok_or_else(|| AppError::NotFound("connection not found".into()))?;

    if existing.identity_id != caller_identity_id {
        return Err(AppError::Forbidden(
            "connection belongs to another identity".into(),
        ));
    }

    let provider =
        overslash_db::repos::oauth_provider::get_by_key(&state.db, &existing.provider_key)
            .await?
            .ok_or_else(|| {
                AppError::NotFound(format!("provider '{}' not found", existing.provider_key))
            })?;

    let enc_key = crypto::parse_hex_key(&state.config.secrets_encryption_key)?;
    // Pin the same BYOC credential the original connection used so the
    // upgrade flow runs against the same OAuth client — otherwise the
    // provider may reject the incremental request as a new client.
    let creds = client_credentials::resolve(
        &state.db,
        &enc_key,
        acl.org_id,
        Some(caller_identity_id),
        &existing.provider_key,
        None,
        existing.byoc_credential_id,
    )
    .await?;

    let redirect_uri = format!(
        "{}/v1/oauth/callback",
        state.config.public_url.trim_end_matches('/')
    );

    let byoc_segment = creds
        .byoc_credential_id
        .map_or_else(|| "_".to_string(), |id| id.to_string());

    let pkce = if provider.supports_pkce {
        Some(oauth::generate_pkce())
    } else {
        None
    };
    let verifier_segment = pkce.as_ref().map(|p| p.verifier.as_str()).unwrap_or("_");

    // Union the existing and newly-requested scopes. Google with
    // `include_granted_scopes=true` would preserve the old ones anyway, but
    // sending the full union is what makes non-Google providers work.
    let merged: Vec<String> = merge_scopes(&existing.scopes, &req.scopes);

    let oauth_state = format!(
        "{}:{}:{}:{}:{}:_:{}",
        acl.org_id, caller_identity_id, existing.provider_key, byoc_segment, verifier_segment, id
    );

    let auth_url = oauth::build_auth_url(
        &provider,
        &creds.client_id,
        &redirect_uri,
        &merged,
        &oauth_state,
        pkce.as_ref().map(|p| p.challenge.as_str()),
    );

    Ok(Json(UpgradeScopesResponse {
        auth_url,
        state: oauth_state,
        connection_id: id,
        requested_scopes: merged,
    }))
}

async fn delete_connection(
    State(state): State<AppState>,
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let auth = acl;
    // Scope delete: if identity-bound, must own the connection.
    // Org-level keys can delete any connection in the org.
    let deleted = if let Some(identity_id) = auth.identity_id {
        UserScope::new(auth.org_id, identity_id, state.db.clone())
            .delete_my_connection(id)
            .await?
    } else {
        OrgScope::new(auth.org_id, state.db.clone())
            .delete_connection(id)
            .await?
    };

    if deleted {
        let _ = OrgScope::new(auth.org_id, state.db.clone())
            .log_audit(AuditEntry {
                org_id: auth.org_id,
                identity_id: auth.identity_id,
                action: "connection.deleted",
                resource_type: Some("connection"),
                resource_id: Some(id),
                detail: serde_json::json!({}),
                description: None,
                ip_address: ip.0.as_deref(),
            })
            .await;
    }

    Ok(Json(serde_json::json!({ "deleted": deleted })))
}
