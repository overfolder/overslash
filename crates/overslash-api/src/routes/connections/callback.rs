//! `GET /v1/oauth/callback` — the OAuth redirect landing endpoint, its
//! JSON/redirect response shapes and the token-exchange inner routine.

use super::*;

#[derive(Deserialize)]
pub(super) struct OAuthCallbackParams {
    code: String,
    state: String,
}

/// Successful-path payload of [`oauth_callback`]. Wrapped here so the
/// outer handler can decide between returning JSON (the legacy default)
/// and a 303 redirect to a tenant-supplied `return_url`. Field shape is identical
/// to the historical `Json(serde_json::json!{...})` body so existing
/// callers keep working without an opt-in.
struct CallbackSuccess {
    connection_id: Uuid,
    provider_key: String,
    account_email: Option<String>,
    scopes: Vec<String>,
    /// When `POST /v1/services` orchestrated this flow AND the callback
    /// successfully bound the new connection to that instance, the id of
    /// that service instance. Suppressed when the bind failed (see
    /// `service_instance_bind_error`) — callers should not infer that
    /// the named instance now points at this connection.
    service_instance_id: Option<Uuid>,
    /// Every instance successfully bound to the new connection (the plural
    /// successor to `service_instance_id`). Empty when no pins were requested
    /// or all failed.
    bound_service_instance_ids: Vec<Uuid>,
    /// Coarse error code when binding the connection to the service
    /// instance failed after the OAuth dance succeeded. The connection
    /// itself is still saved — callers can retry the bind via `PUT
    /// /v1/services/{id}/manage`. Possible codes:
    /// - `service_instance_not_found`: the instance no longer exists.
    /// - `service_instance_owner_mismatch`: the bind would have crossed
    ///   identity ownership (defense against a spoofed
    ///   `service_instance_id` on the flow row).
    /// - `service_instance_bind_failed`: the DB update itself errored.
    service_instance_bind_error: Option<&'static str>,
}

/// Trusted redirect target derived from a flow row that matches the
/// callback's state and whose host is on the operator allow-list. Built
/// once up front so success and error branches share the same gating.
struct VerifiedRedirect {
    url: url::Url,
    provider_key: String,
}

pub(super) async fn oauth_callback(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    ip: ClientIp,
    Query(params): Query<OAuthCallbackParams>,
) -> Response {
    // `state` is the opaque base62 flow-row id. Every field the callback
    // needs (org/identity/provider/byoc/PKCE/actor/upgrade) is read from
    // the row — no other segments to parse, no cross-check to forge.
    let flow_id = params.state.trim();
    if flow_id.is_empty() {
        return AppError::BadRequest("missing state parameter".into()).into_response();
    }
    let flow = match oauth_connection_flow::get_by_id(state.db(&ext), flow_id).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return AppError::BadRequest("invalid state parameter".into()).into_response();
        }
        Err(e) => return AppError::from(e).into_response(),
    };

    let redirect_target = resolve_redirect_target(&state, &flow);

    // The default callback `redirect_uri`. Every flow now completes through this
    // browser callback — there is no per-flow redirect override any more.
    // Recomputed from config so it byte-matches what the authorize URL was built
    // with.
    let redirect_uri = crate::services::platform_connections::default_callback_redirect_uri(
        &state.config.public_url,
    );

    // Merge the singular `service_instance_id` (legacy / in-flight flows) with
    // the plural `pin_service_instance_ids`, preserving order and de-duping.
    let mut pin_ids = flow.pin_service_instance_ids.clone();
    if let Some(sid) = flow.service_instance_id {
        if !pin_ids.contains(&sid) {
            pin_ids.insert(0, sid);
        }
    }

    let outcome = oauth_callback_inner(
        &state,
        &ext,
        &ip,
        &params,
        flow.org_id,
        flow.identity_id,
        &flow.provider_key,
        flow.byoc_credential_id,
        flow.pkce_code_verifier.as_deref(),
        flow.actor_identity_id,
        flow.upgrade_connection_id,
        &pin_ids,
        &flow.scopes,
        &redirect_uri,
    )
    .await;

    match (outcome, redirect_target) {
        (Ok(payload), Some(redir)) => success_redirect(redir, &payload),
        (Ok(payload), None) => Json(callback_success_json(&payload)).into_response(),
        (Err(err), Some(redir)) => error_redirect(redir, &err),
        (Err(err), None) => err.into_response(),
    }
}

/// The `status:"connected"` JSON body for a completed OAuth flow — the
/// no-`return_url` branch of [`oauth_callback`].
fn callback_success_json(payload: &CallbackSuccess) -> serde_json::Value {
    let mut body = serde_json::json!({
        "status": "connected",
        "connection_id": payload.connection_id,
        "provider": payload.provider_key,
        "account_email": payload.account_email,
        "scopes": payload.scopes,
    });
    if let Some(id) = payload.service_instance_id {
        body["service_instance_id"] = serde_json::Value::String(id.to_string());
    }
    if !payload.bound_service_instance_ids.is_empty() {
        body["bound_service_instance_ids"] = serde_json::Value::Array(
            payload
                .bound_service_instance_ids
                .iter()
                .map(|id| serde_json::Value::String(id.to_string()))
                .collect(),
        );
    }
    if let Some(code) = payload.service_instance_bind_error {
        body["service_instance_bind_error"] = serde_json::Value::String(code.into());
    }
    body
}

/// Build a verified redirect target from the flow row, or `None` if any
/// gate fails:
///
/// 1. Allow-list is configured (empty list disables the feature).
/// 2. The flow row carries a `return_url`.
/// 3. The `return_url` parses and its host is on the allow-list.
///
/// Per-tenancy cross-checks that used to live here are gone: the OAuth
/// `state` parameter is now the row id itself, so there's no separate
/// state to forge against the row.
fn resolve_redirect_target(
    state: &AppState,
    flow: &oauth_connection_flow::OauthConnectionFlowRow,
) -> Option<VerifiedRedirect> {
    if state.config.connection_return_url_allowed_hosts.is_empty() {
        return None;
    }
    let raw = flow.return_url.as_deref()?;
    let url = url::Url::parse(raw).ok()?;
    let host = url.host_str()?.to_ascii_lowercase();
    if !state
        .config
        .connection_return_url_allowed_hosts
        .contains(&host)
    {
        return None;
    }
    Some(VerifiedRedirect {
        url,
        provider_key: flow.provider_key.clone(),
    })
}

/// Browser-facing success redirect to the tenant's `return_url`.
///
/// The query string carries only the *stable key* — `connection_id` — plus a
/// coarse `service_instance_id`/`service_instance_bind_error` echo kept for
/// back-compat with single-pin callers. It deliberately does **not** enumerate
/// the full `bound_service_instance_ids` set: a browser-visible query string is
/// the wrong transport for authoritative binding state (it can't losslessly
/// carry a list, and the redirect is user-controllable). The authoritative,
/// complete binding set is the DB — a partner reads it back with
/// `GET /v1/connections/{connection_id}` (its `used_by` list), keyed off the
/// `connection_id` already in this redirect. The JSON branch
/// ([`callback_success_json`]) still includes the full list as a convenience
/// for programmatic callers, who receive it in an authenticated response body
/// rather than a URL.
fn success_redirect(redir: VerifiedRedirect, payload: &CallbackSuccess) -> Response {
    let mut url = redir.url;
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("status", "success");
        pairs.append_pair("connection_id", &payload.connection_id.to_string());
        pairs.append_pair("provider", &payload.provider_key);
        if let Some(email) = payload.account_email.as_deref() {
            pairs.append_pair("account_email", email);
        }
        // Back-compat single-instance echo only. For the full set, the partner
        // queries `GET /v1/connections/{connection_id}` (see doc comment above).
        if let Some(id) = payload.service_instance_id {
            pairs.append_pair("service_instance_id", &id.to_string());
        }
        if let Some(code) = payload.service_instance_bind_error {
            pairs.append_pair("service_instance_bind_error", code);
        }
    }
    Redirect::to(url.as_str()).into_response()
}

fn error_redirect(redir: VerifiedRedirect, err: &AppError) -> Response {
    let mut url = redir.url;
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("status", "error");
        pairs.append_pair("provider", &redir.provider_key);
        pairs.append_pair("reason", redirect_reason_token(err));
    }
    Redirect::to(url.as_str()).into_response()
}

/// Coarse, allow-listed reason token for the redirect URL. The tenant
/// page renders its own copy from this token — we intentionally do NOT
/// pass the raw error text. Echoing `err.to_string()` here would surface
/// internal details (SQL errors, reqwest decode failures, etc.) that
/// `AppError::IntoResponse` deliberately scrubs from the JSON path.
fn redirect_reason_token(err: &AppError) -> &'static str {
    use axum::http::StatusCode;
    match err.status_code() {
        StatusCode::BAD_REQUEST => "bad_request",
        StatusCode::UNAUTHORIZED => "unauthorized",
        StatusCode::FORBIDDEN => "forbidden",
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::CONFLICT => "conflict",
        StatusCode::GONE => "gone",
        StatusCode::TOO_MANY_REQUESTS => "rate_limited",
        StatusCode::BAD_GATEWAY => "upstream_error",
        _ => "internal_error",
    }
}

#[allow(clippy::too_many_arguments)]
async fn oauth_callback_inner(
    state: &AppState,
    ext: &axum::http::Extensions,
    ip: &ClientIp,
    params: &OAuthCallbackParams,
    org_id: Uuid,
    identity_id: Uuid,
    provider_key: &str,
    byoc_credential_id: Option<Uuid>,
    code_verifier: Option<&str>,
    actor_identity_id: Uuid,
    upgrade_connection_id: Option<Uuid>,
    service_instance_ids: &[Uuid],
    requested_scopes: &[String],
    redirect_uri: &str,
) -> Result<CallbackSuccess> {
    let provider = overslash_db::repos::oauth_provider::get_by_key(state.db(ext), provider_key)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("provider '{provider_key}' not found")))?;

    let enc_key = state.config.keyring()?;
    let creds = client_credentials::resolve(
        state.db(ext),
        &enc_key,
        org_id,
        Some(identity_id),
        provider_key,
        None,
        byoc_credential_id,
    )
    .await?;

    let effective_byoc_id = creds.byoc_credential_id;

    // Exchange code for tokens. `redirect_uri` is passed in by the caller — it
    // is the exact value the authorize URL was built with (read off the flow
    // row), so it byte-matches what the provider saw. Recomputing it here would
    // break white-label flows whose authorize `redirect_uri` is partner-hosted.
    let tokens = oauth::exchange_code(
        &state.http_client,
        &provider,
        &creds.client_id,
        &creds.client_secret,
        &params.code,
        redirect_uri,
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
    // When the token response omits `scope` entirely (HubSpot always does),
    // RFC 6749 §5.1 means the requested set was granted verbatim — record
    // that instead of a known-empty `[]` the scope gate would then enforce.
    let granted_scopes = tokens.granted_scopes_or_requested(requested_scopes);

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

    // The OAuth callback is unauthenticated by design (the redirect_uri is
    // public), so all tenancy invariants come from the flow row that the
    // opaque `state` parameter resolved to — that row is what we issued at
    // initiate time and the unguessable id is the only thing the attacker
    // would have to forge.
    let scope = OrgScope::new(org_id, state.db_pool(ext));

    let (connection_id, event_type, effective_scopes) =
        if let Some(existing_id) = upgrade_connection_id {
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
            let merged: Vec<String> =
                merge_scopes(existing.scopes.as_deref().unwrap_or(&[]), &granted_scopes);
            let updated = scope
                .update_connection_tokens_and_scopes(
                    existing_id,
                    &encrypted_access,
                    encrypted_refresh.as_deref(),
                    expires_at,
                    Some(&merged),
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
            (
                existing_id,
                crate::services::events::EventType::ConnectionScopesUpgraded,
                merged,
            )
        } else {
            let conn = scope
                .create_connection(overslash_db::repos::connection::CreateConnection {
                    org_id,
                    identity_id,
                    provider_key,
                    encrypted_access_token: &encrypted_access,
                    encrypted_refresh_token: encrypted_refresh.as_deref(),
                    token_expires_at: expires_at,
                    // Orchestrated flows always know the granted set (echoed
                    // by the token response, or the requested set when the
                    // provider omitted `scope`) — record it, never NULL.
                    scopes: Some(&granted_scopes),
                    account_email: account_email.as_deref(),
                    byoc_credential_id: effective_byoc_id,
                })
                .await?;
            (
                conn.id,
                crate::services::events::EventType::ConnectionCreated,
                granted_scopes.clone(),
            )
        };

    let _ = scope
        .log_audit(AuditEntry {
            org_id,
            identity_id: Some(actor_identity_id),
            action: event_type.as_str(),
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

    {
        // For upgrades, `effective_scopes` is the merged scope set (the
        // connection's full current scopes), not just the delta granted in
        // this OAuth flow. Subscribers want the resulting state, not the diff.
        let payload = serde_json::json!({
            "connection_id": connection_id,
            "provider": provider_key,
            "account_email": account_email,
            "scopes": effective_scopes,
            "identity_id": identity_id,
        });
        let audience = crate::services::events::audience::for_connection(
            &scope,
            Some(identity_id),
            Some(actor_identity_id),
        )
        .await;
        crate::services::events::emit(
            state.db_pool(ext),
            state.http_client.clone(),
            crate::services::events::EventDraft {
                org_id,
                event_type,
                payload,
                audience,
            },
        );
    }

    // Best-effort bind: if `POST /v1/services` orchestrated this flow, the
    // service instance already exists with `connection_id = NULL`. Update
    // it now so the instance is usable immediately. On failure we keep the
    // connection (the OAuth tokens are valuable) and surface a coarse
    // error code; callers can retry via `PUT /v1/services/{id}/manage`.
    //
    // Ownership gate: the `service_instance_id` rides on the flow row,
    // which an MCP caller can pass directly via
    // `CreateConnectionInput.service_instance_id`. Without this check, an
    // attacker in the same org could spoof another user's instance id and
    // hijack it onto their own new connection. We require the instance's
    // `owner_identity_id` to match the flow's `identity_id` (the
    // connection owner). Org-level instances (owner_identity_id = NULL)
    // are also rejected here — connections are identity-bound and the
    // create-time `kernel_create_service` validation already forbids
    // pinning a connection to an org-level service.
    //
    // Best-effort by design (unlike the fully-atomic `/v1/connections/import`
    // path): the OAuth token exchange already succeeded and the connection is
    // valuable, so a bind failure must NOT discard it. We bind each id
    // independently, keep the connection regardless, and surface the first
    // failing id's coarse code — callers retry via `PUT /v1/services/{id}/manage`.
    let scope = OrgScope::new(org_id, state.db_pool(ext));
    let mut service_instance_bind_error: Option<&'static str> = None;
    let mut bound_service_instance_ids: Vec<Uuid> = Vec::new();
    for &svc_id in service_instance_ids {
        // Once one bind has failed, stop attempting the rest — the caller must
        // retry the whole set anyway, and partial binds are already recorded.
        if service_instance_bind_error.is_some() {
            break;
        }
        match scope.get_service_instance(svc_id).await {
            Ok(None) => {
                service_instance_bind_error = Some("service_instance_not_found");
            }
            Ok(Some(instance)) if instance.owner_identity_id != Some(identity_id) => {
                service_instance_bind_error = Some("service_instance_owner_mismatch");
            }
            Ok(Some(_)) => {
                let bind_input = overslash_db::repos::service_instance::UpdateServiceInstance {
                    name: None,
                    connection_id: Some(Some(connection_id)),
                    secret_name: None,
                    credentials: None,
                    config: None,
                    url: None,
                    use_default_connection: None,
                };
                match scope.update_service_instance(svc_id, &bind_input).await {
                    Ok(Some(_)) => bound_service_instance_ids.push(svc_id),
                    Ok(None) => {
                        // Concurrent delete in the gap between the
                        // ownership check above and the UPDATE.
                        service_instance_bind_error = Some("service_instance_not_found");
                    }
                    Err(_) => {
                        service_instance_bind_error = Some("service_instance_bind_failed");
                    }
                }
            }
            Err(_) => {
                service_instance_bind_error = Some("service_instance_bind_failed");
            }
        }
    }

    Ok(CallbackSuccess {
        connection_id,
        provider_key: provider_key.to_string(),
        account_email,
        scopes: granted_scopes,
        // Back-compat: surface the first bound id in the singular field the
        // JSON/redirect shapes have always carried.
        service_instance_id: bound_service_instance_ids.first().copied(),
        bound_service_instance_ids,
        service_instance_bind_error,
    })
}
