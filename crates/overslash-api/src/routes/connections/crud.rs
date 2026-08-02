//! Connection read/update/delete endpoints: list, detail, set-default,
//! keep, scope upgrade and delete (plus the shared deletion side effects).

use super::*;

#[derive(Serialize)]
pub(super) struct ConnectionSummary {
    id: Uuid,
    /// Owner identity of the connection. Connections are bound to the user
    /// identity (D22), so this is the user who owns the linked account. The
    /// dashboard resolves it to a name in the admin "all users" view.
    owner_identity_id: Uuid,
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
    /// When true, this connection is preserved from the service-deletion
    /// auto-cleanup — the dashboard renders it as a "kept" toggle.
    keep: bool,
    /// When true, the connection must be re-authorized before use (e.g. its
    /// pinned BYOC client was replaced) — the dashboard renders a warning badge.
    reauth_required: bool,
    created_at: String,
}

/// Query params for `GET /v1/connections`. Mirrors `ListServicesQuery`.
#[derive(Deserialize, Default)]
pub(super) struct ListConnectionsQuery {
    /// Admin-only: when true, list every connection in the org (all users'
    /// rows) instead of only the caller's own. Silently ignored for non-admin
    /// callers so a stale dashboard tab doesn't start 403'ing when an admin
    /// flag is revoked — same contract as the services list.
    #[serde(default)]
    include_user_level: bool,
    /// Admin-or-self: list connections owned by this specific identity instead
    /// of the caller's own. The service detail page passes the service's
    /// `owner_identity_id` so an admin viewing another user's service sees that
    /// user's bindable connections (connections are identity-scoped). Equal to
    /// the caller's own identity → self path. A non-admin caller passing a
    /// *different* identity is silently downgraded to their own list (no 403,
    /// same contract as `include_user_level`). Takes precedence over
    /// `include_user_level` when both are set.
    #[serde(default)]
    owner_identity_id: Option<Uuid>,
}

pub(super) async fn list_connections(
    scope: UserScope,
    Query(q): Query<ListConnectionsQuery>,
) -> Result<Json<Vec<ConnectionSummary>>> {
    // `include_user_level` is admin-only. Read `is_org_admin` straight off the
    // identity row (same flag-based check as the services list — `AdminAcl`
    // would instead require the `overslash` service admin grant). Non-admins
    // passing the flag fall through to the standard self-scoped listing.
    let is_org_admin = || async {
        Ok::<bool, AppError>(
            scope
                .org()
                .get_identity(scope.user_id())
                .await?
                .map(|i| i.is_org_admin)
                .unwrap_or(false),
        )
    };

    let rows = if let Some(owner) = q.owner_identity_id {
        // Owner-scoped listing. Self is always allowed; another identity
        // requires org admin, else fall through to the caller's own list.
        if owner == scope.user_id() {
            scope.list_my_connections().await?
        } else if is_org_admin().await? {
            let owner_scope = UserScope::new(scope.org_id(), owner, scope.org().db().clone());
            owner_scope.list_my_connections().await?
        } else {
            scope.list_my_connections().await?
        }
    } else if q.include_user_level && is_org_admin().await? {
        scope.org().list_all_connections().await?
    } else {
        scope.list_my_connections().await?
    };
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
                owner_identity_id: r.identity_id,
                provider_key: r.provider_key,
                account_email: r.account_email,
                scopes: r.scopes.unwrap_or_default(),
                is_default: r.is_default,
                keep: r.keep,
                reauth_required: r.reauth_required,
                created_at: fmt_time(r.created_at),
            })
            .collect(),
    ))
}

/// A service instance bound to a connection, for the detail page's "Used by"
/// list. `name` is what the dashboard links to (`/services/{name}`).
#[derive(Serialize)]
struct UsedByService {
    id: Uuid,
    name: String,
    template_key: String,
}

/// Full connection detail returned by `GET /v1/connections/{id}`. Superset of
/// `ConnectionSummary`: adds `updated_at` (so the dashboard can detect an
/// in-place reconnect by polling) and the resolved `used_by` instance list
/// (vs the summary's bare template-key array).
#[derive(Serialize)]
pub(super) struct ConnectionDetail {
    id: Uuid,
    provider_key: String,
    account_email: Option<String>,
    scopes: Vec<String>,
    is_default: bool,
    /// When true, this connection is preserved from the service-deletion
    /// auto-cleanup (see `POST /v1/connections/{id}/keep`).
    keep: bool,
    /// When true, the connection must be re-authorized before use (e.g. its
    /// pinned BYOC client was replaced). Cleared on the next successful reconnect.
    reauth_required: bool,
    created_at: String,
    updated_at: String,
    used_by: Vec<UsedByService>,
    /// What OAuth client credentials the next refresh will use. Mirrors the
    /// `client_credentials::resolve()` cascade against current state (the
    /// connection's stored BYOC may have been deleted out from under it) —
    /// a pinned BYOC for imported connections, the org/env cascade otherwise.
    credential_source: client_credentials::CredentialSource,
}

pub(super) async fn get_connection(
    scope: UserScope,
    Path(id): Path<Uuid>,
) -> Result<Json<ConnectionDetail>> {
    // Caller's own connection takes the fast path. Falling through to an
    // org-scoped lookup only for org admins lets them open another user's
    // connection from the "all users" view; everyone else gets a 404.
    let conn = match scope.get_my_connection(id).await? {
        Some(c) => c,
        None => {
            let org = scope.org();
            let is_admin = org
                .get_identity(scope.user_id())
                .await?
                .map(|i| i.is_org_admin)
                .unwrap_or(false);
            let conn = if is_admin {
                org.get_connection(id).await?
            } else {
                None
            };
            conn.ok_or_else(|| AppError::NotFound("connection not found".into()))?
        }
    };

    // Usage lookup is org-scoped; downgrade to OrgScope like `list_connections`.
    let org = scope.org();
    let used_by = org
        .connection_usage_instances(id)
        .await?
        .into_iter()
        .map(|(id, name, template_key)| UsedByService {
            id,
            name,
            template_key,
        })
        .collect();

    // Every connection refreshes via the credential cascade — a pinned BYOC
    // (imported connections, and orchestrated ones that pinned one) or the
    // org/env fallback. Describe whichever the next refresh would use.
    let credential_source = client_credentials::describe_source(
        &org,
        &conn.provider_key,
        Some(conn.identity_id),
        conn.byoc_credential_id,
    )
    .await?;

    Ok(Json(ConnectionDetail {
        id: conn.id,
        provider_key: conn.provider_key,
        account_email: conn.account_email,
        scopes: conn.scopes.unwrap_or_default(),
        is_default: conn.is_default,
        keep: conn.keep,
        reauth_required: conn.reauth_required,
        created_at: fmt_time(conn.created_at),
        updated_at: fmt_time(conn.updated_at),
        used_by,
        credential_source,
    }))
}

/// Promote a connection to be the default for its (identity, provider). Demotes
/// any sibling that held the flag. Identity-scoped: the caller must own the
/// connection — or be an org admin acting on another user's connection from the
/// "all users" view. Low-risk + idempotent — the dashboard fires it from a
/// radio / toggle with no confirmation.
pub(super) async fn set_connection_default(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let identity_id = acl.identity_id.ok_or_else(|| {
        AppError::BadRequest("set_default requires an identity-bound API key".into())
    })?;

    // The caller's own connection takes the identity-scoped path. For a
    // connection owned by another user, an org admin may still promote it —
    // the org-scoped path demotes siblings within the *owner's* identity, not
    // the admin's. Non-owner non-admins get a 404 (the row stays invisible).
    let updated = UserScope::new(acl.org_id, identity_id, state.db_pool(&ext))
        .set_my_connection_default(id)
        .await?;

    if !updated {
        let org = OrgScope::new(acl.org_id, state.db_pool(&ext));
        let is_admin = org
            .get_identity(identity_id)
            .await?
            .map(|i| i.is_org_admin)
            .unwrap_or(false);
        let promoted = is_admin && org.set_connection_default(id).await?;
        if !promoted {
            return Err(AppError::NotFound("connection not found".into()));
        }
    }

    let _ = OrgScope::new(acl.org_id, state.db_pool(&ext))
        .log_audit(AuditEntry {
            org_id: acl.org_id,
            identity_id: acl.identity_id,
            action: "connection.set_default",
            resource_type: Some("connection"),
            resource_id: Some(id),
            detail: serde_json::json!({}),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(serde_json::json!({ "is_default": true })))
}

#[derive(Deserialize)]
pub(super) struct SetKeepRequest {
    /// Whether to preserve this connection from the service-deletion auto-cleanup.
    keep: bool,
}

/// Set (or clear) the `keep` preserve flag on a connection. When `keep` is true
/// the connection survives service deletion even when no service references it.
/// Owner-or-admin gated, mirroring `set_connection_default`: the caller must own
/// the connection, or be an org admin acting on another user's connection from
/// the "all users" view; a non-owner non-admin gets a 404 (the row stays
/// invisible). Low-risk + idempotent — the dashboard fires it from a toggle.
pub(super) async fn set_connection_keep(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<SetKeepRequest>,
) -> Result<Json<serde_json::Value>> {
    let org = OrgScope::new(acl.org_id, state.db_pool(&ext));

    // Ownership gate: an identity-bound caller must own the connection or be an
    // org admin. An org-level (identity-less) key may set it on any connection
    // in the org — same authority as the org-scoped delete path.
    let allowed = if let Some(identity_id) = acl.identity_id {
        let owns = UserScope::new(acl.org_id, identity_id, state.db_pool(&ext))
            .get_my_connection(id)
            .await?
            .is_some();
        owns || org
            .get_identity(identity_id)
            .await?
            .map(|i| i.is_org_admin)
            .unwrap_or(false)
    } else {
        true
    };
    if !allowed {
        return Err(AppError::NotFound("connection not found".into()));
    }

    if !org.set_connection_keep(id, req.keep).await? {
        return Err(AppError::NotFound("connection not found".into()));
    }

    let _ = org
        .log_audit(AuditEntry {
            org_id: acl.org_id,
            identity_id: acl.identity_id,
            action: "connection.keep_updated",
            resource_type: Some("connection"),
            resource_id: Some(id),
            detail: serde_json::json!({ "keep": req.keep }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(serde_json::json!({ "keep": req.keep })))
}

#[derive(Deserialize)]
pub(super) struct UpgradeScopesRequest {
    /// Additional scopes to request on top of the connection's current set.
    /// May overlap the current set — duplicates are deduped.
    scopes: Vec<String>,
    /// Override the account pre-selected at the provider. Defaults to the
    /// connection's own `account_email`, which is what makes a reconnect
    /// return to the account the connection already belongs to. Set this
    /// only to deliberately move a connection to a different account.
    #[serde(default)]
    login_hint: Option<String>,
}

#[derive(Serialize)]
pub(super) struct UpgradeScopesResponse {
    auth_url: String,
    state: String,
    connection_id: Uuid,
    /// The union of existing + requested scopes the provider will be asked
    /// for. Useful for the UI to show the user what consent they're about
    /// to give.
    requested_scopes: Vec<String>,
}

/// Start an incremental-scope OAuth flow for an existing connection. Mints a
/// flow row whose `upgrade_connection_id` points at this connection — the
/// callback reads that off the row and updates this connection in place
/// instead of minting a new one. The flow completes through the browser gate
/// at `/v1/oauth/callback` like every other connect flow.
pub(super) async fn upgrade_connection_scopes(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpgradeScopesRequest>,
) -> Result<Json<UpgradeScopesResponse>> {
    let caller_identity_id = acl
        .identity_id
        .ok_or_else(|| AppError::BadRequest("OAuth requires an identity-bound API key".into()))?;

    let org_scope = OrgScope::new(acl.org_id, state.db_pool(&ext));
    let existing = org_scope
        .get_connection(id)
        .await?
        .ok_or_else(|| AppError::NotFound("connection not found".into()))?;

    // Connections live at the owner identity (D22/D23) and are shared by every
    // agent under it, so the caller may upgrade a connection held by itself or
    // by its own ceiling user (its `owner_id`) — but not one owned by an
    // unrelated identity. Accept a legacy agent-owned row (`== caller`) too: the
    // flow is minted at `existing.identity_id` below, so it heals either way.
    let ceiling =
        crate::services::group_ceiling::resolve_ceiling_user_id(&org_scope, caller_identity_id)
            .await?;
    if existing.identity_id != caller_identity_id && existing.identity_id != ceiling {
        return Err(AppError::Forbidden(
            "connection belongs to another identity".into(),
        ));
    }

    // Headless (white-label) orgs drive their own OAuth flow — the gated
    // upgrade flow would mint a `/connect-authorize` link their end users can't
    // open. They broaden the grant on their side and re-import the connection
    // with the wider scopes via `POST /v1/connections/import`.
    if overslash_db::repos::org::get_headless(state.db(&ext), acl.org_id)
        .await?
        .unwrap_or(false)
    {
        return Err(AppError::BadRequest(
            "this org is headless; scopes can't be upgraded through Overslash — broaden \
             the grant and re-import the connection via POST /v1/connections/import"
                .into(),
        ));
    }

    // Union existing + requested scopes. Google with `include_granted_scopes=true`
    // would preserve old ones anyway, but sending the full union is what makes
    // non-Google providers work.
    let merged: Vec<String> = merge_scopes(existing.scopes.as_deref().unwrap_or(&[]), &req.scopes);

    // Mirror what `kernel_create_connection_for_identity` will do: union in
    // the provider's identity scopes so `requested_scopes` on the response
    // matches the actual consent the user is about to grant.
    let provider =
        overslash_db::repos::oauth_provider::get_by_key(state.db(&ext), &existing.provider_key)
            .await?
            .ok_or_else(|| {
                AppError::NotFound(format!("provider '{}' not found", existing.provider_key))
            })?;
    let effective_scopes: Vec<String> = merge_scopes(&merged, &provider.default_identity_scopes);

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
    // Mint the upgrade flow at the connection's own identity — the callback
    // rejects a flow whose identity differs from the row it upgrades. Going
    // through `kernel_create_connection` would re-home to the caller's ceiling
    // (D23) and break the upgrade of a legacy agent-owned connection.
    let response = kernel_create_connection_for_identity(
        ctx,
        existing.identity_id,
        caller_identity_id,
        CreateConnectionInput {
            provider: existing.provider_key.clone(),
            scopes: merged.clone(),
            // Pin the same BYOC credential the original connection used so
            // the upgrade flow runs against the same OAuth client.
            byoc_credential_id: existing.byoc_credential_id,
            on_behalf_of: None,
            upgrade_connection_id: Some(id),
            return_url: None,
            service_instance_id: None,
            pin_service_ids: vec![],
            // `None` lets the kernel derive the hint from the connection's
            // `account_email`; an explicit value here overrides it.
            login_hint: req.login_hint,
        },
        RequestMeta {
            ip: ip.0.as_deref(),
            user_agent,
        },
    )
    .await?;

    Ok(Json(UpgradeScopesResponse {
        auth_url: response.auth_url,
        state: response.state,
        connection_id: id,
        requested_scopes: effective_scopes,
    }))
}

pub(super) async fn delete_connection(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let auth = acl;
    // Scope delete: if identity-bound, must own the connection — unless the
    // caller is an org admin, who may delete any connection in the org (the
    // "all users" view). Org-level keys can delete any connection in the org.
    let deleted = if let Some(identity_id) = auth.identity_id {
        let user_scope = UserScope::new(auth.org_id, identity_id, state.db_pool(&ext));
        if user_scope.delete_my_connection(id).await? {
            true
        } else {
            let org = user_scope.org();
            let is_admin = org
                .get_identity(identity_id)
                .await?
                .map(|i| i.is_org_admin)
                .unwrap_or(false);
            is_admin && org.delete_connection(id).await?
        }
    } else {
        OrgScope::new(auth.org_id, state.db_pool(&ext))
            .delete_connection(id)
            .await?
    };

    if deleted {
        fire_connection_deleted(
            &state,
            &ext,
            auth.org_id,
            auth.identity_id,
            ip.0.as_deref(),
            id,
        )
        .await;
    }

    Ok(Json(serde_json::json!({ "deleted": deleted })))
}

/// Fire the side effects of a connection deletion: the `connection.deleted`
/// audit log entry and the `connection.deleted` webhook. Shared by the direct
/// `DELETE /v1/connections/{id}` handler and the service-deletion cascade that
/// cleans up an orphaned connection. Call only after the row was actually
/// deleted.
pub(crate) async fn fire_connection_deleted(
    state: &AppState,
    ext: &axum::http::Extensions,
    org_id: Uuid,
    identity_id: Option<Uuid>,
    ip: Option<&str>,
    connection_id: Uuid,
) {
    let scope = OrgScope::new(org_id, state.db_pool(ext));
    let _ = scope
        .log_audit(AuditEntry {
            org_id,
            identity_id,
            action: "connection.deleted",
            resource_type: Some("connection"),
            resource_id: Some(connection_id),
            detail: serde_json::json!({}),
            description: None,
            ip_address: ip,
        })
        .await;

    // The row is already gone, so `identity_id` — the caller acting on it — is
    // the only identity left to derive an audience from. It is the owner on
    // the `DELETE /v1/connections/{id}` path and the actor on the
    // service-deletion cascade.
    let audience =
        crate::services::events::audience::for_connection(&scope, identity_id, identity_id).await;
    crate::services::events::emit(
        state.db_pool(ext),
        state.http_client.clone(),
        crate::services::events::EventDraft {
            org_id,
            event_type: crate::services::events::EventType::ConnectionDeleted,
            payload: serde_json::json!({
                "connection_id": connection_id,
                "org_id": org_id,
                "identity_id": identity_id,
            }),
            audience,
        },
    );
}
