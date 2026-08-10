//! The service-instance kernels: list, get, create, update.

use super::group_grants::validate_create_group_grants;
use super::reconcile::*;
use super::rows::*;
use super::status::*;
use super::templates::*;
use super::*;

// ── Kernels ───────────────────────────────────────────────────────────────

/// List service instances visible to the caller.
///
/// When `admin_view_all` is true, the group ceiling is bypassed and every
/// service instance in the org is returned (org-level + every owner's
/// user-level rows). The caller is responsible for asserting `is_org_admin`
/// before passing `true` — the kernel does not re-check.
pub async fn kernel_list_services(
    ctx: PlatformCallContext,
    admin_view_all: bool,
) -> Result<Vec<ServiceInstanceSummary>, AppError> {
    let scope = OrgScope::new(ctx.org_id, ctx.db.clone());
    // Service-instance kernels require an identity binding (group ceiling +
    // owner-tier filtering both need a user-tier ancestor); org-level API
    // keys go through the HTTP route, not this kernel.
    let auth_identity = ctx.identity_id.ok_or_else(|| {
        AppError::BadRequest("listing services requires an identity-bound API key".into())
    })?;
    let identity_id = Some(auth_identity);

    let rows = if admin_view_all {
        scope.list_all_service_instances_in_org().await?
    } else {
        let ceiling_user_id = group_ceiling::resolve_ceiling_user_id(&scope, auth_identity).await?;
        let visible_ids = scope.get_visible_service_ids(ceiling_user_id).await?;
        scope
            .list_available_service_instances_with_groups(
                identity_id,
                Some(ceiling_user_id),
                Some(&visible_ids),
            )
            .await?
    };

    // Bulk grants → ServiceGroupRef map.
    let service_ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let grants = scope.list_groups_for_services(&service_ids).await?;
    let mut groups_by_service: HashMap<Uuid, Vec<ServiceGroupRef>> = HashMap::new();
    for g in grants {
        groups_by_service
            .entry(g.service_instance_id)
            .or_default()
            .push(g.into());
    }

    // Bulk-load connections + templates so credentials_status is one pass.
    let connection_ids: Vec<Uuid> = rows.iter().filter_map(|r| r.connection_id).collect();
    let connections_by_id = scope.get_connections_by_ids(&connection_ids).await?;

    let mut templates: HashMap<(Option<Uuid>, String), ServiceDefinition> = HashMap::new();
    for row in &rows {
        let key = (row.owner_identity_id, row.template_key.clone());
        if templates.contains_key(&key) {
            continue;
        }
        if let Ok(tpl) = resolve_template_definition(
            &ctx.db,
            &ctx.registry,
            row.org_id,
            row.owner_identity_id,
            &row.template_key,
        )
        .await
        {
            templates.insert(key, tpl);
        }
    }

    // Mirror execution's auto-resolve for unbound OAuth instances: a row with
    // no explicit `connection_id` is served at call time by the owner
    // identity's connection for the template's provider. Resolve those here
    // (deduped by (owner, provider)) so the badge matches a real call instead
    // of falsely reading "needs setup".
    let mut conn_by_owner_provider: HashMap<(Uuid, String), Option<Vec<String>>> = HashMap::new();
    // Track looked-up pairs separately from found ones: an owner with no
    // connection for the provider must still be cached, or each of its unbound
    // instances would re-query (N+1 on the no-connection path).
    let mut looked_up: HashSet<(Uuid, String)> = HashSet::new();
    for row in &rows {
        if row.connection_id.is_some() {
            continue;
        }
        // Opted out of the default-connection fallback: execution won't resolve
        // a connection for this unbound instance, so the classifier must not
        // either — otherwise the badge would read "ok" while calls 401. Leave it
        // out of `conn_by_owner_provider` so it classifies NoConnection below.
        if !row.use_default_connection {
            continue;
        }
        let (Some(owner), Some(tpl)) = (
            row.owner_identity_id,
            templates.get(&(row.owner_identity_id, row.template_key.clone())),
        ) else {
            continue;
        };
        let Some(provider) = template_oauth_provider(tpl) else {
            continue;
        };
        let key = (owner, provider.to_string());
        if !looked_up.insert(key.clone()) {
            continue;
        }
        if let Ok(Some(conn)) = UserScope::new(ctx.org_id, owner, ctx.db.clone())
            .find_my_connection_by_provider(provider)
            .await
        {
            conn_by_owner_provider.insert(key, conn.scopes);
        }
    }

    let summaries = rows
        .into_iter()
        .map(|row| {
            let tpl_key = (row.owner_identity_id, row.template_key.clone());
            let template = templates.get(&tpl_key);
            let credentials_status = template.and_then(|tpl| {
                let scopes: ScopeKnowledge = if let Some(cid) = row.connection_id {
                    match connections_by_id.get(&cid) {
                        Some(c) => scope_knowledge(c.scopes.as_deref()),
                        None => ScopeKnowledge::NoConnection,
                    }
                } else if !row.use_default_connection {
                    // Opted out of the default fallback and nothing pinned:
                    // execution resolves no connection, so the badge is
                    // NoConnection regardless of what the owner has for the
                    // provider (a sibling instance may have populated the cache).
                    ScopeKnowledge::NoConnection
                } else if let (Some(owner), Some(provider)) =
                    (row.owner_identity_id, template_oauth_provider(tpl))
                {
                    match conn_by_owner_provider.get(&(owner, provider.to_string())) {
                        Some(opt) => scope_knowledge(opt.as_deref()),
                        None => ScopeKnowledge::NoConnection,
                    }
                } else {
                    ScopeKnowledge::NoConnection
                };
                derive_credentials_status(tpl, scopes, &row.credentials, row.secret_name.as_deref())
            });
            let groups = groups_by_service.remove(&row.id).unwrap_or_default();
            let mut summary = row_to_summary(row, groups);
            summary.credentials_status = credentials_status;
            summary
        })
        .collect();

    Ok(summaries)
}

pub async fn kernel_get_service(
    ctx: PlatformCallContext,
    input: GetServiceInput,
) -> Result<ServiceInstanceDetail, AppError> {
    let scope = OrgScope::new(ctx.org_id, ctx.db.clone());
    let auth_identity = ctx.identity_id.ok_or_else(|| {
        AppError::BadRequest("getting a service requires an identity-bound API key".into())
    })?;

    let row = if let Ok(uuid) = input.name.parse::<Uuid>() {
        scope.get_service_instance(uuid).await?
    } else {
        let ceiling = Some(group_ceiling::resolve_ceiling_user_id(&scope, auth_identity).await?);
        if input.include_inactive {
            scope
                .resolve_service_instance_by_name_any_status(
                    Some(auth_identity),
                    ceiling,
                    &input.name,
                )
                .await?
        } else {
            scope
                .resolve_service_instance_by_name(Some(auth_identity), ceiling, &input.name)
                .await?
        }
    }
    .ok_or_else(|| AppError::NotFound(format!("service '{}' not found", input.name)))?;

    let credentials_status =
        compute_credentials_status(&ctx.db, &ctx.registry, &scope, &row, row.owner_identity_id)
            .await;
    let mut detail = row_to_detail(row);
    detail.credentials_status = credentials_status;
    Ok(detail)
}

pub async fn kernel_create_service(
    ctx: PlatformCallContext,
    input: CreateServiceInput,
) -> Result<ServiceInstanceDetail, AppError> {
    // The `http` template is system-managed: every org gets exactly one
    // org-level instance at bootstrap time, and there's nothing to
    // configure on it (no auth, no host binding). Reject create attempts
    // up front so callers can't shadow the singleton with a duplicate row.
    if input.template_key == "http" {
        return Err(AppError::BadRequest(
            "the 'http' service is system-managed; instances cannot be created".into(),
        ));
    }
    let scope = OrgScope::new(ctx.org_id, ctx.db.clone());
    let auth_identity = ctx.identity_id.ok_or_else(|| {
        AppError::BadRequest("creating a service requires an identity-bound API key".into())
    })?;
    let name = input.name.as_deref().unwrap_or(&input.template_key);

    // Resolve owner identity.
    //   - on_behalf_of: validate against the caller's owner chain, use the user
    //   - user_level (default true since the kernel always runs identity-bound):
    //     owner is the caller's ceiling user. Matches the SPEC rule that agents
    //     create resources at owner-user level so all sibling agents share them,
    //     and ensures the auto-created Myself grant lands on the user whose
    //     ceiling actually gates the action call.
    //   - explicit user_level=false: org-level service, no owner. Requires admin
    //     on the overslash service since this is effectively a sharing act.
    let owner_identity_id = if input.on_behalf_of.is_some() {
        group_ceiling::resolve_owner_identity(&scope, Some(auth_identity), input.on_behalf_of)
            .await?
    } else {
        let user_level = input.user_level.unwrap_or(true);
        if user_level {
            Some(group_ceiling::resolve_ceiling_user_id(&scope, auth_identity).await?)
        } else {
            if ctx.access_level < AccessLevel::Admin {
                return Err(AppError::Forbidden(
                    "creating org-level services requires admin access".into(),
                ));
            }
            None
        }
    };

    // User-tier templates are scoped to the creator. When `on_behalf_of`
    // redirects ownership, the lookup must use the owner's identity, not the
    // caller agent's.
    let template_lookup_identity = owner_identity_id.or(Some(auth_identity));
    let (template_source, template_id) = resolve_template_source(
        &ctx.db,
        &ctx.registry,
        ctx.org_id,
        template_lookup_identity,
        &input.template_key,
    )
    .await?;

    // Curated-catalog enforcement. A global template the org has curated out is
    // hidden from discovery already; here we also block *instantiating* it
    // unless the org opts into a soft (discovery-only) catalog via
    // `allow_services_outside_catalog`. Org admins are always exempt. Only the
    // global tier is curated — org/user templates are in-catalog by definition.
    if template_source == "global" && ctx.access_level < AccessLevel::Admin {
        let curated_out = crate::services::platform_templates::is_global_curated_out(
            &ctx.db,
            ctx.org_id,
            &input.template_key,
        )
        .await?;
        if curated_out {
            let allow_outside = org_repo::get_allow_services_outside_catalog(&ctx.db, ctx.org_id)
                .await?
                .unwrap_or(false);
            if !allow_outside {
                return Err(AppError::Forbidden(format!(
                    "service '{}' is not in your organization's curated catalog",
                    input.template_key
                )));
            }
        }
    }

    if !["draft", "active", "archived"].contains(&input.status.as_str()) {
        return Err(AppError::BadRequest(format!(
            "invalid status '{}'; must be draft, active, or archived",
            input.status
        )));
    }

    // Validate the requested group grants *before* the insert. There is no
    // transaction spanning the row and its grants, so a late failure would
    // leave exactly the thing this rule exists to prevent: an org-level
    // instance with no grant, reachable by nobody.
    let group_grants = validate_create_group_grants(
        &scope,
        auth_identity,
        ctx.access_level,
        owner_identity_id,
        &input.groups,
    )
    .await?;

    // Resolve once for downstream validation + credential classification.
    let template_def = resolve_template_definition(
        &ctx.db,
        &ctx.registry,
        ctx.org_id,
        template_lookup_identity,
        &input.template_key,
    )
    .await?;

    // If the caller pinned a connection, assert it actually belongs to this
    // service's owner and targets the same OAuth provider.
    if let Some(connection_id) = input.connection_id {
        let expected_owner = owner_identity_id.ok_or_else(|| {
            AppError::BadRequest(
                "org-level services cannot pin a connection_id (connections are identity-owned)"
                    .into(),
            )
        })?;
        let connection = scope
            .get_connection(connection_id)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("connection '{connection_id}' not found")))?;
        let connection_acceptable =
            connection.identity_id == expected_owner || connection.identity_id == auth_identity;
        if !connection_acceptable {
            return Err(AppError::Forbidden(
                "connection belongs to another identity".into(),
            ));
        }

        // Covers both an HTTP `oauth` scheme and an MCP `auth.kind: oauth`
        // provider — a pinned connection on an mcp-oauth template (HubSpot,
        // Slack) must validate the same as an HTTP OAuth template.
        let expected_provider = template_oauth_provider(&template_def).map(str::to_string);
        match expected_provider {
            Some(tpl_provider) if tpl_provider != connection.provider_key => {
                return Err(AppError::BadRequest(format!(
                    "connection_provider_mismatch: template '{}' uses '{}' but connection is for '{}'",
                    input.template_key, tpl_provider, connection.provider_key
                )));
            }
            None => {
                return Err(AppError::BadRequest(format!(
                    "connection_provider_mismatch: template '{}' does not use OAuth",
                    input.template_key
                )));
            }
            _ => {}
        }
    }

    // secret_name / url validation against template requirements.
    let is_mcp = template_def.runtime == Runtime::Mcp;
    let mcp_auth = template_def.mcp.as_ref().map(|m| &m.auth);
    let is_mcp_bearer = matches!(mcp_auth, Some(McpAuth::Bearer { .. }));
    let mcp_bearer_has_default_secret = matches!(
        mcp_auth,
        Some(McpAuth::Bearer {
            secret_name: Some(_)
        })
    );
    // An org layer's `instance_defaults.url` counts as a default here, exactly
    // as it does at execution (`resolve_effective_mcp`'s `layer_url`) — that is
    // the whole point for an MCP template that ships without a URL: the org
    // names its own deployment once on the layer, and instances need no `url`.
    let mcp_has_default_url = template_def
        .mcp
        .as_ref()
        .and_then(|m| m.url.as_ref())
        .is_some()
        || template_def
            .instance_defaults
            .as_ref()
            .is_some_and(|d| d.url.is_some());

    if input.secret_name.as_deref().is_some_and(|s| !s.is_empty()) {
        // The scalar alias only makes sense for a template with an
        // instance-source secret scheme to bind (or an MCP bearer secret) —
        // org-source schemes resolve their fixed default name and are bound
        // per scheme via `credentials`.
        let has_instance_secret = template_def.auth.iter().any(|a| {
            matches!(
                a,
                ServiceAuth::Secret {
                    secret_source: SecretSource::Instance,
                    ..
                }
            )
        });
        if !has_instance_secret && !is_mcp_bearer {
            return Err(AppError::BadRequest(format!(
                "template '{}' does not use secret or MCP bearer auth",
                input.template_key
            )));
        }
    }

    // Reconcile per-scheme `credentials` with the legacy `secret_name` alias
    // into the map to store + the mirrored scalar (rolling-deploy compat).
    let (credentials, stored_secret_name) = reconcile_credentials(
        &template_def,
        input.credentials.as_ref(),
        input.secret_name.as_deref(),
    )?;

    let config = validate_instance_config(&template_def, input.config.as_ref())?;

    if is_mcp && !mcp_has_default_url {
        let provided = input.url.as_deref().is_some_and(|u| !u.is_empty());
        if !provided {
            return Err(AppError::BadRequest(format!(
                "template '{}' has no default MCP URL; provide `url` in the request",
                input.template_key
            )));
        }
    }

    // The HTTP twin of the MCP check above. A template with no host has nothing
    // for `effective_base` to fall back to, so without `url` every call would
    // fail at send time with an opaque error instead of here, where the
    // operator is actually looking. Reachable two ways: `servers: []`, and
    // since D44 a `${VAR?}` endpoint this deployment left unset (metabase).
    if !is_mcp && template_def.hosts.is_empty() {
        let has_default = template_def
            .instance_defaults
            .as_ref()
            .is_some_and(|d| d.url.is_some());
        let provided = input.url.as_deref().is_some_and(|u| !u.is_empty());
        if !has_default && !provided {
            return Err(AppError::BadRequest(format!(
                "template '{}' declares no endpoint; provide `url` in the request \
                 (or set one org-wide on a layer's `instance_defaults.url`)",
                input.template_key
            )));
        }
    }

    if is_mcp && is_mcp_bearer && !mcp_bearer_has_default_secret {
        let provided = input.secret_name.as_deref().is_some_and(|s| !s.is_empty());
        if !provided {
            return Err(AppError::BadRequest(format!(
                "template '{}' MCP bearer auth has no default secret_name; provide `secret_name` in the request",
                input.template_key
            )));
        }
    }

    if let Some(url) = input.url.as_deref()
        && !url.is_empty()
        && !url.starts_with("http://")
        && !url.starts_with("https://")
    {
        return Err(AppError::BadRequest(
            "`url` must start with http:// or https://".into(),
        ));
    }

    let create_input = CreateServiceInstance {
        org_id: ctx.org_id,
        owner_identity_id,
        name,
        template_source: &template_source,
        template_key: &input.template_key,
        template_id,
        connection_id: input.connection_id,
        secret_name: stored_secret_name.as_deref(),
        credentials: &credentials,
        config: &config,
        url: input.url.as_deref(),
        use_default_connection: input.use_default_connection.unwrap_or(true),
        status: &input.status,
    };

    let row = scope
        .create_service_instance(create_input)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e
                && db_err.constraint().is_some()
            {
                return AppError::Conflict(format!("service '{name}' already exists"));
            }
            AppError::Database(e)
        })?;

    // Auto-grant to the owner's Myself group with admin + auto_approve_reads.
    // This is what makes the service reachable by the owner under the unified
    // group-ceiling model. The Myself group is created on-demand if missing.
    if let Some(owner_id) = row.owner_identity_id {
        let label = owner_id.to_string();
        scope
            .grant_service_to_self_group(owner_id, row.id, &label)
            .await?;
    }

    // Explicit group grants. Everything here was validated above, so a failure
    // means the world moved underneath us — most plausibly a concurrent group
    // delete between validation and here. There is no transaction spanning the
    // instance row and its grants (the repos take a pool, not a `Transaction`),
    // so compensate by hand: drop the instance rather than leave the exact
    // thing this rule exists to prevent — an org-level service with no grant,
    // reachable by nobody.
    for grant in &group_grants {
        let attached = scope
            .add_group_grant(
                grant.group_id,
                row.id,
                &grant.access_level,
                grant.auto_approve_reads,
            )
            .await
            .map_err(AppError::Database)
            .and_then(|opt| {
                opt.ok_or_else(|| {
                    AppError::Conflict(format!(
                        "group '{}' disappeared while creating the service; nothing was created",
                        grant.group_id
                    ))
                })
            });
        let grant_row = match attached {
            Ok(r) => r,
            Err(e) => {
                // Cascades the grants written so far (FK ON DELETE CASCADE).
                let _ = scope.delete_service_instance(row.id).await;
                return Err(e);
            }
        };
        let _ = scope
            .log_audit(overslash_db::repos::audit::AuditEntry {
                org_id: ctx.org_id,
                identity_id: Some(auth_identity),
                action: "group_grant.created",
                resource_type: Some("group_grant"),
                resource_id: Some(grant_row.id),
                detail: serde_json::json!({
                    "group_id": grant.group_id,
                    "service_instance_id": row.id,
                    "service_name": &row.name,
                    "access_level": &grant.access_level,
                    "auto_approve_reads": grant.auto_approve_reads,
                }),
                description: None,
                ip_address: None,
            })
            .await;
    }

    let credentials_status = derive_credentials_status(
        &template_def,
        // No connection bulk-fetch here; if pinned, look it up.
        ScopeKnowledge::NoConnection,
        &row.credentials,
        row.secret_name.as_deref(),
    );
    // If a connection was pinned at create time, refine via real scopes.
    let credentials_status = if let Some(conn_id) = row.connection_id {
        scope
            .get_connection(conn_id)
            .await
            .ok()
            .flatten()
            .and_then(|conn| {
                derive_credentials_status(
                    &template_def,
                    scope_knowledge(conn.scopes.as_deref()),
                    &row.credentials,
                    row.secret_name.as_deref(),
                )
            })
            .or(credentials_status)
    } else {
        credentials_status
    };

    let row_id = row.id;
    let mut detail = row_to_detail(row);
    detail.credentials_status = credentials_status;

    // Auto-connect orchestration: when the template is OAuth-backed and the
    // caller didn't pin or opt out, kick off the OAuth flow now and surface
    // the auth_url on the response. The just-created instance's id rides on
    // the flow row so the callback binds the resulting connection back to
    // this row when the dance finishes.
    //
    // Best-effort: if the connection kernel fails (typically because the
    // org hasn't configured BYOC creds yet or the OAuth provider row is
    // missing), keep the instance and just omit the `connect` bundle. The
    // caller can configure credentials and call `POST /v1/connections`
    // later. Rolling back would break the existing "create instance now,
    // wire up credentials later" workflow.
    // Org-level services (no owner) cannot pin a connection — the manual
    // path explicitly rejects this earlier when `connection_id` is set
    // (see the `expected_owner` check above), and the OAuth callback's
    // bind would refuse anyway because connections are identity-bound.
    // Skip auto-connect for org-level services to keep the two paths
    // symmetric and avoid orchestrating a flow that can never bind.
    let want_auto_connect = input.connection_id.is_none()
        && !input.skip_connect.unwrap_or(false)
        && owner_identity_id.is_some()
        && template_oauth_provider(&template_def).is_some();
    if want_auto_connect {
        let provider = template_oauth_provider(&template_def)
            .expect("checked above")
            .to_string();
        let scopes = template_action_scopes(&template_def);
        // Owner identity: when the service is owned by someone other than
        // the calling agent (the SPEC "agents create at owner-user level"
        // rule), thread that through via `on_behalf_of` so the connection
        // lands on the same identity the service binds to.
        let on_behalf_of = match owner_identity_id {
            Some(owner) if Some(owner) != ctx.identity_id => Some(owner),
            _ => None,
        };
        let connect_ctx = crate::services::platform_caller::PlatformCallContext {
            org_id: ctx.org_id,
            identity_id: ctx.identity_id,
            access_level: ctx.access_level,
            db: ctx.db.clone(),
            registry: ctx.registry.clone(),
            config: ctx.config.clone(),
            http_client: ctx.http_client.clone(),
        };
        let connect_input = crate::services::platform_connections::CreateConnectionInput {
            provider,
            scopes,
            byoc_credential_id: None,
            on_behalf_of,
            upgrade_connection_id: None,
            return_url: input.connect_return_url.clone(),
            service_instance_id: Some(row_id),
            pin_service_ids: vec![],
            // Fresh connect as part of service setup — no account context to
            // hint with. `CreateServiceInput` can grow a pass-through later
            // if callers turn out to know the account up front.
            login_hint: None,
        };
        match crate::services::platform_connections::kernel_create_connection(
            connect_ctx,
            connect_input,
            crate::services::platform_connections::RequestMeta::default(),
        )
        .await
        {
            Ok(resp) => {
                detail.connect = Some(ConnectBundle {
                    auth_url: resp.auth_url,
                    state: resp.state,
                    flow_id: resp.flow_id,
                    expires_at: resp.expires_at,
                });
            }
            Err(err) => {
                tracing::warn!(
                    service_instance_id = %row_id,
                    template_key = %input.template_key,
                    error = %err,
                    "auto-connect failed; instance created without connection bundle"
                );
            }
        }
    }

    Ok(detail)
}

pub async fn kernel_update_service(
    ctx: PlatformCallContext,
    id: Uuid,
    input: UpdateServiceInput,
) -> Result<ServiceInstanceDetail, AppError> {
    let scope = OrgScope::new(ctx.org_id, ctx.db.clone());
    let auth_identity = ctx.identity_id.ok_or_else(|| {
        AppError::BadRequest("updating a service requires an identity-bound API key".into())
    })?;

    let existing = scope
        .get_service_instance(id)
        .await?
        .ok_or_else(|| AppError::NotFound("service instance not found".into()))?;
    if existing.is_system {
        return Err(AppError::BadRequest("cannot modify system service".into()));
    }

    // Reconcile credential changes against the template. Any of: a whole-map
    // `credentials` replace, the legacy `secret_name` alias (set or clear), or
    // both — merged and validated by `reconcile_credentials`, then stored as
    // one consistent (map, mirrored scalar) pair.
    let touches_credentials = input.credentials.is_some() || input.secret_name.is_some();
    // `config` is validated against the same template definition, so resolve
    // it once here rather than twice inside each branch.
    let template_def = if touches_credentials || input.config.is_some() {
        let template_lookup_identity = existing.owner_identity_id.or(Some(auth_identity));
        Some(
            resolve_template_definition(
                &ctx.db,
                &ctx.registry,
                ctx.org_id,
                template_lookup_identity,
                &existing.template_key,
            )
            .await?,
        )
    } else {
        None
    };

    let (new_credentials, new_secret_name) = if touches_credentials {
        let template_def = template_def
            .as_ref()
            .expect("resolved above whenever touches_credentials");

        if input
            .secret_name
            .as_ref()
            .is_some_and(|o| o.as_deref().is_some_and(|s| !s.is_empty()))
        {
            let has_instance_secret = template_def.auth.iter().any(|a| {
                matches!(
                    a,
                    ServiceAuth::Secret {
                        secret_source: SecretSource::Instance,
                        ..
                    }
                )
            });
            let is_mcp_bearer = matches!(
                template_def.mcp.as_ref().map(|m| &m.auth),
                Some(McpAuth::Bearer { .. })
            );
            if !has_instance_secret && !is_mcp_bearer {
                return Err(AppError::BadRequest(format!(
                    "template '{}' does not use secret or MCP bearer auth",
                    existing.template_key
                )));
            }
        }

        // Base map: an explicit `credentials` is a whole-map replace; a
        // scalar-only request patches the existing map so the two stay in
        // sync. On a scalar-only request the stored slot value is what the
        // alias is REPLACING, not a competing caller intent — drop it before
        // the fold or `reconcile_credentials` would flag every legacy rebind
        // as a conflict (the create path mirrors the scalar into the map, so
        // the slot is always populated). `secret_name: null` clears the slot.
        // When both fields ride one request, the slot stays so a disagreement
        // between them still 400s.
        let instance_slots = instance_slot_keys(template_def);
        let mut base = match input.credentials.as_ref() {
            Some(explicit) => explicit.clone(),
            None => existing.credentials.0.clone(),
        };
        if input.credentials.is_none()
            && input.secret_name.is_some()
            && let [sole] = instance_slots.as_slice()
        {
            base.remove(sole);
        }
        let legacy = input.secret_name.as_ref().and_then(|o| o.as_deref());
        let (map, mut scalar) = reconcile_credentials(template_def, Some(&base), legacy)?;
        // A credentials-only request on a template with no instance-source
        // slot (MCP bearer) mustn't clobber the scalar the map doesn't cover.
        if instance_slots.is_empty() && input.secret_name.is_none() {
            scalar = existing.secret_name.clone();
        }
        (Some(map), Some(scalar))
    } else {
        (None, None)
    };

    if let Some(Some(ref url)) = input.url
        && !url.is_empty()
        && !url.starts_with("http://")
        && !url.starts_with("https://")
    {
        return Err(AppError::BadRequest(
            "`url` must start with http:// or https://".into(),
        ));
    }

    // An explicit `config` is a whole-map replace (an empty map clears every
    // pinned value); absent leaves the stored map untouched.
    let new_config = match input.config.as_ref() {
        Some(explicit) => {
            let template_def = template_def
                .as_ref()
                .expect("resolved above whenever config is present");
            Some(validate_instance_config(template_def, Some(explicit))?)
        }
        None => None,
    };

    let update = UpdateServiceInstance {
        name: input.name.as_deref(),
        connection_id: input.connection_id,
        secret_name: new_secret_name.as_ref().map(|o| o.as_deref()),
        credentials: new_credentials.as_ref(),
        config: new_config.as_ref(),
        url: input.url.as_ref().map(|o| o.as_deref()),
        use_default_connection: input.use_default_connection,
    };

    let row = scope
        .update_service_instance(id, &update)
        .await?
        .ok_or_else(|| AppError::NotFound("service instance not found".into()))?;
    Ok(row_to_detail(row))
}
