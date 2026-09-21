//! `kernel_create_service`.
//!
//! One function, in a file of its own for length alone: it is several times
//! the size of its three siblings in `kernels.rs` put together, because
//! creating an instance is where every other concern in this module meets.
//! Owner resolution, template lookup and curated-catalog enforcement,
//! credential and config validation, the insert and its name-collision
//! translation, the Myself auto-grant, and the two best-effort orchestrations
//! — auto-connect and auto-setup — that hang off the row it just wrote.

use super::group_grants::validate_create_group_grants;
use super::instance_names::{instance_name_conflict, is_instance_name_collision};
use super::reconcile::*;
use super::rows::*;
use super::status::*;
use super::templates::*;
use super::*;

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

    // Every per-instance slot the auto-mint below is about to claim.
    //
    // Computed once, here, because two separate pre-insert decisions read it
    // and neither may re-derive it: the secret-name conflict check (D85) and
    // the verification gate (D86).
    let pending_slots = crate::services::service_setup::unbound_instance_slots(
        &template_def,
        &credentials,
        stored_secret_name.as_deref(),
    );

    // Pre-flight the secret names the auto-mint below is about to claim.
    //
    // The same check runs inside `mint`, but it runs there *after* the
    // instance row and its Myself grant are committed, and the auto-mint
    // block deliberately swallows mint failures so a shortener outage cannot
    // fail a create. A conflict swallowed that way would leave an orphan
    // instance and a 200 with no `setup` bundle — the caller would see a
    // half-finished service and no reason for it. Checking here means the
    // 409 arrives before anything is written.
    let force_credentials = input.force.unwrap_or(false);
    if !input.skip_credentials.unwrap_or(false)
        && !force_credentials
        && owner_identity_id.is_some()
        && !pending_slots.is_empty()
    {
        let candidates: Vec<(Option<String>, String)> = pending_slots
            .iter()
            .map(|s| (Some(s.key.clone()), s.default_secret_name.clone()))
            .collect();
        let conflicts =
            crate::services::service_setup::conflicting_secret_names(&scope, &candidates).await?;
        if !conflicts.is_empty() {
            return Err(crate::services::service_setup::conflict_error_for_create(
                conflicts,
            ));
        }
    }

    // The status the row is written in. Deliberately *not* derived from
    // `detail.setup.is_some()` further down: a mint failure is
    // warn-and-continue, so reading the bundle would let one silently un-gate
    // the instance and create it live with no credential — the exact bug this
    // gate exists to prevent.
    let create_status = super::verify::resolve_create_status(
        &input,
        &template_def,
        &pending_slots,
        owner_identity_id,
    )?;

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
        status: create_status,
    };

    let row = match scope.create_service_instance(create_input).await {
        Ok(row) => row,
        Err(e) if is_instance_name_collision(&e) => {
            return Err(instance_name_conflict(&scope, owner_identity_id, name).await);
        }
        Err(e) => return Err(AppError::Database(e)),
    };

    // Auto-grant to the owner's Myself group with admin access and
    // read-level auto-approval.
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
                // `validate_create_group_grants` normalizes and bounds this,
                // so it is always Some here; fail closed if that ever changes.
                grant.auto_approve_level.as_deref().unwrap_or("none"),
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
                    "auto_approve_level": &grant_row.auto_approve_level,
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
    // Set from the definition already in hand rather than through
    // `template_view`, which would resolve the template a second time — but
    // *both* fields, or this reproduces the drift that helper exists to
    // prevent. The dashboard assigns this response straight onto the row it
    // renders.
    detail.test_action = crate::routes::actions::probe::describe(&template_def);
    detail.icon_url = crate::services::icon_url::resolve_icon_url(
        template_def.icon.as_ref(),
        &ctx.config.public_url,
    );

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

    // Auto-setup orchestration: the secret-path twin of auto-connect above,
    // and best-effort for the same reason. A secret-backed template whose
    // per-instance slots nobody bound leaves the instance uncallable and the
    // caller — typically an agent, which must never see the value — with no
    // way to fix it except asking its user to visit the dashboard. Minting
    // the links here means one `create_service` call yields one URL to hand
    // over, exactly as the OAuth path already does.
    //
    // Org-level instances are skipped alongside auto-connect, and for the
    // same reason: `mint` needs a target identity to store the secret under,
    // and an instance nobody owns names none.
    if !input.skip_credentials.unwrap_or(false)
        && let Some(owner) = owner_identity_id
    {
        let pending = &pending_slots;
        if !pending.is_empty() {
            match crate::services::service_setup::mint_bundle(
                &ctx.db,
                &ctx.http_client,
                &ctx.config,
                ctx.org_id,
                owner,
                auth_identity,
                row_id,
                pending,
                force_credentials,
            )
            .await
            {
                Ok(bundle) => detail.setup = Some(bundle),
                Err(err) => tracing::warn!(
                    service_instance_id = %row_id,
                    template_key = %input.template_key,
                    error = %err,
                    "setup-link mint failed; instance created without setup bundle"
                ),
            }
        }
    }

    // Last, so the fleet a subscriber refetches on hearing this already has
    // the connection and the setup links this call wired up.
    super::fire_service_event(
        ctx.db.clone(),
        ctx.http_client.clone(),
        super::ServiceEvent {
            org_id: ctx.org_id,
            event_type: crate::services::events::EventType::ServiceCreated,
            service_instance_id: row_id,
            name: &detail.name,
            owner_identity_id,
            status: &detail.status,
            actor_identity_id: Some(auth_identity),
        },
    )
    .await;

    Ok(detail)
}
