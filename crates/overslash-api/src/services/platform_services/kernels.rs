//! The service-instance kernels: list, get and update.
//!
//! Create is the fourth, and lives in `create.rs` — see that file's header
//! for why it is on its own.

use super::instance_names::{instance_name_conflict, is_instance_name_collision};
use super::reconcile::*;
use super::rows::*;
use super::status::*;
use super::templates::*;
use super::*;

// ── Kernels ───────────────────────────────────────────────────────────────

/// Owner-or-admin gate for an instance addressed **by id** through the
/// platform runtime.
///
/// The REST twins call `routes::services::require_owner_or_admin` before they
/// reach these kernels; the platform/MCP bridge calls the kernel directly
/// (`services::platform_registry`), so without this the guard simply was not
/// there on that path. An agent holding `overslash:manage_services_own:*`
/// could rebind any non-system instance in the org by id — including its
/// `url`, which turns another owner's injected credential into a request
/// aimed at a host the caller picked.
///
/// The test is the **ceiling user**, not `caller_may_manage_owned`'s ancestry:
/// instances are owned by users (`kernel_create_service` resolves the owner to
/// `on_behalf_of` or the caller's ceiling user), and an agent is deliberately
/// not an ancestor of its own owner-user. Ancestry would therefore refuse an
/// agent the very instance it just created, which is the flow this whole
/// surface exists to serve. Org-level rows (`owner_identity_id IS NULL`) match
/// nobody's ceiling and so always require admin — the same conclusion
/// `caller_may_manage_owned` reaches for them.
pub(crate) async fn require_owned_by_ceiling_or_admin(
    scope: &OrgScope,
    row: &overslash_db::repos::service_instance::ServiceInstanceRow,
    auth_identity: Uuid,
    access_level: AccessLevel,
) -> Result<(), AppError> {
    if access_level >= AccessLevel::Admin {
        return Ok(());
    }
    let ceiling_user_id = group_ceiling::resolve_ceiling_user_id(scope, auth_identity).await?;
    if row.owner_identity_id == Some(ceiling_user_id) {
        return Ok(());
    }
    // `NotFound`, not `Forbidden`: a caller with no reach on this row should
    // not be able to probe which ids exist in the org.
    Err(AppError::NotFound("service instance not found".into()))
}

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
            // The bulk list already has the resolved template in hand from its
            // own one-pass fetch, so it fills the pair itself rather than
            // paying `template_view`'s per-row resolve N times over.
            let icon_url = template.and_then(|tpl| {
                crate::services::icon_url::resolve_icon_url(
                    tpl.icon.as_ref(),
                    &ctx.config.public_url,
                )
            });
            let groups = groups_by_service.remove(&row.id).unwrap_or_default();
            let test_action = template.and_then(crate::routes::actions::probe::describe);
            let mut summary = row_to_summary(row, groups);
            summary.credentials_status = credentials_status;
            summary.icon_url = icon_url;
            summary.test_action = test_action;
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
        // The by-id branch skips the ceiling-scoped resolvers the name branch
        // uses below, so it has to re-impose the same reach itself.
        let row = scope.get_service_instance(uuid).await?;
        if let Some(ref row) = row {
            require_owned_by_ceiling_or_admin(&scope, row, auth_identity, ctx.access_level).await?;
        }
        row
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
    let tv = template_view(
        &ctx.db,
        &ctx.registry,
        &row,
        row.owner_identity_id,
        &ctx.config.public_url,
    )
    .await;
    let mut detail = row_to_detail(row);
    detail.credentials_status = credentials_status;
    detail.icon_url = tv.icon_url;
    detail.test_action = tv.test_action;
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
    require_owned_by_ceiling_or_admin(&scope, &existing, auth_identity, ctx.access_level).await?;

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

    let row = match scope.update_service_instance(id, &update).await {
        Ok(row) => row,
        // Renaming onto a taken name is the same collision the create path
        // reports as a 409; without this it fell through to `AppError::Database`
        // and reached the caller as a 500 "database error".
        Err(e) if is_instance_name_collision(&e) => {
            let attempted = input.name.as_deref().unwrap_or(&existing.name);
            return Err(
                instance_name_conflict(&scope, existing.owner_identity_id, attempted).await,
            );
        }
        Err(e) => return Err(AppError::Database(e)),
    }
    .ok_or_else(|| AppError::NotFound("service instance not found".into()))?;
    // The dashboard assigns this response straight onto the row it renders, so
    // an undecorated one hides the instance's own icon and Test button until a
    // reload — the moment a user most wants to press it.
    let tv = template_view(
        &ctx.db,
        &ctx.registry,
        &row,
        row.owner_identity_id,
        &ctx.config.public_url,
    )
    .await;
    let mut detail = row_to_detail(row);
    detail.icon_url = tv.icon_url;
    detail.test_action = tv.test_action;

    // The owner *after* the update, which is also the owner before it: nothing
    // here moves an instance between owners, so one audience covers both.
    super::fire_service_event(
        ctx.db.clone(),
        ctx.http_client.clone(),
        super::ServiceEvent {
            org_id: ctx.org_id,
            event_type: crate::services::events::EventType::ServiceUpdated,
            service_instance_id: id,
            name: &detail.name,
            owner_identity_id: detail.owner_identity_id,
            status: &detail.status,
            actor_identity_id: Some(auth_identity),
        },
    )
    .await;

    Ok(detail)
}
