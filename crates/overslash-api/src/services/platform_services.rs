//! Platform kernels for service-instance CRUD.
//!
//! These mirror `platform_templates.rs`: pure async functions that take a
//! [`PlatformCallContext`] plus typed inputs and return a typed response.
//! Both the REST handlers in `routes/services.rs` and the MCP platform
//! dispatcher (via `platform_registry`) call into the same kernel — this
//! keeps the auto-add-to-Myself behavior, owner resolution, template
//! validation, and credential-status derivation in one place.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_core::permissions::AccessLevel;
use overslash_core::types::{
    McpAuth, Runtime, SecretSource, ServiceAction, ServiceAuth, ServiceDefinition,
};
use overslash_db::repos::group::ServiceGroupRow;
use overslash_db::repos::org as org_repo;
use overslash_db::repos::service_instance::{
    ConfigMap, CreateServiceInstance, CredentialsMap, ServiceInstanceRow, UpdateServiceInstance,
};
use overslash_db::repos::service_template;
use overslash_db::scopes::{OrgScope, UserScope};

use super::group_ceiling;
use super::platform_caller::PlatformCallContext;
use crate::error::AppError;
use crate::routes::util::fmt_time;

// ── Request types ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
pub struct CreateServiceInput {
    pub template_key: String,
    pub name: Option<String>,
    pub connection_id: Option<Uuid>,
    /// Legacy scalar alias for the template's sole instance-source secret
    /// scheme (or the MCP bearer secret). Rejected when the template declares
    /// several instance-source schemes — bind those via `credentials`.
    pub secret_name: Option<String>,
    /// Per-scheme secret bindings: securityScheme key → secret NAME in the
    /// org vault. Keys must match the template's secret scheme keys.
    #[serde(default)]
    pub credentials: Option<CredentialsMap>,
    /// Per-instance non-secret param values: param name → value. Keys must
    /// name a template param marked `x-overslash-instance-config`.
    #[serde(default)]
    pub config: Option<ConfigMap>,
    pub url: Option<String>,
    #[serde(default = "default_status")]
    pub status: String,
    pub user_level: Option<bool>,
    #[serde(default)]
    pub on_behalf_of: Option<Uuid>,
    /// Suppress the default auto-connect behavior for OAuth-backed
    /// templates. With this `true` the kernel creates the instance with
    /// `connection_id = NULL` and never initiates an OAuth flow — the
    /// caller is expected to pin a connection later via `PUT
    /// /v1/services/{id}/manage`. Ignored when `connection_id` is already
    /// pinned or when the template is not OAuth-backed.
    #[serde(default)]
    pub skip_connect: Option<bool>,
    /// When `false`, this instance must never fall back to the identity's
    /// default connection for the provider at execution time — it requires an
    /// explicit `connection_id`. Defaults to `true` (legacy fallback). White-
    /// label callers that mint a dedicated connection per service set this
    /// `false` and pin the connection via `pin_service_ids` on connection
    /// creation. See `service_instances.use_default_connection` (migration 090).
    #[serde(default)]
    pub use_default_connection: Option<bool>,
    /// Tenant-supplied URL the OAuth callback redirects back to once the
    /// dance finishes. Only consulted when the kernel auto-initiates a
    /// flow (OAuth template + no pinned connection + not opted out). See
    /// [`crate::services::platform_connections::CreateConnectionInput::return_url`]
    /// for the validation contract.
    #[serde(default)]
    pub connect_return_url: Option<String>,
}

fn default_status() -> String {
    "active".into()
}

#[derive(Debug, Deserialize, Default)]
pub struct UpdateServiceInput {
    pub name: Option<String>,
    pub connection_id: Option<Option<Uuid>>,
    /// Legacy scalar alias for the template's sole instance-source secret
    /// scheme (or the MCP bearer secret). Rejected when the template declares
    /// several instance-source schemes — bind those via `credentials`.
    pub secret_name: Option<Option<String>>,
    /// Per-scheme secret bindings: securityScheme key → secret NAME in the
    /// org vault. `Some` = whole-map replace (an empty map clears every
    /// binding); absent = leave unchanged. Keys must match the template's
    /// secret scheme keys.
    #[serde(default)]
    pub credentials: Option<CredentialsMap>,
    /// Per-instance non-secret param values. `Some` = whole-map replace (an
    /// empty map clears every value); absent = leave unchanged. Keys must name
    /// a template param marked `x-overslash-instance-config`.
    #[serde(default)]
    pub config: Option<ConfigMap>,
    pub url: Option<Option<String>>,
    /// `Some` = update the flag; `None` = leave unchanged.
    pub use_default_connection: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
pub struct GetServiceInput {
    pub name: String,
    #[serde(default)]
    pub include_inactive: bool,
}

// ── Response types ────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ServiceInstanceSummary {
    pub id: Uuid,
    pub name: String,
    pub template_source: String,
    pub template_key: String,
    pub status: String,
    pub is_system: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_identity_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_name: Option<String>,
    /// Per-scheme secret bindings: securityScheme key → secret NAME in the
    /// org vault. Names only — secret values never leave the vault.
    #[serde(skip_serializing_if = "CredentialsMap::is_empty")]
    pub credentials: CredentialsMap,
    /// Per-instance non-secret param values. Plain values, not vault
    /// references — see `service_instances.config`.
    #[serde(skip_serializing_if = "ConfigMap::is_empty")]
    pub config: ConfigMap,
    /// Per-instance MCP server URL override. Overrides the template's `mcp.url`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// When `false`, an unbound instance won't fall back to the default
    /// connection. See `service_instances.use_default_connection`.
    pub use_default_connection: bool,
    #[serde(default)]
    pub groups: Vec<ServiceGroupRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials_status: Option<CredentialsStatus>,
}

#[derive(Serialize, Clone)]
pub struct ServiceGroupRef {
    pub grant_id: Uuid,
    pub group_id: Uuid,
    pub group_name: String,
    /// `'everyone'`, `'admins'`, `'self'` for system groups; absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_kind: Option<String>,
    pub access_level: String,
    pub auto_approve_reads: bool,
}

impl From<ServiceGroupRow> for ServiceGroupRef {
    fn from(r: ServiceGroupRow) -> Self {
        Self {
            grant_id: r.grant_id,
            group_id: r.group_id,
            group_name: r.group_name,
            system_kind: r.system_kind,
            access_level: r.access_level,
            auto_approve_reads: r.auto_approve_reads,
        }
    }
}

#[derive(Serialize)]
pub struct ServiceInstanceDetail {
    pub id: Uuid,
    pub org_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_identity_id: Option<Uuid>,
    pub name: String,
    pub template_source: String,
    pub template_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_name: Option<String>,
    /// Per-scheme secret bindings: securityScheme key → secret NAME in the
    /// org vault. Names only — secret values never leave the vault.
    #[serde(skip_serializing_if = "CredentialsMap::is_empty")]
    pub credentials: CredentialsMap,
    /// Per-instance non-secret param values. Plain values, not vault
    /// references — see `service_instances.config`.
    #[serde(skip_serializing_if = "ConfigMap::is_empty")]
    pub config: ConfigMap,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// When `false`, an unbound instance won't fall back to the default
    /// connection. See `service_instances.use_default_connection`.
    pub use_default_connection: bool,
    pub status: String,
    pub is_system: bool,
    pub created_at: String,
    pub updated_at: String,
    /// When this instance's MCP tools were last resynced (RFC3339). Absent
    /// until the first `POST /v1/services/{id}/mcp/resync`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovered_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials_status: Option<CredentialsStatus>,
    /// Present on the response to `POST /v1/services` when the kernel
    /// auto-initiated an OAuth flow as part of setting up the instance.
    /// The caller hands `auth_url` to the user and the OAuth callback
    /// will write `connection_id` back onto this row when the dance
    /// finishes. Omitted on every other code path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect: Option<ConnectBundle>,
}

/// OAuth bootstrap bundle returned alongside a freshly-created service
/// instance. Callers hand the gated `auth_url` to the user; the raw upstream
/// provider URL is never surfaced.
#[derive(Serialize, Debug)]
pub struct ConnectBundle {
    pub auth_url: String,
    pub state: String,
    pub flow_id: String,
    pub expires_at: time::OffsetDateTime,
}

/// Derived credential-health state for a service instance.
///
/// - `NeedsAuthentication` — service has no connection (and the template
///   declares an OAuth auth scheme). The agent must run the OAuth dance
///   before any call will succeed. This is the freshly-instantiated state
///   when an agent creates a service from a template via `create_service`.
/// - `Ok` — at least one action is fully covered by the connection's scopes.
/// - `PartiallyDegraded` — some actions covered, some not. Calls outside the
///   covered set 403 with `missing_scopes`.
/// - `NeedsReconnect` — every scope-bearing action is uncovered. The
///   connection is bound but useless for this service.
#[derive(Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialsStatus {
    NeedsAuthentication,
    Ok,
    PartiallyDegraded,
    NeedsReconnect,
}

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
        let curated_out = super::platform_templates::is_global_curated_out(
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

    if is_mcp && is_mcp_bearer && !mcp_bearer_has_default_secret {
        let provided = input.secret_name.as_deref().is_some_and(|s| !s.is_empty());
        if !provided {
            return Err(AppError::BadRequest(format!(
                "template '{}' MCP bearer auth has no default secret_name; provide `secret_name` in the request",
                input.template_key
            )));
        }
    }

    if let Some(url) = input.url.as_deref() {
        if !url.is_empty() && !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(AppError::BadRequest(
                "`url` must start with http:// or https://".into(),
            ));
        }
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
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.constraint().is_some() {
                    return AppError::Conflict(format!("service '{name}' already exists"));
                }
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
        if input.credentials.is_none() && input.secret_name.is_some() {
            if let [sole] = instance_slots.as_slice() {
                base.remove(sole);
            }
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

    if let Some(Some(ref url)) = input.url {
        if !url.is_empty() && !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(AppError::BadRequest(
                "`url` must start with http:// or https://".into(),
            ));
        }
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

// ── Helpers ───────────────────────────────────────────────────────────────

/// The template's credential slot keys whose fallback is the instance's legacy
/// scalar `secret_name` (i.e. `source: instance`). Empty keys
/// (programmatically-built templates) are skipped — they can't key a binding.
fn instance_slot_keys(template: &ServiceDefinition) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for slot in template.all_slots() {
        if slot.source == SecretSource::Instance && !slot.key.is_empty() && !out.contains(&slot.key)
        {
            out.push(slot.key);
        }
    }
    out
}

/// Every credential slot key the template declares, in `auth` order.
fn all_slot_keys(template: &ServiceDefinition) -> Vec<String> {
    template
        .all_slots()
        .into_iter()
        .map(|s| s.key)
        .filter(|k| !k.is_empty())
        .collect()
}

/// Validate a per-instance `config` map against the template.
///
/// The rules themselves live in `overslash_core::instance_config`, shared with
/// the layer write path — an org layer supplying `instance_defaults.config`
/// must accept exactly the same keys an instance may pin. This wrapper only
/// renders the outcome as an `AppError`.
fn validate_instance_config(
    template: &ServiceDefinition,
    explicit: Option<&ConfigMap>,
) -> Result<ConfigMap, AppError> {
    let Some(explicit) = explicit else {
        return Ok(ConfigMap::new());
    };
    overslash_core::instance_config::validate_config(template, explicit)
        .map_err(|e| AppError::BadRequest(e.message(&template.key)))
}

/// Reconcile explicit per-slot `credentials` with the legacy scalar
/// `secret_name` alias into the map to store, validating both against the
/// template.
///
/// - Every explicit key must name one of the template's credential slots, and
///   every value must be non-empty (whole-map replace: omit a key to unbind).
/// - A non-empty `secret_name` folds into the sole instance-source slot.
///   With several instance-source slots the alias is ambiguous → 400. With
///   none (MCP bearer) it stays scalar-only and the map is untouched.
/// - Both provided with different values for the same slot → 400.
///
/// Returns `(credentials_to_store, secret_name_to_store)`. The scalar is kept
/// mirrored (dual-write) so binaries from the previous release keep resolving
/// during a rolling deploy; it is dropped once the column goes.
fn reconcile_credentials(
    template: &ServiceDefinition,
    explicit: Option<&CredentialsMap>,
    legacy_secret_name: Option<&str>,
) -> Result<(CredentialsMap, Option<String>), AppError> {
    let slot_keys = all_slot_keys(template);
    let instance_slots = instance_slot_keys(template);

    let mut map = CredentialsMap::new();
    if let Some(explicit) = explicit {
        for (key, value) in explicit {
            if !slot_keys.contains(key) {
                // A key that is now a config var is the shape of a template
                // that stopped vaulting a value (the `email` mailbox username).
                // Saying only "unknown credential" would leave the operator
                // hunting; this is the one message they get.
                if template.config.iter().any(|c| &c.key == key) {
                    return Err(AppError::BadRequest(format!(
                        "'{key}' is no longer a credential on template '{}'; it is a \
                         plain config value — move it from `credentials` to `config`",
                        template.key
                    )));
                }
                return Err(AppError::BadRequest(format!(
                    "unknown credential '{key}'; template '{}' declares: {}",
                    template.key,
                    if slot_keys.is_empty() {
                        "none".to_string()
                    } else {
                        slot_keys.join(", ")
                    }
                )));
            }
            if value.trim().is_empty() {
                return Err(AppError::BadRequest(format!(
                    "credential '{key}' must name a secret; omit the key to unbind it"
                )));
            }
            map.insert(key.clone(), value.clone());
        }
    }

    let legacy = legacy_secret_name.filter(|s| !s.is_empty());
    if let Some(legacy) = legacy {
        match instance_slots.as_slice() {
            [] => {} // MCP bearer / legacy scalar-only template: stays scalar.
            [sole] => match map.get(sole) {
                Some(bound) if bound != legacy => {
                    return Err(AppError::BadRequest(format!(
                        "secret_name '{legacy}' conflicts with credentials['{sole}'] = '{bound}'; \
                         pass one or the other"
                    )));
                }
                _ => {
                    map.insert(sole.clone(), legacy.to_string());
                }
            },
            _ => {
                return Err(AppError::BadRequest(format!(
                    "template '{}' declares several instance credentials ({}); \
                     bind them via `credentials` instead of `secret_name`",
                    template.key,
                    instance_slots.join(", ")
                )));
            }
        }
    }

    // Dual-write the scalar: mirror the sole instance-source slot's binding
    // (whatever provided it), else preserve a scalar-only legacy value.
    let secret_name = match instance_slots.as_slice() {
        [sole] => map.get(sole).cloned(),
        _ => legacy.map(str::to_string),
    };
    Ok((map, secret_name))
}

pub fn row_to_summary(
    row: ServiceInstanceRow,
    groups: Vec<ServiceGroupRef>,
) -> ServiceInstanceSummary {
    ServiceInstanceSummary {
        id: row.id,
        name: row.name,
        template_source: row.template_source,
        template_key: row.template_key,
        status: row.status,
        is_system: row.is_system,
        owner_identity_id: row.owner_identity_id,
        connection_id: row.connection_id,
        secret_name: row.secret_name,
        credentials: row.credentials.0,
        config: row.config.0,
        url: row.url,
        use_default_connection: row.use_default_connection,
        groups,
        credentials_status: None,
    }
}

pub fn row_to_detail(row: ServiceInstanceRow) -> ServiceInstanceDetail {
    ServiceInstanceDetail {
        id: row.id,
        org_id: row.org_id,
        owner_identity_id: row.owner_identity_id,
        name: row.name,
        template_source: row.template_source,
        template_key: row.template_key,
        template_id: row.template_id,
        connection_id: row.connection_id,
        secret_name: row.secret_name,
        credentials: row.credentials.0,
        config: row.config.0,
        url: row.url,
        use_default_connection: row.use_default_connection,
        status: row.status,
        is_system: row.is_system,
        created_at: fmt_time(row.created_at),
        updated_at: fmt_time(row.updated_at),
        discovered_at: row.discovered_at.map(fmt_time),
        credentials_status: None,
        connect: None,
    }
}

/// Pull the OAuth provider declared on a template's auth schemes, if any.
/// Returns `None` for templates that don't declare an OAuth auth (secret-based
/// only, MCP bearer only, no auth, etc.) — in which case the auto-connect
/// orchestration in `kernel_create_service` is a no-op.
pub(crate) fn template_oauth_provider(def: &ServiceDefinition) -> Option<&str> {
    // HTTP-runtime OAuth scheme first…
    if let Some(provider) = def.auth.iter().find_map(|a| match a {
        ServiceAuth::OAuth { provider, .. } => Some(provider.as_str()),
        _ => None,
    }) {
        return Some(provider);
    }
    // …then an MCP-runtime `auth.kind: oauth` provider — both resolve through
    // the same connection machinery, so auto-connect orchestration, pinned-
    // connection validation, and credentials-status surfacing treat them
    // identically. Covers HubSpot + Slack (remote OAuth MCP servers).
    match def.mcp.as_ref().map(|m| &m.auth) {
        Some(McpAuth::OAuth { provider, .. }) => Some(provider.as_str()),
        _ => None,
    }
}

/// Union the scopes the auto-connect flow should request into a sorted, deduped
/// list. For HTTP-runtime templates this is every action's `required_scopes`.
/// For MCP-runtime `auth.kind: oauth` templates the scopes live at the service
/// level in `McpAuth::OAuth { scopes }` (MCP tools carry no per-action scopes),
/// so include those too — otherwise the connect flow requests an empty scope
/// set and the minted token lacks the permissions every tool needs.
fn template_action_scopes(def: &ServiceDefinition) -> Vec<String> {
    let mut scopes: std::collections::BTreeSet<String> = def
        .actions
        .values()
        .flat_map(|a| a.required_scopes.iter().cloned())
        .collect();
    if let Some(McpAuth::OAuth {
        scopes: mcp_scopes, ..
    }) = def.mcp.as_ref().map(|m| &m.auth)
    {
        scopes.extend(mcp_scopes.iter().cloned());
    }
    scopes.into_iter().collect()
}

/// Resolve the [`ServiceDefinition`] for a template key through the
/// layered-template fold (user/org/global tiers, derived layers folded over
/// their base). Thin wrapper over the shared resolver.
pub async fn resolve_template_definition(
    db: &sqlx::PgPool,
    registry: &overslash_core::registry::ServiceRegistry,
    org_id: Uuid,
    identity_id: Option<Uuid>,
    key: &str,
) -> Result<ServiceDefinition, AppError> {
    crate::services::template_resolve::resolve_definition(db, registry, org_id, identity_id, key)
        .await
}

/// Determine the template source tier and optional DB template id for a given key.
pub async fn resolve_template_source(
    db: &sqlx::PgPool,
    registry: &overslash_core::registry::ServiceRegistry,
    org_id: Uuid,
    identity_id: Option<Uuid>,
    key: &str,
) -> Result<(String, Option<Uuid>), AppError> {
    if let Some(identity_id) = identity_id {
        if let Some(t) = service_template::get_by_key(db, org_id, Some(identity_id), key).await? {
            return Ok(("user".into(), Some(t.id)));
        }
    }
    if let Some(t) = service_template::get_by_key(db, org_id, None, key).await? {
        return Ok(("org".into(), Some(t.id)));
    }
    if registry.get(key).is_some() {
        return Ok(("global".into(), None));
    }
    Err(AppError::NotFound(format!(
        "template '{key}' not found in any tier"
    )))
}

/// Compute credential-health for a service instance against its template.
///
/// Loads the connection (if any) and template, then defers to
/// [`derive_credentials_status`] for the pure classification logic.
pub async fn compute_credentials_status(
    db: &sqlx::PgPool,
    registry: &overslash_core::registry::ServiceRegistry,
    scope: &OrgScope,
    row: &ServiceInstanceRow,
    template_owner: Option<Uuid>,
) -> Option<CredentialsStatus> {
    let template =
        resolve_template_definition(db, registry, row.org_id, template_owner, &row.template_key)
            .await
            .ok()?;
    let conn_scopes = resolve_effective_scopes(db, scope, &template, row).await;
    let scopes = match &conn_scopes {
        None => ScopeKnowledge::NoConnection,
        Some(opt) => scope_knowledge(opt.as_deref()),
    };
    derive_credentials_status(
        &template,
        scopes,
        &row.credentials,
        row.secret_name.as_deref(),
    )
}

/// Granted scopes of the connection the *execution* path would actually use.
///
/// Mirrors `resolve_service_auth` / `check_required_scopes` at call time: an
/// explicit `connection_id` binding wins (resolved org-scoped, so agent-owned
/// connections still classify — see PR #321); otherwise an OAuth template
/// auto-resolves the *owner identity's* connection for its provider. Without
/// this, an instance that was never explicitly bound but works via provider
/// auto-resolve (e.g. a `google_calendar` instance with `connection_id = NULL`
/// when the owner has a Google connection) was misreported as needing setup —
/// both on the dashboard badge and on the agent-facing `service_status`.
/// Returns `None` when no connection backs the instance, `Some(None)` when one
/// does but its scopes are unknown, and `Some(Some(scopes))` for a known set.
pub(crate) async fn resolve_effective_scopes(
    db: &sqlx::PgPool,
    scope: &OrgScope,
    template: &ServiceDefinition,
    row: &ServiceInstanceRow,
) -> Option<Option<Vec<String>>> {
    if let Some(conn_id) = row.connection_id {
        return scope
            .get_connection(conn_id)
            .await
            .ok()
            .flatten()
            .map(|c| c.scopes);
    }
    // Opted out of the default-connection fallback: execution resolves no
    // connection, so the classifier reports NoConnection (mirrors
    // `resolve_instance_auth`). Without this the badge would read "ok" while
    // calls 401.
    if !row.use_default_connection {
        return None;
    }
    let provider = template_oauth_provider(template)?;
    let owner = row.owner_identity_id?;
    UserScope::new(row.org_id, owner, db.clone())
        .find_my_connection_by_provider(provider)
        .await
        .ok()
        .flatten()
        .map(|c| c.scopes)
}

/// What is known about a connection's granted scopes when classifying a
/// service instance's credential health. Distinguishes "no connection at all"
/// from "a connection exists but its granted scopes are unknown" (an imported
/// token vaulted without declaring scopes) — the latter gets the benefit of the
/// doubt, mirroring the call-time scope-gate.
#[derive(Debug, Clone, Copy)]
pub enum ScopeKnowledge<'a> {
    /// No connection is bound and none auto-resolves.
    NoConnection,
    /// A connection exists but its granted scopes weren't recorded.
    Unknown,
    /// The known granted scope set (possibly empty).
    Known(&'a [String]),
}

/// Map a *present* connection's optional scopes to [`ScopeKnowledge`]. Call
/// sites that reach here have already established the connection exists, so
/// `None` scopes means "recorded as unknown", not "no connection".
fn scope_knowledge(scopes: Option<&[String]>) -> ScopeKnowledge<'_> {
    match scopes {
        Some(s) => ScopeKnowledge::Known(s),
        None => ScopeKnowledge::Unknown,
    }
}

/// Per-action scope coverage, surfaced at discovery time so an agent can see
/// an action is uncovered *before* calling it (instead of after a raw upstream
/// 403). Mirrors the call-time gate in `routes/actions/auth.rs`.
#[derive(Serialize, Debug, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum ScopeCoverage {
    /// Every required scope is granted (or the action declares none).
    Covered,
    /// At least one required scope is missing — calling it will 403.
    NeedsReconnect,
    /// A connection exists but its granted scopes weren't recorded — same
    /// benefit-of-the-doubt the call-time gate gives, surfaced honestly.
    Unknown,
}

/// Coverage of a single action's `required_scopes` against the connection's
/// scope knowledge, plus the missing-scope delta (empty unless
/// [`ScopeCoverage::NeedsReconnect`]). Shared by [`derive_credentials_status`]
/// and the discovery endpoints (`search`, `list_service_actions`) so the
/// classification stays identical at discovery time and call time.
pub fn action_scope_coverage(
    action: &ServiceAction,
    scopes: ScopeKnowledge<'_>,
) -> (ScopeCoverage, Vec<String>) {
    if action.required_scopes.is_empty() {
        return (ScopeCoverage::Covered, Vec::new());
    }
    let granted = match scopes {
        ScopeKnowledge::Known(list) => list,
        // No bound connection, or one whose scopes weren't recorded: we can't
        // prove a gap, so don't cry wolf — report Unknown.
        ScopeKnowledge::NoConnection | ScopeKnowledge::Unknown => {
            return (ScopeCoverage::Unknown, Vec::new());
        }
    };
    let granted_set: HashSet<&str> = granted.iter().map(String::as_str).collect();
    let missing: Vec<String> = action
        .required_scopes
        .iter()
        .filter(|s| !granted_set.contains(s.as_str()))
        .cloned()
        .collect();
    if missing.is_empty() {
        (ScopeCoverage::Covered, Vec::new())
    } else {
        (ScopeCoverage::NeedsReconnect, missing)
    }
}

/// Pure classifier: takes a template + scope knowledge + the instance's
/// credential bindings and returns a [`CredentialsStatus`] or `None` when the
/// template has no auth scheme to evaluate.
pub fn derive_credentials_status(
    template: &ServiceDefinition,
    scopes: ScopeKnowledge<'_>,
    credentials: &CredentialsMap,
    secret_name: Option<&str>,
) -> Option<CredentialsStatus> {
    // An OAuth MCP server (mcp.auth kind: oauth) needs the same connection
    // dance as an HTTP OAuth template, so fold it into `has_oauth`.
    let mcp_oauth = matches!(
        template.mcp.as_ref().map(|m| &m.auth),
        Some(McpAuth::OAuth { .. })
    );
    let has_oauth = mcp_oauth
        || template
            .auth
            .iter()
            .any(|a| matches!(a, ServiceAuth::OAuth { .. }));
    let has_secret = template
        .auth
        .iter()
        .any(|a| matches!(a, ServiceAuth::Secret { .. }));
    // A required credential slot is unbound when the execution-time resolution
    // chain (`credentials[slot]` → legacy `secret_name` for instance-source
    // → fixed `default_secret_name` for org-source) yields no name. Mirrors
    // `resolve_instance_auth`; whether the named secret actually exists in
    // the vault is a send-time concern a pure classifier can't check. In
    // particular a template whose slots are all org-source needs no instance
    // binding at all — it must NOT report NeedsAuthentication just because the
    // instance's scalar `secret_name` is empty.
    //
    // Per *slot*, not per scheme: a header joined from a username and a
    // password is only bound once both halves are.
    // Counted over ALL instance-source slots, including the unkeyed one a
    // programmatically-built template carries — the scalar alias stood for
    // that credential too, so excluding it would report every such instance
    // unbound.
    let single_instance_slot = template
        .all_slots()
        .iter()
        .filter(|s| s.source == SecretSource::Instance)
        .count()
        <= 1;
    let secret_unbound = template.all_slots().into_iter().any(|slot| {
        !slot.optional
            && credentials.get(&slot.key).is_none_or(|n| n.is_empty())
            && match slot.source {
                // The scalar alias only ever stood for a single credential, so
                // it cannot vouch for one half of a composed one.
                SecretSource::Instance => {
                    !single_instance_slot || secret_name.is_none() || secret_name == Some("")
                }
                SecretSource::Org => slot.default_secret_name.is_empty(),
            }
    });
    let mcp_bearer = matches!(
        template.mcp.as_ref().map(|m| &m.auth),
        Some(McpAuth::Bearer { .. })
    );
    let no_secret = secret_name.is_none() || secret_name == Some("");

    let granted_list = match scopes {
        // No connection bound and no inline secret: a freshly-instantiated
        // service for an auth-bearing template needs the OAuth dance / secret to
        // be provided. Surface that explicitly so the agent doesn't guess.
        ScopeKnowledge::NoConnection => {
            if has_oauth {
                return Some(CredentialsStatus::NeedsAuthentication);
            }
            if has_secret || mcp_bearer {
                let missing =
                    (has_secret && secret_unbound) || (!has_secret && mcp_bearer && no_secret);
                return Some(if missing {
                    CredentialsStatus::NeedsAuthentication
                } else {
                    CredentialsStatus::Ok
                });
            }
            return None;
        }
        // A connection exists but we don't know its scopes — benefit of the
        // doubt (same as the call-time gate). Classify as Ok for OAuth.
        ScopeKnowledge::Unknown => {
            return if has_oauth {
                Some(CredentialsStatus::Ok)
            } else {
                None
            };
        }
        ScopeKnowledge::Known(list) => list,
    };

    if !has_oauth {
        return None;
    }

    // MCP-oauth templates carry their scopes at the service level, not per
    // action, so the per-action loop below is a no-op that would always report
    // `Ok`. Check the mcp scopes against the connection's granted set directly
    // (all-or-nothing — there's one scope set, no per-action granularity) so
    // the backend status agrees with the dashboard's missing-scope warning.
    if let Some(McpAuth::OAuth {
        scopes: mcp_scopes, ..
    }) = template.mcp.as_ref().map(|m| &m.auth)
    {
        if mcp_scopes.is_empty() {
            return Some(CredentialsStatus::Ok);
        }
        let granted: std::collections::HashSet<&str> =
            granted_list.iter().map(String::as_str).collect();
        let all_covered = mcp_scopes.iter().all(|s| granted.contains(s.as_str()));
        return Some(if all_covered {
            CredentialsStatus::Ok
        } else {
            CredentialsStatus::NeedsReconnect
        });
    }

    let mut any_ok = false;
    let mut any_gap = false;
    for action in template.actions.values() {
        match action_scope_coverage(action, ScopeKnowledge::Known(granted_list)).0 {
            ScopeCoverage::Covered => any_ok = true,
            ScopeCoverage::NeedsReconnect => any_gap = true,
            // Known scopes never yield Unknown.
            ScopeCoverage::Unknown => {}
        }
    }

    Some(match (any_ok, any_gap) {
        (false, true) => CredentialsStatus::NeedsReconnect,
        (true, true) => CredentialsStatus::PartiallyDegraded,
        _ => CredentialsStatus::Ok,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use overslash_core::types::{McpSpec, Risk, ServiceAction, TokenInjection};
    use std::collections::HashMap;

    fn mcp_bearer_template(default_secret: Option<&str>) -> ServiceDefinition {
        ServiceDefinition {
            secrets: Vec::new(),
            config: Vec::new(),
            key: "t".into(),
            display_name: "T".into(),
            description: None,
            hosts: vec![],
            category: None,
            hidden: false,
            auth: vec![],
            actions: HashMap::new(),
            runtime: Runtime::Mcp,
            mcp: Some(McpSpec {
                url: Some("https://example.com".into()),
                auth: McpAuth::Bearer {
                    secret_name: default_secret.map(|s| s.to_string()),
                },
                autodiscover: false,
            }),
            instance_defaults: None,
        }
    }

    fn mcp_oauth_template(provider: &str, scopes: &[&str]) -> ServiceDefinition {
        ServiceDefinition {
            secrets: Vec::new(),
            config: Vec::new(),
            key: "t".into(),
            display_name: "T".into(),
            description: None,
            hosts: vec![],
            category: None,
            hidden: false,
            auth: vec![],
            // MCP tools carry no per-action required_scopes; scopes live on the
            // service-level oauth block.
            actions: HashMap::new(),
            runtime: Runtime::Mcp,
            mcp: Some(McpSpec {
                url: Some("https://mcp.example.com/mcp".into()),
                auth: McpAuth::OAuth {
                    provider: provider.to_string(),
                    scopes: scopes.iter().map(|s| s.to_string()).collect(),
                },
                autodiscover: false,
            }),
            instance_defaults: None,
        }
    }

    #[test]
    fn mcp_oauth_provider_and_scopes_surface_for_auto_connect() {
        let def = mcp_oauth_template("slack", &["chat:write", "channels:read"]);
        // Provider must resolve so auto-connect / pinned-connection validation fire.
        assert_eq!(template_oauth_provider(&def), Some("slack"));
        // Scopes come from the mcp.auth block, not (empty) per-action scopes —
        // otherwise the connect flow requests nothing and the token is useless.
        assert_eq!(
            template_action_scopes(&def),
            vec!["channels:read".to_string(), "chat:write".to_string()]
        );
    }

    #[test]
    fn mcp_oauth_credentials_status_checks_service_level_scopes() {
        let def = mcp_oauth_template("slack", &["chat:write", "channels:read"]);
        // No connection → must connect.
        assert_eq!(
            derive_credentials_status(
                &def,
                ScopeKnowledge::NoConnection,
                &CredentialsMap::new(),
                None
            ),
            Some(CredentialsStatus::NeedsAuthentication)
        );
        // Connection covers every mcp scope → Ok.
        let full = ["chat:write".to_string(), "channels:read".to_string()];
        assert_eq!(
            derive_credentials_status(
                &def,
                ScopeKnowledge::Known(&full),
                &CredentialsMap::new(),
                None
            ),
            Some(CredentialsStatus::Ok)
        );
        // Connection missing a scope → NeedsReconnect (not a false Ok from the
        // per-action loop, which is empty for MCP tools).
        let partial = ["channels:read".to_string()];
        assert_eq!(
            derive_credentials_status(
                &def,
                ScopeKnowledge::Known(&partial),
                &CredentialsMap::new(),
                None
            ),
            Some(CredentialsStatus::NeedsReconnect)
        );
        // Unknown granted scopes → benefit of the doubt (Ok), matching the gate.
        assert_eq!(
            derive_credentials_status(&def, ScopeKnowledge::Unknown, &CredentialsMap::new(), None),
            Some(CredentialsStatus::Ok)
        );
    }

    fn secret_template() -> ServiceDefinition {
        ServiceDefinition {
            secrets: Vec::new(),
            config: Vec::new(),
            key: "t".into(),
            display_name: "T".into(),
            description: None,
            hosts: vec![],
            category: None,
            hidden: false,
            auth: vec![ServiceAuth::Secret {
                template: None,
                slots: Vec::new(),
                config_keys: Vec::new(),
                scheme: String::new(),
                label: String::new(),
                description: String::new(),
                default_secret_name: "default".into(),
                injection: TokenInjection {
                    inject_as: "header".into(),
                    header_name: Some("Authorization".into()),
                    query_param: None,
                    prefix: Some("Bearer ".into()),
                },
                secret_source: overslash_core::types::SecretSource::Instance,
                optional: false,
            }],
            actions: HashMap::new(),
            runtime: Runtime::Http,
            mcp: None,
            instance_defaults: None,
        }
    }

    fn oauth_template(actions: Vec<(&str, Vec<&str>)>) -> ServiceDefinition {
        let mut map = HashMap::new();
        for (key, required) in actions {
            map.insert(
                key.to_string(),
                ServiceAction {
                    method: "GET".into(),
                    path: "/".into(),
                    description: String::new(),
                    summary: None,
                    risk: Risk::Read,
                    response_type: None,
                    params: HashMap::new(),
                    scope_param: None,
                    required_scopes: required.iter().map(|s| s.to_string()).collect(),
                    permission: None,
                    disclose: Vec::new(),
                    redact: Vec::new(),
                    mcp_tool: None,
                    output_schema: None,
                    disabled: false,
                    request_body: None,
                },
            );
        }
        ServiceDefinition {
            secrets: Vec::new(),
            config: Vec::new(),
            key: "t".into(),
            display_name: "T".into(),
            description: None,
            hosts: vec![],
            category: None,
            hidden: false,
            auth: vec![ServiceAuth::OAuth {
                provider: "google".into(),
                scopes: vec![],
                token_injection: TokenInjection {
                    inject_as: "header".into(),
                    header_name: Some("Authorization".into()),
                    query_param: None,
                    prefix: Some("Bearer ".into()),
                },
            }],
            actions: map,
            runtime: Runtime::Http,
            mcp: None,
            instance_defaults: None,
        }
    }

    fn scopes(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn needs_authentication_when_oauth_template_has_no_connection() {
        let tpl = oauth_template(vec![("a", vec!["s1"])]);
        assert_eq!(
            derive_credentials_status(
                &tpl,
                ScopeKnowledge::NoConnection,
                &CredentialsMap::new(),
                None
            ),
            Some(CredentialsStatus::NeedsAuthentication)
        );
    }

    #[test]
    fn none_when_template_has_no_auth_and_no_connection() {
        let tpl = ServiceDefinition {
            secrets: Vec::new(),
            config: Vec::new(),
            key: "t".into(),
            display_name: "T".into(),
            description: None,
            hosts: vec![],
            category: None,
            hidden: false,
            auth: vec![],
            actions: HashMap::new(),
            runtime: Runtime::Http,
            mcp: None,
            instance_defaults: None,
        };
        assert!(
            derive_credentials_status(
                &tpl,
                ScopeKnowledge::NoConnection,
                &CredentialsMap::new(),
                None
            )
            .is_none()
        );
    }

    #[test]
    fn ok_when_connection_covers_every_action() {
        let tpl = oauth_template(vec![("a", vec!["s1"]), ("b", vec!["s2"])]);
        let granted = scopes(&["s1", "s2"]);
        assert_eq!(
            derive_credentials_status(
                &tpl,
                ScopeKnowledge::Known(&granted),
                &CredentialsMap::new(),
                None
            ),
            Some(CredentialsStatus::Ok)
        );
    }

    #[test]
    fn ok_when_template_declares_no_required_scopes() {
        let tpl = oauth_template(vec![("a", vec![]), ("b", vec![])]);
        let granted = scopes(&[]);
        assert_eq!(
            derive_credentials_status(
                &tpl,
                ScopeKnowledge::Known(&granted),
                &CredentialsMap::new(),
                None
            ),
            Some(CredentialsStatus::Ok)
        );
    }

    #[test]
    fn ok_when_connection_scopes_unknown_benefit_of_the_doubt() {
        // An imported connection with no declared scopes classifies as Ok, not
        // degraded — mirrors the call-time scope-gate giving it the benefit of
        // the doubt.
        let tpl = oauth_template(vec![("a", vec!["s1"]), ("b", vec!["s2"])]);
        assert_eq!(
            derive_credentials_status(&tpl, ScopeKnowledge::Unknown, &CredentialsMap::new(), None),
            Some(CredentialsStatus::Ok)
        );
    }

    #[test]
    fn partially_degraded_when_some_actions_covered() {
        let tpl = oauth_template(vec![("a", vec!["s1"]), ("b", vec!["s2"])]);
        let granted = scopes(&["s1"]);
        assert_eq!(
            derive_credentials_status(
                &tpl,
                ScopeKnowledge::Known(&granted),
                &CredentialsMap::new(),
                None
            ),
            Some(CredentialsStatus::PartiallyDegraded)
        );
    }

    #[test]
    fn needs_reconnect_when_no_action_covered() {
        let tpl = oauth_template(vec![("a", vec!["s1"]), ("b", vec!["s2"])]);
        let granted = scopes(&["other"]);
        assert_eq!(
            derive_credentials_status(
                &tpl,
                ScopeKnowledge::Known(&granted),
                &CredentialsMap::new(),
                None
            ),
            Some(CredentialsStatus::NeedsReconnect)
        );
    }

    #[test]
    fn ok_when_mcp_bearer_has_secret_and_no_connection() {
        let tpl = mcp_bearer_template(None);
        assert_eq!(
            derive_credentials_status(
                &tpl,
                ScopeKnowledge::NoConnection,
                &CredentialsMap::new(),
                Some("whatsapp_mcp_token")
            ),
            Some(CredentialsStatus::Ok)
        );
    }

    #[test]
    fn needs_authentication_when_mcp_bearer_has_no_secret_and_no_connection() {
        let tpl = mcp_bearer_template(None);
        assert_eq!(
            derive_credentials_status(
                &tpl,
                ScopeKnowledge::NoConnection,
                &CredentialsMap::new(),
                None
            ),
            Some(CredentialsStatus::NeedsAuthentication)
        );
        assert_eq!(
            derive_credentials_status(
                &tpl,
                ScopeKnowledge::NoConnection,
                &CredentialsMap::new(),
                Some("")
            ),
            Some(CredentialsStatus::NeedsAuthentication)
        );
    }

    #[test]
    fn ok_when_secret_template_has_secret_and_no_connection() {
        let tpl = secret_template();
        assert_eq!(
            derive_credentials_status(
                &tpl,
                ScopeKnowledge::NoConnection,
                &CredentialsMap::new(),
                Some("my_api_key")
            ),
            Some(CredentialsStatus::Ok)
        );
    }

    /// email.yaml-shaped auth: an optional org-source `gateway` slot plus a
    /// required instance-source `mailbox` slot.
    fn dual_scheme_template() -> ServiceDefinition {
        let mut tpl = secret_template();
        let injection = TokenInjection {
            inject_as: "header".into(),
            header_name: Some("Authorization".into()),
            query_param: None,
            prefix: Some("Bearer ".into()),
        };
        tpl.auth = vec![
            ServiceAuth::Secret {
                template: None,
                slots: Vec::new(),
                config_keys: Vec::new(),
                scheme: "gateway".into(),
                label: String::new(),
                description: String::new(),
                default_secret_name: "overfwd_gateway_key".into(),
                injection: injection.clone(),
                secret_source: overslash_core::types::SecretSource::Org,
                optional: true,
            },
            ServiceAuth::Secret {
                template: None,
                slots: Vec::new(),
                config_keys: Vec::new(),
                scheme: "mailbox".into(),
                label: String::new(),
                description: String::new(),
                default_secret_name: "mailbox_credential".into(),
                injection,
                secret_source: overslash_core::types::SecretSource::Instance,
                optional: false,
            },
        ];
        tpl
    }

    /// A template whose only secret scheme resolves an org-vault default needs
    /// no instance binding — the old `.any(ApiKey)` predicate (pre-rename) misreported it
    /// as NeedsAuthentication forever.
    #[test]
    fn ok_when_all_secret_schemes_are_org_source_and_nothing_bound() {
        let mut tpl = secret_template();
        if let ServiceAuth::Secret { secret_source, .. } = &mut tpl.auth[0] {
            *secret_source = overslash_core::types::SecretSource::Org;
        }
        assert_eq!(
            derive_credentials_status(
                &tpl,
                ScopeKnowledge::NoConnection,
                &CredentialsMap::new(),
                None
            ),
            Some(CredentialsStatus::Ok)
        );
    }

    #[test]
    fn credentials_map_binding_satisfies_instance_scheme_without_scalar() {
        let tpl = dual_scheme_template();
        let bound = CredentialsMap::from([("mailbox".to_string(), "my_login".to_string())]);
        assert_eq!(
            derive_credentials_status(&tpl, ScopeKnowledge::NoConnection, &bound, None),
            Some(CredentialsStatus::Ok)
        );
        // Binding only the optional org slot leaves the required mailbox slot
        // empty → still needs authentication.
        let gateway_only = CredentialsMap::from([("gateway".to_string(), "gw".to_string())]);
        assert_eq!(
            derive_credentials_status(&tpl, ScopeKnowledge::NoConnection, &gateway_only, None),
            Some(CredentialsStatus::NeedsAuthentication)
        );
    }

    // ── reconcile_credentials ────────────────────────────────────────

    #[test]
    fn reconcile_rejects_unknown_scheme_and_empty_value() {
        let tpl = dual_scheme_template();
        let unknown = CredentialsMap::from([("gatway".to_string(), "x".to_string())]);
        assert!(reconcile_credentials(&tpl, Some(&unknown), None).is_err());
        let blank = CredentialsMap::from([("mailbox".to_string(), "  ".to_string())]);
        assert!(reconcile_credentials(&tpl, Some(&blank), None).is_err());
    }

    #[test]
    fn reconcile_folds_legacy_scalar_into_sole_instance_slot_and_mirrors_it() {
        let tpl = dual_scheme_template();
        let (map, scalar) = reconcile_credentials(&tpl, None, Some("my_login")).unwrap();
        assert_eq!(map.get("mailbox").map(String::as_str), Some("my_login"));
        assert_eq!(scalar.as_deref(), Some("my_login"));
        // Map binding wins the mirror when both agree; a disagreement is a 400.
        let explicit = CredentialsMap::from([("mailbox".to_string(), "my_login".to_string())]);
        assert!(reconcile_credentials(&tpl, Some(&explicit), Some("my_login")).is_ok());
        assert!(reconcile_credentials(&tpl, Some(&explicit), Some("other")).is_err());
    }

    #[test]
    fn reconcile_rejects_scalar_alias_when_several_instance_slots_exist() {
        let mut tpl = dual_scheme_template();
        if let ServiceAuth::Secret {
            secret_source,
            optional,
            ..
        } = &mut tpl.auth[0]
        {
            *secret_source = overslash_core::types::SecretSource::Instance;
            *optional = false;
        }
        assert!(reconcile_credentials(&tpl, None, Some("ambiguous")).is_err());
        // …but per-scheme bindings work, and no scalar is mirrored (it would
        // be ambiguous for old readers).
        let both = CredentialsMap::from([
            ("gateway".to_string(), "gw".to_string()),
            ("mailbox".to_string(), "mb".to_string()),
        ]);
        let (map, scalar) = reconcile_credentials(&tpl, Some(&both), None).unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(scalar, None);
    }

    fn scoped_action(required: &[&str]) -> ServiceAction {
        let tpl = oauth_template(vec![("a", required.to_vec())]);
        tpl.actions.get("a").unwrap().clone()
    }

    #[test]
    fn coverage_covered_when_all_required_granted() {
        let action = scoped_action(&["s1", "s2"]);
        let granted = scopes(&["s1", "s2", "s3"]);
        let (cov, missing) = action_scope_coverage(&action, ScopeKnowledge::Known(&granted));
        assert_eq!(cov, ScopeCoverage::Covered);
        assert!(missing.is_empty());
    }

    #[test]
    fn coverage_needs_reconnect_lists_only_missing() {
        let action = scoped_action(&["s1", "s2"]);
        let granted = scopes(&["s1"]);
        let (cov, missing) = action_scope_coverage(&action, ScopeKnowledge::Known(&granted));
        assert_eq!(cov, ScopeCoverage::NeedsReconnect);
        assert_eq!(missing, vec!["s2".to_string()]);
    }

    #[test]
    fn coverage_unknown_for_unrecorded_or_absent_connection() {
        let action = scoped_action(&["s1"]);
        assert_eq!(
            action_scope_coverage(&action, ScopeKnowledge::Unknown).0,
            ScopeCoverage::Unknown
        );
        assert_eq!(
            action_scope_coverage(&action, ScopeKnowledge::NoConnection).0,
            ScopeCoverage::Unknown
        );
    }

    #[test]
    fn coverage_covered_when_action_requires_no_scopes() {
        let action = scoped_action(&[]);
        // Even with an unrecorded grant, an action that declares no scopes is
        // always covered.
        let (cov, missing) = action_scope_coverage(&action, ScopeKnowledge::Unknown);
        assert_eq!(cov, ScopeCoverage::Covered);
        assert!(missing.is_empty());
    }
}
