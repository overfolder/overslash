//! Platform kernels for service-instance CRUD.
//!
//! These mirror `platform_templates.rs`: pure async functions that take a
//! [`PlatformCallContext`] plus typed inputs and return a typed response.
//! Both the REST handlers in `routes/services.rs` and the MCP platform
//! dispatcher (via `platform_registry`) call into the same kernel — this
//! keeps the auto-add-to-Myself behavior, owner resolution, template
//! validation, and credential-status derivation in one place.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_core::permissions::AccessLevel;
use overslash_core::types::{McpAuth, Runtime, ServiceAuth, ServiceDefinition};
use overslash_db::repos::group::ServiceGroupRow;
use overslash_db::repos::service_instance::{
    CreateServiceInstance, ServiceInstanceRow, UpdateServiceInstance,
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
    pub secret_name: Option<String>,
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
    /// Tenant-supplied URL the OAuth callback redirects back to once the
    /// dance finishes. Only consulted when the kernel auto-initiates a
    /// flow (OAuth template + no pinned connection + not opted out). See
    /// [`crate::services::platform_connections::CreateConnectionInput::return_url`]
    /// for the validation contract.
    #[serde(default)]
    pub connect_return_url: Option<String>,
    /// REST-only opt-in: surface the raw upstream provider authorize URL
    /// (e.g. `https://accounts.google.com/...`) on the `connect` bundle
    /// in addition to the Overslash-gated `auth_url`. White-label
    /// integrators wrap the raw URL in their own consent UI so users
    /// never see Overslash branding. Mirrors `include_raw` on
    /// `POST /v1/connections` — same Obsidian threat-model gating: PKCE +
    /// state binding still hold either way, but raw delivery skips the
    /// chat-delivery hardening that `connect-authorize` provides. The
    /// MCP `CreateServiceHandler` strips this field so agents can't ever
    /// hand the user a raw provider URL over chat.
    #[serde(default)]
    pub connect_include_raw: Option<bool>,
}

fn default_status() -> String {
    "active".into()
}

#[derive(Debug, Deserialize, Default)]
pub struct UpdateServiceInput {
    pub name: Option<String>,
    pub connection_id: Option<Option<Uuid>>,
    pub secret_name: Option<Option<String>>,
    pub url: Option<Option<String>>,
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
    /// Per-instance MCP server URL override. Overrides the template's `mcp.url`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub status: String,
    pub is_system: bool,
    pub created_at: String,
    pub updated_at: String,
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
/// instance. `raw` mirrors the same opt-in field on `POST /v1/connections`
/// (`include_raw`) — surfaced here as `connect_include_raw` on the
/// request — for white-label integrators that wrap the upstream provider
/// URL in their own consent UI. Default callers see only the gated
/// `auth_url`.
#[derive(Serialize, Debug)]
pub struct ConnectBundle {
    pub auth_url: String,
    pub state: String,
    pub flow_id: String,
    pub expires_at: time::OffsetDateTime,
    /// Raw upstream provider authorize URL. Only populated when the
    /// REST caller set `connect_include_raw: true` on the request. The
    /// MCP path always strips that opt-in, so this field stays `None`
    /// on every agent-driven flow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
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
    let mut conn_by_owner_provider: HashMap<(Uuid, String), Vec<String>> = HashMap::new();
    for row in &rows {
        if row.connection_id.is_some() {
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
        if conn_by_owner_provider.contains_key(&key) {
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
                let scopes: Option<&[String]> = if let Some(cid) = row.connection_id {
                    connections_by_id.get(&cid).map(|c| c.scopes.as_slice())
                } else if let (Some(owner), Some(provider)) =
                    (row.owner_identity_id, template_oauth_provider(tpl))
                {
                    conn_by_owner_provider
                        .get(&(owner, provider.to_string()))
                        .map(|s| s.as_slice())
                } else {
                    None
                };
                derive_credentials_status(tpl, scopes, row.secret_name.as_deref())
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

        let expected_provider = template_def.auth.iter().find_map(|a| match a {
            ServiceAuth::OAuth { provider, .. } => Some(provider.clone()),
            _ => None,
        });
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
    let mcp_has_default_url = template_def
        .mcp
        .as_ref()
        .and_then(|m| m.url.as_ref())
        .is_some();

    if input.secret_name.as_deref().is_some_and(|s| !s.is_empty()) {
        let has_api_key = template_def
            .auth
            .iter()
            .any(|a| matches!(a, ServiceAuth::ApiKey { .. }));
        if !has_api_key && !is_mcp_bearer {
            return Err(AppError::BadRequest(format!(
                "template '{}' does not use api key or MCP bearer auth",
                input.template_key
            )));
        }
    }

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
        secret_name: input.secret_name.as_deref(),
        url: input.url.as_deref(),
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
        None,
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
                    Some(conn.scopes.as_slice()),
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
        };
        match crate::services::platform_connections::kernel_create_connection(
            connect_ctx,
            connect_input,
            crate::services::platform_connections::RequestMeta::default(),
        )
        .await
        {
            Ok(resp) => {
                let raw = if input.connect_include_raw.unwrap_or(false) {
                    Some(resp.raw.clone())
                } else {
                    None
                };
                detail.connect = Some(ConnectBundle {
                    auth_url: resp.auth_url,
                    state: resp.state,
                    flow_id: resp.flow_id,
                    expires_at: resp.expires_at,
                    raw,
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

    if let Some(Some(ref new_secret)) = input.secret_name {
        if !new_secret.is_empty() {
            let template_lookup_identity = existing.owner_identity_id.or(Some(auth_identity));
            let template_def = resolve_template_definition(
                &ctx.db,
                &ctx.registry,
                ctx.org_id,
                template_lookup_identity,
                &existing.template_key,
            )
            .await?;
            let has_api_key = template_def
                .auth
                .iter()
                .any(|a| matches!(a, ServiceAuth::ApiKey { .. }));
            let is_mcp_bearer = matches!(
                template_def.mcp.as_ref().map(|m| &m.auth),
                Some(McpAuth::Bearer { .. })
            );
            if !has_api_key && !is_mcp_bearer {
                return Err(AppError::BadRequest(format!(
                    "template '{}' does not use api key or MCP bearer auth",
                    existing.template_key
                )));
            }
        }
    }

    if let Some(Some(ref url)) = input.url {
        if !url.is_empty() && !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(AppError::BadRequest(
                "`url` must start with http:// or https://".into(),
            ));
        }
    }

    let update = UpdateServiceInstance {
        name: input.name.as_deref(),
        connection_id: input.connection_id,
        secret_name: input.secret_name.as_ref().map(|o| o.as_deref()),
        url: input.url.as_ref().map(|o| o.as_deref()),
    };

    let row = scope
        .update_service_instance(id, &update)
        .await?
        .ok_or_else(|| AppError::NotFound("service instance not found".into()))?;
    Ok(row_to_detail(row))
}

// ── Helpers ───────────────────────────────────────────────────────────────

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
        url: row.url,
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
        url: row.url,
        status: row.status,
        is_system: row.is_system,
        created_at: fmt_time(row.created_at),
        updated_at: fmt_time(row.updated_at),
        credentials_status: None,
        connect: None,
    }
}

/// Pull the OAuth provider declared on a template's auth schemes, if any.
/// Returns `None` for templates that don't declare an OAuth auth (api-key
/// only, MCP bearer only, no auth, etc.) — in which case the auto-connect
/// orchestration in `kernel_create_service` is a no-op.
fn template_oauth_provider(def: &ServiceDefinition) -> Option<&str> {
    def.auth.iter().find_map(|a| match a {
        ServiceAuth::OAuth { provider, .. } => Some(provider.as_str()),
        _ => None,
    })
}

/// Union every action's `required_scopes` into a sorted, deduped list.
/// Same `BTreeSet` flatten that the previous `resolve_template_scopes`
/// helper on the connection kernel used — now lives next to the only
/// remaining caller (auto-connect orchestration in `kernel_create_service`).
fn template_action_scopes(def: &ServiceDefinition) -> Vec<String> {
    def.actions
        .values()
        .flat_map(|a| a.required_scopes.iter().cloned())
        .collect::<std::collections::BTreeSet<String>>()
        .into_iter()
        .collect()
}

/// Resolve the [`ServiceDefinition`] for a template key across user/org/global tiers.
pub async fn resolve_template_definition(
    db: &sqlx::PgPool,
    registry: &overslash_core::registry::ServiceRegistry,
    org_id: Uuid,
    identity_id: Option<Uuid>,
    key: &str,
) -> Result<ServiceDefinition, AppError> {
    if let Some(identity_id) = identity_id {
        if let Some(t) = service_template::get_by_key(db, org_id, Some(identity_id), key).await? {
            return compile_row(&t);
        }
    }
    if let Some(t) = service_template::get_by_key(db, org_id, None, key).await? {
        return compile_row(&t);
    }
    registry
        .get(key)
        .cloned()
        .ok_or_else(|| AppError::NotFound(format!("template '{key}' not found")))
}

fn compile_row(t: &service_template::ServiceTemplateRow) -> Result<ServiceDefinition, AppError> {
    overslash_core::openapi::compile_service(&t.openapi)
        .map(|(def, _)| def)
        .map_err(|errors| {
            AppError::Internal(format!(
                "stored openapi for '{}' failed to compile: {:?}",
                t.key, errors
            ))
        })
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
    derive_credentials_status(
        &template,
        conn_scopes.as_deref(),
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
async fn resolve_effective_scopes(
    db: &sqlx::PgPool,
    scope: &OrgScope,
    template: &ServiceDefinition,
    row: &ServiceInstanceRow,
) -> Option<Vec<String>> {
    if let Some(conn_id) = row.connection_id {
        return scope
            .get_connection(conn_id)
            .await
            .ok()
            .flatten()
            .map(|c| c.scopes);
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

/// Pure classifier: takes a template + (optional) granted scopes + secret name
/// and returns a [`CredentialsStatus`] or `None` when the template has no auth
/// scheme to evaluate.
pub fn derive_credentials_status(
    template: &ServiceDefinition,
    granted_scopes: Option<&[String]>,
    secret_name: Option<&str>,
) -> Option<CredentialsStatus> {
    let has_oauth = template
        .auth
        .iter()
        .any(|a| matches!(a, ServiceAuth::OAuth { .. }));
    let has_api_key = template
        .auth
        .iter()
        .any(|a| matches!(a, ServiceAuth::ApiKey { .. }));
    let mcp_bearer = matches!(
        template.mcp.as_ref().map(|m| &m.auth),
        Some(McpAuth::Bearer { .. })
    );

    // No connection bound and no inline secret: a freshly-instantiated service
    // for an auth-bearing template needs the OAuth dance / secret to be
    // provided. Surface that explicitly so the agent doesn't need to guess.
    let no_connection = granted_scopes.is_none();
    let no_secret = secret_name.is_none() || secret_name == Some("");
    if no_connection {
        if has_oauth {
            return Some(CredentialsStatus::NeedsAuthentication);
        }
        if has_api_key || mcp_bearer {
            return Some(if no_secret {
                CredentialsStatus::NeedsAuthentication
            } else {
                CredentialsStatus::Ok
            });
        }
    }

    // No granted scopes to compare against: nothing more to classify.
    let granted_list = granted_scopes?;

    if !has_oauth {
        return None;
    }

    let granted: std::collections::HashSet<&str> =
        granted_list.iter().map(String::as_str).collect();

    let mut any_ok = false;
    let mut any_gap = false;
    for action in template.actions.values() {
        if action.required_scopes.is_empty() {
            any_ok = true;
            continue;
        }
        let covered = action
            .required_scopes
            .iter()
            .all(|s| granted.contains(s.as_str()));
        if covered {
            any_ok = true;
        } else {
            any_gap = true;
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
        }
    }

    fn api_key_template() -> ServiceDefinition {
        ServiceDefinition {
            key: "t".into(),
            display_name: "T".into(),
            description: None,
            hosts: vec![],
            category: None,
            hidden: false,
            auth: vec![ServiceAuth::ApiKey {
                default_secret_name: "default".into(),
                injection: TokenInjection {
                    inject_as: "header".into(),
                    header_name: Some("Authorization".into()),
                    query_param: None,
                    prefix: Some("Bearer ".into()),
                },
            }],
            actions: HashMap::new(),
            runtime: Runtime::Http,
            mcp: None,
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
                },
            );
        }
        ServiceDefinition {
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
        }
    }

    fn scopes(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn needs_authentication_when_oauth_template_has_no_connection() {
        let tpl = oauth_template(vec![("a", vec!["s1"])]);
        assert_eq!(
            derive_credentials_status(&tpl, None, None),
            Some(CredentialsStatus::NeedsAuthentication)
        );
    }

    #[test]
    fn none_when_template_has_no_auth_and_no_connection() {
        let tpl = ServiceDefinition {
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
        };
        assert!(derive_credentials_status(&tpl, None, None).is_none());
    }

    #[test]
    fn ok_when_connection_covers_every_action() {
        let tpl = oauth_template(vec![("a", vec!["s1"]), ("b", vec!["s2"])]);
        let granted = scopes(&["s1", "s2"]);
        assert_eq!(
            derive_credentials_status(&tpl, Some(&granted), None),
            Some(CredentialsStatus::Ok)
        );
    }

    #[test]
    fn ok_when_template_declares_no_required_scopes() {
        let tpl = oauth_template(vec![("a", vec![]), ("b", vec![])]);
        let granted = scopes(&[]);
        assert_eq!(
            derive_credentials_status(&tpl, Some(&granted), None),
            Some(CredentialsStatus::Ok)
        );
    }

    #[test]
    fn partially_degraded_when_some_actions_covered() {
        let tpl = oauth_template(vec![("a", vec!["s1"]), ("b", vec!["s2"])]);
        let granted = scopes(&["s1"]);
        assert_eq!(
            derive_credentials_status(&tpl, Some(&granted), None),
            Some(CredentialsStatus::PartiallyDegraded)
        );
    }

    #[test]
    fn needs_reconnect_when_no_action_covered() {
        let tpl = oauth_template(vec![("a", vec!["s1"]), ("b", vec!["s2"])]);
        let granted = scopes(&["other"]);
        assert_eq!(
            derive_credentials_status(&tpl, Some(&granted), None),
            Some(CredentialsStatus::NeedsReconnect)
        );
    }

    #[test]
    fn ok_when_mcp_bearer_has_secret_and_no_connection() {
        let tpl = mcp_bearer_template(None);
        assert_eq!(
            derive_credentials_status(&tpl, None, Some("whatsapp_mcp_token")),
            Some(CredentialsStatus::Ok)
        );
    }

    #[test]
    fn needs_authentication_when_mcp_bearer_has_no_secret_and_no_connection() {
        let tpl = mcp_bearer_template(None);
        assert_eq!(
            derive_credentials_status(&tpl, None, None),
            Some(CredentialsStatus::NeedsAuthentication)
        );
        assert_eq!(
            derive_credentials_status(&tpl, None, Some("")),
            Some(CredentialsStatus::NeedsAuthentication)
        );
    }

    #[test]
    fn ok_when_api_key_template_has_secret_and_no_connection() {
        let tpl = api_key_template();
        assert_eq!(
            derive_credentials_status(&tpl, None, Some("my_api_key")),
            Some(CredentialsStatus::Ok)
        );
    }
}
