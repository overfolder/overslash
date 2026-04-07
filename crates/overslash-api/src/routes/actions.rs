use std::collections::HashMap;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::repos::audit::{self, AuditEntry};

use crate::{
    AppState,
    error::AppError,
    extractors::{AuthContext, ClientIp},
    services::http_executor,
};
use overslash_core::{
    crypto,
    permissions::{GroupCeilingResult, PermissionKey},
    secret_injection::inject_secrets,
    types::{ActionRequest, ActionResult, InjectAs, SecretRef, service::Risk},
};

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/actions/execute", post(execute_action))
}

/// Unified execute request: supports Mode A (raw HTTP) and Mode C (service + action).
#[derive(Debug, Deserialize)]
struct ExecuteRequest {
    // Mode A fields
    method: Option<String>,
    url: Option<String>,
    #[serde(default)]
    headers: HashMap<String, String>,
    body: Option<String>,
    #[serde(default)]
    secrets: Vec<SecretRef>,

    // Mode C fields
    service: Option<String>,
    action: Option<String>,
    #[serde(default)]
    params: HashMap<String, serde_json::Value>,

    // Mode B: explicit connection
    connection: Option<Uuid>,

    // Large file handling
    #[serde(default)]
    prefer_stream: Option<bool>,
}

#[derive(Serialize)]
#[serde(tag = "status")]
enum ExecuteResponse {
    #[serde(rename = "executed")]
    Executed {
        result: ActionResult,
        action_description: Option<String>,
    },
    #[serde(rename = "pending_approval")]
    PendingApproval {
        approval_id: Uuid,
        approval_url: String,
        action_description: String,
        expires_at: String,
    },
    #[serde(rename = "denied")]
    Denied { reason: String },
}

/// Metadata from request resolution, used to derive the correct permission key type.
struct ResolvedMeta {
    description: Option<String>,
    auth_injected: bool,
    /// Present only for Mode C — carries info needed to derive service-action permission keys.
    service_scope: Option<ServiceScope>,
    /// Risk level of the action (Mode C only, from the action definition).
    risk: Option<Risk>,
    /// Owner identity ID of the resolved service instance (for user-owned service bypass).
    service_instance_owner: Option<Uuid>,
}

struct ServiceScope {
    service_key: String,
    action_key: String,
    scope_param: Option<String>,
}

async fn execute_action(
    State(state): State<AppState>,
    auth: AuthContext,
    ip: ClientIp,
    Json(req): Json<ExecuteRequest>,
) -> Result<Response, AppError> {
    let identity_id = auth
        .identity_id
        .ok_or_else(|| AppError::BadRequest("api key must be bound to an identity".into()))?;

    // Resolve the identity to determine kind and owner for ceiling check
    let identity = overslash_db::repos::identity::get_by_id(&state.db, identity_id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;

    let ceiling_user_id = crate::services::group_ceiling::ceiling_user_id_from_identity(&identity)?;

    // Resolve the request to a concrete ActionRequest
    let (action_req, meta) = resolve_request(&state, &auth, identity_id, &req).await?;

    let perm_keys = if let Some(ref scope) = meta.service_scope {
        PermissionKey::from_service_action(
            &scope.service_key,
            &scope.action_key,
            scope.scope_param.as_deref(),
            &req.params,
        )
    } else {
        PermissionKey::from_http(&action_req.method, &action_req.url)
    };

    // ── Layer 1: Group ceiling check ─────────────────────────────────
    let mut auto_approved = false;

    // Determine service name and risk for ceiling check
    let ceiling_service = if let Some(ref scope) = meta.service_scope {
        scope.service_key.clone()
    } else {
        "http".to_string()
    };
    let ceiling_risk = if let Some(risk) = meta.risk {
        risk
    } else {
        Risk::from_http_method(&action_req.method)
    };

    // User-owned service instances bypass the ceiling for the creator
    // (matches if the service owner is the calling identity or the ceiling user)
    let is_user_owned_service = meta.service_instance_owner.is_some()
        && (meta.service_instance_owner == Some(ceiling_user_id)
            || meta.service_instance_owner == Some(identity_id));

    if !is_user_owned_service {
        let ceiling =
            crate::services::group_ceiling::load_ceiling(&state.db, ceiling_user_id).await?;

        if ceiling.has_groups {
            match crate::services::group_ceiling::check_ceiling(
                &ceiling,
                &ceiling_service,
                ceiling_risk,
            ) {
                GroupCeilingResult::ExceedsCeiling(reason) => {
                    return Ok((
                        StatusCode::FORBIDDEN,
                        Json(ExecuteResponse::Denied { reason }),
                    )
                        .into_response());
                }
                GroupCeilingResult::WithinCeilingAutoApprove if identity.kind != "user" => {
                    // Auto-create permission rules for the agent
                    for key in &perm_keys {
                        overslash_db::repos::permission_rule::create(
                            &state.db,
                            auth.org_id,
                            identity_id,
                            &key.0,
                            "allow",
                            None,
                        )
                        .await?;
                    }
                    auto_approved = true;
                }
                GroupCeilingResult::WithinCeiling
                | GroupCeilingResult::WithinCeilingAutoApprove
                | GroupCeilingResult::NoGroups => {}
            }
        }
        // has_groups == false → NoGroups → permissive (no ceiling enforced)
    }

    // ── Layer 2: Hierarchical permission check (agents/sub-agents only) ──
    let needs_gate =
        !action_req.secrets.is_empty() || req.connection.is_some() || meta.auth_injected;

    // Users are gated by groups only — they are their own approvers.
    // Agents walk the ancestor chain; first gap → approval at gap level.
    if identity.kind != "user" && needs_gate && !auto_approved {
        let bubble_secs =
            overslash_db::repos::org::get_approval_auto_bubble_secs(&state.db, auth.org_id)
                .await?
                .unwrap_or(300);
        let force_user_resolver = bubble_secs == 0;

        match crate::services::permission_chain::walk(
            &state.db,
            identity_id,
            &perm_keys,
            force_user_resolver,
        )
        .await?
        {
            crate::services::permission_chain::ChainWalkResult::Allowed => {}
            crate::services::permission_chain::ChainWalkResult::Gap {
                uncovered_keys,
                gap_identity_id,
                initial_resolver_id,
                rule_placement_id: _,
            } => {
                let token = generate_token();
                let expires_at = time::OffsetDateTime::now_utc()
                    + time::Duration::seconds(state.config.approval_expiry_secs as i64);
                let summary = meta
                    .description
                    .clone()
                    .unwrap_or_else(|| format!("{} {}", action_req.method, action_req.url));
                let keys: Vec<String> = uncovered_keys.iter().map(|k| k.0.clone()).collect();

                let approval = overslash_db::repos::approval::create(
                    &state.db,
                    &overslash_db::repos::approval::CreateApproval {
                        org_id: auth.org_id,
                        identity_id,
                        current_resolver_identity_id: initial_resolver_id,
                        action_summary: &summary,
                        action_detail: Some(serde_json::to_value(&action_req).unwrap_or_default()),
                        permission_keys: &keys,
                        token: &token,
                        expires_at,
                    },
                )
                .await?;

                let _ = audit::log(
                    &state.db,
                    &AuditEntry {
                        org_id: auth.org_id,
                        identity_id: Some(identity_id),
                        action: "approval.created",
                        resource_type: Some("approval"),
                        resource_id: Some(approval.id),
                        detail: serde_json::json!({
                            "summary": summary,
                            "current_resolver_identity_id": initial_resolver_id,
                        }),
                        description: Some(&summary),
                        ip_address: ip.0.as_deref(),
                    },
                )
                .await;

                // ── approval.created webhook (SPEC §5) ───────────────────
                // can_be_handled_by lists every identity in the resolver chain
                // who can act on this approval right now: the current resolver
                // and its strict ancestors (excluding the requester, who can
                // never self-resolve). Computed once here so subscribers don't
                // have to walk the tree themselves.
                let resolver_chain = overslash_db::repos::identity::get_ancestor_chain(
                    &state.db,
                    initial_resolver_id,
                )
                .await
                .unwrap_or_default();
                let can_be_handled_by: Vec<serde_json::Value> = resolver_chain
                    .iter()
                    .filter(|i| i.id != identity_id)
                    .map(|i| {
                        serde_json::json!({
                            "identity_id": i.id,
                            "kind": i.kind,
                            "name": i.name,
                        })
                    })
                    .collect();
                let webhook_payload = serde_json::json!({
                    "approval_id": approval.id,
                    "identity_id": identity_id,
                    "gap_identity": gap_identity_id,
                    "current_resolver_identity_id": initial_resolver_id,
                    "action_summary": summary,
                    "permission_keys": keys,
                    "can_be_handled_by": can_be_handled_by,
                });
                {
                    let db = state.db.clone();
                    let client = state.http_client.clone();
                    let org_id = auth.org_id;
                    tokio::spawn(async move {
                        crate::services::webhook_dispatcher::dispatch(
                            &db,
                            &client,
                            org_id,
                            "approval.created",
                            webhook_payload,
                        )
                        .await;
                    });
                }

                return Ok((
                    StatusCode::ACCEPTED,
                    Json(ExecuteResponse::PendingApproval {
                        approval_id: approval.id,
                        approval_url: format!("/approve/{}", approval.token),
                        action_description: summary,
                        expires_at: expires_at.to_string(),
                    }),
                )
                    .into_response());
            }
            crate::services::permission_chain::ChainWalkResult::Denied(reason) => {
                return Ok((
                    StatusCode::FORBIDDEN,
                    Json(ExecuteResponse::Denied { reason }),
                )
                    .into_response());
            }
        }
    }

    // Resolve secrets and inject
    let enc_key = crypto::parse_hex_key(&state.config.secrets_encryption_key)?;
    let mut secret_values = HashMap::new();
    for secret_ref in &action_req.secrets {
        let version = overslash_db::repos::secret::get_current_value(
            &state.db,
            auth.org_id,
            &secret_ref.name,
        )
        .await?
        .ok_or_else(|| AppError::BadRequest(format!("secret '{}' not found", secret_ref.name)))?;
        let decrypted = crypto::decrypt(&enc_key, &version.encrypted_value)?;
        let value = String::from_utf8(decrypted)
            .map_err(|_| AppError::Internal("secret is not valid utf-8".into()))?;
        secret_values.insert(secret_ref.name.clone(), value);
    }

    let (resolved_url, resolved_headers) = inject_secrets(&action_req, &secret_values)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    // Streaming proxy path
    if req.prefer_stream.unwrap_or(false) {
        let upstream = http_executor::execute_streaming(
            &state.http_client,
            &action_req.method,
            &resolved_url,
            &resolved_headers,
            action_req.body.as_deref(),
        )
        .await?;

        let upstream_status = upstream.status();
        let upstream_headers = upstream.headers().clone();
        let content_length = upstream
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let _ = audit::log(
            &state.db,
            &AuditEntry {
                org_id: auth.org_id,
                identity_id: Some(identity_id),
                action: "action.streamed",
                resource_type: req.service.as_deref(),
                resource_id: None,
                detail: serde_json::json!({
                    "method": action_req.method,
                    "url": action_req.url,
                    "status_code": upstream_status.as_u16(),
                    "content_length": content_length,
                    "service": req.service,
                    "action": req.action,
                }),
                description: meta.description.as_deref(),
                ip_address: ip.0.as_deref(),
            },
        )
        .await;

        // Build streaming response — pipe upstream bytes through to caller
        let stream = upstream.bytes_stream();
        let body = axum::body::Body::from_stream(stream);

        let mut response = Response::builder().status(upstream_status.as_u16());
        // Forward safe upstream headers (content-type, content-length, content-disposition)
        for (name, value) in upstream_headers.iter() {
            let name_str = name.as_str();
            match name_str {
                "content-type"
                | "content-length"
                | "content-disposition"
                | "etag"
                | "last-modified"
                | "cache-control" => {
                    response = response.header(name, value);
                }
                _ => {}
            }
        }

        return Ok(response.body(body).unwrap());
    }

    // Buffered execution path (default)
    let result = http_executor::execute(
        &state.http_client,
        &action_req.method,
        &resolved_url,
        &resolved_headers,
        action_req.body.as_deref(),
        state.config.max_response_body_bytes,
    )
    .await
    .map_err(|e| match e {
        http_executor::ExecuteError::ResponseTooLarge {
            content_length,
            content_type,
            limit_bytes,
        } => AppError::ResponseTooLarge {
            content_length,
            content_type,
            limit_bytes,
        },
        http_executor::ExecuteError::Request(e) => AppError::Request(e),
    })?;

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: auth.org_id,
            identity_id: Some(identity_id),
            action: "action.executed",
            resource_type: req.service.as_deref(),
            resource_id: None,
            detail: serde_json::json!({
                "method": action_req.method,
                "url": action_req.url,
                "status_code": result.status_code,
                "duration_ms": result.duration_ms,
                "service": req.service,
                "action": req.action,
            }),
            description: meta.description.as_deref(),
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(ExecuteResponse::Executed {
            result,
            action_description: meta.description,
        }),
    )
        .into_response())
}

/// Resolve an ExecuteRequest into a concrete ActionRequest + metadata.
/// Handles Mode A (raw HTTP), Mode B (connection-based), and Mode C (service+action).
async fn resolve_request(
    state: &AppState,
    auth: &AuthContext,
    identity_id: Uuid,
    req: &ExecuteRequest,
) -> Result<(ActionRequest, ResolvedMeta), AppError> {
    // Mode B: explicit connection — resolve OAuth token and inject as header
    if let Some(conn_id) = req.connection {
        let conn = overslash_db::repos::connection::get_by_id(&state.db, conn_id).await?;
        let conn = crate::ownership::require_org_owned(conn, auth.org_id, "connection")?;

        let enc_key = crypto::parse_hex_key(&state.config.secrets_encryption_key)?;
        let provider_key = conn.provider_key.clone();

        let creds = crate::services::client_credentials::resolve(
            &state.db,
            &enc_key,
            auth.org_id,
            auth.identity_id,
            &provider_key,
            Some(&conn),
            None,
        )
        .await?;

        let access_token = crate::services::oauth::resolve_access_token(
            &state.db,
            &state.http_client,
            &enc_key,
            &conn,
            &creds.client_id,
            &creds.client_secret,
        )
        .await
        .map_err(|e| AppError::Internal(format!("OAuth token resolution failed: {e}")))?;

        let method = req.method.clone().unwrap_or_else(|| "GET".into());
        let url = req
            .url
            .clone()
            .ok_or_else(|| AppError::BadRequest("'url' required for connection mode".into()))?;

        let mut headers = req.headers.clone();
        headers.insert("Authorization".into(), format!("Bearer {access_token}"));

        return Ok((
            ActionRequest {
                method,
                url,
                headers,
                body: req.body.clone(),
                secrets: vec![],
            },
            ResolvedMeta {
                description: Some(format!("OAuth request via {provider_key} connection")),
                auth_injected: true,
                service_scope: None,
                risk: None,
                service_instance_owner: None,
            },
        ));
    }

    // Mode C: service + action
    if let (Some(service_key), Some(action_key)) = (&req.service, &req.action) {
        // Try to resolve through a service instance first (user-shadows-org)
        let instance = overslash_db::repos::service_instance::resolve_by_name(
            &state.db,
            auth.org_id,
            auth.identity_id,
            service_key,
        )
        .await?;

        // Resolve the template: if instance found use its template_key, else use service_key directly
        let svc =
            if let Some(ref inst) = instance {
                // Instance exists — resolve its template; propagate errors (don't fall back
                // to global registry, which could match on the wrong key)
                super::templates::resolve_template_definition(
                    state,
                    auth.org_id,
                    auth.identity_id,
                    &inst.template_key,
                )
                .await?
            } else {
                // No instance — try unified resolution, then fall back to global registry
                super::templates::resolve_template_definition(
                    state,
                    auth.org_id,
                    auth.identity_id,
                    service_key,
                )
                .await
                .or_else(|_| {
                    state.registry.get(service_key).cloned().ok_or_else(|| {
                        AppError::NotFound(format!("service '{service_key}' not found"))
                    })
                })?
            };

        let action = svc.actions.get(action_key).ok_or_else(|| {
            AppError::NotFound(format!(
                "action '{action_key}' not found in service '{service_key}'"
            ))
        })?;

        let host = svc
            .hosts
            .first()
            .ok_or_else(|| AppError::Internal(format!("service '{service_key}' has no hosts")))?;

        let mut path = action.path.clone();
        for (k, v) in &req.params {
            let placeholder = format!("{{{k}}}");
            if path.contains(&placeholder) {
                let val = v.as_str().unwrap_or(&v.to_string()).to_string();
                path = path.replace(&placeholder, &val);
            }
        }

        // Support hosts with explicit scheme (e.g. "http://localhost:1234" for tests)
        let base_url = if host.contains("://") {
            format!("{host}{path}")
        } else {
            format!("https://{host}{path}")
        };

        let non_path_params: HashMap<String, serde_json::Value> = req
            .params
            .iter()
            .filter(|(k, _)| !action.path.contains(&format!("{{{k}}}")))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let (url, body) = if action.method == "GET" || action.method == "HEAD" {
            // Append non-path params as query string
            let url = if non_path_params.is_empty() {
                base_url
            } else {
                let qs = non_path_params
                    .iter()
                    .map(|(k, v)| {
                        let val = v.as_str().unwrap_or(&v.to_string()).to_string();
                        format!("{k}={}", urlencoding::encode(&val))
                    })
                    .collect::<Vec<_>>()
                    .join("&");
                format!("{base_url}?{qs}")
            };
            (url, None)
        } else {
            // Non-path params become JSON body
            let body = if non_path_params.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&non_path_params).unwrap_or_default())
            };
            (base_url, body)
        };

        let mut headers = HashMap::new();
        if body.is_some() {
            headers.insert("Content-Type".to_string(), "application/json".to_string());
        }

        // Auth resolution: if instance has a bound connection/secret, use that;
        // otherwise fall back to auto-resolve from the template's auth config
        let (secrets, oauth_injected) = if let Some(ref inst) = instance {
            resolve_instance_auth(
                state,
                auth.org_id,
                identity_id,
                inst,
                &svc,
                &req.secrets,
                &mut headers,
            )
            .await
        } else {
            resolve_service_auth(
                state,
                auth.org_id,
                identity_id,
                &svc,
                &req.secrets,
                &mut headers,
            )
            .await
        };

        let resolver_base = if host.contains("://") {
            host.to_string()
        } else {
            format!("https://{host}")
        };
        let resolved = crate::services::param_resolver::resolve_display_params(
            &state.http_client,
            &resolver_base,
            &headers,
            action,
            &req.params,
        )
        .await;

        let interpolated = overslash_core::description::interpolate_description_with_resolved(
            &action.description,
            &req.params,
            &resolved,
        );
        let description = format!("{interpolated} ({})", svc.display_name);

        let instance_owner = instance.as_ref().and_then(|i| i.owner_identity_id);
        let action_risk = action.risk;

        return Ok((
            ActionRequest {
                method: action.method.clone(),
                url,
                headers,
                body,
                secrets,
            },
            ResolvedMeta {
                description: Some(description),
                auth_injected: oauth_injected,
                service_scope: Some(ServiceScope {
                    service_key: service_key.clone(),
                    action_key: action_key.clone(),
                    scope_param: action.scope_param.clone(),
                }),
                risk: Some(action_risk),
                service_instance_owner: instance_owner,
            },
        ));
    }

    // Mode A: raw HTTP
    let method = req.method.clone().ok_or_else(|| {
        AppError::BadRequest("either 'method'+'url' or 'service'+'action' required".into())
    })?;
    let url = req
        .url
        .clone()
        .ok_or_else(|| AppError::BadRequest("'url' required for raw HTTP mode".into()))?;

    let description = {
        let display_url = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(&url);
        format!("{method} {display_url}")
    };

    Ok((
        ActionRequest {
            method,
            url,
            headers: req.headers.clone(),
            body: req.body.clone(),
            secrets: req.secrets.clone(),
        },
        ResolvedMeta {
            description: Some(description),
            auth_injected: false,
            service_scope: None,
            risk: None,
            service_instance_owner: None,
        },
    ))
}

/// Auto-resolve auth for a service. Tries OAuth connection first, then API key secret.
/// Returns (secret_refs, oauth_was_injected).
/// If OAuth token is resolved, it's injected directly into headers (not via SecretRef).
async fn resolve_service_auth(
    state: &AppState,
    org_id: Uuid,
    identity_id: Uuid,
    svc: &overslash_core::types::ServiceDefinition,
    explicit_secrets: &[SecretRef],
    headers: &mut HashMap<String, String>,
) -> (Vec<SecretRef>, bool) {
    if !explicit_secrets.is_empty() {
        return (explicit_secrets.to_vec(), false);
    }

    // Try OAuth first: check if identity has a connection for this service's OAuth provider
    for service_auth in &svc.auth {
        if let overslash_core::types::ServiceAuth::OAuth {
            provider,
            token_injection,
        } = service_auth
        {
            if let Ok(Some(conn)) =
                overslash_db::repos::connection::find_by_provider(&state.db, identity_id, provider)
                    .await
            {
                let enc_key = match crypto::parse_hex_key(&state.config.secrets_encryption_key) {
                    Ok(k) => k,
                    Err(_) => continue,
                };
                let creds = match crate::services::client_credentials::resolve(
                    &state.db,
                    &enc_key,
                    org_id,
                    Some(identity_id),
                    provider,
                    Some(&conn),
                    None,
                )
                .await
                {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                if let Ok(access_token) = crate::services::oauth::resolve_access_token(
                    &state.db,
                    &state.http_client,
                    &enc_key,
                    &conn,
                    &creds.client_id,
                    &creds.client_secret,
                )
                .await
                {
                    // Inject directly into headers
                    let value = match &token_injection.prefix {
                        Some(p) => format!("{p}{access_token}"),
                        None => access_token,
                    };
                    if let Some(header_name) = &token_injection.header_name {
                        headers.insert(header_name.clone(), value);
                    }
                    return (vec![], true); // OAuth token injected into headers
                }
            }
        }
    }

    // Fall back to API key secret
    for service_auth in &svc.auth {
        if let overslash_core::types::ServiceAuth::ApiKey {
            default_secret_name,
            injection,
        } = service_auth
        {
            return (
                vec![SecretRef {
                    name: default_secret_name.clone(),
                    inject_as: if injection.inject_as == "query" {
                        InjectAs::Query
                    } else {
                        InjectAs::Header
                    },
                    header_name: injection.header_name.clone(),
                    query_param: injection.query_param.clone(),
                    prefix: injection.prefix.clone(),
                }],
                false, // API key via SecretRef, not OAuth
            );
        }
    }

    (Vec::new(), false)
}

/// Resolve auth for a service instance. If the instance has a bound connection_id or secret_name,
/// use that directly. Otherwise fall back to auto-resolve from the template's auth config.
async fn resolve_instance_auth(
    state: &AppState,
    org_id: Uuid,
    identity_id: Uuid,
    instance: &overslash_db::repos::service_instance::ServiceInstanceRow,
    svc: &overslash_core::types::ServiceDefinition,
    explicit_secrets: &[SecretRef],
    headers: &mut HashMap<String, String>,
) -> (Vec<SecretRef>, bool) {
    if !explicit_secrets.is_empty() {
        return (explicit_secrets.to_vec(), false);
    }

    // If instance has a bound connection, use it directly
    if let Some(conn_id) = instance.connection_id {
        if let Ok(Some(conn)) = overslash_db::repos::connection::get_by_id(&state.db, conn_id).await
        {
            let enc_key = match crypto::parse_hex_key(&state.config.secrets_encryption_key) {
                Ok(k) => k,
                Err(_) => {
                    return resolve_service_auth(
                        state,
                        org_id,
                        identity_id,
                        svc,
                        explicit_secrets,
                        headers,
                    )
                    .await;
                }
            };
            let creds = match crate::services::client_credentials::resolve(
                &state.db,
                &enc_key,
                org_id,
                Some(identity_id),
                &conn.provider_key,
                Some(&conn),
                None,
            )
            .await
            {
                Ok(c) => c,
                Err(_) => {
                    return resolve_service_auth(
                        state,
                        org_id,
                        identity_id,
                        svc,
                        explicit_secrets,
                        headers,
                    )
                    .await;
                }
            };

            if let Ok(access_token) = crate::services::oauth::resolve_access_token(
                &state.db,
                &state.http_client,
                &enc_key,
                &conn,
                &creds.client_id,
                &creds.client_secret,
            )
            .await
            {
                // Find the matching token_injection from the template's auth config
                for service_auth in &svc.auth {
                    if let overslash_core::types::ServiceAuth::OAuth {
                        provider,
                        token_injection,
                    } = service_auth
                    {
                        if *provider == conn.provider_key {
                            let value = match &token_injection.prefix {
                                Some(p) => format!("{p}{access_token}"),
                                None => access_token,
                            };
                            if let Some(header_name) = &token_injection.header_name {
                                headers.insert(header_name.clone(), value);
                            }
                            return (vec![], true);
                        }
                    }
                }
                // No matching auth config found, inject as Bearer by default
                headers.insert("Authorization".into(), format!("Bearer {access_token}"));
                return (vec![], true);
            }
        }
    }

    // If instance has a bound secret_name, use it
    if let Some(ref secret_name) = instance.secret_name {
        // Find the matching API key auth config from the template for injection settings
        for service_auth in &svc.auth {
            if let overslash_core::types::ServiceAuth::ApiKey { injection, .. } = service_auth {
                return (
                    vec![SecretRef {
                        name: secret_name.clone(),
                        inject_as: if injection.inject_as == "query" {
                            InjectAs::Query
                        } else {
                            InjectAs::Header
                        },
                        header_name: injection.header_name.clone(),
                        query_param: injection.query_param.clone(),
                        prefix: injection.prefix.clone(),
                    }],
                    false,
                );
            }
        }
        // No API key auth config in template — inject as header with no prefix
        return (
            vec![SecretRef {
                name: secret_name.clone(),
                inject_as: InjectAs::Header,
                header_name: Some("Authorization".into()),
                query_param: None,
                prefix: Some("Bearer ".into()),
            }],
            false,
        );
    }

    // No bound credentials on instance — fall back to auto-resolve
    resolve_service_auth(state, org_id, identity_id, svc, explicit_secrets, headers).await
}

fn generate_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
