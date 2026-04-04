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
    permissions::{PermissionKey, PermissionResult, check_permissions},
    secret_injection::inject_secrets,
    types::{ActionRequest, ActionResult, InjectAs, PermissionEffect, PermissionRule, SecretRef},
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

async fn execute_action(
    State(state): State<AppState>,
    auth: AuthContext,
    ip: ClientIp,
    Json(req): Json<ExecuteRequest>,
) -> Result<Response, AppError> {
    let identity_id = auth
        .identity_id
        .ok_or_else(|| AppError::BadRequest("api key must be bound to an identity".into()))?;

    // Resolve the request to a concrete ActionRequest
    // `auth_injected` is true when OAuth tokens were resolved and injected into headers
    let (action_req, description, auth_injected) =
        resolve_request(&state, &auth, identity_id, &req).await?;

    // Derive permission keys
    let perm_keys = PermissionKey::from_http(&action_req.method, &action_req.url);

    // Gate if any auth is involved: secrets, connection, or OAuth token injected
    let needs_gate = !action_req.secrets.is_empty() || req.connection.is_some() || auth_injected;

    if needs_gate {
        let rule_rows =
            overslash_db::repos::permission_rule::list_by_identity(&state.db, identity_id).await?;

        let rules: Vec<PermissionRule> = rule_rows
            .into_iter()
            .map(|r| PermissionRule {
                id: r.id,
                org_id: r.org_id,
                identity_id: r.identity_id,
                action_pattern: r.action_pattern,
                effect: if r.effect == "deny" {
                    PermissionEffect::Deny
                } else {
                    PermissionEffect::Allow
                },
                created_at: r.created_at,
            })
            .collect();

        match check_permissions(&rules, &perm_keys) {
            PermissionResult::Allowed => {}
            PermissionResult::NeedsApproval(uncovered) => {
                let token = generate_token();
                let expires_at = time::OffsetDateTime::now_utc()
                    + time::Duration::seconds(state.config.approval_expiry_secs as i64);
                let summary = description
                    .clone()
                    .unwrap_or_else(|| format!("{} {}", action_req.method, action_req.url));
                let keys: Vec<String> = uncovered.iter().map(|k| k.0.clone()).collect();

                let approval = overslash_db::repos::approval::create(
                    &state.db,
                    &overslash_db::repos::approval::CreateApproval {
                        org_id: auth.org_id,
                        identity_id,
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
                        detail: serde_json::json!({ "summary": summary }),
                        ip_address: ip.0.as_deref(),
                    },
                )
                .await;

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
            PermissionResult::Denied(reason) => {
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
                resource_type: None,
                resource_id: None,
                detail: serde_json::json!({
                    "method": action_req.method,
                    "url": action_req.url,
                    "status_code": upstream_status.as_u16(),
                    "content_length": content_length,
                }),
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
                "description": description,
                "service": req.service,
                "action": req.action,
            }),
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(ExecuteResponse::Executed {
            result,
            action_description: description,
        }),
    )
        .into_response())
}

/// Resolve an ExecuteRequest into a concrete ActionRequest + human-readable description.
/// Handles Mode A (raw HTTP), Mode B (connection-based), and Mode C (service+action).
async fn resolve_request(
    state: &AppState,
    auth: &AuthContext,
    identity_id: Uuid,
    req: &ExecuteRequest,
) -> Result<(ActionRequest, Option<String>, bool), AppError> {
    // Returns: (request, description, auth_was_injected)
    // Mode B: explicit connection — resolve OAuth token and inject as header
    if let Some(conn_id) = req.connection {
        let conn = overslash_db::repos::connection::get_by_id(&state.db, conn_id)
            .await?
            .ok_or_else(|| AppError::NotFound("connection not found".into()))?;

        // Verify ownership
        if conn.org_id != auth.org_id {
            return Err(AppError::Forbidden(
                "connection belongs to another org".into(),
            ));
        }

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
            Some(format!("OAuth request via {provider_key} connection")),
            true, // auth was injected
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

        let description = format!("{} ({})", action.description, svc.display_name);

        return Ok((
            ActionRequest {
                method: action.method.clone(),
                url,
                headers,
                body,
                secrets,
            },
            Some(description),
            oauth_injected,
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

    Ok((
        ActionRequest {
            method,
            url,
            headers: req.headers.clone(),
            body: req.body.clone(),
            secrets: req.secrets.clone(),
        },
        None,
        false, // no OAuth injection in raw HTTP mode
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
