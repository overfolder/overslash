use std::collections::HashMap;

use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::post};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{AppState, error::AppError, extractors::AuthContext, services::http_executor};
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
    Json(req): Json<ExecuteRequest>,
) -> Result<impl IntoResponse, AppError> {
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

                let _ = overslash_db::repos::audit::log(
                    &state.db,
                    auth.org_id,
                    Some(identity_id),
                    "approval.created",
                    Some("approval"),
                    Some(approval.id),
                    serde_json::json!({ "summary": summary }),
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
                ));
            }
            PermissionResult::Denied(reason) => {
                return Ok((
                    StatusCode::FORBIDDEN,
                    Json(ExecuteResponse::Denied { reason }),
                ));
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

    // Execute
    let result = http_executor::execute(
        &state.http_client,
        &action_req.method,
        &resolved_url,
        &resolved_headers,
        action_req.body.as_deref(),
    )
    .await?;

    let _ = overslash_db::repos::audit::log(
        &state.db,
        auth.org_id,
        Some(identity_id),
        "action.executed",
        None,
        None,
        serde_json::json!({
            "method": action_req.method,
            "url": action_req.url,
            "status_code": result.status_code,
            "duration_ms": result.duration_ms,
        }),
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(ExecuteResponse::Executed {
            result,
            action_description: description,
        }),
    ))
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

        // Get client credentials for token refresh
        let client_id = std::env::var(format!("OAUTH_{}_CLIENT_ID", provider_key.to_uppercase()))
            .unwrap_or_default();
        let client_secret = std::env::var(format!(
            "OAUTH_{}_CLIENT_SECRET",
            provider_key.to_uppercase()
        ))
        .unwrap_or_default();

        let access_token = crate::services::oauth::resolve_access_token(
            &state.db,
            &state.http_client,
            &enc_key,
            &conn,
            &client_id,
            &client_secret,
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
        let svc = state
            .registry
            .get(service_key)
            .ok_or_else(|| AppError::NotFound(format!("service '{service_key}' not found")))?;

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

        let url = format!("https://{host}{path}");

        let body = if action.method != "GET" && action.method != "HEAD" {
            let body_params: HashMap<String, serde_json::Value> = req
                .params
                .iter()
                .filter(|(k, _)| !action.path.contains(&format!("{{{k}}}")))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            if body_params.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&body_params).unwrap_or_default())
            }
        } else {
            None
        };

        let mut headers = HashMap::new();
        if body.is_some() {
            headers.insert("Content-Type".to_string(), "application/json".to_string());
        }

        // Auto-resolve auth: try OAuth connection first, then API key secret
        let (secrets, oauth_injected) =
            resolve_service_auth(state, identity_id, svc, &req.secrets, &mut headers).await;

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
            oauth_injected, // true if OAuth token was injected into headers
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
                let client_id =
                    std::env::var(format!("OAUTH_{}_CLIENT_ID", provider.to_uppercase()))
                        .unwrap_or_default();
                let client_secret =
                    std::env::var(format!("OAUTH_{}_CLIENT_SECRET", provider.to_uppercase()))
                        .unwrap_or_default();

                if let Ok(access_token) = crate::services::oauth::resolve_access_token(
                    &state.db,
                    &state.http_client,
                    &enc_key,
                    &conn,
                    &client_id,
                    &client_secret,
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

fn generate_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
