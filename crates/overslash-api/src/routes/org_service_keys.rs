//! Org Service Keys — long-lived `osk_…` API keys minted from the
//! dashboard's Org Settings page for org-level automation (CI, cron,
//! server-side integrations).
//!
//! All keys minted here bind to a single shared per-org Agent identity
//! (`overslash:org-service`) auto-created on first use and attached to
//! the org's Admins group. Both plain and impersonate-capable keys use
//! the same binding — the impersonation power therefore lives on a
//! synthetic shared actor rather than an individual person.
//!
//! Audit-log provenance is the load-bearing compensating control.
//! Three audit shapes participate:
//!   1. `org_service_agent.created` — once, on the very first call,
//!      `identity_id = <human minter>`.
//!   2. `api_key.created` — every call, `identity_id = <human minter>`,
//!      `detail.bound_to_identity_id = <agent.id>`,
//!      `detail.kind = "org_service_key"`.
//!   3. `api_key.revoked` — every revoke, `identity_id = <human revoker>`.
//!
//! Runtime impersonation rows already capture `impersonated_by` (the
//! org-service agent) via `OrgScope::new_impersonated`. The audit chain
//! to a real human is therefore:
//!     impersonated row → impersonator (agent) → matching api_key.created
//!     row → minter (human admin).
//! Any change to these audit shapes breaks attribution; coordinate with
//! the dashboard's audit log views before touching them.

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use overslash_db::OrgScope;
use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::identity::ORG_SERVICE_EXTERNAL_ID;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, ClientIp},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/org-service-keys", get(list).post(create))
        .route("/v1/org-service-keys/{id}/revoke", post(revoke))
}

/// Pseudo-scope tagged on every key minted from this endpoint. Lets the
/// list/revoke endpoints filter to "service keys" without a schema column.
const SERVICE_SCOPE: &str = "service";
const IMPERSONATE_SCOPE: &str = "impersonate";

#[derive(Deserialize)]
struct CreateRequest {
    org_id: Uuid,
    name: String,
    #[serde(default)]
    allow_impersonate: bool,
}

#[derive(Serialize)]
struct CreateResponse {
    id: Uuid,
    identity_id: Uuid,
    /// Plaintext `osk_…`. Returned exactly once.
    key: String,
    key_prefix: String,
    name: String,
    scopes: Vec<String>,
}

#[derive(Serialize)]
struct ServiceKeySummary {
    id: Uuid,
    identity_id: Uuid,
    name: String,
    key_prefix: String,
    scopes: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    last_used_at: Option<OffsetDateTime>,
}

async fn create(
    State(state): State<AppState>,
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Json(req): Json<CreateRequest>,
) -> Result<Json<CreateResponse>> {
    if req.org_id != acl.org_id {
        return Err(AppError::Forbidden(
            "org_id must match the authenticated org".into(),
        ));
    }
    let minter_id = acl
        .identity_id
        .ok_or_else(|| AppError::Forbidden("identity-bound credential required".into()))?;
    let trimmed_name = req.name.trim();
    if trimmed_name.is_empty() {
        return Err(AppError::BadRequest("name is required".into()));
    }

    let (agent, agent_created) =
        overslash_db::repos::identity::get_or_create_org_service_agent(&state.db, req.org_id)
            .await?;

    if agent_created {
        let _ = scope
            .log_audit(AuditEntry {
                org_id: req.org_id,
                identity_id: Some(minter_id),
                action: "org_service_agent.created",
                resource_type: Some("identity"),
                resource_id: Some(agent.id),
                detail: serde_json::json!({
                    "external_id": ORG_SERVICE_EXTERNAL_ID,
                    "kind": "agent",
                    "name": "org-service",
                }),
                description: Some("Auto-created shared org-service agent for first service key"),
                ip_address: ip.0.as_deref(),
            })
            .await;
    }

    let mut scopes: Vec<String> = vec![SERVICE_SCOPE.to_string()];
    if req.allow_impersonate {
        scopes.push(IMPERSONATE_SCOPE.to_string());
    }

    let (raw_key, key_hash, key_prefix) = super::api_keys::generate_api_key()?;

    let row = scope
        .create_api_key(agent.id, trimmed_name, &key_hash, &key_prefix, &scopes)
        .await?;

    let _ = scope
        .log_audit(AuditEntry {
            org_id: req.org_id,
            identity_id: Some(minter_id),
            action: "api_key.created",
            resource_type: Some("api_key"),
            resource_id: Some(row.id),
            detail: serde_json::json!({
                "name": &row.name,
                "key_prefix": &key_prefix,
                "scopes": &row.scopes,
                "bound_to_identity_id": agent.id,
                "kind": "org_service_key",
            }),
            description: Some(if req.allow_impersonate {
                "Created impersonation-capable org service key"
            } else {
                "Created org service key"
            }),
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(CreateResponse {
        id: row.id,
        identity_id: agent.id,
        key: raw_key,
        key_prefix,
        name: row.name,
        scopes: row.scopes,
    }))
}

async fn list(AdminAcl(_): AdminAcl, scope: OrgScope) -> Result<Json<Vec<ServiceKeySummary>>> {
    let rows = scope.list_api_keys().await?;
    let out = rows
        .into_iter()
        .filter(|r| r.scopes.iter().any(|s| s == SERVICE_SCOPE))
        .map(|r| ServiceKeySummary {
            id: r.id,
            identity_id: r.identity_id,
            name: r.name,
            key_prefix: r.key_prefix,
            scopes: r.scopes,
            created_at: r.created_at,
            last_used_at: r.last_used_at,
        })
        .collect();
    Ok(Json(out))
}

async fn revoke(
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    let revoker_id = acl
        .identity_id
        .ok_or_else(|| AppError::Forbidden("identity-bound credential required".into()))?;

    let rows = scope.list_api_keys().await?;
    let target = rows
        .into_iter()
        .find(|r| r.id == id)
        .ok_or_else(|| AppError::NotFound("service key not found".into()))?;

    // Defence in depth: this endpoint must not be a backdoor for revoking
    // arbitrary user-bound keys. Only keys carrying the SERVICE_SCOPE tag
    // are reachable through here.
    if !target.scopes.iter().any(|s| s == SERVICE_SCOPE) {
        return Err(AppError::NotFound("service key not found".into()));
    }

    let revoked = scope.revoke_api_key(id).await?;
    if !revoked {
        // Already revoked between list and revoke — surface as 404 so the UI
        // refreshes rather than swallowing silently.
        return Err(AppError::NotFound("service key not found".into()));
    }

    let _ = scope
        .log_audit(AuditEntry {
            org_id: acl.org_id,
            identity_id: Some(revoker_id),
            action: "api_key.revoked",
            resource_type: Some("api_key"),
            resource_id: Some(target.id),
            detail: serde_json::json!({
                "name": &target.name,
                "key_prefix": &target.key_prefix,
                "scopes": &target.scopes,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(StatusCode::NO_CONTENT)
}
