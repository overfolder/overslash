use axum::{
    Json, Router,
    extract::Path,
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use overslash_db::OrgScope;
use overslash_db::repos::audit::AuditEntry;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, ClientIp},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/webhooks", post(create_webhook).get(list_webhooks))
        .route("/v1/webhooks/{id}", delete(delete_webhook))
        .route("/v1/webhooks/{id}/deliveries", get(list_webhook_deliveries))
}

#[derive(Deserialize)]
struct CreateWebhookRequest {
    url: String,
    events: Vec<String>,
}

#[derive(Serialize)]
struct WebhookResponse {
    id: Uuid,
    url: String,
    events: Vec<String>,
    active: bool,
}

async fn create_webhook(
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Json(req): Json<CreateWebhookRequest>,
) -> Result<Json<WebhookResponse>> {
    let auth = acl;
    // Generate a signing secret for this subscription
    use rand::RngCore;
    let mut secret_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut secret_bytes);
    let secret = hex::encode(secret_bytes);

    let row = scope
        .create_webhook_subscription(&req.url, &req.events, &secret)
        .await?;

    let _ = scope
        .log_audit(AuditEntry {
            org_id: scope.org_id(),
            identity_id: auth.identity_id,
            action: "webhook.created",
            resource_type: Some("webhook"),
            resource_id: Some(row.id),
            detail: serde_json::json!({ "url": &row.url, "events": &row.events }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(WebhookResponse {
        id: row.id,
        url: row.url,
        events: row.events,
        active: row.active,
    }))
}

async fn list_webhooks(scope: OrgScope) -> Result<Json<Vec<WebhookResponse>>> {
    let rows = scope.list_webhook_subscriptions().await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| WebhookResponse {
                id: r.id,
                url: r.url,
                events: r.events,
                active: r.active,
            })
            .collect(),
    ))
}

async fn delete_webhook(
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let auth = acl;
    let deleted = scope.delete_webhook_subscription(id).await?;

    if deleted {
        let _ = scope
            .log_audit(AuditEntry {
                org_id: scope.org_id(),
                identity_id: auth.identity_id,
                action: "webhook.deleted",
                resource_type: Some("webhook"),
                resource_id: Some(id),
                detail: serde_json::json!({}),
                description: None,
                ip_address: ip.0.as_deref(),
            })
            .await;
    }

    Ok(Json(serde_json::json!({ "deleted": deleted })))
}

#[derive(Serialize)]
struct WebhookDeliveryResponse {
    id: Uuid,
    event: String,
    status_code: Option<i32>,
    attempts: i32,
    #[serde(with = "time::serde::rfc3339::option")]
    delivered_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    next_retry_at: Option<OffsetDateTime>,
}

async fn list_webhook_deliveries(
    AdminAcl(_acl): AdminAcl,
    scope: OrgScope,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<WebhookDeliveryResponse>>> {
    let rows = scope
        .list_webhook_deliveries(id, 50)
        .await?
        .ok_or_else(|| AppError::NotFound("webhook not found".into()))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| WebhookDeliveryResponse {
                id: r.id,
                event: r.event,
                status_code: r.status_code,
                attempts: r.attempts,
                delivered_at: r.delivered_at,
                created_at: r.created_at,
                next_retry_at: r.next_retry_at,
            })
            .collect(),
    ))
}
