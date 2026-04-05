use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::repos::audit::{self, AuditEntry};

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AuthContext, ClientIp},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/webhooks", post(create_webhook).get(list_webhooks))
        .route("/v1/webhooks/{id}", delete(delete_webhook))
        .route("/v1/webhooks/{id}/deliveries", get(list_deliveries))
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
    State(state): State<AppState>,
    auth: AuthContext,
    ip: ClientIp,
    Json(req): Json<CreateWebhookRequest>,
) -> Result<Json<WebhookResponse>> {
    // Generate a signing secret for this subscription
    use rand::RngCore;
    let mut secret_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut secret_bytes);
    let secret = hex::encode(secret_bytes);

    let row = overslash_db::repos::webhook::create_subscription(
        &state.db,
        auth.org_id,
        &req.url,
        &req.events,
        &secret,
    )
    .await?;

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "webhook.created",
            resource_type: Some("webhook"),
            resource_id: Some(row.id),
            detail: serde_json::json!({ "url": &row.url, "events": &row.events }),
            description: None,
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(Json(WebhookResponse {
        id: row.id,
        url: row.url,
        events: row.events,
        active: row.active,
    }))
}

async fn list_webhooks(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<Vec<WebhookResponse>>> {
    let rows = overslash_db::repos::webhook::list_by_org(&state.db, auth.org_id).await?;
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
    State(state): State<AppState>,
    auth: AuthContext,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let deleted =
        overslash_db::repos::webhook::delete_subscription(&state.db, id, auth.org_id).await?;

    if deleted {
        let _ = overslash_db::repos::audit::log(
            &state.db,
            &overslash_db::repos::audit::AuditEntry {
                org_id: auth.org_id,
                identity_id: auth.identity_id,
                action: "webhook.deleted",
                resource_type: Some("webhook"),
                resource_id: Some(id),
                detail: serde_json::json!({}),
                description: None,
                ip_address: ip.0.as_deref(),
            },
        )
        .await;
    }

    Ok(Json(serde_json::json!({ "deleted": deleted })))
}

// ── Delivery log ────────────────────────────────────────────────────

#[derive(Deserialize)]
struct DeliveryQuery {
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Serialize)]
struct DeliveryResponse {
    id: Uuid,
    subscription_id: Uuid,
    event: String,
    status_code: Option<i32>,
    response_body: Option<String>,
    attempts: i32,
    delivered_at: Option<String>,
    created_at: String,
}

async fn list_deliveries(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Query(query): Query<DeliveryQuery>,
) -> Result<Json<Vec<DeliveryResponse>>> {
    // Verify the subscription belongs to this org
    let subs = overslash_db::repos::webhook::list_by_org(&state.db, auth.org_id).await?;
    if !subs.iter().any(|s| s.id == id) {
        return Err(AppError::NotFound("webhook not found".into()));
    }

    let limit = query.limit.clamp(1, 200);
    let rows =
        overslash_db::repos::webhook::list_deliveries_by_subscription(&state.db, id, limit).await?;

    Ok(Json(
        rows.into_iter()
            .map(|r| DeliveryResponse {
                id: r.id,
                subscription_id: r.subscription_id,
                event: r.event,
                status_code: r.status_code,
                response_body: r.response_body,
                attempts: r.attempts,
                delivered_at: r.delivered_at.map(|d| d.to_string()),
                created_at: r.created_at.to_string(),
            })
            .collect(),
    ))
}
