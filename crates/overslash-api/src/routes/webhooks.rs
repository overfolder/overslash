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
use overslash_db::repos::webhook::WebhookSubscriptionRow;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, ClientIp, OrgAcl},
    services::{https_policy::HttpsUrl, webhook_dispatcher},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/webhooks", post(create_webhook).get(list_webhooks))
        .route("/v1/webhooks/{id}", delete(delete_webhook))
        .route("/v1/webhooks/{id}/verify", post(verify_webhook))
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
    /// Set when the platform switched the subscription off. `needs_https`: the
    /// URL is plain `http://`, registered before HTTPS was enforced; nothing is
    /// delivered to it. Replace it with an `https://` subscription.
    #[serde(skip_serializing_if = "Option::is_none")]
    disabled_reason: Option<String>,
    #[serde(flatten)]
    verification: VerificationView,
}

/// Endpoint-ownership state (CASA 7.1.2), on every subscription response.
#[derive(Serialize)]
struct VerificationView {
    /// `pending_verification` until the endpoint echoes the challenge; only
    /// `verified` subscriptions are delivered to. Events raised while pending
    /// are held, and sent once it verifies.
    verification_status: String,
    #[serde(with = "time::serde::rfc3339::option")]
    verified_at: Option<OffsetDateTime>,
    /// Verified by migration because it predates the handshake, not by
    /// echoing a challenge. Cleared by `POST /v1/webhooks/{id}/verify`.
    grandfathered: bool,
    /// Why the last handshake failed; absent after a success.
    #[serde(skip_serializing_if = "Option::is_none")]
    verification_error: Option<String>,
}

impl From<&WebhookSubscriptionRow> for VerificationView {
    fn from(r: &WebhookSubscriptionRow) -> Self {
        Self {
            verification_status: r.verification_status.clone(),
            verified_at: r.verified_at,
            grandfathered: r.grandfathered,
            verification_error: r.verification_error.clone(),
        }
    }
}

impl From<WebhookSubscriptionRow> for WebhookResponse {
    fn from(r: WebhookSubscriptionRow) -> Self {
        let verification = VerificationView::from(&r);
        Self {
            id: r.id,
            url: r.url,
            events: r.events,
            active: r.active,
            disabled_reason: r.disabled_reason,
            verification,
        }
    }
}

#[derive(Serialize)]
struct WebhookCreatedResponse {
    id: Uuid,
    url: String,
    events: Vec<String>,
    active: bool,
    /// HMAC signing secret. Returned only on creation; never re-fetchable.
    secret: String,
    #[serde(flatten)]
    verification: VerificationView,
}

async fn create_webhook(
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Json(req): Json<CreateWebhookRequest>,
) -> Result<Json<WebhookCreatedResponse>> {
    let auth = acl;
    // CASA 7.1.1: webhook traffic is HTTPS-only. Plain http survives only to a
    // loopback host the SSRF allow-list already opens (tests, self-hosters).
    let url = HttpsUrl::parse(&req.url)
        .map_err(|e| AppError::BadRequest(format!("invalid webhook url: {e}")))?;

    // Generate a signing secret for this subscription
    use rand::RngExt;
    let mut secret_bytes = [0u8; 32];
    rand::rng().fill(&mut secret_bytes);
    let secret = hex::encode(secret_bytes);

    let row = scope
        .create_webhook_subscription(url.as_str(), &req.events, &secret)
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

    // CASA 7.1.2: the subscription is stored `pending_verification` and the
    // handshake runs before we answer, so the registrant sees the outcome.
    // A failure is not an error here — the subscription exists, receives
    // nothing, and can be re-checked with `POST /v1/webhooks/{id}/verify`.
    // Deleted by someone else while the handshake was in flight: creation
    // still succeeded, so answer with the row as stored rather than a 404.
    let row = match run_verification(&scope, &auth, &ip, &row).await? {
        Some(updated) => updated,
        None => row,
    };

    Ok(Json(WebhookCreatedResponse {
        verification: VerificationView::from(&row),
        id: row.id,
        url: row.url,
        events: row.events,
        active: row.active,
        secret,
    }))
}

/// `POST /v1/webhooks/{id}/verify` — run the ownership handshake again.
///
/// For a pending subscription whose endpoint was not ready at registration
/// (it rejected the unsigned-to-it challenge, or was not deployed yet), and
/// for a grandfathered one whose owner wants it verified for real. A success
/// verifies it and releases held deliveries; a failure is recorded in
/// `verification_error` and leaves the status as it was, so a re-check can
/// never cut off a subscription that is already receiving events.
async fn verify_webhook(
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<WebhookResponse>> {
    let row = scope
        .get_webhook_subscription(id)
        .await?
        .ok_or_else(|| AppError::NotFound("webhook not found".into()))?;
    if !row.active {
        return Err(AppError::BadRequest(format!(
            "webhook is disabled ({}); it cannot be verified",
            row.disabled_reason.as_deref().unwrap_or("inactive")
        )));
    }
    let row = run_verification(&scope, &acl, &ip, &row)
        .await?
        .ok_or_else(|| AppError::NotFound("webhook not found".into()))?;
    Ok(Json(row.into()))
}

/// Challenge the subscription's endpoint and record the outcome, audited.
/// No DB connection is held across the outbound request. `None` when the
/// subscription was deleted (or, for a success, re-pointed) while the
/// handshake was in flight — there is nothing left to record it on.
async fn run_verification(
    scope: &OrgScope,
    acl: &OrgAcl,
    ip: &ClientIp,
    row: &WebhookSubscriptionRow,
) -> Result<Option<WebhookSubscriptionRow>> {
    let outcome = webhook_dispatcher::verify_endpoint(&row.url, &row.secret).await;
    let was_grandfathered = row.grandfathered;
    let (updated, action, detail) = match &outcome {
        Ok(()) => (
            scope.mark_webhook_verified(row.id, &row.url).await?,
            "webhook.verified",
            serde_json::json!({ "url": &row.url, "was_grandfathered": was_grandfathered }),
        ),
        Err(reason) => (
            scope
                .record_webhook_verification_failure(row.id, reason)
                .await?,
            "webhook.verification_failed",
            serde_json::json!({ "url": &row.url, "error": reason }),
        ),
    };
    let Some(updated) = updated else {
        return Ok(None);
    };

    let _ = scope
        .log_audit(AuditEntry {
            org_id: scope.org_id(),
            identity_id: acl.identity_id,
            action,
            resource_type: Some("webhook"),
            resource_id: Some(updated.id),
            detail,
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Some(updated))
}

async fn list_webhooks(scope: OrgScope) -> Result<Json<Vec<WebhookResponse>>> {
    let rows = scope.list_webhook_subscriptions().await?;
    Ok(Json(rows.into_iter().map(WebhookResponse::from).collect()))
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
    /// `pending_verification`: raised before the subscription verified, so
    /// not sent yet. Released to delivery when it verifies.
    #[serde(skip_serializing_if = "Option::is_none")]
    held_reason: Option<String>,
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
                held_reason: r.held_reason,
            })
            .collect(),
    ))
}
