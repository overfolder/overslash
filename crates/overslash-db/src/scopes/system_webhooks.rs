//! `SystemScope` SQL methods for cross-org webhook delivery.
//!
//! The webhook dispatcher is a background loop that polls for pending
//! deliveries across every org and updates their status. It has no caller
//! org context, so these methods live on `SystemScope`. Per-delivery rows
//! still inherit their org via the `subscription_id` foreign key — the
//! dispatcher is trusted to act on whichever org's row it pulls.

use uuid::Uuid;

use crate::repos::webhook::{PendingDeliveryRow, WebhookDeliveryRow};
use crate::scopes::SystemScope;

impl SystemScope {
    /// Insert a delivery row for an existing subscription. Used by the
    /// dispatcher fan-out, which has already resolved the subscription
    /// from `find_matching_webhook_subscriptions` on the per-org scope.
    pub async fn create_webhook_delivery(
        &self,
        subscription_id: Uuid,
        event: &str,
        payload: serde_json::Value,
    ) -> Result<WebhookDeliveryRow, sqlx::Error> {
        crate::repos::webhook::create_delivery(self.db(), subscription_id, event, payload).await
    }

    /// Mark a delivery as successfully delivered.
    pub async fn mark_webhook_delivered(
        &self,
        id: Uuid,
        status_code: i32,
        body: &str,
    ) -> Result<(), sqlx::Error> {
        crate::repos::webhook::mark_delivered(self.db(), id, status_code, body).await
    }

    /// Mark a delivery as failed and bump the retry counter.
    pub async fn mark_webhook_failed(
        &self,
        id: Uuid,
        status_code: Option<i32>,
        error: &str,
    ) -> Result<(), sqlx::Error> {
        crate::repos::webhook::mark_failed(self.db(), id, status_code, error).await
    }

    /// Pull pending webhook deliveries across all orgs for retry.
    pub async fn get_pending_webhook_deliveries(
        &self,
        limit: i64,
    ) -> Result<Vec<PendingDeliveryRow>, sqlx::Error> {
        crate::repos::webhook::get_pending_deliveries(self.db(), limit).await
    }
}
