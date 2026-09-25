//! `OrgScope` SQL methods for the `webhooks` resource.
//!
//! Webhook subscriptions are org-owned. Subscription mutations and matching
//! lookups all funnel through `self.org_id()` so a row id from another tenant
//! can never be touched. Per-delivery operations (`create_delivery`,
//! `mark_delivered`, `mark_failed`) and the cross-org `get_pending_deliveries`
//! sweep live on `SystemScope` because they are driven by the background
//! webhook dispatcher loop, which iterates across all orgs.

use uuid::Uuid;

use crate::repos::webhook::{WebhookDeliveryRow, WebhookSubscriptionRow};
use crate::scopes::OrgScope;

impl OrgScope {
    /// Create a webhook subscription in this org.
    pub async fn create_webhook_subscription(
        &self,
        url: &str,
        events: &[String],
        secret: &str,
    ) -> Result<WebhookSubscriptionRow, sqlx::Error> {
        crate::repos::webhook::create_subscription(self.db(), self.org_id(), url, events, secret)
            .await
    }

    /// List this org's webhook subscriptions, including ones the platform
    /// disabled (`active = false`, with `disabled_reason`) — the owner has to
    /// see those to replace them.
    pub async fn list_webhook_subscriptions(
        &self,
    ) -> Result<Vec<WebhookSubscriptionRow>, sqlx::Error> {
        crate::repos::webhook::list_by_org(self.db(), self.org_id()).await
    }

    /// Delete a webhook subscription, scoped to this org. Returns `false`
    /// if the id belongs to another tenant.
    pub async fn delete_webhook_subscription(&self, id: Uuid) -> Result<bool, sqlx::Error> {
        crate::repos::webhook::delete_subscription(self.db(), id, self.org_id()).await
    }

    /// List recent deliveries for a subscription in this org. Returns `None`
    /// if the subscription does not exist or belongs to another tenant.
    pub async fn list_webhook_deliveries(
        &self,
        subscription_id: Uuid,
        limit: i64,
    ) -> Result<Option<Vec<WebhookDeliveryRow>>, sqlx::Error> {
        crate::repos::webhook::list_deliveries_for_subscription(
            self.db(),
            subscription_id,
            self.org_id(),
            limit,
        )
        .await
    }

    /// Fetch one subscription in this org, or `None` for another tenant's id.
    pub async fn get_webhook_subscription(
        &self,
        id: Uuid,
    ) -> Result<Option<WebhookSubscriptionRow>, sqlx::Error> {
        crate::repos::webhook::get_subscription(self.db(), id, self.org_id()).await
    }

    /// Mark a subscription verified after its endpoint echoed the challenge
    /// sent to `url`, and release the deliveries held while it was pending.
    /// `None` if it is gone or its URL no longer matches.
    pub async fn mark_webhook_verified(
        &self,
        id: Uuid,
        url: &str,
    ) -> Result<Option<WebhookSubscriptionRow>, sqlx::Error> {
        crate::repos::webhook::mark_verified(self.db(), id, self.org_id(), url).await
    }

    /// Record why a verification handshake failed; the status is unchanged.
    pub async fn record_webhook_verification_failure(
        &self,
        id: Uuid,
        error: &str,
    ) -> Result<Option<WebhookSubscriptionRow>, sqlx::Error> {
        crate::repos::webhook::record_verification_failure(self.db(), id, self.org_id(), error)
            .await
    }

    /// Find active subscriptions in this org listening for the given event —
    /// verified or not; the dispatcher holds events for a pending one.
    pub async fn find_matching_webhook_subscriptions(
        &self,
        event: &str,
    ) -> Result<Vec<WebhookSubscriptionRow>, sqlx::Error> {
        crate::repos::webhook::find_matching_subscriptions(self.db(), self.org_id(), event).await
    }
}
