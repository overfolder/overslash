//! The single seam through which every Overslash event leaves the system.
//!
//! SPEC.md §10 promises that "the same event payload is delivered regardless of
//! transport", which only holds if there is one place that decides an event
//! happened. [`emit`] is that place: it appends to the durable log that feeds
//! the SSE stream *and* hands the identical payload to the webhook dispatcher.
//! Call sites do not choose a transport, and adding a third one later means
//! editing this function rather than hunting call sites again.

pub mod audience;
pub mod bus;
pub mod types;

use sqlx::PgPool;
use uuid::Uuid;

use overslash_db::OrgScope;

pub use bus::{ConnPermit, EventBus, run_pg_listener, run_prune_loop};
pub use types::{EventType, Topic, parse_topics};

/// One event, ready to publish.
pub struct EventDraft {
    pub org_id: Uuid,
    pub event_type: EventType,
    /// The `data` object of the wire envelope — identical across transports.
    /// Must never carry a credential: webhook subscriptions are org-wide, so
    /// anything in here is visible to any operator who can configure a hook.
    pub payload: serde_json::Value,
    /// Identity ids allowed to receive this over the stream. Does not affect
    /// webhook delivery, which is org-scoped by subscription.
    pub audience: Vec<Uuid>,
}

/// Publish an event to every transport. Fire-and-forget by design — matching
/// the webhook dispatcher it replaces, an observer failing must not fail the
/// request that was observed.
///
/// The two transports are independent: a failed log append still attempts
/// webhook delivery, and vice versa.
pub fn emit(pool: PgPool, http_client: reqwest::Client, draft: EventDraft) {
    tokio::spawn(async move {
        let event = draft.event_type.as_str();

        let org = OrgScope::new(draft.org_id, pool.clone());
        if let Err(e) = org
            .insert_event(
                event,
                draft.event_type.topic().as_str(),
                draft.payload.clone(),
                &draft.audience,
            )
            .await
        {
            tracing::error!("failed to append {event} to the event log: {e}");
        }

        super::webhook_dispatcher::dispatch(
            &pool,
            &http_client,
            draft.org_id,
            event,
            draft.payload,
        )
        .await;
    });
}
