//! The `service.*` stream events.
//!
//! One seam for all three, because the kernels and the REST handlers both
//! raise them: create and manage go through `kernels.rs` (so the MCP
//! `create_service` path raises them too), while the status flip and the
//! delete live in `routes/services.rs` and never reach a kernel.
//!
//! The payload is routing information, not a rendering of the instance. That
//! is the consumers' own stated contract — `dashboard/src/lib/stores/
//! events.svelte.ts` and `sdk/src/controllers/events.ts` both open with
//! "events are notifications, not state; handlers should refetch the resource
//! they care about" — and it is not laziness here: `icon_url` and
//! `test_action` are properties of the *template*, resolved per caller, and
//! an event is a historical fact that must not go stale when the template
//! behind it is edited.

use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use overslash_db::OrgScope;

use crate::services::events::{EventDraft, EventType, audience, emit};

/// One service-instance lifecycle event, before its audience is resolved.
pub(crate) struct ServiceEvent<'a> {
    pub org_id: Uuid,
    pub event_type: EventType,
    pub service_instance_id: Uuid,
    pub name: &'a str,
    /// `None` for an org-level instance. May name an agent rather than a user
    /// — [`audience::for_service`] is what turns that into the owner-user.
    pub owner_identity_id: Option<Uuid>,
    pub status: &'a str,
    /// Whoever performed the act, so the actor sees their own change even when
    /// they are not on the owner's chain (an admin editing someone else's).
    pub actor_identity_id: Option<Uuid>,
}

/// Resolve the audience and publish. Fire-and-forget past this point: [`emit`]
/// spawns, so a failure to observe never fails the request that was observed.
pub(crate) async fn fire_service_event(db: PgPool, ev: ServiceEvent<'_>) {
    let scope = OrgScope::new(ev.org_id, db.clone());
    let audience = audience::for_service(&scope, ev.owner_identity_id, ev.actor_identity_id).await;
    emit(
        db,
        EventDraft {
            org_id: ev.org_id,
            event_type: ev.event_type,
            payload: json!({
                "service_instance_id": ev.service_instance_id,
                "name": ev.name,
                "owner_identity_id": ev.owner_identity_id,
                "status": ev.status,
                "actor_identity_id": ev.actor_identity_id,
            }),
            audience,
        },
    );
}
