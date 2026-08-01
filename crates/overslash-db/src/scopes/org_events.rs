//! `OrgScope` SQL methods for the `events` resource (the SSE stream's log).

use uuid::Uuid;

use crate::repos::event::{self, EventRow};
use crate::scopes::OrgScope;

/// Ceiling on how many rows one reconnect replays. A client that falls further
/// behind than this keeps its cursor and catches up over successive
/// reconnects rather than blocking the stream on a huge backlog.
const REPLAY_LIMIT: i64 = 200;

impl OrgScope {
    /// Append an event to the log. `audience` is the frozen list of identity
    /// ids allowed to receive it; org admins bypass it at read time. The
    /// `org_id` comes from the scope, never from the caller.
    pub async fn insert_event(
        &self,
        event_type: &str,
        topic: &str,
        payload: serde_json::Value,
        audience: &[Uuid],
    ) -> Result<EventRow, sqlx::Error> {
        event::insert(
            self.db(),
            self.org_id(),
            event_type,
            topic,
            payload,
            audience,
        )
        .await
    }

    /// Events after `cursor` that `identity_id` is allowed to see, restricted
    /// to `topics`. Visibility is enforced in SQL — see
    /// `repos::event::replay_for_identity`.
    pub async fn replay_events(
        &self,
        cursor: i64,
        identity_id: Uuid,
        is_org_admin: bool,
        topics: &[String],
    ) -> Result<Vec<EventRow>, sqlx::Error> {
        event::replay_for_identity(
            self.db(),
            self.org_id(),
            cursor,
            identity_id,
            is_org_admin,
            topics,
            REPLAY_LIMIT,
        )
        .await
    }

    /// The org's newest cursor, handed to fresh subscribers as their resume
    /// point.
    pub async fn latest_event_cursor(&self) -> Result<i64, sqlx::Error> {
        event::latest_cursor_for_org(self.db(), self.org_id()).await
    }
}
