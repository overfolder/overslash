//! `SystemScope` SQL methods for the `events` resource.
//!
//! These are the cross-org reads: the fan-out listener forwards every row to
//! its locally-connected subscribers (which each re-apply their own visibility
//! filter in memory) and the retention sweep deletes across all orgs. Neither
//! belongs on `OrgScope`, because neither has an org to be bound to.

use time::OffsetDateTime;

use crate::repos::event::{self, EventRow};
use crate::scopes::SystemScope;

impl SystemScope {
    /// Fetch the row a `NOTIFY` announced.
    pub async fn get_event_by_cursor(&self, cursor: i64) -> Result<Option<EventRow>, sqlx::Error> {
        event::get_by_cursor(self.db(), cursor).await
    }

    /// Rows the listener missed while its connection was down.
    pub async fn get_events_after(
        &self,
        cursor: i64,
        limit: i64,
    ) -> Result<Vec<EventRow>, sqlx::Error> {
        event::get_after(self.db(), cursor, limit).await
    }

    /// Delete events older than `cutoff`. Returns the number removed.
    pub async fn prune_events(&self, cutoff: OffsetDateTime) -> Result<u64, sqlx::Error> {
        event::prune_older_than(self.db(), cutoff).await
    }
}
