//! `UserScope` SQL methods for the caller's `preferences` JSONB column.
//!
//! Preferences live on `identities.preferences` and are read/written only by
//! the owning user. Both methods filter by `(id = self.user_id AND
//! org_id = self.org_id)` so a session for user A in org X can never touch
//! user B's row, even if a bug elsewhere were to feed in the wrong id.

use crate::repos::identity::IdentityRow;
use crate::scopes::UserScope;

impl UserScope {
    /// Load the caller's own identity row.
    pub async fn get_self_identity(&self) -> Result<Option<IdentityRow>, sqlx::Error> {
        sqlx::query_as!(
            IdentityRow,
            "SELECT id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, created_at, updated_at
             FROM identities WHERE id = $1 AND org_id = $2",
            self.user_id(),
            self.org_id(),
        )
        .fetch_optional(self.db())
        .await
    }

    /// Atomically merge a JSON patch into the caller's `preferences` column.
    /// `merge_fn` runs against the *current* stored preferences inside a
    /// `SELECT ... FOR UPDATE` so two concurrent PUTs touching different
    /// keys cannot clobber each other.
    pub async fn update_self_preferences<F>(
        &self,
        merge_fn: F,
    ) -> Result<Option<IdentityRow>, sqlx::Error>
    where
        F: FnOnce(&serde_json::Value) -> serde_json::Value,
    {
        let mut tx = self.db().begin().await?;
        let existing = sqlx::query_scalar!(
            "SELECT preferences FROM identities WHERE id = $1 AND org_id = $2 FOR UPDATE",
            self.user_id(),
            self.org_id(),
        )
        .fetch_optional(&mut *tx)
        .await?;
        let Some(existing) = existing else {
            return Ok(None);
        };
        let merged = merge_fn(&existing);
        let row = sqlx::query_as!(
            IdentityRow,
            "UPDATE identities SET preferences = $3, updated_at = now()
             WHERE id = $1 AND org_id = $2
             RETURNING id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, created_at, updated_at",
            self.user_id(),
            self.org_id(),
            merged,
        )
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row)
    }
}
