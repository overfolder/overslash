//! `UserScope` SQL methods for the `connections` resource.
//!
//! Per-identity connection operations: list and find-by-provider for the
//! caller's own connections, plus identity-scoped delete. Every method here
//! filters by `self.user_id()` AND joins through `identities.org_id =
//! self.org_id()` so a connection whose identity belongs to a different org
//! is invisible — defence in depth on top of the `(org_id, identity_id)` FK
//! invariants.

use uuid::Uuid;

use crate::repos::connection::ConnectionRow;
use crate::scopes::UserScope;

impl UserScope {
    /// List the caller's own connections in this org.
    pub async fn list_my_connections(&self) -> Result<Vec<ConnectionRow>, sqlx::Error> {
        sqlx::query_as!(
            ConnectionRow,
            "SELECT c.id, c.org_id, c.identity_id, c.provider_key, c.encrypted_access_token,
                    c.encrypted_refresh_token, c.token_expires_at, c.scopes, c.account_email,
                    c.byoc_credential_id, c.is_default, c.created_at, c.updated_at
             FROM connections c
             JOIN identities i ON i.id = c.identity_id
             WHERE c.identity_id = $1 AND i.org_id = $2
             ORDER BY c.created_at DESC",
            self.user_id(),
            self.org_id(),
        )
        .fetch_all(self.db())
        .await
    }

    /// Find the caller's connection for a given provider in this org. Used
    /// by the auto-resolve path when executing service actions on behalf of
    /// the user.
    pub async fn find_my_connection_by_provider(
        &self,
        provider_key: &str,
    ) -> Result<Option<ConnectionRow>, sqlx::Error> {
        sqlx::query_as!(
            ConnectionRow,
            "SELECT c.id, c.org_id, c.identity_id, c.provider_key, c.encrypted_access_token,
                    c.encrypted_refresh_token, c.token_expires_at, c.scopes, c.account_email,
                    c.byoc_credential_id, c.is_default, c.created_at, c.updated_at
             FROM connections c
             JOIN identities i ON i.id = c.identity_id
             WHERE c.identity_id = $1 AND i.org_id = $2 AND c.provider_key = $3
             ORDER BY c.is_default DESC, c.created_at DESC LIMIT 1",
            self.user_id(),
            self.org_id(),
            provider_key,
        )
        .fetch_optional(self.db())
        .await
    }

    /// Delete one of the caller's own connections. Returns `false` if the id
    /// is not owned by the caller (or belongs to another org).
    pub async fn delete_my_connection(&self, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query!(
            "DELETE FROM connections c
             USING identities i
             WHERE c.id = $1 AND c.identity_id = $2 AND i.id = c.identity_id AND i.org_id = $3",
            id,
            self.user_id(),
            self.org_id(),
        )
        .execute(self.db())
        .await?;
        Ok(result.rows_affected() > 0)
    }
}
