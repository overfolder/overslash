//! `OrgScope` SQL methods for the `api_keys` resource.
//!
//! Every method here filters by `self.org_id()`, so a row id from
//! another tenant returns `None` / has no effect. Cross-org prefix
//! lookups (used by the auth bootstrap path) live on `SystemScope`.

use uuid::Uuid;

use crate::repos::api_key::{self, ApiKeyRow};
use crate::scopes::OrgScope;

impl OrgScope {
    /// Create a new API key in this org, bound to an identity.
    pub async fn create_api_key(
        &self,
        identity_id: Uuid,
        name: &str,
        key_hash: &str,
        key_prefix: &str,
        scopes: &[String],
    ) -> Result<ApiKeyRow, sqlx::Error> {
        api_key::create(
            self.db(),
            self.org_id(),
            identity_id,
            name,
            key_hash,
            key_prefix,
            scopes,
        )
        .await
    }

    /// Count live (non-revoked) API keys in this org.
    pub async fn count_api_keys(&self) -> Result<i64, sqlx::Error> {
        api_key::count_by_org(self.db(), self.org_id()).await
    }

    /// List live (non-revoked) API keys in this org.
    pub async fn list_api_keys(&self) -> Result<Vec<ApiKeyRow>, sqlx::Error> {
        api_key::list_by_org(self.db(), self.org_id()).await
    }

    /// Revoke an API key by id, scoped to this org. Returns true if a row
    /// was affected. A revoke for an id belonging to another tenant is a
    /// no-op (returns `false`).
    pub async fn revoke_api_key(&self, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query!(
            "UPDATE api_keys SET revoked_at = now()
             WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL",
            id,
            self.org_id(),
        )
        .execute(self.db())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Stamp `last_used_at = now()` for an API key in this org. Used by
    /// the auth middleware after a successful key verification. Bounded
    /// to this org so a stray id from another tenant has no effect.
    pub async fn touch_api_key_last_used(&self, id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query!(
            "UPDATE api_keys SET last_used_at = now()
             WHERE id = $1 AND org_id = $2",
            id,
            self.org_id(),
        )
        .execute(self.db())
        .await?;
        Ok(())
    }
}
