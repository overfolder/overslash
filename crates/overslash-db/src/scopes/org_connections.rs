//! `OrgScope` SQL methods for the `connections` resource.
//!
//! Org-level admin operations on OAuth connections. Per-identity operations
//! (list_my_connections, find_by_provider) live on `UserScope` where the
//! `(org_id, user_id)` pair is required at the type level.
//!
//! Every method here funnels through `self.org_id()` so an id from another
//! org returns `None` / `false` at the SQL boundary.

use uuid::Uuid;

use crate::repos::connection::{self, ConnectionRow, CreateConnection};
use crate::scopes::OrgScope;

impl OrgScope {
    /// Create a new connection. The caller's `OrgScope` is the source of
    /// truth for `org_id` — any `org_id` field on the input is ignored and
    /// overwritten to prevent cross-tenant smuggling at the construction
    /// site.
    pub async fn create_connection<'a>(
        &self,
        mut input: CreateConnection<'a>,
    ) -> Result<ConnectionRow, sqlx::Error> {
        input.org_id = self.org_id();
        connection::create(self.db(), &input).await
    }

    /// Look up a connection by id, scoped to this org. Returns `None` if the
    /// id belongs to another tenant.
    pub async fn get_connection(&self, id: Uuid) -> Result<Option<ConnectionRow>, sqlx::Error> {
        connection::get_by_id(self.db(), self.org_id(), id).await
    }

    /// Batch fetch connections by ids, indexed by id. Returns only connections
    /// that belong to this org — foreign ids are silently dropped. Used by
    /// the services list to avoid N+1 lookups while classifying credential
    /// health.
    pub async fn get_connections_by_ids(
        &self,
        ids: &[Uuid],
    ) -> Result<std::collections::HashMap<Uuid, ConnectionRow>, sqlx::Error> {
        let rows = connection::get_by_ids(self.db(), self.org_id(), ids).await?;
        Ok(rows.into_iter().map(|r| (r.id, r)).collect())
    }

    /// Update the encrypted access/refresh token pair for a connection in
    /// this org. Used by the OAuth refresh path. No-ops silently if the id
    /// belongs to another tenant.
    pub async fn update_connection_tokens(
        &self,
        id: Uuid,
        encrypted_access_token: &[u8],
        encrypted_refresh_token: Option<&[u8]>,
        token_expires_at: Option<time::OffsetDateTime>,
    ) -> Result<(), sqlx::Error> {
        connection::update_tokens(
            self.db(),
            self.org_id(),
            id,
            encrypted_access_token,
            encrypted_refresh_token,
            token_expires_at,
        )
        .await
    }

    /// Update tokens *and* scopes in place. Used by the incremental scope
    /// upgrade callback — keeps the existing `connection_id` so services
    /// bound to it stay bound.
    pub async fn update_connection_tokens_and_scopes(
        &self,
        id: Uuid,
        encrypted_access_token: &[u8],
        encrypted_refresh_token: Option<&[u8]>,
        token_expires_at: Option<time::OffsetDateTime>,
        scopes: &[String],
        account_email: Option<&str>,
    ) -> Result<bool, sqlx::Error> {
        connection::update_tokens_and_scopes(
            self.db(),
            self.org_id(),
            id,
            encrypted_access_token,
            encrypted_refresh_token,
            token_expires_at,
            scopes,
            account_email,
        )
        .await
    }

    /// For each given connection id, return the template keys of active
    /// service instances currently bound to it. Scoped to this org. Used by
    /// the dashboard's existing-connection picker.
    pub async fn connection_usage_by_template(
        &self,
        connection_ids: &[Uuid],
    ) -> Result<Vec<(Uuid, String)>, sqlx::Error> {
        connection::usage_by_template(self.db(), self.org_id(), connection_ids).await
    }

    /// Delete a connection by id, scoped to this org. Returns `false` if the
    /// id belongs to another tenant. Used by org-admin connection deletion.
    pub async fn delete_connection(&self, id: Uuid) -> Result<bool, sqlx::Error> {
        connection::delete_by_org(self.db(), id, self.org_id()).await
    }
}
