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
use crate::repos::service_instance;
use crate::scopes::OrgScope;

/// Failure modes of [`OrgScope::create_connection_and_pin`]. A `Bind` error
/// means the whole transaction rolled back — **no** connection was created —
/// so the caller can surface which instance id was at fault without leaking an
/// orphan connection.
#[derive(Debug)]
pub enum CreateAndPinError {
    Db(sqlx::Error),
    /// A pinned instance couldn't be bound. `code` matches the coarse
    /// `service_instance_bind_error` vocabulary the OAuth callback already uses
    /// (`service_instance_not_found`, `service_instance_owner_mismatch`).
    Bind {
        service_instance_id: Uuid,
        code: &'static str,
    },
}

impl From<sqlx::Error> for CreateAndPinError {
    fn from(e: sqlx::Error) -> Self {
        CreateAndPinError::Db(e)
    }
}

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

    /// Create a connection and atomically bind it to `pin_service_ids` in a
    /// single transaction. Either every named instance ends up pointing at the
    /// new connection, or nothing is written at all.
    ///
    /// Ownership gate (mirrors the OAuth-callback bind): each instance must
    /// exist and its `owner_identity_id` must equal the connection's
    /// `identity_id`. Org-level instances (`owner_identity_id IS NULL`) are
    /// rejected — connections are identity-bound. Any violation rolls the whole
    /// transaction back so a bad id never leaves an orphaned connection behind.
    pub async fn create_connection_and_pin<'a>(
        &self,
        mut input: CreateConnection<'a>,
        pin_service_ids: &[Uuid],
    ) -> Result<ConnectionRow, CreateAndPinError> {
        input.org_id = self.org_id();
        let org_id = self.org_id();
        let mut tx = self.db().begin().await?;

        let conn = connection::create_with(&mut *tx, &input).await?;
        pin_within_tx(&mut tx, org_id, conn.id, conn.identity_id, pin_service_ids).await?;

        tx.commit().await?;
        Ok(conn)
    }

    /// Atomically bind an already-existing connection to `pin_service_ids`.
    /// Same ownership gate and all-or-nothing semantics as
    /// [`create_connection_and_pin`]; used by the re-import path where the
    /// connection row already exists (idempotent token re-import). A no-op when
    /// `pin_service_ids` is empty.
    pub async fn pin_service_instances(
        &self,
        connection_id: Uuid,
        connection_identity_id: Uuid,
        pin_service_ids: &[Uuid],
    ) -> Result<(), CreateAndPinError> {
        if pin_service_ids.is_empty() {
            return Ok(());
        }
        let org_id = self.org_id();
        let mut tx = self.db().begin().await?;
        pin_within_tx(
            &mut tx,
            org_id,
            connection_id,
            connection_identity_id,
            pin_service_ids,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Look up a connection by id, scoped to this org. Returns `None` if the
    /// id belongs to another tenant.
    pub async fn get_connection(&self, id: Uuid) -> Result<Option<ConnectionRow>, sqlx::Error> {
        connection::get_by_id(self.db(), self.org_id(), id).await
    }

    /// List every connection in this org, across all identities. Powers the
    /// dashboard's admin-only "show all users' connections" view. See
    /// [`connection::list_all_in_org`].
    pub async fn list_all_connections(&self) -> Result<Vec<ConnectionRow>, sqlx::Error> {
        connection::list_all_in_org(self.db(), self.org_id()).await
    }

    /// Find the connection a token import should update in place for an
    /// (identity, provider[, account_email]), scoped to this org. See
    /// [`connection::find_for_import`].
    pub async fn find_connection_for_import(
        &self,
        identity_id: Uuid,
        provider_key: &str,
        account_email: Option<&str>,
    ) -> Result<Option<ConnectionRow>, sqlx::Error> {
        connection::find_for_import(
            self.db(),
            self.org_id(),
            identity_id,
            provider_key,
            account_email,
        )
        .await
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
        scopes: Option<&[String]>,
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

    /// Active service instances (id, name, template_key) bound to a single
    /// connection, scoped to this org. Powers the connection-detail "Used by"
    /// list. See [`connection::usage_instances_by_connection`].
    pub async fn connection_usage_instances(
        &self,
        connection_id: Uuid,
    ) -> Result<Vec<(Uuid, String, String)>, sqlx::Error> {
        connection::usage_instances_by_connection(self.db(), self.org_id(), connection_id).await
    }

    /// Delete a connection by id, scoped to this org. Returns `false` if the
    /// id belongs to another tenant. Used by org-admin connection deletion.
    pub async fn delete_connection(&self, id: Uuid) -> Result<bool, sqlx::Error> {
        connection::delete_by_org(self.db(), id, self.org_id()).await
    }

    /// Atomically delete a connection for the service-deletion auto-cleanup —
    /// only when it isn't marked `keep` and no service instance (any status)
    /// still references it. Returns whether it deleted. See
    /// [`connection::delete_if_orphaned`].
    pub async fn delete_connection_if_orphaned(
        &self,
        connection_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        connection::delete_if_orphaned(self.db(), self.org_id(), connection_id).await
    }

    /// Set or clear the `keep` preserve flag on a connection, scoped to this
    /// org. Returns `false` if the id belongs to another tenant.
    pub async fn set_connection_keep(&self, id: Uuid, keep: bool) -> Result<bool, sqlx::Error> {
        connection::set_keep(self.db(), self.org_id(), id, keep).await
    }

    /// Promote a connection to be the default for its provider, scoped to this
    /// org — demoting any sibling that held the flag *within the connection's
    /// own owner identity*, not the caller's. Powers an org-admin setting the
    /// default on another user's connection. Returns `false` if the id belongs
    /// to another tenant.
    pub async fn set_connection_default(&self, id: Uuid) -> Result<bool, sqlx::Error> {
        let Some(conn) = self.get_connection(id).await? else {
            return Ok(false);
        };
        connection::set_default(self.db(), self.org_id(), conn.identity_id, id).await
    }
}

/// Validate ownership and bind each pinned service instance to `connection_id`
/// inside `tx`. Returns a `Bind` error (naming the offending id) on the first
/// violation, leaving `tx` uncommitted so the caller's whole transaction rolls
/// back. Shared by [`OrgScope::create_connection_and_pin`] and
/// [`OrgScope::pin_service_instances`].
async fn pin_within_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: Uuid,
    connection_id: Uuid,
    connection_identity_id: Uuid,
    pin_service_ids: &[Uuid],
) -> Result<(), CreateAndPinError> {
    for &sid in pin_service_ids {
        let instance = service_instance::get_by_id_with(&mut **tx, org_id, sid)
            .await?
            .ok_or(CreateAndPinError::Bind {
                service_instance_id: sid,
                code: "service_instance_not_found",
            })?;
        // Connections are identity-bound: reject org-level instances
        // (owner_identity_id IS NULL) and any instance owned by a different
        // identity than the connection's owner.
        if instance.owner_identity_id != Some(connection_identity_id) {
            return Err(CreateAndPinError::Bind {
                service_instance_id: sid,
                code: "service_instance_owner_mismatch",
            });
        }
        let bound =
            service_instance::bind_connection_with(&mut **tx, org_id, sid, connection_id).await?;
        if bound.is_none() {
            // Deleted between the ownership check and the UPDATE.
            return Err(CreateAndPinError::Bind {
                service_instance_id: sid,
                code: "service_instance_not_found",
            });
        }
    }
    Ok(())
}
