//! `OrgScope` SQL methods for the `service_instances` resource.
//!
//! Service instances are org-owned. Every method here funnels through
//! `self.org_id()` so a row id from another org returns `None` / `false`
//! at the SQL boundary instead of leaking or mutating cross-tenant rows.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::repos::service_instance::{
    self, CreateServiceInstance, ServiceInstanceRow, UpdateServiceInstance,
};
use crate::scopes::OrgScope;

impl OrgScope {
    /// Create a new service instance. The caller's `OrgScope` is the source of
    /// truth for `org_id` — any `org_id` field on the input is ignored and
    /// overwritten to prevent cross-tenant smuggling at the construction site.
    pub async fn create_service_instance<'a>(
        &self,
        mut input: CreateServiceInstance<'a>,
    ) -> Result<ServiceInstanceRow, sqlx::Error> {
        input.org_id = self.org_id();
        service_instance::create(self.db(), &input).await
    }

    /// Identities that minted a setup link for this instance — "who is
    /// blocked on it going live". Not org-scoped in the query: the instance id
    /// is already the tenant boundary, and every `secret_requests` row keyed on
    /// it shares its org by construction (migration 118's FK).
    pub async fn setup_requesters(
        &self,
        service_instance_id: Uuid,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        crate::repos::secret_request::setup_requesters(self.db(), service_instance_id).await
    }

    /// Look up a service instance by id, scoped to this org. Returns `None`
    /// if the id belongs to another tenant.
    pub async fn get_service_instance(
        &self,
        id: Uuid,
    ) -> Result<Option<ServiceInstanceRow>, sqlx::Error> {
        service_instance::get_by_id(self.db(), self.org_id(), id).await
    }

    /// Look up a service instance by name within this org and an optional
    /// owner identity (for user-level instances).
    pub async fn get_service_instance_by_name(
        &self,
        owner_identity_id: Option<Uuid>,
        name: &str,
    ) -> Result<Option<ServiceInstanceRow>, sqlx::Error> {
        service_instance::get_by_name(self.db(), self.org_id(), owner_identity_id, name).await
    }

    /// Resolve a service instance by name with user-shadows-org semantics
    /// within this org. `ceiling_user_id` is the caller's owner user (itself when
    /// the caller is a user identity); services it owns are always reachable.
    pub async fn resolve_service_instance_by_name(
        &self,
        identity_id: Option<Uuid>,
        ceiling_user_id: Option<Uuid>,
        raw_name: &str,
    ) -> Result<Option<ServiceInstanceRow>, sqlx::Error> {
        service_instance::resolve_by_name(
            self.db(),
            self.org_id(),
            identity_id,
            ceiling_user_id,
            raw_name,
        )
        .await
    }

    /// Resolve a service instance by name without filtering by status. Used by
    /// the dashboard so draft and archived instances remain viewable.
    pub async fn resolve_service_instance_by_name_any_status(
        &self,
        identity_id: Option<Uuid>,
        ceiling_user_id: Option<Uuid>,
        raw_name: &str,
    ) -> Result<Option<ServiceInstanceRow>, sqlx::Error> {
        service_instance::resolve_by_name_any_status(
            self.db(),
            self.org_id(),
            identity_id,
            ceiling_user_id,
            raw_name,
        )
        .await
    }

    /// List org-level service instances in this org.
    pub async fn list_org_service_instances(&self) -> Result<Vec<ServiceInstanceRow>, sqlx::Error> {
        service_instance::list_by_org(self.db(), self.org_id()).await
    }

    /// List user-level service instances for a specific identity in this org.
    pub async fn list_user_service_instances(
        &self,
        identity_id: Uuid,
    ) -> Result<Vec<ServiceInstanceRow>, sqlx::Error> {
        service_instance::list_by_user(self.db(), self.org_id(), identity_id).await
    }

    /// List all service instances available to a caller in this org:
    /// org-level + caller-owned + ceiling-user-owned.
    pub async fn list_available_service_instances(
        &self,
        identity_id: Option<Uuid>,
        ceiling_user_id: Option<Uuid>,
    ) -> Result<Vec<ServiceInstanceRow>, sqlx::Error> {
        service_instance::list_available(self.db(), self.org_id(), identity_id, ceiling_user_id)
            .await
    }

    /// List every service instance in this org regardless of owner or group
    /// grants. Caller is responsible for gating this on `is_org_admin`.
    pub async fn list_all_service_instances_in_org(
        &self,
    ) -> Result<Vec<ServiceInstanceRow>, sqlx::Error> {
        service_instance::list_all_in_org(self.db(), self.org_id()).await
    }

    /// List service instances visible to a caller in this org, filtered by
    /// the supplied set of group-visible org-level service ids.
    ///
    /// Caller-owned and ceiling-user-owned services bypass the group filter — a
    /// user always sees the services they've created themselves.
    pub async fn list_available_service_instances_with_groups(
        &self,
        identity_id: Option<Uuid>,
        ceiling_user_id: Option<Uuid>,
        visible_service_ids: Option<&[Uuid]>,
    ) -> Result<Vec<ServiceInstanceRow>, sqlx::Error> {
        service_instance::list_available_with_groups(
            self.db(),
            self.org_id(),
            identity_id,
            ceiling_user_id,
            visible_service_ids,
        )
        .await
    }

    /// Update a service instance's lifecycle status, scoped to this org.
    /// Returns `None` if the id belongs to another tenant.
    pub async fn update_service_instance_status(
        &self,
        id: Uuid,
        status: &str,
    ) -> Result<Option<ServiceInstanceRow>, sqlx::Error> {
        service_instance::update_status(self.db(), self.org_id(), id, status).await
    }

    /// Update a service instance's mutable fields, scoped to this org.
    /// Returns `None` if the id belongs to another tenant.
    pub async fn update_service_instance(
        &self,
        id: Uuid,
        input: &UpdateServiceInstance<'_>,
    ) -> Result<Option<ServiceInstanceRow>, sqlx::Error> {
        service_instance::update(self.db(), self.org_id(), id, input).await
    }

    /// Bind one credential slot on an instance to a vault secret name, scoped
    /// to this org. Returns `None` if the id belongs to another tenant.
    ///
    /// Deliberately narrower than [`Self::update_service_instance`], which is
    /// what `kernel_update_service` reaches for: that path re-derives the
    /// template's slot set and checks the caller may manage the instance. The
    /// public setup-link handler has no caller identity to check — it holds a
    /// signed capability token — and the slot key it passes was already
    /// validated against the template at *mint* time, by the caller that did
    /// hold `manage_services_own`. Re-entering the kernel there would mean
    /// inventing an identity to satisfy a check that has already happened.
    pub async fn bind_credential_slot(
        &self,
        id: Uuid,
        slot_key: &str,
        secret_name: &str,
    ) -> Result<Option<ServiceInstanceRow>, sqlx::Error> {
        service_instance::bind_credential_slot(self.db(), self.org_id(), id, slot_key, secret_name)
            .await
    }

    /// Overwrite a service instance's MCP discovery result, scoped to this org.
    /// Returns `false` if the id belongs to another tenant. Used by the
    /// instance-scoped MCP resync route.
    pub async fn update_service_instance_discovered_tools(
        &self,
        id: Uuid,
        tools: &[serde_json::Value],
        at: OffsetDateTime,
    ) -> Result<bool, sqlx::Error> {
        service_instance::update_discovered_tools(self.db(), self.org_id(), id, tools, at).await
    }

    /// Delete a service instance, scoped to this org. Returns `false` if the
    /// id belongs to another tenant.
    pub async fn delete_service_instance(&self, id: Uuid) -> Result<bool, sqlx::Error> {
        service_instance::delete(self.db(), self.org_id(), id).await
    }
}
