//! `OrgScope` SQL methods for the `service_instances` resource.
//!
//! Service instances are org-owned. Every method here funnels through
//! `self.org_id()` so a row id from another org returns `None` / `false`
//! at the SQL boundary instead of leaking or mutating cross-tenant rows.

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
    /// within this org.
    pub async fn resolve_service_instance_by_name(
        &self,
        identity_id: Option<Uuid>,
        raw_name: &str,
    ) -> Result<Option<ServiceInstanceRow>, sqlx::Error> {
        service_instance::resolve_by_name(self.db(), self.org_id(), identity_id, raw_name).await
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

    /// List all service instances available to a caller in this org
    /// (the user's own + the org's).
    pub async fn list_available_service_instances(
        &self,
        identity_id: Option<Uuid>,
    ) -> Result<Vec<ServiceInstanceRow>, sqlx::Error> {
        service_instance::list_available(self.db(), self.org_id(), identity_id).await
    }

    /// List service instances visible to a caller in this org, filtered by
    /// the supplied set of group-visible org-level service ids.
    pub async fn list_available_service_instances_with_groups(
        &self,
        identity_id: Option<Uuid>,
        visible_service_ids: Option<&[Uuid]>,
    ) -> Result<Vec<ServiceInstanceRow>, sqlx::Error> {
        service_instance::list_available_with_groups(
            self.db(),
            self.org_id(),
            identity_id,
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

    /// Delete a service instance, scoped to this org. Returns `false` if the
    /// id belongs to another tenant.
    pub async fn delete_service_instance(&self, id: Uuid) -> Result<bool, sqlx::Error> {
        service_instance::delete(self.db(), self.org_id(), id).await
    }
}
