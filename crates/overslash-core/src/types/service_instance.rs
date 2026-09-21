use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::service::TemplateTier;

/// A service instance — a named instantiation of a template with bound credentials and lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInstance {
    pub id: Uuid,
    pub org_id: Uuid,
    pub owner_identity_id: Option<Uuid>,
    pub name: String,
    pub template_source: TemplateTier,
    pub template_key: String,
    pub template_id: Option<Uuid>,
    pub connection_id: Option<Uuid>,
    pub secret_name: Option<String>,
    pub status: ServiceInstanceStatus,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Lifecycle status of a service instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceInstanceStatus {
    Draft,
    Active,
    Archived,
    /// Created by a setup flow, credentials not yet proven to work. Only
    /// `Active` resolves by name or appears in search, so this is uncallable
    /// for the same reason `Draft` is — see migration 119 for why it is a
    /// separate value rather than a reuse of `Draft`.
    ///
    /// Spelled out because the container's `rename_all = "lowercase"` would
    /// otherwise emit `pendingsetup`, and the wire value is the `status`
    /// column verbatim.
    #[serde(rename = "pending_setup")]
    PendingSetup,
}

impl ServiceInstanceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Archived => "archived",
            Self::PendingSetup => "pending_setup",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "draft" => Some(Self::Draft),
            "active" => Some(Self::Active),
            "archived" => Some(Self::Archived),
            "pending_setup" => Some(Self::PendingSetup),
            _ => None,
        }
    }
}
