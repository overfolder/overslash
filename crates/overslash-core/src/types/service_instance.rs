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
}

impl ServiceInstanceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Archived => "archived",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "draft" => Some(Self::Draft),
            "active" => Some(Self::Active),
            "archived" => Some(Self::Archived),
            _ => None,
        }
    }
}
