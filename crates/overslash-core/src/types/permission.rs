use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionRule {
    pub id: Uuid,
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub action_pattern: String,
    pub effect: PermissionEffect,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PermissionEffect {
    Allow,
    Deny,
}
