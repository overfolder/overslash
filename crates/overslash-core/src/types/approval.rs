use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalStatus {
    Pending,
    Allowed,
    Denied,
    Expired,
}

impl ApprovalStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Expired => "expired",
        }
    }
}

impl std::fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ApprovalStatus {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "allowed" => Ok(Self::Allowed),
            "denied" => Ok(Self::Denied),
            "expired" => Ok(Self::Expired),
            other => Err(format!("invalid approval status: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub id: Uuid,
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub action_summary: String,
    pub action_detail: Option<serde_json::Value>,
    pub permission_keys: Vec<String>,
    pub status: ApprovalStatus,
    pub resolved_at: Option<OffsetDateTime>,
    pub resolved_by: Option<String>,
    pub remember: bool,
    pub token: String,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
    pub gap_identity_id: Option<Uuid>,
    pub can_be_handled_by: Vec<Uuid>,
    pub grant_to: Option<Uuid>,
}
