use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityKind {
    User,
    Agent,
    SubAgent,
}

impl IdentityKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Agent => "agent",
            Self::SubAgent => "subagent",
        }
    }
}

impl std::fmt::Display for IdentityKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for IdentityKind {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "user" => Ok(Self::User),
            "agent" => Ok(Self::Agent),
            "subagent" => Ok(Self::SubAgent),
            other => Err(format!("invalid identity kind: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub id: Uuid,
    pub org_id: Uuid,
    pub name: String,
    pub kind: IdentityKind,
    pub external_id: Option<String>,
    pub metadata: serde_json::Value,
    pub parent_id: Option<Uuid>,
    pub owner_id: Option<Uuid>,
    pub depth: i32,
    pub inherit_permissions: bool,
    pub can_create_sub: bool,
    pub max_sub_depth: Option<i32>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}
