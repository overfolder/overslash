use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub id: Uuid,
    pub org_id: Uuid,
    pub name: String,
    pub current_version: i32,
    pub deleted_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVersion {
    pub id: Uuid,
    pub secret_id: Uuid,
    pub version: i32,
    pub created_at: OffsetDateTime,
    pub created_by: Option<Uuid>,
}
