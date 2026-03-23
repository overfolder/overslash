use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Org {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}
