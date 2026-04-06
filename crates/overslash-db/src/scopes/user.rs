use sqlx::PgPool;
use uuid::Uuid;

use super::org::OrgScope;

/// Capability proving the holder is authenticated as user `user_id` in `org_id`.
///
/// Strictly stronger than `OrgScope`: every `UserScope` can be downgraded to
/// an `OrgScope` for free via [`UserScope::org`].
#[derive(Debug, Clone)]
pub struct UserScope {
    pub(crate) org_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) db: PgPool,
}

impl UserScope {
    pub fn new(org_id: Uuid, user_id: Uuid, db: PgPool) -> Self {
        Self {
            org_id,
            user_id,
            db,
        }
    }

    pub fn org_id(&self) -> Uuid {
        self.org_id
    }

    pub fn user_id(&self) -> Uuid {
        self.user_id
    }

    /// Free downgrade. The org membership was verified when this scope was
    /// constructed, so no additional check is needed.
    pub fn org(&self) -> OrgScope {
        OrgScope::new(self.org_id, self.db.clone())
    }

    pub(crate) fn db(&self) -> &PgPool {
        &self.db
    }
}
