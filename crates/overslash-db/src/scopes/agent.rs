use sqlx::PgPool;
use uuid::Uuid;

use super::{org::OrgScope, user::UserScope};

/// Capability proving the holder is authenticated as agent `agent_id`,
/// rooted at user `user_id` in `org_id`.
///
/// Every agent has a root user (the `on_behalf_of` owner). Some agents
/// additionally have a parent agent — `parent_agent_id` is `Some` for those.
/// Permission inheritance walks `parent_agent_id` upward until it reaches the
/// root user. There is no separate "sub-agent" type; depth is just data.
///
/// Free downgrades to [`UserScope`] (the root owner) and [`OrgScope`]. Both
/// relationships were verified when this scope was constructed.
#[derive(Debug, Clone)]
pub struct AgentScope {
    pub(crate) org_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) agent_id: Uuid,
    pub(crate) parent_agent_id: Option<Uuid>,
    pub(crate) db: PgPool,
}

impl AgentScope {
    pub fn new(
        org_id: Uuid,
        user_id: Uuid,
        agent_id: Uuid,
        parent_agent_id: Option<Uuid>,
        db: PgPool,
    ) -> Self {
        Self {
            org_id,
            user_id,
            agent_id,
            parent_agent_id,
            db,
        }
    }

    pub fn org_id(&self) -> Uuid {
        self.org_id
    }
    pub fn user_id(&self) -> Uuid {
        self.user_id
    }
    pub fn agent_id(&self) -> Uuid {
        self.agent_id
    }
    /// `Some` if this agent's immediate parent is another agent; `None` if
    /// the parent is the root user directly.
    pub fn parent_agent_id(&self) -> Option<Uuid> {
        self.parent_agent_id
    }

    /// Free downgrade to the root user's scope. This is the `on_behalf_of`
    /// path: an agent acting on user-level resources (shared secrets,
    /// connections) does so by calling `agent.user().my_secrets()`.
    pub fn user(&self) -> UserScope {
        UserScope::new(self.org_id, self.user_id, self.db.clone())
    }

    pub fn org(&self) -> OrgScope {
        OrgScope::new(self.org_id, self.db.clone())
    }
}
