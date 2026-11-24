//! Who may see which identities, and whose audit trail.
//!
//! An org admin sees the whole org. Everyone else (a user, or an agent
//! acting for one) sees a single user tree: their root user and that user's
//! agents and sub-agents. This applies to the identity listings behind the
//! Agents page and the Live Map, and to the audit log and its export.
//!
//! "Admin" here means the same thing as in [`crate::extractors::OrgAcl`]:
//! the `is_org_admin` flag, or an admin-level `overslash` grant. The rule
//! lives in one place on purpose, so these listings cannot drift into their
//! own idea of who counts as an admin.

use overslash_core::permissions::AccessLevel;
use overslash_db::OrgScope;
use overslash_db::repos::identity::IdentityRow;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::extractors::OrgAcl;
use crate::services::group_ceiling::resolve_ceiling_user_id;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    /// Org admin: every identity, every audit row.
    Org,
    /// Everyone else: only the tree rooted at this user.
    User(Uuid),
}

impl Visibility {
    /// Visibility for the caller described by `acl`.
    pub async fn for_acl(scope: &OrgScope, acl: &OrgAcl) -> Result<Self> {
        if acl.access_level >= AccessLevel::Admin {
            return Ok(Self::Org);
        }
        let caller = acl
            .identity_id
            .ok_or_else(|| AppError::Forbidden("identity-bound credential required".into()))?;
        Ok(Self::User(resolve_ceiling_user_id(scope, caller).await?))
    }

    /// Visibility for a raw caller id (for handlers that do not take an
    /// `OrgAcl`). Uses the same admin rule as `OrgAcl`.
    pub async fn for_caller(scope: &OrgScope, caller: Option<Uuid>) -> Result<Self> {
        let caller = caller
            .ok_or_else(|| AppError::Forbidden("identity-bound credential required".into()))?;
        let level = crate::extractors::resolve_access_level(scope, caller).await?;
        if level >= AccessLevel::Admin {
            return Ok(Self::Org);
        }
        Ok(Self::User(resolve_ceiling_user_id(scope, caller).await?))
    }

    /// May the caller see `row`? A user tree is the user itself plus every
    /// identity whose `owner_id` is that user (agents and sub-agents alike).
    pub fn sees(&self, row: &IdentityRow) -> bool {
        match self {
            Self::Org => true,
            Self::User(root) => row.id == *root || row.owner_id == Some(*root),
        }
    }

    /// Load `id` if it exists in the org **and** the caller may see it. An
    /// out-of-view id gets the same 404 as a missing or cross-tenant one, so
    /// another user's agents cannot be probed or mutated.
    pub async fn load(&self, scope: &OrgScope, id: Uuid) -> Result<IdentityRow> {
        scope
            .get_identity(id)
            .await?
            .filter(|r| self.sees(r))
            .ok_or_else(|| AppError::NotFound("identity not found".into()))
    }

    /// The user the caller's view is limited to, or `None` for an org admin.
    pub fn user_root(&self) -> Option<Uuid> {
        match self {
            Self::Org => None,
            Self::User(root) => Some(*root),
        }
    }
}
