//! Identity repository: the `identities` table and every write path that
//! touches it. Split by seam:
//!
//! - `create` — plain inserts (no lookup-then-insert race handling).
//! - `lookup` — read-only queries, including the ancestor-chain CTE.
//! - `provision` — advisory-lock-serialised get-or-create paths.
//! - `profile` — single-column updates to an existing identity.
//! - `membership` — everything that also touches `user_org_memberships`
//!   or the `Admins` system group.
//! - `tree` — parent/child structure: rename, move, patch, leaf delete.
//! - `lifecycle` — archive, restore, purge, remove-from-org.
//!
//! Shared below: the row type, the archive-reason constants, the reserved
//! org-service `external_id`, and `MAX_TREE_DEPTH` (used by both the tree
//! cascade and the archive cascade).

use time::OffsetDateTime;
use uuid::Uuid;

mod create;
mod lifecycle;
mod lookup;
mod membership;
mod profile;
mod provision;
mod tree;

pub use create::{create, create_with_email, create_with_parent};
pub use lifecycle::{
    ArchiveOutcome, RemoveUserOutcome, RestoreOutcome, archive_idle_subagents,
    purge_archived_subagents,
};
// `archive_identity_tx` is deliberately not re-exported: its only callers are
// `archive_identity` and `remove_user_from_org`, both inside `lifecycle`.
pub(crate) use lifecycle::{archive_identity, remove_user_from_org, restore, touch_last_active};
pub(crate) use lookup::{
    count_by_org, find_user_by_email_global, list_by_org, list_pending_invites_by_email,
};
pub use lookup::{
    find_by_org_and_user, find_child_by_name, find_user_by_email_in_org,
    find_user_by_external_id_in_org, get_ancestor_chain, get_by_id, list_children,
};
pub use membership::{
    SetOrgMemberAdminOutcome, get_or_create_org_service_agent, set_is_org_admin,
    set_org_member_admin,
};
pub use profile::{
    set_auto_call_on_approve, set_external_id, set_inherit_permissions, set_user_id, update_profile,
};
pub use provision::{get_or_create_child, get_or_create_user_by_email};
pub use tree::{ApplyPatchOutcome, DeleteLeafOutcome, MoveTo, PatchIdentity};
pub(crate) use tree::{apply_patch, delete, delete_leaf, move_under, rename};

/// Reason an identity was archived. Stored in `archived_reason`.
pub const ARCHIVED_REASON_IDLE_TIMEOUT: &str = "idle_timeout";

/// Default reason for an on-demand (caller-initiated) archive when the caller
/// supplies no explicit reason. Keeps archived rows carrying provenance, in
/// parity with the idle sweep above.
pub const ARCHIVED_REASON_MANUAL: &str = "manual";

/// `external_id` reserved for the per-org Agent that owns "service keys"
/// minted from Org Settings. The colon-prefixed namespace cannot collide
/// with IdP-issued subjects (IdP subs come from per-provider strings
/// without that namespace).
pub const ORG_SERVICE_EXTERNAL_ID: &str = "overslash:org-service";

#[derive(Debug, sqlx::FromRow)]
pub struct IdentityRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub name: String,
    pub kind: String,
    pub external_id: Option<String>,
    pub email: Option<String>,
    pub metadata: serde_json::Value,
    pub parent_id: Option<Uuid>,
    pub depth: i32,
    pub owner_id: Option<Uuid>,
    pub inherit_permissions: bool,
    pub last_active_at: OffsetDateTime,
    pub archived_at: Option<OffsetDateTime>,
    pub archived_reason: Option<String>,
    pub preferences: serde_json::Value,
    pub is_org_admin: bool,
    pub user_id: Option<Uuid>,
    pub auto_call_on_approve: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

super::impl_org_owned!(IdentityRow);

/// Maximum recursive descent for both the cycle check and the descendant
/// `depth`/`owner_id` cascade. Matches `get_ancestor_chain`'s bound.
/// Defence-in-depth so a leftover cycle (e.g. from a manual SQL fixup) can't
/// loop forever inside a recursive CTE.
const MAX_TREE_DEPTH: i32 = 50;
