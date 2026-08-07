//! Create-time validation of the `groups[]` grants on `CreateServiceInput`.
//!
//! An org-level service instance (`owner_identity_id IS NULL`) has no Myself
//! group to fall back on, so a group grant is the *only* way anyone reaches
//! it. Creating one with no grant produces a row nobody can resolve or call,
//! which is why the cardinality rule below is a hard error rather than a
//! warning.

use std::collections::HashSet;

use uuid::Uuid;

use overslash_core::permissions::AccessLevel;
use overslash_db::scopes::OrgScope;

use super::CreateServiceGroupGrant;
use super::group_ceiling;
use crate::error::AppError;

/// Validate the requested grants against the org, the caller, and the
/// ownership tier the instance is about to be created at.
///
/// Runs entirely before the instance row is inserted — see the call site in
/// [`super::kernels::kernel_create_service`].
pub(super) async fn validate_create_group_grants(
    scope: &OrgScope,
    auth_identity: Uuid,
    access_level: AccessLevel,
    owner_identity_id: Option<Uuid>,
    requested: &[CreateServiceGroupGrant],
) -> Result<Vec<CreateServiceGroupGrant>, AppError> {
    let org_level = owner_identity_id.is_none();

    if org_level && requested.is_empty() {
        return Err(AppError::BadRequest(
            "org-level services must be granted to at least one group; \
             pass `groups` with a group you belong to"
                .into(),
        ));
    }

    // Granting a service to a group is the *social* half of service management
    // and is admin-gated on `POST /v1/groups/{id}/grants`. The org-level path
    // already required admin to get here; this stops the user-level path from
    // becoming a side door around the same gate.
    if !requested.is_empty() && access_level < AccessLevel::Admin {
        return Err(AppError::Forbidden(
            "granting a service to a group requires admin access".into(),
        ));
    }

    let mut seen: HashSet<Uuid> = HashSet::new();
    for grant in requested {
        if !seen.insert(grant.group_id) {
            return Err(AppError::BadRequest(format!(
                "duplicate group '{}' in `groups`",
                grant.group_id
            )));
        }

        if !matches!(grant.access_level.as_str(), "read" | "write" | "admin") {
            return Err(AppError::BadRequest(format!(
                "invalid access_level '{}': must be read, write, or admin",
                grant.access_level
            )));
        }

        let group = scope
            .get_group(grant.group_id)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("group '{}' not found", grant.group_id)))?;

        // Myself grants are auto-managed by the kernel and only ever target
        // their owner's services — the same guard `POST /v1/groups/{id}/grants`
        // applies after the fact.
        if group.system_kind.as_deref() == Some("self") {
            return Err(AppError::BadRequest(
                "Myself groups are managed automatically and cannot be selected at creation".into(),
            ));
        }
    }

    // Membership floor, org-level only. On the user-level path the Myself
    // auto-grant already guarantees the owner can reach the instance, so extra
    // groups there are pure sharing and carry no membership requirement.
    //
    // Membership resolves through the *ceiling user*: agents are never group
    // members themselves, they inherit via their owner user.
    if org_level {
        let ceiling_user = group_ceiling::resolve_ceiling_user_id(scope, auth_identity).await?;
        let member_of: HashSet<Uuid> = scope
            .list_groups_for_identity(ceiling_user)
            .await?
            .into_iter()
            .map(|g| g.id)
            .collect();
        if !requested.iter().any(|g| member_of.contains(&g.group_id)) {
            return Err(AppError::BadRequest(
                "you must be a member of at least one of the selected groups".into(),
            ));
        }
    }

    Ok(requested.to_vec())
}
