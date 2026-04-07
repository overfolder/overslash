use uuid::Uuid;

use overslash_core::permissions::{
    AccessLevel, CeilingGrant, GroupCeilingResult, check_group_ceiling,
};
use overslash_core::types::service::Risk;

use overslash_db::OrgScope;
use overslash_db::repos::identity::IdentityRow;

/// Resolved ceiling data ready for checking.
pub struct ResolvedCeiling {
    pub has_groups: bool,
    pub allow_raw_http: bool,
    pub grants: Vec<CeilingGrant>,
}

/// Resolve the ceiling user ID from an already-fetched identity row.
/// Users are their own ceiling. Agents/sub-agents use their owner_id.
pub fn ceiling_user_id_from_identity(
    identity: &IdentityRow,
) -> Result<Uuid, crate::error::AppError> {
    match identity.kind.as_str() {
        "user" => Ok(identity.id),
        _ => identity
            .owner_id
            .ok_or_else(|| crate::error::AppError::Internal("agent has no owner_id".into())),
    }
}

/// Resolve the ceiling user ID by fetching the identity from the database,
/// bounded to the caller's org via `scope`.
pub async fn resolve_ceiling_user_id(
    scope: &OrgScope,
    identity_id: Uuid,
) -> Result<Uuid, crate::error::AppError> {
    let identity = scope
        .get_identity(identity_id)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("identity not found".into()))?;
    ceiling_user_id_from_identity(&identity)
}

/// Load and transform the group ceiling for a user identity.
/// `has_groups` reflects user-created group membership only — system groups
/// (Everyone, Admins) don't count for ceiling enforcement.
pub async fn load_ceiling(
    scope: &OrgScope,
    user_identity_id: Uuid,
) -> Result<ResolvedCeiling, crate::error::AppError> {
    let groups = scope.list_groups_for_identity(user_identity_id).await?;
    let has_groups = groups.iter().any(|g| !g.is_system);

    let ceiling = scope.get_ceiling_for_user(user_identity_id).await?;

    let grants = ceiling
        .grants
        .iter()
        .map(|g| CeilingGrant {
            service_name: g.service_name.clone(),
            access_level: AccessLevel::parse(&g.access_level).unwrap_or(AccessLevel::Read),
            auto_approve_reads: g.auto_approve_reads,
        })
        .collect();

    Ok(ResolvedCeiling {
        has_groups,
        allow_raw_http: ceiling.allow_raw_http,
        grants,
    })
}

/// Check if a request is within the group ceiling.
/// Returns `GroupCeilingResult::NoGroups` if no groups are assigned (permissive).
pub fn check_ceiling(
    ceiling: &ResolvedCeiling,
    service_name: &str,
    risk: Risk,
) -> GroupCeilingResult {
    if !ceiling.has_groups {
        return GroupCeilingResult::NoGroups;
    }
    check_group_ceiling(
        service_name,
        risk,
        &ceiling.grants,
        ceiling.allow_raw_http,
        true,
    )
}
