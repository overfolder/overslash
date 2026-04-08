use sqlx::PgPool;
use uuid::Uuid;

use overslash_core::permissions::{
    AccessLevel, CeilingGrant, GroupCeilingResult, check_group_ceiling,
};
use overslash_core::types::service::Risk;

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

/// Resolve the ceiling user ID by fetching the identity from the database.
pub async fn resolve_ceiling_user_id(
    pool: &PgPool,
    identity_id: Uuid,
) -> Result<Uuid, crate::error::AppError> {
    let identity = overslash_db::repos::identity::get_by_id(pool, identity_id)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("identity not found".into()))?;
    ceiling_user_id_from_identity(&identity)
}

/// Validate that `caller_identity_id` is allowed to act `on_behalf_of` `target_user_id`.
///
/// Rules:
/// - target must exist, belong to `org_id`, be `kind = 'user'`, and not archived
/// - caller is a User: `caller.id == target_user_id` (self only)
/// - caller is an Agent/SubAgent: `caller.owner_id == target_user_id`
pub async fn validate_on_behalf_of(
    pool: &PgPool,
    org_id: Uuid,
    caller_identity_id: Uuid,
    target_user_id: Uuid,
) -> Result<Uuid, crate::error::AppError> {
    let caller = overslash_db::repos::identity::get_by_id(pool, caller_identity_id)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("caller identity not found".into()))?;
    if caller.org_id != org_id {
        return Err(crate::error::AppError::Forbidden(
            "caller identity not in org".into(),
        ));
    }

    let target = overslash_db::repos::identity::get_by_id(pool, target_user_id)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("on_behalf_of target not found".into()))?;
    if target.org_id != org_id {
        return Err(crate::error::AppError::Forbidden(
            "on_behalf_of target not in org".into(),
        ));
    }
    if target.kind != "user" {
        return Err(crate::error::AppError::Forbidden(
            "on_behalf_of target must be a user identity".into(),
        ));
    }
    if target.archived_at.is_some() {
        return Err(crate::error::AppError::Forbidden(
            "on_behalf_of target is archived".into(),
        ));
    }

    let allowed_owner = ceiling_user_id_from_identity(&caller)?;
    if allowed_owner != target.id {
        return Err(crate::error::AppError::Forbidden(
            "caller may only act on_behalf_of its owner user".into(),
        ));
    }
    Ok(target.id)
}

/// Resolve the effective owner identity for a create operation.
///
/// - If `on_behalf_of` is `Some`, validate it and return the user id.
/// - If `None`, return `caller_identity_id` (today's behavior).
/// - Org-level keys (no caller identity) cannot use `on_behalf_of`.
pub async fn resolve_owner_identity(
    pool: &PgPool,
    org_id: Uuid,
    caller_identity_id: Option<Uuid>,
    on_behalf_of: Option<Uuid>,
) -> Result<Option<Uuid>, crate::error::AppError> {
    match (caller_identity_id, on_behalf_of) {
        (_, None) => Ok(caller_identity_id),
        (None, Some(_)) => Err(crate::error::AppError::BadRequest(
            "on_behalf_of requires an identity-bound API key".into(),
        )),
        (Some(caller), Some(target)) => {
            let resolved = validate_on_behalf_of(pool, org_id, caller, target).await?;
            Ok(Some(resolved))
        }
    }
}

/// Load and transform the group ceiling for a user identity.
/// `has_groups` reflects user-created group membership only — system groups
/// (Everyone, Admins) don't count for ceiling enforcement.
pub async fn load_ceiling(
    pool: &PgPool,
    user_identity_id: Uuid,
) -> Result<ResolvedCeiling, crate::error::AppError> {
    let groups =
        overslash_db::repos::group::list_groups_for_identity(pool, user_identity_id).await?;
    let has_groups = groups.iter().any(|g| !g.is_system);

    let ceiling = overslash_db::repos::group::get_ceiling_for_user(pool, user_identity_id).await?;

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
