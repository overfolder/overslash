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

/// Convenience wrapper: resolve the ceiling user for an optional identity.
/// Returns `None` for org-level API keys (no identity), `Some(user_id)`
/// otherwise.
pub async fn resolve_ceiling_user_id_opt(
    scope: &OrgScope,
    identity_id: Option<Uuid>,
) -> Result<Option<Uuid>, crate::error::AppError> {
    match identity_id {
        Some(id) => Ok(Some(resolve_ceiling_user_id(scope, id).await?)),
        None => Ok(None),
    }
}

/// Validate that `caller_identity_id` is allowed to act `on_behalf_of`
/// `target_user_id`.
///
/// Rules:
/// - caller must exist in `scope`'s org and not be archived (defense in depth:
///   the request extractor already rejects archived callers, but we re-check
///   so this validator is safe to call from any future context)
/// - target must exist in `scope`'s org, be `kind = 'user'`, and not be archived
/// - if caller is a User: `caller.id == target_user_id` (self only)
/// - if caller is an Agent/SubAgent: `caller.owner_id == target_user_id`
pub async fn validate_on_behalf_of(
    scope: &OrgScope,
    caller_identity_id: Uuid,
    target_user_id: Uuid,
) -> Result<Uuid, crate::error::AppError> {
    let caller = scope
        .get_identity(caller_identity_id)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("caller identity not found".into()))?;
    if caller.archived_at.is_some() {
        return Err(crate::error::AppError::Forbidden(
            "caller identity is archived".into(),
        ));
    }

    let target = scope
        .get_identity(target_user_id)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("on_behalf_of target not found".into()))?;
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
/// - If `on_behalf_of` is `Some`, validate it via [`validate_on_behalf_of`].
/// - If `None`, return `caller_identity_id` (today's behavior).
/// - Org-level keys (no caller identity) cannot use `on_behalf_of`.
pub async fn resolve_owner_identity(
    scope: &OrgScope,
    caller_identity_id: Option<Uuid>,
    on_behalf_of: Option<Uuid>,
) -> Result<Option<Uuid>, crate::error::AppError> {
    match (caller_identity_id, on_behalf_of) {
        (_, None) => Ok(caller_identity_id),
        (None, Some(_)) => Err(crate::error::AppError::BadRequest(
            "on_behalf_of requires an identity-bound API key".into(),
        )),
        (Some(caller), Some(target)) => {
            let resolved = validate_on_behalf_of(scope, caller, target).await?;
            Ok(Some(resolved))
        }
    }
}

/// Load and transform the group ceiling for a user identity.
///
/// `has_groups` is true whenever the user has any service grants. Bootstrapped
/// users always satisfy this (the Everyone group carries a write grant on the
/// `overslash` service from migration 023, and the Myself group adds grants
/// for anything the user owns), so for normal callers the ceiling is always
/// enforced. The `NoGroups` permissive path remains only for org-level keys
/// that have no identity at all and for theoretical edge cases where a
/// user-identity exists without ever being bootstrapped.
pub async fn load_ceiling(
    scope: &OrgScope,
    user_identity_id: Uuid,
) -> Result<ResolvedCeiling, crate::error::AppError> {
    let ceiling = scope.get_ceiling_for_user(user_identity_id).await?;
    let has_groups = !ceiling.grants.is_empty();

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
