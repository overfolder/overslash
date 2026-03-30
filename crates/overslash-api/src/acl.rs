use sqlx::PgPool;
use uuid::Uuid;

use overslash_core::types::acl::{AclAction, AclResourceType};

use crate::error::AppError;

/// Check that the calling identity has the required permission.
///
/// Backward compatibility: if the identity has zero role assignments (pre-ACL state),
/// the request is allowed through. Once an identity has any role assignment, all
/// permission checks are enforced.
pub async fn require_permission(
    pool: &PgPool,
    identity_id: Option<Uuid>,
    resource_type: AclResourceType,
    action: AclAction,
) -> Result<(), AppError> {
    let identity_id = identity_id
        .ok_or_else(|| AppError::Forbidden("no identity context".into()))?;

    // Backward compat: if no roles assigned, allow through
    if !overslash_db::repos::acl::has_any_assignments(pool, identity_id).await
        .map_err(|e| AppError::Internal(format!("acl check error: {e}")))?
    {
        return Ok(());
    }

    let allowed = overslash_db::repos::acl::check_permission(
        pool,
        identity_id,
        &resource_type.to_string(),
        &action.to_string(),
    )
    .await
    .map_err(|e| AppError::Internal(format!("acl check error: {e}")))?;

    if allowed {
        Ok(())
    } else {
        Err(AppError::Forbidden(format!(
            "missing permission: {action} on {resource_type}"
        )))
    }
}

/// Check that the calling identity is an org-admin.
pub async fn require_org_admin(
    pool: &PgPool,
    identity_id: Option<Uuid>,
) -> Result<(), AppError> {
    let identity_id = identity_id
        .ok_or_else(|| AppError::Forbidden("no identity context".into()))?;

    // Backward compat: if no roles assigned, allow through
    if !overslash_db::repos::acl::has_any_assignments(pool, identity_id).await
        .map_err(|e| AppError::Internal(format!("acl check error: {e}")))?
    {
        return Ok(());
    }

    let is_admin = overslash_db::repos::acl::is_org_admin(pool, identity_id)
        .await
        .map_err(|e| AppError::Internal(format!("acl check error: {e}")))?;

    if is_admin {
        Ok(())
    } else {
        Err(AppError::Forbidden("org-admin role required".into()))
    }
}
