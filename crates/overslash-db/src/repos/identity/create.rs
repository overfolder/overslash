use sqlx::PgPool;
use uuid::Uuid;

use super::IdentityRow;

pub async fn create(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
    kind: &str,
    external_id: Option<&str>,
) -> Result<IdentityRow, sqlx::Error> {
    // `auto_call_on_approve` is seeded from the inverse of
    // `orgs.default_deferred_execution`: when the org has flipped its policy
    // to deferred-by-default, a new agent is born with auto-call OFF. The
    // value is meaningless for `user`-kind rows but storing it uniformly
    // avoids branching here.
    sqlx::query_as!(
        IdentityRow,
        "INSERT INTO identities (org_id, name, kind, external_id, auto_call_on_approve)
         VALUES ($1, $2, $3, $4, (SELECT NOT default_deferred_execution FROM orgs WHERE id = $1))
         RETURNING id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at",
        org_id,
        name,
        kind,
        external_id,
    )
    .fetch_one(pool)
    .await
}

pub async fn create_with_email(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
    kind: &str,
    external_id: Option<&str>,
    email: Option<&str>,
    metadata: serde_json::Value,
) -> Result<IdentityRow, sqlx::Error> {
    sqlx::query_as!(
        IdentityRow,
        "INSERT INTO identities (org_id, name, kind, external_id, email, metadata, auto_call_on_approve)
         VALUES ($1, $2, $3, $4, $5, $6, (SELECT NOT default_deferred_execution FROM orgs WHERE id = $1))
         RETURNING id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at",
        org_id,
        name,
        kind,
        external_id,
        email,
        metadata,
    )
    .fetch_one(pool)
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn create_with_parent(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
    kind: &str,
    external_id: Option<&str>,
    parent_id: Uuid,
    depth: i32,
    owner_id: Uuid,
    inherit_permissions: bool,
) -> Result<IdentityRow, sqlx::Error> {
    sqlx::query_as!(
        IdentityRow,
        "INSERT INTO identities (org_id, name, kind, external_id, parent_id, depth, owner_id, inherit_permissions, auto_call_on_approve)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, (SELECT NOT default_deferred_execution FROM orgs WHERE id = $1))
         RETURNING id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at",
        org_id,
        name,
        kind,
        external_id,
        parent_id,
        depth,
        owner_id,
        inherit_permissions,
    )
    .fetch_one(pool)
    .await
}
