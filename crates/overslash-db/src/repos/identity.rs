use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

const IDENTITY_COLUMNS: &str = "id, org_id, name, kind, external_id, email, metadata, parent_id, owner_id, depth, inherit_permissions, can_create_sub, max_sub_depth, created_at, updated_at";

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
    pub owner_id: Option<Uuid>,
    pub depth: i32,
    pub inherit_permissions: bool,
    pub can_create_sub: bool,
    pub max_sub_depth: Option<i32>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

pub async fn create(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
    kind: &str,
    external_id: Option<&str>,
) -> Result<IdentityRow, sqlx::Error> {
    let query = format!(
        "INSERT INTO identities (org_id, name, kind, external_id) VALUES ($1, $2, $3, $4)
         RETURNING {IDENTITY_COLUMNS}"
    );
    sqlx::query_as::<_, IdentityRow>(&query)
        .bind(org_id)
        .bind(name)
        .bind(kind)
        .bind(external_id)
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
    let query = format!(
        "INSERT INTO identities (org_id, name, kind, external_id, email, metadata)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING {IDENTITY_COLUMNS}"
    );
    sqlx::query_as::<_, IdentityRow>(&query)
        .bind(org_id)
        .bind(name)
        .bind(kind)
        .bind(external_id)
        .bind(email)
        .bind(metadata)
        .fetch_one(pool)
        .await
}

pub async fn find_by_email(pool: &PgPool, email: &str) -> Result<Option<IdentityRow>, sqlx::Error> {
    let query =
        format!("SELECT {IDENTITY_COLUMNS} FROM identities WHERE email = $1 AND kind = 'user'");
    sqlx::query_as::<_, IdentityRow>(&query)
        .bind(email)
        .fetch_optional(pool)
        .await
}

pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<IdentityRow>, sqlx::Error> {
    let query = format!("SELECT {IDENTITY_COLUMNS} FROM identities WHERE id = $1");
    sqlx::query_as::<_, IdentityRow>(&query)
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn list_by_org(pool: &PgPool, org_id: Uuid) -> Result<Vec<IdentityRow>, sqlx::Error> {
    let query =
        format!("SELECT {IDENTITY_COLUMNS} FROM identities WHERE org_id = $1 ORDER BY created_at");
    sqlx::query_as::<_, IdentityRow>(&query)
        .bind(org_id)
        .fetch_all(pool)
        .await
}

pub async fn delete(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM identities WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

// --- Hierarchy functions ---

pub struct CreateSubIdentity<'a> {
    pub org_id: Uuid,
    pub parent_id: Uuid,
    pub name: &'a str,
    pub kind: &'a str,
    pub inherit_permissions: bool,
    pub can_create_sub: bool,
    pub max_sub_depth: Option<i32>,
}

pub async fn create_sub_identity(
    pool: &PgPool,
    input: &CreateSubIdentity<'_>,
) -> Result<IdentityRow, sqlx::Error> {
    let parent = get_by_id(pool, input.parent_id)
        .await?
        .ok_or_else(|| sqlx::Error::RowNotFound)?;

    let depth = parent.depth + 1;
    let owner_id = if parent.kind == "user" {
        parent.id
    } else {
        parent.owner_id.unwrap_or(parent.id)
    };

    let query = format!(
        "INSERT INTO identities (org_id, name, kind, parent_id, owner_id, depth, inherit_permissions, can_create_sub, max_sub_depth)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING {IDENTITY_COLUMNS}"
    );
    sqlx::query_as::<_, IdentityRow>(&query)
        .bind(input.org_id)
        .bind(input.name)
        .bind(input.kind)
        .bind(input.parent_id)
        .bind(owner_id)
        .bind(depth)
        .bind(input.inherit_permissions)
        .bind(input.can_create_sub)
        .bind(input.max_sub_depth)
        .fetch_one(pool)
        .await
}

/// Walk from identity up to root via parent_id. Returns ordered root-to-leaf.
pub async fn get_ancestor_chain(
    pool: &PgPool,
    identity_id: Uuid,
) -> Result<Vec<IdentityRow>, sqlx::Error> {
    let query = format!(
        "WITH RECURSIVE ancestors AS (
            SELECT {IDENTITY_COLUMNS} FROM identities WHERE id = $1
            UNION ALL
            SELECT i.id, i.org_id, i.name, i.kind, i.external_id, i.email, i.metadata,
                   i.parent_id, i.owner_id, i.depth, i.inherit_permissions, i.can_create_sub,
                   i.max_sub_depth, i.created_at, i.updated_at
            FROM identities i
            JOIN ancestors a ON i.id = a.parent_id
        )
        SELECT * FROM ancestors ORDER BY depth ASC"
    );
    sqlx::query_as::<_, IdentityRow>(&query)
        .bind(identity_id)
        .fetch_all(pool)
        .await
}

/// Check if potential_ancestor is an ancestor of descendant.
pub async fn is_ancestor_of(
    pool: &PgPool,
    potential_ancestor_id: Uuid,
    descendant_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let chain = get_ancestor_chain(pool, descendant_id).await?;
    Ok(chain
        .iter()
        .any(|i| i.id == potential_ancestor_id && i.id != descendant_id))
}

/// List direct children of an identity.
pub async fn list_children(
    pool: &PgPool,
    parent_id: Uuid,
) -> Result<Vec<IdentityRow>, sqlx::Error> {
    let query = format!(
        "SELECT {IDENTITY_COLUMNS} FROM identities WHERE parent_id = $1 ORDER BY created_at"
    );
    sqlx::query_as::<_, IdentityRow>(&query)
        .bind(parent_id)
        .fetch_all(pool)
        .await
}

/// Delete identities that have exceeded their TTL.
pub async fn cleanup_expired_sub_identities(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result =
        sqlx::query("DELETE FROM identities WHERE ttl IS NOT NULL AND created_at + ttl < now()")
            .execute(pool)
            .await?;
    Ok(result.rows_affected())
}
